// SPDX-License-Identifier: MPL-2.0
#include "privileged_broker.h"
#include "broker_io.h"
#include "broker_security.h"
#include "broker_protocol.h"
#include "broker_passive_connect.h"
#include "broker_development_policy.h"
#include "installation_security.h"
#include "distribution_mode.h"
#include "portable_runtime.h"
#include "portable_runtime_client.h"
#include "maintenance_state.h"
#include "runtime_ownership.h"
#include "service_idle_handoff.h"
#include "service_handoff_mutex.h"
#include "diagnostics_snapshot.h"

#include "openvpn_tunnel.h"
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
#include "openvpn_core_module.h"
#endif
#include "network_protection.h"
#include "protected_store.h"
#include "privileged_runtime.h"
#include "wireguard_tunnel.h"

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <softpub.h>
#include <wintrust.h>
#include <winsvc.h>

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <flutter/standard_method_codec.h>

namespace {

constexpr wchar_t kBrokerSwitch[] = L"--fuzevpn-privileged-broker";
constexpr wchar_t kPortableBrokerSwitch[] = L"--fuzevpn-portable-broker";
constexpr wchar_t kServiceSwitch[] = L"--fuzevpn-vpn-service";
constexpr wchar_t kInstallServiceSwitch[] = L"--fuzevpn-install-service";
constexpr wchar_t kUninstallServiceSwitch[] =
    L"--fuzevpn-uninstall-service";
constexpr wchar_t kVpnServiceName[] = L"FuzeVPNService";
constexpr wchar_t kVpnServiceDisplayName[] = L"FuzeVPN — service VPN";
constexpr wchar_t kServiceExecutableName[] = L"fuzevpn-service.exe";
constexpr wchar_t kUiExecutableName[] = L"fuzevpn_windows.exe";
constexpr wchar_t kServicePipeName[] = L"\\\\.\\pipe\\FuzeVPN-Service-v1";
constexpr wchar_t kServiceReadyEventName[] =
    L"Global\\FuzeVPN-Service-Ready-v1";
constexpr wchar_t kServiceWireGuardStatusEventName[] =
    L"Global\\FuzeVPN-Service-WireGuard-v1";
constexpr wchar_t kServiceOpenVpnStatusEventName[] =
    L"Global\\FuzeVPN-Service-OpenVPN-v1";
constexpr uint32_t kFrameMagic = 0x31455056;  // "VPE1", little endian.
constexpr uint32_t kFrameVersion = 1;
constexpr uint32_t kResponseAckMagic = 0x314B4341;  // "ACK1".
constexpr uint32_t kMaximumPayloadBytes = 1024 * 1024;
constexpr DWORD kBrokerStartupTimeoutMs = 30000;
constexpr DWORD kBrokerResponseTimeoutMs = 75000;

struct FrameHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t payload_size;
};

enum class ExchangeFailure {
  kNone,
  kBrokerUnavailable,
  kInstallationRequired,
  kRequestWriteFailed,
  kResponseUnavailable,
};

std::mutex client_mutex;
HANDLE launched_broker_process = nullptr;  // Retained until dispatcher shutdown.
std::filesystem::path launched_portable_engine;
std::atomic<DWORD> launched_broker_pid{0};
HANDLE client_cancel_event = nullptr;
SERVICE_STATUS_HANDLE service_status_handle = nullptr;
HANDLE service_stop_event = nullptr;
HANDLE service_yield_event = nullptr;
std::atomic<bool> service_accepts_yield{false};
fuzevpn_handoff::IdleRequest service_idle_request;
std::atomic<DWORD> service_checkpoint{0};
fuzevpn::RuntimeOwnership runtime_ownership;

void Wipe(std::vector<uint8_t>* bytes) {
  if (bytes != nullptr && !bytes->empty()) {
    SecureZeroMemory(bytes->data(), bytes->size());
    bytes->clear();
  }
}

std::optional<std::filesystem::path> CurrentExecutablePath() {
  std::wstring executable(32768, L'\0');
  const DWORD length = GetModuleFileNameW(
      nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  if (length == 0 || length >= executable.size()) {
    return std::nullopt;
  }
  executable.resize(length);
  return std::filesystem::path(executable);
}

std::optional<std::filesystem::path> SiblingExecutable(
    const wchar_t* filename) {
  const auto current = CurrentExecutablePath();
  if (!current.has_value()) {
    return std::nullopt;
  }
  return current->parent_path() / filename;
}

std::wstring PipeName(DWORD parent_process_id) {
  return L"\\\\.\\pipe\\FuzeVPN-PrivilegedBroker-" +
         std::to_wstring(parent_process_id);
}

std::wstring ReadyEventName(DWORD parent_process_id) {
  return L"Local\\FuzeVPN-PrivilegedBroker-Ready-" +
         std::to_wstring(parent_process_id);
}

std::wstring TunnelStatusEventName(DWORD parent_process_id,
                                   const std::string& scope) {
  const wchar_t* suffix = scope == "wireguard" ? L"WireGuard" : L"OpenVPN";
  return L"Local\\FuzeVPN-PrivilegedBroker-" + std::wstring(suffix) + L"-" +
         std::to_wstring(parent_process_id);
}

LONG FileTrustStatus(const std::wstring& executable) {
  WINTRUST_FILE_INFO file{};
  file.cbStruct = sizeof(file);
  file.pcwszFilePath = executable.c_str();
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust);
  trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust.dwUnionChoice = WTD_CHOICE_FILE;
  trust.pFile = &file;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  const LONG status = WinVerifyTrust(nullptr, &policy, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policy, &trust);
  return status;
}

bool IsFileTrusted(const std::wstring& executable) {
  return FileTrustStatus(executable) == ERROR_SUCCESS;
}

bool IsUnsignedDevelopmentPair() {
  const auto ui = SiblingExecutable(kUiExecutableName);
  const auto service = SiblingExecutable(kServiceExecutableName);
  return ui.has_value() && service.has_value() &&
         FileTrustStatus(ui->wstring()) == TRUST_E_NOSIGNATURE &&
         FileTrustStatus(service->wstring()) == TRUST_E_NOSIGNATURE;
}

bool IsCurrentExecutableTrusted() {
  const auto executable = CurrentExecutablePath();
  return executable.has_value() && IsFileTrusted(executable->wstring());
}

bool QueryProcessImage(HANDLE process, std::wstring* image) {
  image->assign(32768, L'\0');
  DWORD size = static_cast<DWORD>(image->size());
  if (!QueryFullProcessImageNameW(process, 0, image->data(), &size) ||
      size == 0) {
    image->clear();
    return false;
  }
  image->resize(size);
  return true;
}

bool IsTrustedUiProcess(HANDLE process) {
  std::wstring client_image;
  if (!QueryProcessImage(process, &client_image)) {
    return false;
  }
  const auto expected_ui = SiblingExecutable(kUiExecutableName);
  if (!expected_ui.has_value()) {
    return false;
  }
  const std::wstring expected = expected_ui->wstring();
  return CompareStringOrdinal(client_image.c_str(), -1, expected.c_str(), -1,
                              TRUE) == CSTR_EQUAL &&
         IsFileTrusted(client_image);
}

class ScopedProcessInspectionPrivilege final {
 public:
  ScopedProcessInspectionPrivilege() {
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY |
        TOKEN_ADJUST_PRIVILEGES, &token_)) return;
    TOKEN_PRIVILEGES requested{};
    requested.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME,
                              &requested.Privileges[0].Luid)) return;
    requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    DWORD returned = 0;
    // A different administrator's UAC token may need this existing privilege
    // to inspect the parent token. It is restored before handling any command.
    restore_ = AdjustTokenPrivileges(token_, FALSE, &requested,
        sizeof(previous_), &previous_, &returned) != FALSE;
  }
  ~ScopedProcessInspectionPrivilege() {
    if (restore_)
      AdjustTokenPrivileges(token_, FALSE, &previous_, 0, nullptr, nullptr);
    if (token_ != nullptr) CloseHandle(token_);
  }
  ScopedProcessInspectionPrivilege(const ScopedProcessInspectionPrivilege&) = delete;
  ScopedProcessInspectionPrivilege& operator=(const ScopedProcessInspectionPrivilege&) = delete;

 private:
  HANDLE token_ = nullptr;
  TOKEN_PRIVILEGES previous_{};
  bool restore_ = false;
};

HANDLE ServiceClientToken(HANDLE pipe) {
  ULONG process_id = 0;
  if (!GetNamedPipeClientProcessId(pipe, &process_id) || process_id == 0) {
    return nullptr;
  }
  ScopedProcessInspectionPrivilege inspection_privilege;
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               static_cast<DWORD>(process_id));
  if (process == nullptr || !IsTrustedUiProcess(process)) {
    if (process != nullptr) CloseHandle(process);
    return nullptr;
  }
  HANDLE process_token = nullptr;
  HANDLE impersonation_token = nullptr;
  if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE,
                       &process_token)) {
    DuplicateTokenEx(process_token, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr,
                     SecurityImpersonation, TokenImpersonation,
                     &impersonation_token);
    CloseHandle(process_token);
  }
  CloseHandle(process);
  return impersonation_token;
}

bool WaitForOverlapped(HANDLE pipe, HANDLE cancel, OVERLAPPED* operation,
                       DWORD* transferred, ULONGLONG deadline = 0) {
  return fuzevpn_ipc::AwaitOperation(pipe, cancel, operation, transferred,
                                    deadline);
}

bool ReadExactOverlapped(HANDLE pipe, HANDLE cancel, void* buffer, DWORD size,
                         ULONGLONG deadline = 0) {
  return fuzevpn_ipc::Transfer(pipe, cancel, buffer, size, false,
      deadline == 0 ? GetTickCount64() + kBrokerResponseTimeoutMs : deadline);
}

bool WriteExactOverlapped(HANDLE pipe, HANDLE cancel, const void* buffer,
                          DWORD size, ULONGLONG deadline = 0) {
  return fuzevpn_ipc::Transfer(pipe, cancel, const_cast<void*>(buffer), size, true,
      deadline == 0 ? GetTickCount64() + kBrokerResponseTimeoutMs : deadline);
}

bool ReadFrameOverlapped(HANDLE pipe, HANDLE parent,
                         std::vector<uint8_t>* payload,
                         ULONGLONG deadline = 0) {
  if (deadline == 0) deadline = GetTickCount64() + kBrokerResponseTimeoutMs;
  FrameHeader header{};
  if (!ReadExactOverlapped(pipe, parent, &header, sizeof(header), deadline) ||
      header.magic != kFrameMagic || header.version != kFrameVersion ||
      header.payload_size == 0 ||
      header.payload_size > kMaximumPayloadBytes) {
    return false;
  }
  payload->assign(header.payload_size, 0);
  return ReadExactOverlapped(pipe, parent, payload->data(),
                             header.payload_size, deadline);
}

bool WriteFrameOverlapped(HANDLE pipe, HANDLE parent,
                          const std::vector<uint8_t>& payload,
                          ULONGLONG deadline = 0) {
  if (deadline == 0) deadline = GetTickCount64() + kBrokerResponseTimeoutMs;
  if (payload.empty() || payload.size() > kMaximumPayloadBytes) {
    return false;
  }
  const FrameHeader header{kFrameMagic, kFrameVersion,
                           static_cast<uint32_t>(payload.size())};
  return WriteExactOverlapped(pipe, parent, &header, sizeof(header), deadline) &&
         WriteExactOverlapped(pipe, parent, payload.data(),
                              header.payload_size, deadline);
}

bool WaitForPipeClient(HANDLE pipe, HANDLE parent, HANDLE wake = nullptr) {
  OVERLAPPED connection{};
  connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (connection.hEvent == nullptr) {
    return false;
  }
  bool connected = ConnectNamedPipe(pipe, &connection) != FALSE;
  if (!connected) {
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
      connected = true;
    } else if (error == ERROR_IO_PENDING) {
      DWORD transferred = 0;
      if (!wake) connected = WaitForOverlapped(pipe, parent, &connection, &transferred);
      else {
        HANDLE waits[]{connection.hEvent, parent, wake};
        const DWORD state = WaitForMultipleObjects(3, waits, FALSE, INFINITE);
        connected = GetOverlappedResult(pipe, &connection, &transferred, FALSE) != FALSE;
        if (!connected) {
          CancelIoEx(pipe, &connection);
          GetOverlappedResult(pipe, &connection, &transferred, TRUE);
          SetLastError(state == WAIT_FAILED ? GetLastError() : ERROR_CANCELLED);
        }
      }
    }
  }
  CloseHandle(connection.hEvent);
  return connected;
}

bool TokenUserSid(HANDLE token, std::vector<BYTE>* storage, PSID* sid) {
  DWORD required = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &required);
  if (required == 0) {
    return false;
  }
  storage->assign(required, 0);
  if (!GetTokenInformation(token, TokenUser, storage->data(), required,
                           &required)) {
    storage->clear();
    return false;
  }
  const auto* user = reinterpret_cast<const TOKEN_USER*>(storage->data());
  if (!IsValidSid(user->User.Sid)) {
    storage->clear();
    return false;
  }
  *sid = user->User.Sid;
  return true;
}

bool ProcessUserSid(HANDLE process, std::vector<BYTE>* storage, PSID* sid) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
    return false;
  }
  const bool success = TokenUserSid(token, storage, sid);
  CloseHandle(token);
  return success;
}

bool IsElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;
  }
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0;
  const bool elevated =
      GetTokenInformation(token, TokenElevation, &elevation,
                          sizeof(elevation), &returned) &&
      elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return elevated;
}

bool IsExpectedProcessImage(HANDLE process, const wchar_t* filename) {
  std::wstring image;
  const auto expected = SiblingExecutable(filename);
  return expected.has_value() && QueryProcessImage(process, &image) &&
         CompareStringOrdinal(image.c_str(), -1, expected->c_str(), -1,
                              TRUE) == CSTR_EQUAL;
}

bool IsProcessElevated(HANDLE process) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0;
  const bool result = GetTokenInformation(token, TokenElevation, &elevation,
      sizeof(elevation), &returned) && elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return result;
}

bool IsLocalSystemProcess(HANDLE process) {
  std::vector<BYTE> storage;
  PSID sid = nullptr;
  return ProcessUserSid(process, &storage, &sid) &&
         IsWellKnownSid(sid, WinLocalSystemSid);
}

bool GrantInteractiveInspection(HANDLE object, DWORD rights) {
  BYTE sid_buffer[SECURITY_MAX_SID_SIZE]{};
  DWORD sid_size = sizeof(sid_buffer);
  if (!CreateWellKnownSid(WinInteractiveSid, nullptr, sid_buffer, &sid_size))
    return false;
  PACL existing = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (GetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &existing, nullptr, &descriptor) != ERROR_SUCCESS)
    return false;
  EXPLICIT_ACCESSW access{};
  access.grfAccessPermissions = rights;
  access.grfAccessMode = GRANT_ACCESS;
  access.grfInheritance = NO_INHERITANCE;
  access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid_buffer);
  PACL updated = nullptr;
  const bool success = SetEntriesInAclW(1, &access, existing, &updated) ==
      ERROR_SUCCESS && SetSecurityInfo(object, SE_KERNEL_OBJECT,
          DACL_SECURITY_INFORMATION, nullptr, nullptr, updated, nullptr) ==
      ERROR_SUCCESS;
  if (updated != nullptr) LocalFree(updated);
  LocalFree(descriptor);
  return success;
}

bool AllowServerIdentityInspection() {
  // Standard users must be able to authenticate this elevated process. Grant
  // only identity inspection: never process write/create-thread or token
  // duplication/impersonation rights. Preserve every existing ACE.
  if (!GrantInteractiveInspection(GetCurrentProcess(),
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)) return false;
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL |
                         WRITE_DAC, &token)) return false;
  const bool granted = GrantInteractiveInspection(token, TOKEN_QUERY);
  CloseHandle(token);
  return granted;
}

std::optional<DWORD> QueryServiceProcessId(bool* running = nullptr) {
  if (running != nullptr) *running = false;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) return std::nullopt;
  SC_HANDLE service = OpenServiceW(manager, kVpnServiceName,
                                   SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const DWORD error = GetLastError();
    CloseServiceHandle(manager);
    SetLastError(error == ERROR_SERVICE_DOES_NOT_EXIST ? ERROR_SUCCESS : error);
    return error == ERROR_SERVICE_DOES_NOT_EXIST ? std::optional<DWORD>(0) :
                                                 std::nullopt;
  }
  SERVICE_STATUS_PROCESS status{};
  DWORD returned = 0;
  const bool queried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
      reinterpret_cast<BYTE*>(&status), sizeof(status), &returned) != FALSE;
  const DWORD query_error = queried ? ERROR_SUCCESS : GetLastError();
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!queried) {
    SetLastError(query_error);
    return std::nullopt;
  }
  if (status.dwCurrentState == SERVICE_STOPPED) return 0;
  // A service still starting/stopping with no PID is not confirmed absent.
  if (status.dwProcessId == 0) {
    SetLastError(ERROR_NOT_READY);
    return std::nullopt;
  }
  if (running != nullptr) *running = status.dwCurrentState == SERVICE_RUNNING;
  return status.dwProcessId;
}

DWORD ServiceProcessId() {
  return QueryServiceProcessId().value_or(0);
}

bool ClientCancelled() {
  return client_cancel_event != nullptr &&
         WaitForSingleObject(client_cancel_event, 0) == WAIT_OBJECT_0;
}

bool AuthenticatePipeServer(HANDLE pipe, bool service) {
  ULONG server_id = 0;
  if (!GetNamedPipeServerProcessId(pipe, &server_id) || server_id == 0)
    return false;
  if (service) {
    if (server_id != ServiceProcessId()) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                  FALSE, server_id);
    if (process == nullptr) return false;
    const auto expected = SiblingExecutable(kServiceExecutableName);
    const bool valid = expected.has_value() &&
        WaitForSingleObject(process, 0) == WAIT_TIMEOUT &&
        IsExpectedProcessImage(process, kServiceExecutableName) &&
        IsLocalSystemProcess(process) && IsFileTrusted(expected->wstring());
    CloseHandle(process);
    return valid;
  }
  // The handle came from our own ShellExecuteEx call and is retained: a
  // pre-created named pipe or recycled PID cannot become an authorized broker.
  if (launched_broker_process == nullptr ||
      server_id != GetProcessId(launched_broker_process) ||
      WaitForSingleObject(launched_broker_process, 0) != WAIT_TIMEOUT) return false;
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_id);
  if (process == nullptr) return false;
  std::wstring actual;
  const bool portable = !launched_portable_engine.empty();
  const bool image_valid = portable
      ? QueryProcessImage(process, &actual) &&
          fuzevpn_installation::SamePath(actual, launched_portable_engine.wstring())
      : IsExpectedProcessImage(process, kServiceExecutableName) && IsUnsignedDevelopmentPair();
  // Portable identity was established through the authenticated bootstrap and
  // retained process handle. Never accept an arbitrary same-named process.
  const bool valid = image_valid && IsProcessElevated(process);
  CloseHandle(process);
  return valid;
}

bool IsExpectedPipeClientProcess(HANDLE pipe, DWORD expected_process_id) {
  ULONG client_process_id = 0;
  return GetNamedPipeClientProcessId(pipe, &client_process_id) &&
         client_process_id == expected_process_id;
}

class EncodedMethodResult final
    : public flutter::MethodResult<flutter::EncodableValue> {
 public:
  std::vector<uint8_t> Take() { return std::move(response_); }
  const std::string& error_code() const { return error_code_; }
  void IncludeOwnership(bool owned_by_another_user) {
    owned_by_another_user_ = owned_by_another_user;
  }

 protected:
  void SuccessInternal(const flutter::EncodableValue* result) override {
    std::optional<flutter::EncodableValue> annotated;
    if (owned_by_another_user_.has_value() && result != nullptr) {
      if (const auto* map = std::get_if<flutter::EncodableMap>(result)) {
        auto copy = *map;
        copy[flutter::EncodableValue("ownedByAnotherUser")] =
            flutter::EncodableValue(*owned_by_another_user_);
        annotated = flutter::EncodableValue(std::move(copy));
        result = &*annotated;
      }
    }
    auto encoded = flutter::StandardMethodCodec::GetInstance()
                       .EncodeSuccessEnvelope(result);
    if (encoded != nullptr) {
      response_ = std::move(*encoded);
    }
  }

  void ErrorInternal(const std::string& error_code,
                     const std::string& error_message,
                     const flutter::EncodableValue* error_details) override {
    error_code_ = error_code;
    auto encoded = flutter::StandardMethodCodec::GetInstance()
                       .EncodeErrorEnvelope(error_code, error_message,
                                            error_details);
    if (encoded != nullptr) {
      response_ = std::move(*encoded);
    }
  }

  void NotImplementedInternal() override {
    auto encoded = flutter::StandardMethodCodec::GetInstance()
                       .EncodeErrorEnvelope("not_implemented",
                                            "Unsupported broker operation.");
    if (encoded != nullptr) {
      response_ = std::move(*encoded);
    }
  }

 private:
  std::vector<uint8_t> response_;
  std::string error_code_;
  std::optional<bool> owned_by_another_user_;
};

bool IsSafeDiagnosticIdentifier(const std::string& value) {
  if (value.empty() || value.size() > 80) return false;
  for (const char character : value) {
    if (!((character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '_' ||
          character == '.' || character == '-')) {
      return false;
    }
  }
  return true;
}

void AppendNativeDiagnostic(const std::string& area,
                            const std::string& event,
                            const std::string& code = "") {
  if (!IsSafeDiagnosticIdentifier(area) ||
      !IsSafeDiagnosticIdentifier(event) ||
      (!code.empty() && !IsSafeDiagnosticIdentifier(code))) {
    return;
  }
  SYSTEMTIME now{};
  GetSystemTime(&now);
  char timestamp[32]{};
  std::snprintf(timestamp, sizeof(timestamp),
                "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", now.wYear,
                now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
                now.wMilliseconds);
  std::string text = std::string(timestamp) + " area=" + area + " event=" + event;
  if (!code.empty()) text += " code=" + code;
  text += "\r\n";
  WriteUserDiagnostic("native_diagnostic.log", text, true);
}

void WriteSafeDiagnostic(const std::string& operation,
                         const std::string& error_code) {
  if (error_code.empty() || error_code.size() > 80 ||
      (operation != "wireguard.connect" &&
       operation != "wireguard.prepareConnection" &&
       operation != "wireguard.prepareIdentityForAccount" &&
       operation != "wireguard.recreateIdentityForAccount" &&
       operation != "wireguard.resetIdentity" &&
       operation != "openvpn.importAndConnect" &&
       operation != "openvpn.prepareConnection" &&
       operation != "openvpn.suspendForMigration")) {
    return;
  }
  for (const char character : error_code) {
    if (!((character >= 'a' && character <= 'z') || character == '_')) {
      return;
    }
  }
  WriteUserDiagnostic("native_last_error.txt", operation + '=' + error_code, false);
  AppendNativeDiagnostic(operation.substr(0, operation.find('.')),
                         "native_error", error_code);
}

void WriteSafeOperation(const std::string& operation, const char* state) {
  const bool allowed_operation =
      operation == "wireguard.connect" ||
      operation == "wireguard.prepareConnection" ||
      operation == "wireguard.disconnect" ||
      operation == "wireguard.prepareIdentityForAccount" ||
      operation == "wireguard.recreateIdentityForAccount" ||
      operation == "wireguard.resetIdentity" ||
      operation == "openvpn.importAndConnect" ||
      operation == "openvpn.prepareConnection" ||
      operation == "openvpn.suspendForMigration" ||
      operation == "openvpn.disconnect";
  const bool allowed_state = strcmp(state, "started") == 0 ||
                             strcmp(state, "succeeded") == 0 ||
                             strcmp(state, "failed") == 0;
  if (!allowed_operation || !allowed_state) {
    return;
  }
  WriteUserDiagnostic("native_last_operation.txt", operation + '=' + state, false);
  AppendNativeDiagnostic(operation.substr(0, operation.find('.')),
                         operation.substr(operation.find('.') + 1) + "_" +
                             state);
}

void WriteSafeStage(const char* stage) {
  constexpr const char* kAllowedStages[] = {
      "broker_ready",          "client_connected",
      "request_read",          "client_authenticated",
      "request_decoded",       "wireguard_dispatch",
      "wireguard_complete",    "openvpn_dispatch",
      "openvpn_complete",      "response_acknowledged",
      "shutdown_pending",      "shutdown_unconfirmed",
      "shutdown_complete",
  };
  bool allowed = false;
  for (const char* candidate : kAllowedStages) {
    if (strcmp(stage, candidate) == 0) {
      allowed = true;
      break;
    }
  }
  if (!allowed) {
    return;
  }
  WriteUserDiagnostic("native_stage.txt", stage, false);
  AppendNativeDiagnostic("broker", stage);
}

void PublishTunnelStatus(HANDLE wireguard_status, HANDLE openvpn_status) {
  if (IsWireGuardTunnelConnected()) {
    SetEvent(wireguard_status);
  } else {
    ResetEvent(wireguard_status);
  }
  if (IsOpenVpnTunnelConnected()) {
    SetEvent(openvpn_status);
  } else {
    ResetEvent(openvpn_status);
  }
}

std::optional<bool> RuntimeConfirmedIdle() {
  if (!IsNetworkProtectionStateKnown()) return std::nullopt;
  const auto wireguard_stopped = IsWireGuardTunnelStopped();
  if (!wireguard_stopped.has_value()) return std::nullopt;
  return *wireguard_stopped && IsOpenVpnTunnelStopped() &&
      !IsNetworkProtectionActive(NetworkProtectionOwner::wire_guard) &&
      !IsNetworkProtectionActive(NetworkProtectionOwner::open_vpn);
}

bool IsRuntimeStatusMethod(const std::string& name) {
  return name == "diagnostics.collectSnapshot" || name == "wireguard.isConnected" || name == "openvpn.isConnected" ||
      name == "wireguard.isNetworkProtectionActive" ||
      name == "openvpn.isNetworkProtectionActive" ||
      name == "wireguard.networkProtectionStatus" ||
      name == "openvpn.networkProtectionStatus";
}

bool MayReleaseRuntimeOwnership(const std::string& name, bool had_owner) {
  return name == "wireguard.disconnect" || name == "openvpn.disconnect" ||
      name == "wireguard.resetIdentity" || name == "openvpn.deleteProfile" ||
      // A standalone identity/cache lookup borrows the runtime only briefly.
      // Inside an existing prepare/enrol/connect sequence it must preserve
      // ownership even if all WFP options are disabled and no tunnel exists yet.
      (!had_owner && (name == "wireguard.prepareIdentityForAccount" ||
       name == "wireguard.recreateIdentityForAccount" ||
       name == "wireguard.getOrCreatePublicKey" ||
       name == "openvpn.getOrCreateCsr" || name == "openvpn.renewCsr" ||
       name == "wireguard.reconnect" || name == "openvpn.reconnect"));
}

std::vector<uint8_t> Dispatch(const std::vector<uint8_t>& request,
                              bool* shutdown_requested,
                              HANDLE wireguard_status,
                              HANDLE openvpn_status,
                              bool allow_shutdown) {
  EncodedMethodResult result;
  if (!fuzevpn_ipc::ValidateMethodRequest(request.data(), request.size())) {
    result.Error("invalid_request", "Invalid broker request.");
    return result.Take();
  }
  const auto& codec = flutter::StandardMethodCodec::GetInstance();
  auto call = codec.DecodeMethodCall(request);
  if (call == nullptr) {
    result.Error("invalid_request", "Invalid broker request.");
    return result.Take();
  }
  WriteSafeStage("request_decoded");

  const std::string& name = call->method_name();
  WriteSafeOperation(name, "started");
  if (name == "broker.shutdown") {
    fuzevpn_diagnostics::InvalidateRuntimeSnapshots();
    if (allow_shutdown) {
      *shutdown_requested = true;
      result.Success();
    } else {
      result.NotImplemented();
    }
    return result.Take();
  }

  const std::string user = ProtectedStoreUserId();
  if (user.empty()) {
    result.Error("runtime_status_unavailable", "Windows account is unavailable.");
    return result.Take();
  }
  if (name == "diagnostics.collectSnapshot") {
    // Authenticated, query-only, and never reserves/releases tunnel ownership.
    // A damaged WFP session is reported as unknown rather than bypassing the
    // report entirely. Other users never receive retained engine evidence.
    try {
      const bool other = runtime_ownership.OwnedByAnotherUser(user);
      result.Success(flutter::EncodableValue(fuzevpn_diagnostics::RequestRuntimeSnapshot(
          user, runtime_ownership.HasOwner() && !other, other)));
    } catch (...) {
      result.Error("runtime_status_unavailable", "Windows diagnostics are unavailable.");
    }
    return result.Take();
  }
  const bool is_status = IsRuntimeStatusMethod(name);
  if (fuzevpn_maintenance::IsBlocked() && !is_status &&
      name != "wireguard.disconnect" && name != "openvpn.disconnect") {
    result.Error("maintenance_in_progress", "FuzeVPN is being updated. Retry after setup completes.");
    return result.Take();
  }
  if (is_status && !IsNetworkProtectionStateKnown()) {
    result.Error("runtime_status_unavailable",
                 "Windows could not verify the VPN filtering policy.");
    return result.Take();
  }
  const bool is_resolver = name == "wireguard.resolveApiAddresses";
  const bool had_owner = runtime_ownership.HasOwner();
  if (name == "wireguard.networkProtectionStatus" ||
      name == "openvpn.networkProtectionStatus") {
    result.IncludeOwnership(runtime_ownership.OwnedByAnotherUser(user));
  }
  if (is_resolver && runtime_ownership.OwnedByAnotherUser(user)) {
    result.Error("runtime_owned_by_another_user",
                 "The VPN is managed by another Windows account.");
    return result.Take();
  }
  if (!is_status && !is_resolver) {
    fuzevpn_diagnostics::InvalidateRuntimeSnapshots();
    const auto authorization = runtime_ownership.AuthorizeMutation(
        user, had_owner ? std::optional<bool>() : RuntimeConfirmedIdle());
    if (authorization != fuzevpn::RuntimeOwnership::Authorization::allowed) {
      result.Error(
          authorization == fuzevpn::RuntimeOwnership::Authorization::another_user ?
              "runtime_owned_by_another_user" : "runtime_status_unavailable",
          "Windows could not authorize control of the VPN runtime.");
      return result.Take();
    }
  }

  constexpr char kWireGuardPrefix[] = "wireguard.";
  constexpr char kOpenVpnPrefix[] = "openvpn.";
  const flutter::EncodableValue* arguments = call->arguments();
  auto copy_arguments = [&]() -> std::unique_ptr<flutter::EncodableValue> {
    return arguments == nullptr
               ? nullptr
               : std::make_unique<flutter::EncodableValue>(*arguments);
  };

  if (name.rfind(kWireGuardPrefix, 0) == 0) {
    WriteSafeStage("wireguard_dispatch");
    flutter::MethodCall<flutter::EncodableValue> scoped(
        name.substr(sizeof(kWireGuardPrefix) - 1), copy_arguments());
    HandleWireGuardPrivilegedCall(scoped, &result);
    PublishTunnelStatus(wireguard_status, openvpn_status);
    WriteSafeStage("wireguard_complete");
  } else if (name.rfind(kOpenVpnPrefix, 0) == 0) {
    WriteSafeStage("openvpn_dispatch");
    flutter::MethodCall<flutter::EncodableValue> scoped(
        name.substr(sizeof(kOpenVpnPrefix) - 1), copy_arguments());
    HandleOpenVpnPrivilegedCall(scoped, &result);
    PublishTunnelStatus(wireguard_status, openvpn_status);
    WriteSafeStage("openvpn_complete");
  } else {
    result.NotImplemented();
  }
  if (!is_status && !is_resolver &&
      (MayReleaseRuntimeOwnership(name, had_owner) ||
       (!had_owner && !result.error_code().empty()))) {
    runtime_ownership.ReleaseIfIdle(RuntimeConfirmedIdle());
  }
  WriteSafeDiagnostic(name, result.error_code());
  WriteSafeOperation(name,
                     result.error_code().empty() ? "succeeded" : "failed");
  return result.Take();
}

bool StopBrokerTunnels() {
  fuzevpn_diagnostics::InvalidateRuntimeSnapshots();
  EncodedMethodResult ignored_wireguard;
  flutter::MethodCall<flutter::EncodableValue> disconnect_wireguard(
      "disconnect", nullptr);
  HandleWireGuardPrivilegedCall(disconnect_wireguard, &ignored_wireguard);

  EncodedMethodResult ignored_openvpn;
  flutter::MethodCall<flutter::EncodableValue> disconnect_openvpn(
      "disconnect", nullptr);
  HandleOpenVpnPrivilegedCall(disconnect_openvpn, &ignored_openvpn);

  // Normal WireGuard disconnects keep an inert service registration so a
  // reconnect does not race SCM deletion. The privileged runtime owns that
  // registration and removes it when the runtime itself exits or recovers.
  if (ignored_wireguard.error_code().empty()) RemoveWireGuardTunnelService();
  return ignored_wireguard.error_code().empty() &&
      ignored_openvpn.error_code().empty();
}

bool CreatePipeSecurity(SECURITY_ATTRIBUTES* attributes,
                        PSECURITY_DESCRIPTOR* descriptor, HANDLE client_process,
                        bool events) {
  std::vector<BYTE> sid_storage;
  PSID sid = nullptr;
  if (!ProcessUserSid(client_process, &sid_storage, &sid)) return false;
  LPWSTR sid_text = nullptr;
  if (!ConvertSidToStringSidW(sid, &sid_text)) return false;
  const std::wstring sddl =
      L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;" +
      std::wstring(events ? L"0x00100000" : L"0x00100083") + L";;;" +
      sid_text + L")S:(ML;;NW;;;ME)";
  LocalFree(sid_text);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, descriptor, nullptr)) return false;
  attributes->nLength = sizeof(*attributes);
  attributes->lpSecurityDescriptor = *descriptor;
  attributes->bInheritHandle = FALSE;
  return true;
}

bool CreateServiceObjectSecurity(SECURITY_ATTRIBUTES* attributes,
                                 PSECURITY_DESCRIPTOR* descriptor,
                                 bool events = false) {
  const wchar_t* sddl = events ? fuzevpn_ipc::kServiceEventSddl :
                                fuzevpn_ipc::kServicePipeSddl;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl, SDDL_REVISION_1, descriptor, nullptr)) return false;
  attributes->nLength = sizeof(*attributes);
  attributes->lpSecurityDescriptor = *descriptor;
  attributes->bInheritHandle = FALSE;
  return true;
}

void SetVpnServiceStatus(DWORD state, DWORD win32_exit_code = NO_ERROR,
                         DWORD wait_hint = 0) {
  if (service_status_handle == nullptr) {
    return;
  }
  SERVICE_STATUS status{};
  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = state;
  status.dwControlsAccepted =
      state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                               : 0;
  status.dwWin32ExitCode = win32_exit_code;
  status.dwWaitHint = wait_hint;
  if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
    status.dwCheckPoint = service_checkpoint.fetch_add(1) + 1;
  else service_checkpoint.store(0);
  SetServiceStatus(service_status_handle, &status);
}

void DrainBrokerTunnels(HANDLE ready_event, bool service) {
  // Once requests stop, never advertise a usable endpoint while a native
  // driver or a network cleanup action still prevents confirmed shutdown.
  ResetEvent(ready_event);
  WriteSafeStage("shutdown_pending");
  bool reported_unconfirmed = false;
  for (;;) {
    if (service) SetVpnServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 60000);
    if (StopBrokerTunnels()) break;
    if (!reported_unconfirmed) {
      WriteSafeStage("shutdown_unconfirmed");
      reported_unconfirmed = true;
    }
    // Keep the worker, machine lock and WFP session alive. A Windows driver
    // call that never returns cannot safely be forced from this process; the
    // service stays STOP_PENDING and this broker cannot accept new requests.
    Sleep(250);
  }
  WriteSafeStage("shutdown_complete");
}

DWORD WINAPI VpnServiceControlHandler(DWORD control, DWORD, void*, void*) {
  if (control == fuzevpn_handoff::kYieldIdleControl) {
    // The existing service DACL grants this user-defined control only to
    // administrators/SYSTEM. Never inspect mutable ownership on this thread.
    if (!service_yield_event || !service_accepts_yield.load()) return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
    if (!service_idle_request.Queue(GetTickCount64())) return ERROR_BUSY;
    if (!SetEvent(service_yield_event)) { service_idle_request.Clear(); return GetLastError(); }
    return NO_ERROR;
  }
  if ((control == SERVICE_CONTROL_STOP ||
       control == SERVICE_CONTROL_SHUTDOWN) &&
      service_stop_event != nullptr) {
    service_accepts_yield.store(false);
    SetVpnServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30000);
    SetEvent(service_stop_event);
  }
  return NO_ERROR;
}

bool ConsumeServiceIdleHandoff() {
  // Always clear the wake first: the handler's SetEvent may arrive after the
  // preceding request was consumed, leaving a wake with no pending request.
  // A later queue remains visible in Pending() or signals its own wake.
  if (service_yield_event) ResetEvent(service_yield_event);
  if (!service_idle_request.Pending()) return false;
  const bool has_owner = runtime_ownership.HasOwner();
  const auto idle = has_owner ? std::optional<bool>() : RuntimeConfirmedIdle();
  const bool accepted = service_idle_request.Consume(GetTickCount64(), has_owner, idle);
  if (accepted) {
    service_accepts_yield.store(false);
    // Publish acceptance before any logging or shutdown I/O. The helper must
    // distinguish a rejected queue from a slow but committed idle handoff.
    SetVpnServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30000);
  }
  return accepted;
}

int RunVpnServiceLoop() {
  SECURITY_ATTRIBUTES security{};
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!CreateServiceObjectSecurity(&security, &descriptor)) {
    return ERROR_ACCESS_DENIED;
  }

  SECURITY_ATTRIBUTES event_security{};
  PSECURITY_DESCRIPTOR event_descriptor = nullptr;
  if (!CreateServiceObjectSecurity(&event_security, &event_descriptor, true)) {
    LocalFree(descriptor);
    return ERROR_ACCESS_DENIED;
  }
  HANDLE ready_event = CreateEventW(&event_security, TRUE, TRUE,
                                    kServiceReadyEventName);
  HANDLE wireguard_status = CreateEventW(
      &event_security, TRUE, FALSE, kServiceWireGuardStatusEventName);
  HANDLE openvpn_status = CreateEventW(
      &event_security, TRUE, FALSE, kServiceOpenVpnStatusEventName);
  LocalFree(event_descriptor);
  if (ready_event == nullptr || wireguard_status == nullptr ||
      openvpn_status == nullptr) {
    if (ready_event != nullptr) CloseHandle(ready_event);
    if (wireguard_status != nullptr) CloseHandle(wireguard_status);
    if (openvpn_status != nullptr) CloseHandle(openvpn_status);
    LocalFree(descriptor);
    return ERROR_NOT_ENOUGH_MEMORY;
  }

  // A hard crash of an earlier service instance can leave WireGuard's
  // transient tunnel service alive after its dynamic WFP session disappeared.
  // We cannot reconstruct the missing policy without a fresh connect request,
  // so remove every stale tunnel before publishing status.
  if (!StopBrokerTunnels()) {
    CloseHandle(openvpn_status);
    CloseHandle(wireguard_status);
    CloseHandle(ready_event);
    LocalFree(descriptor);
    return ERROR_BUSY;
  }
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
  if (!OpenVpnCoreRecoverNetworkState()) {
    CloseHandle(openvpn_status);
    CloseHandle(wireguard_status);
    CloseHandle(ready_event);
    LocalFree(descriptor);
    return ERROR_INVALID_DATA;
  }
#endif
  PublishTunnelStatus(wireguard_status, openvpn_status);
  SetVpnServiceStatus(SERVICE_RUNNING);
  HANDLE pipe = CreateNamedPipeW(
      kServicePipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
          FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, kMaximumPayloadBytes, kMaximumPayloadBytes, 0, &security);
  const DWORD pipe_error = pipe == INVALID_HANDLE_VALUE ? GetLastError() : NO_ERROR;
  service_accepts_yield.store(pipe != INVALID_HANDLE_VALUE);
  // Keep the server instance for the entire runtime: no name-squatting window
  // exists between authenticated requests.
  bool yielded_idle = false;
  while (pipe != INVALID_HANDLE_VALUE &&
         WaitForSingleObject(service_stop_event, 0) == WAIT_TIMEOUT) {
    if (ConsumeServiceIdleHandoff()) { yielded_idle = true; break; }
    const bool connected = WaitForPipeClient(pipe, service_stop_event, service_yield_event);
    if (connected) {
      // A connection completed concurrently with the SCM wake. Decide the
      // handoff first; no mutation can run after an idle yield is accepted.
      if (ConsumeServiceIdleHandoff()) { yielded_idle = true; DisconnectNamedPipe(pipe); break; }
      HANDLE user_token = ServiceClientToken(pipe);
      if (user_token != nullptr) {
        std::vector<uint8_t> request;
        if (ReadFrameOverlapped(pipe, service_stop_event, &request)) {
          bool ignored_shutdown = false;
          ScopedProtectedStoreUser user_scope(user_token);
          std::vector<uint8_t> response =
              Dispatch(request, &ignored_shutdown, wireguard_status,
                       openvpn_status, false);
          Wipe(&request);
          uint32_t response_ack = 0;
          if (WriteFrameOverlapped(pipe, service_stop_event, response) &&
              ReadExactOverlapped(pipe, service_stop_event, &response_ack,
                                  sizeof(response_ack)) &&
              response_ack == kResponseAckMagic) {
            // DisconnectNamedPipe may discard unread response bytes. The UI
            // sends this acknowledgement only after it has consumed the
            // entire response frame, making the one-request pipe deterministic.
            WriteSafeStage("response_acknowledged");
          }
          Wipe(&response);
        }
        CloseHandle(user_token);
      }
      DisconnectNamedPipe(pipe);
    }
  }
  service_accepts_yield.store(false);
  if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);

  // The worker accepted the handoff only after proving both protocols and
  // protections idle. No cleanup mutation is necessary for that transfer.
  if (!yielded_idle) DrainBrokerTunnels(ready_event, true);
  fuzevpn_diagnostics::ShutdownRuntimeSnapshots();
  ResetEvent(wireguard_status);
  ResetEvent(openvpn_status);
  CloseHandle(openvpn_status);
  CloseHandle(wireguard_status);
  CloseHandle(ready_event);
  LocalFree(descriptor);
  return static_cast<int>(pipe_error);
}

void WINAPI VpnServiceMain(DWORD, wchar_t**) {
  service_status_handle = RegisterServiceCtrlHandlerExW(
      kVpnServiceName, VpnServiceControlHandler, nullptr);
  if (service_status_handle == nullptr) {
    return;
  }
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::vpn_service);
  SetVpnServiceStatus(SERVICE_START_PENDING, NO_ERROR, 30000);
  if (!AllowServerIdentityInspection()) {
    SetVpnServiceStatus(SERVICE_STOPPED, ERROR_ACCESS_DENIED);
    return;
  }
  service_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  service_yield_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  service_idle_request.Clear();
  service_accepts_yield.store(false);
  if (service_stop_event == nullptr || service_yield_event == nullptr) {
    if (service_stop_event) CloseHandle(service_stop_event);
    if (service_yield_event) CloseHandle(service_yield_event);
    service_stop_event = service_yield_event = nullptr;
    SetVpnServiceStatus(SERVICE_STOPPED, GetLastError());
    return;
  }
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  bool secure_installation = false;
  fuzevpn_ipc::ExclusiveRuntimeLock runtime_lock;
  {
    const auto executable = CurrentExecutablePath();
    fuzevpn_installation::ProtectedInstallation installation;
    secure_installation = executable && IsCurrentExecutableTrusted() &&
        installation.Validate(*executable);
  }
  const int result = secure_installation && runtime_lock.AcquireMachineRuntime()
      ? (fuzevpn_maintenance::IsBlocked() ? ERROR_INSTALL_ALREADY_RUNNING : RunVpnServiceLoop())
      : ERROR_ACCESS_DENIED;
  CoUninitialize();
  CloseHandle(service_stop_event);
  CloseHandle(service_yield_event);
  service_stop_event = nullptr;
  service_yield_event = nullptr;
  SetVpnServiceStatus(SERVICE_STOPPED, static_cast<DWORD>(result));
}

int RunVpnServiceDispatcher() {
  SERVICE_TABLE_ENTRYW table[] = {
      {const_cast<LPWSTR>(kVpnServiceName), VpnServiceMain},
      {nullptr, nullptr},
  };
  return StartServiceCtrlDispatcherW(table) ? EXIT_SUCCESS : EXIT_FAILURE;
}

bool StopExistingVpnService(SC_HANDLE service) {
  SERVICE_STATUS status{};
  if (!QueryServiceStatus(service, &status)) {
    return false;
  }
  if (status.dwCurrentState == SERVICE_STOPPED) {
    return true;
  }
  ControlService(service, SERVICE_CONTROL_STOP, &status);
  const ULONGLONG deadline = GetTickCount64() + 30000;
  do {
    if (QueryServiceStatus(service, &status) &&
        status.dwCurrentState == SERVICE_STOPPED) {
      return true;
    }
    Sleep(100);
  } while (GetTickCount64() < deadline);
  return false;
}

bool StartExistingExpectedVpnService(SC_HANDLE service,
                                    const std::wstring& command) {
  DWORD needed = 0;
  QueryServiceConfigW(service, nullptr, 0, &needed);
  if (needed < sizeof(QUERY_SERVICE_CONFIGW) || needed > 64 * 1024) return false;
  std::vector<BYTE> buffer(needed);
  auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
  if (!QueryServiceConfigW(service, config, needed, &needed)) return false;
  if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
      config->lpBinaryPathName == nullptr || config->lpServiceStartName == nullptr ||
      !fuzevpn_installation::SamePath(config->lpBinaryPathName, command) ||
      _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0) {
    SetLastError(ERROR_BAD_CONFIGURATION);
    return false;
  }
  // Preserve the registered service, its ACL, recovery policy and handles held
  // by management tools. A different installation needs an explicit installer
  // migration; silently deleting its registration is not a repair operation.
  return StartServiceW(service, 0, nullptr) != FALSE ||
      GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

int InstallVpnService() {
  if (fuzevpn_maintenance::IsBlocked()) return ERROR_BUSY;
  if (!IsElevated() || !IsCurrentExecutableTrusted()) {
    return EXIT_FAILURE;
  }
  // A healthy portable engine temporarily owns the service's idle lease.
  // Starting the installed service here would race its machine runtime mutex.
  fuzevpn_handoff::Reservation portable_lease;
  if (!portable_lease.Acquire()) return static_cast<int>(GetLastError());
  const auto current = CurrentExecutablePath();
  fuzevpn_installation::ProtectedInstallation installation;
  if (!current || !installation.Validate(*current)) {
    return EXIT_FAILURE;
  }
  std::wstring executable(32768, L'\0');
  DWORD length = GetModuleFileNameW(nullptr, executable.data(),
                                    static_cast<DWORD>(executable.size()));
  if (length == 0 || length >= executable.size()) {
    return EXIT_FAILURE;
  }
  executable.resize(length);
  const std::wstring command =
      L"\"" + executable + L"\" " + kServiceSwitch;

  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (manager == nullptr) {
    return EXIT_FAILURE;
  }
  SC_HANDLE existing = OpenServiceW(
      manager, kVpnServiceName,
      SERVICE_QUERY_CONFIG | SERVICE_START);
  if (existing != nullptr) {
    const bool started = StartExistingExpectedVpnService(existing, command);
    const DWORD start_error = started ? ERROR_SUCCESS : GetLastError();
    CloseServiceHandle(existing);
    CloseServiceHandle(manager);
    // Last-error belongs to this process. Return the mismatch explicitly so
    // the unelevated parent can diagnose it in the original user's log.
    return started ? EXIT_SUCCESS : start_error == ERROR_BAD_CONFIGURATION
        ? static_cast<int>(ERROR_BAD_CONFIGURATION) : EXIT_FAILURE;
  }
  if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
    CloseServiceHandle(manager);
    return EXIT_FAILURE;
  }

  const wchar_t dependencies[] = L"Nsi\0TcpIp\0\0";
  SC_HANDLE service = CreateServiceW(
      manager, kVpnServiceName, kVpnServiceDisplayName, SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
      command.c_str(), nullptr, nullptr, dependencies, nullptr, nullptr);
  if (service == nullptr) {
    CloseServiceHandle(manager);
    return EXIT_FAILURE;
  }
  SERVICE_SID_INFO sid_info{};
  sid_info.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
  SERVICE_DELAYED_AUTO_START_INFO delayed{};
  delayed.fDelayedAutostart = TRUE;
  SERVICE_DESCRIPTIONW description{};
  description.lpDescription = const_cast<LPWSTR>(
      L"Gère uniquement les tunnels WireGuard et OpenVPN de FuzeVPN.");
  SC_ACTION recovery_actions[3] = {
      {SC_ACTION_RESTART, 1000},
      {SC_ACTION_RESTART, 5000},
      {SC_ACTION_RESTART, 30000},
  };
  SERVICE_FAILURE_ACTIONSW recovery{};
  recovery.dwResetPeriod = 24 * 60 * 60;
  recovery.cActions = 3;
  recovery.lpsaActions = recovery_actions;
  SERVICE_FAILURE_ACTIONS_FLAG recovery_flag{};
  recovery_flag.fFailureActionsOnNonCrashFailures = TRUE;
  const bool configured =
      ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
                            &sid_info) &&
      ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                            &delayed) &&
      ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION,
                            &description) &&
      ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS,
                            &recovery) &&
      ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                            &recovery_flag);
  const bool started = configured &&
                       (StartServiceW(service, 0, nullptr) != FALSE ||
                        GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
  // Roll back only the record created by this invocation. An existing service
  // never enters this branch and can no longer be lost to a partial repair.
  if (!started && StopExistingVpnService(service)) DeleteService(service);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return started ? EXIT_SUCCESS : EXIT_FAILURE;
}

int UninstallVpnService() {
  if (!IsElevated()) {
    return EXIT_FAILURE;
  }
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return EXIT_FAILURE;
  }
  SC_HANDLE service = OpenServiceW(
      manager, kVpnServiceName,
      SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
  if (service == nullptr) {
    const DWORD error = GetLastError();
    CloseServiceHandle(manager);
    return error == ERROR_SERVICE_DOES_NOT_EXIST ? EXIT_SUCCESS
                                                  : EXIT_FAILURE;
  }
  const bool stopped = StopExistingVpnService(service);
  const bool removed = stopped &&
                       (DeleteService(service) != FALSE ||
                        GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return removed ? EXIT_SUCCESS : EXIT_FAILURE;
}

int RunBroker(DWORD parent_process_id, bool portable) {
  if (!IsElevated()) {
    return EXIT_FAILURE;
  }
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::elevated_broker);
  fuzevpn_ipc::ExclusiveRuntimeLock runtime_lock;
  if (!runtime_lock.AcquireMachineRuntime()) return EXIT_FAILURE;
  if (fuzevpn_maintenance::IsBlocked()) return ERROR_BUSY;
  HANDLE parent = nullptr;
  HANDLE user_token = nullptr;
  // Pin the mutable UI and its ancestors for the entire WFP exception lifetime,
  // including all cleanup retries after the UI process has exited.
  fuzevpn_update::PinnedFile portable_ui, portable_helper, portable_engine;
  fuzevpn_installation::ProtectedInstallation protected_engine;
  struct UiPathScope {
    ~UiPathScope() { ClearAuthenticatedBrokerUiPath(); }
  } ui_path_scope;
  {
    ScopedProcessInspectionPrivilege inspection_privilege;
    parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                         FALSE, parent_process_id);
    bool trusted_parent = false;
    if (parent != nullptr && portable) {
      std::wstring actual_ui;
      fuzevpn_portable::Manifest manifest;
      const auto self = CurrentExecutablePath();
      if (self && QueryProcessImage(parent, &actual_ui) &&
          fuzevpn_installation::SamePath(std::filesystem::path(actual_ui).filename().wstring(),
                                        kUiExecutableName) &&
          portable_ui.Open(actual_ui, true) &&
          portable_helper.Open(std::filesystem::path(actual_ui).parent_path() / L"fuzevpn-runtime.exe", true) &&
          portable_engine.Open(*self) &&
          fuzevpn_portable::ReadEmbeddedManifest(portable_helper.path(), &manifest) &&
          fuzevpn_portable::ValidatePublisherPair(portable_ui, portable_helper, manifest.version) &&
          fuzevpn_portable::ValidatePublisherPair(portable_ui, portable_engine, manifest.version) &&
          fuzevpn_portable::ValidateProtectedRuntime(self->parent_path(), manifest) &&
          protected_engine.ValidateEngine(*self)) {
        trusted_parent = SetAuthenticatedBrokerUiPath(actual_ui);
      }
    } else if (parent != nullptr) {
      trusted_parent = IsExpectedProcessImage(parent, kUiExecutableName) &&
          IsUnsignedDevelopmentPair();
    }
    if (!trusted_parent) {
      if (parent != nullptr) CloseHandle(parent);
      return EXIT_FAILURE;
    }
    HANDLE parent_token = nullptr;
    if (OpenProcessToken(parent, TOKEN_QUERY | TOKEN_DUPLICATE, &parent_token)) {
      DuplicateTokenEx(parent_token, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr,
                       SecurityImpersonation, TokenImpersonation, &user_token);
      CloseHandle(parent_token);
    }
  }
  if (user_token == nullptr || !AllowServerIdentityInspection()) {
    if (user_token != nullptr) CloseHandle(user_token);
    CloseHandle(parent);
    return EXIT_FAILURE;
  }
  // Early lifecycle diagnostics use the same account as request diagnostics,
  // including an over-the-shoulder UAC elevation by a different administrator.
  ScopedProtectedStoreUser broker_user_scope(user_token);

  // Holding the machine lock proves that no supported broker/service owns an
  // active tunnel. Recover resources orphaned by a previous hard process exit.
  if (!StopBrokerTunnels()) {
    CloseHandle(user_token);
    CloseHandle(parent);
    return EXIT_FAILURE;
  }
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
  if (!OpenVpnCoreRecoverNetworkState()) {
    CloseHandle(user_token);
    CloseHandle(parent);
    return EXIT_FAILURE;
  }
#endif

  SECURITY_ATTRIBUTES security{};
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!CreatePipeSecurity(&security, &descriptor, parent, false)) {
    CloseHandle(user_token);
    CloseHandle(parent);
    return EXIT_FAILURE;
  }

  SECURITY_ATTRIBUTES event_security{};
  PSECURITY_DESCRIPTOR event_descriptor = nullptr;
  if (user_token == nullptr ||
      !CreatePipeSecurity(&event_security, &event_descriptor, parent, true)) {
    if (user_token != nullptr) CloseHandle(user_token);
    LocalFree(descriptor);
    CloseHandle(parent);
    return EXIT_FAILURE;
  }
  const std::wstring pipe_name = PipeName(parent_process_id);
  HANDLE ready_event = CreateEventW(&event_security, TRUE, TRUE,
                                    ReadyEventName(parent_process_id).c_str());
  HANDLE wireguard_status =
      CreateEventW(&event_security, TRUE, FALSE,
                   TunnelStatusEventName(parent_process_id, "wireguard").c_str());
  HANDLE openvpn_status =
      CreateEventW(&event_security, TRUE, FALSE,
                   TunnelStatusEventName(parent_process_id, "openvpn").c_str());
  LocalFree(event_descriptor);
  if (ready_event == nullptr || wireguard_status == nullptr ||
      openvpn_status == nullptr) {
    if (ready_event != nullptr) CloseHandle(ready_event);
    if (wireguard_status != nullptr) CloseHandle(wireguard_status);
    if (openvpn_status != nullptr) CloseHandle(openvpn_status);
    LocalFree(descriptor);
    CloseHandle(user_token);
    CloseHandle(parent);
    return EXIT_FAILURE;
  }
  PublishTunnelStatus(wireguard_status, openvpn_status);
  WriteSafeStage("broker_ready");
  bool shutdown_requested = false;
  HANDLE pipe = CreateNamedPipeW(
      pipe_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
          FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, kMaximumPayloadBytes, kMaximumPayloadBytes, 0, &security);
  const bool pipe_created = pipe != INVALID_HANDLE_VALUE;
  while (pipe_created && !shutdown_requested &&
         WaitForSingleObject(parent, 0) == WAIT_TIMEOUT) {
    const bool connected = WaitForPipeClient(pipe, parent);

    if (connected) {
      WriteSafeStage("client_connected");
      if (IsExpectedPipeClientProcess(pipe, parent_process_id)) {
        std::vector<uint8_t> request;
        const bool request_complete =
            ReadFrameOverlapped(pipe, parent, &request);
        if (request_complete) {
          WriteSafeStage("request_read");
        }
        // The broker was launched for one already-validated parent process,
        // and Windows confirms that the connected pipe client is exactly that
        // process. DPAPI uses the separately duplicated parent token, including
        // when UAC credentials belong to a different administrator account.
        if (request_complete) {
          WriteSafeStage("client_authenticated");
          ScopedProtectedStoreUser user_scope(user_token);
          std::vector<uint8_t> response =
              Dispatch(request, &shutdown_requested, wireguard_status,
                       openvpn_status, true);
          Wipe(&request);
          uint32_t response_ack = 0;
          if (WriteFrameOverlapped(pipe, parent, response) &&
              ReadExactOverlapped(pipe, parent, &response_ack,
                                  sizeof(response_ack)) &&
              response_ack == kResponseAckMagic) {
            // Do not close the pipe until Flutter has consumed the complete
            // response. This removes the intermittent native-success/UI-error
            // race for small WireGuard replies.
            WriteSafeStage("response_acknowledged");
          }
          Wipe(&response);
        }
      }
      DisconnectNamedPipe(pipe);
    }
  }
  if (pipe_created) CloseHandle(pipe);

  DrainBrokerTunnels(ready_event, false);
  fuzevpn_diagnostics::ShutdownRuntimeSnapshots();
  ResetEvent(wireguard_status);
  ResetEvent(openvpn_status);
  CloseHandle(wireguard_status);
  CloseHandle(openvpn_status);
  CloseHandle(ready_event);
  LocalFree(descriptor);
  CloseHandle(user_token);
  CloseHandle(parent);
  return pipe_created ? EXIT_SUCCESS : EXIT_FAILURE;
}

HANDLE OpenAuthenticatedPipe(bool service) {
  const std::wstring name = service ? kServicePipeName :
                                      PipeName(GetCurrentProcessId());
  HANDLE pipe = CreateFileW(name.c_str(), fuzevpn_ipc::kPipeClientAccess, 0,
      nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED |
          SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
  if (pipe != INVALID_HANDLE_VALUE && !AuthenticatePipeServer(pipe, service)) {
    CloseHandle(pipe);
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_HANDLE_VALUE;
  }
  return pipe;
}

const char* ServiceInstallerFailureCode(DWORD exit_code) {
  if (exit_code == ERROR_SUCCESS || exit_code == STILL_ACTIVE) return nullptr;
  return exit_code == ERROR_BAD_CONFIGURATION
      ? "service_configuration_mismatch" : "service_install_failed";
}

void RecordServiceInstallerResult(HANDLE installer) {
  DWORD exit_code = STILL_ACTIVE;
  if (!GetExitCodeProcess(installer, &exit_code)) return;
  const char* failure = ServiceInstallerFailureCode(exit_code);
  if (failure == nullptr) return;
  // The GUI writes this after the installer exits, including when UAC used a
  // different administrator. Do not disclose the other installation's path.
  WriteUserDiagnostic("native_last_error.txt",
      std::string("broker.installService=") + failure, false);
  AppendNativeDiagnostic("broker", "service_install_failed", failure);
}

HANDLE LaunchServiceInstaller(bool* installation_required) {
  const auto executable = SiblingExecutable(kServiceExecutableName);
  if (!executable.has_value() || !IsCurrentExecutableTrusted() ||
      !IsFileTrusted(executable->wstring())) {
    return nullptr;
  }
  fuzevpn_installation::ProtectedInstallation installation;
  if (!installation.Validate(*executable)) {
    *installation_required = true;
    SetLastError(ERROR_BAD_CONFIGURATION);
    return nullptr;
  }
  SHELLEXECUTEINFOW execution{};
  execution.cbSize = sizeof(execution);
  execution.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  execution.lpVerb = L"runas";
  const std::wstring executable_path = executable->wstring();
  execution.lpFile = executable_path.c_str();
  execution.lpParameters = kInstallServiceSwitch;
  execution.nShow = SW_HIDE;
  if (!ShellExecuteExW(&execution)) {
    return nullptr;
  }
  return execution.hProcess;
}

HANDLE LaunchBroker(bool* installation_required) {
  const auto executable = SiblingExecutable(kServiceExecutableName);
  if (!executable.has_value()) {
    return nullptr;
  }
  // This check runs in the unelevated UI, before Windows loads the elevated
  // executable's imported DLLs. A check inside the service entry point would
  // be too late. Keep the checked tree pinned until process creation finishes.
  fuzevpn_installation::ProtectedInstallation installation;
  if (!installation.Validate(*executable)) {
    *installation_required = true;
    SetLastError(ERROR_BAD_CONFIGURATION);
    return nullptr;
  }
  if (!IsUnsignedDevelopmentPair()) return nullptr;
  const std::wstring executable_path = executable->wstring();
  const std::wstring parameters =
      std::wstring(kBrokerSwitch) + L" " +
      std::to_wstring(GetCurrentProcessId());
  SHELLEXECUTEINFOW execution{};
  execution.cbSize = sizeof(execution);
  execution.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  execution.lpVerb = L"runas";
  execution.lpFile = executable_path.c_str();
  execution.lpParameters = parameters.c_str();
  execution.nShow = SW_HIDE;
  if (!ShellExecuteExW(&execution)) {
    return nullptr;
  }
  return execution.hProcess;
}

HANDLE ConnectToBroker(bool start_if_missing, bool allow_service,
                       bool* installation_required, bool single_attempt = false) {
  *installation_required = false;
  if (ClientCancelled()) { SetLastError(ERROR_CANCELLED); return INVALID_HANDLE_VALUE; }
  const auto mode = fuzevpn_distribution::CurrentMode();
  if (mode == fuzevpn_distribution::Mode::unavailable) {
    return INVALID_HANDLE_VALUE;
  }
  const bool portable = mode == fuzevpn_distribution::Mode::portable;
  if (portable) allow_service = false;
  DWORD service_pipe_error = ERROR_SUCCESS;
  if (allow_service) {
    HANDLE pipe = OpenAuthenticatedPipe(true);
    service_pipe_error = GetLastError();
    if (pipe != INVALID_HANDLE_VALUE || service_pipe_error == ERROR_ACCESS_DENIED)
      return pipe;
    // A response ACK can precede the service's next pipe listener. Status
    // reads wait briefly for that existing service without starting/installing
    // anything or weakening the per-attempt server authentication.
    if (single_attempt) { SetLastError(service_pipe_error); return INVALID_HANDLE_VALUE; }
    if (!start_if_missing && fuzevpn_ipc::RetryableServicePipeError(service_pipe_error)) {
      bool running = false;
      const auto pid = QueryServiceProcessId(&running);
      if (!pid.has_value()) return INVALID_HANDLE_VALUE;
      if (running && *pid != 0) {
        return fuzevpn_ipc::RetryRunningServicePipe(*pid, service_pipe_error,
            [] { return OpenAuthenticatedPipe(true); },
            [] {
              bool still_running = false;
              const auto current = QueryServiceProcessId(&still_running);
              return !current.has_value() ? current :
                  std::optional<DWORD>(still_running ? *current : 0);
            }, [] { return ClientCancelled(); }, [] { return GetTickCount64(); },
            [](DWORD milliseconds) {
              if (client_cancel_event != nullptr)
                WaitForSingleObject(client_cancel_event, milliseconds);
              else std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
            });
      }
    }
  }

  const bool development = IsUnsignedDevelopmentPair();
  if (allow_service) SetLastError(service_pipe_error);
  if (!portable && !development) {
    // A signed or invalidly signed distribution never falls back to an
    // unsigned elevated broker, even when service installation fails.
    if (!allow_service || !start_if_missing) return INVALID_HANDLE_VALUE;
    const auto service_pid = QueryServiceProcessId();
    if (!service_pid.has_value()) return INVALID_HANDLE_VALUE;
    HANDLE installer = *service_pid == 0 ? LaunchServiceInstaller(installation_required) : nullptr;
    if (*service_pid == 0 && installer == nullptr) return INVALID_HANDLE_VALUE;
    const ULONGLONG deadline = GetTickCount64() + kBrokerStartupTimeoutMs;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    while (!ClientCancelled() && GetTickCount64() < deadline) {
      pipe = OpenAuthenticatedPipe(true);
      if (pipe != INVALID_HANDLE_VALUE || GetLastError() == ERROR_ACCESS_DENIED)
        break;
      if (installer != nullptr &&
          WaitForSingleObject(installer, 0) != WAIT_TIMEOUT &&
          ServiceProcessId() == 0) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(75));
    }
    if (installer != nullptr) {
      RecordServiceInstallerResult(installer);
      CloseHandle(installer);
    }
    return pipe;
  }

  if (launched_broker_process != nullptr &&
      WaitForSingleObject(launched_broker_process, 0) != WAIT_TIMEOUT) {
    CloseHandle(launched_broker_process);
    launched_broker_process = nullptr;
    launched_portable_engine.clear();
    launched_broker_pid.store(0);
  }
  if (launched_broker_process == nullptr) {
    if (!start_if_missing) {
      if (allow_service) SetLastError(service_pipe_error);
      return INVALID_HANDLE_VALUE;
    }
    launched_portable_engine.clear();
    launched_broker_process = portable
        ? LaunchPortableRuntime(client_cancel_event, &launched_portable_engine)
        : LaunchBroker(installation_required);
    if (launched_broker_process == nullptr) return INVALID_HANDLE_VALUE;
    launched_broker_pid.store(GetProcessId(launched_broker_process));
  }
  // A diagnostic cache poll never waits for another client's pipe transaction.
  if (single_attempt) return OpenAuthenticatedPipe(false);
  const ULONGLONG deadline = GetTickCount64() +
      (start_if_missing ? kBrokerStartupTimeoutMs : 2000);
  while (!ClientCancelled() && GetTickCount64() < deadline) {
    HANDLE pipe = OpenAuthenticatedPipe(false);
    if (pipe != INVALID_HANDLE_VALUE || GetLastError() == ERROR_ACCESS_DENIED)
      return pipe;
    if (WaitForSingleObject(launched_broker_process, 0) != WAIT_TIMEOUT) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(75));
  }
  return INVALID_HANDLE_VALUE;
}

bool Exchange(const flutter::MethodCall<flutter::EncodableValue>& call,
              bool start_if_missing, std::vector<uint8_t>* response,
              bool allow_service = true,
              ExchangeFailure* exchange_failure = nullptr,
              DWORD* windows_error = nullptr) {
  if (windows_error != nullptr) *windows_error = ERROR_SUCCESS;
  if (exchange_failure != nullptr) {
    *exchange_failure = ExchangeFailure::kNone;
  }
  const auto& codec = flutter::StandardMethodCodec::GetInstance();
  auto request = codec.EncodeMethodCall(call);
  if (request == nullptr || request->empty() ||
      request->size() > kMaximumPayloadBytes) {
    if (exchange_failure != nullptr) {
      *exchange_failure = ExchangeFailure::kRequestWriteFailed;
    }
    return false;
  }

  std::lock_guard<std::mutex> lock(client_mutex);
  bool installation_required = false;
  const bool diagnostic = call.method_name() == "diagnostics.collectSnapshot";
  HANDLE pipe = ConnectToBroker(start_if_missing, allow_service, &installation_required, diagnostic);
  if (pipe == INVALID_HANDLE_VALUE) {
    // Keep the failing worker thread's value before logging, wiping buffers or
    // closing handles can overwrite it. Platform delivery never re-reads
    // GetLastError() on the GUI thread.
    const DWORD connection_error = GetLastError();
    if (windows_error != nullptr) *windows_error = connection_error;
    if (exchange_failure != nullptr) {
      *exchange_failure = installation_required
          ? ExchangeFailure::kInstallationRequired
          : ExchangeFailure::kBrokerUnavailable;
    }
    AppendNativeDiagnostic("broker", "connection_failed",
                           std::to_string(connection_error));
    Wipe(request.get());
    return false;
  }
  const ULONGLONG deadline = GetTickCount64() + (diagnostic ? 1000 : kBrokerResponseTimeoutMs);
  const bool wrote = WriteFrameOverlapped(pipe, client_cancel_event, *request,
                                         deadline);
  if (!wrote) {
    const DWORD write_error = GetLastError();
    if (windows_error != nullptr) *windows_error = write_error;
    if (exchange_failure != nullptr) {
      *exchange_failure = ExchangeFailure::kRequestWriteFailed;
    }
    AppendNativeDiagnostic("broker", "request_write_failed",
                           std::to_string(write_error));
  }
  const bool response_read =
      wrote &&
      ReadFrameOverlapped(pipe, client_cancel_event, response, deadline);
  if (wrote && !response_read) {
    const DWORD response_error = GetLastError();
    if (windows_error != nullptr) *windows_error = response_error;
    if (exchange_failure != nullptr) {
      *exchange_failure = ExchangeFailure::kResponseUnavailable;
    }
    AppendNativeDiagnostic("broker", "response_unavailable",
                           std::to_string(response_error));
  }
  // The broker disconnects only after this acknowledgement. It therefore
  // cannot discard a response between WriteFile and DisconnectNamedPipe.
  if (response_read &&
      !WriteExactOverlapped(pipe, client_cancel_event, &kResponseAckMagic,
                            sizeof(kResponseAckMagic), deadline)) {
    AppendNativeDiagnostic("broker", "response_ack_failed",
                           std::to_string(GetLastError()));
  }
  // Once the full response has been read it is safe to decode it. A failed
  // acknowledgement merely makes the server observe a closed pipe; it must
  // not convert an already received success response into a UI failure.
  const bool success = response_read;
  Wipe(request.get());
  CloseHandle(pipe);
  return success;
}

}  // namespace

std::optional<int> RunPrivilegedBrokerIfRequested() {
  int argument_count = 0;
  LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
  if (arguments == nullptr) {
    return std::nullopt;
  }
  const bool portable_requested =
      argument_count == 3 && wcscmp(arguments[1], kPortableBrokerSwitch) == 0;
  const bool requested = portable_requested ||
      (argument_count == 3 && wcscmp(arguments[1], kBrokerSwitch) == 0);
  const bool service_requested =
      argument_count == 2 && wcscmp(arguments[1], kServiceSwitch) == 0;
  const bool install_requested =
      argument_count == 2 && wcscmp(arguments[1], kInstallServiceSwitch) == 0;
  const bool uninstall_requested =
      argument_count == 2 &&
      wcscmp(arguments[1], kUninstallServiceSwitch) == 0;
  wchar_t* end = nullptr;
  const unsigned long parsed = requested ? wcstoul(arguments[2], &end, 10) : 0;
  const bool valid = requested && parsed != 0 && end != nullptr && *end == L'\0';
  LocalFree(arguments);
  if (service_requested) {
    return RunVpnServiceDispatcher();
  }
  if (install_requested) {
    return InstallVpnService();
  }
  if (uninstall_requested) {
    return UninstallVpnService();
  }
  if (!requested) {
    return std::nullopt;
  }
  if (!valid) {
    return EXIT_FAILURE;
  }
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const int result = RunBroker(static_cast<DWORD>(parsed), portable_requested);
  CoUninitialize();
  return result;
}

namespace {
void CompletePrivilegedCall(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result,
    bool exchanged, ExchangeFailure exchange_failure,
    std::vector<uint8_t>* response, DWORD windows_error) {
  if (!exchanged) {
    const char* code = "broker_unavailable";
    const char* stage = "broker_connection";
    switch (exchange_failure) {
      case ExchangeFailure::kRequestWriteFailed:
        code = "broker_write_failed";
        stage = "broker_write";
        break;
      case ExchangeFailure::kResponseUnavailable:
        code = "broker_response_timeout";
        stage = "broker_response";
        break;
      case ExchangeFailure::kInstallationRequired: code = "installation_required"; break;
      case ExchangeFailure::kNone:
      case ExchangeFailure::kBrokerUnavailable: break;
    }
    flutter::EncodableMap error_details{
        {flutter::EncodableValue("stage"), flutter::EncodableValue(stage)}};
    if (windows_error != ERROR_SUCCESS) {
      error_details.emplace(flutter::EncodableValue("win32_error"),
          flutter::EncodableValue(static_cast<int64_t>(windows_error)));
    }
    Wipe(response);
    result->Error(code, exchange_failure == ExchangeFailure::kInstallationRequired
        ? "Install FuzeVPN in an administrator-protected directory before enabling the VPN."
        : "Windows could not authorize the VPN operation.",
        flutter::EncodableValue(std::move(error_details)));
    return;
  }
  if (!fuzevpn_ipc::ValidateResponseEnvelope(response->data(), response->size())) {
    Wipe(response);
    result->Error("broker_protocol_error", "Invalid broker response.");
    return;
  }
  const bool decoded = flutter::StandardMethodCodec::GetInstance()
      .DecodeAndProcessResponseEnvelope(response->data(), response->size(),
                                         result.get());
  Wipe(response);
  if (!decoded) result->Error("broker_protocol_error", "Invalid broker response.");
}

#ifndef FUZEVPN_SERVICE_PROCESS
struct PendingPrivilegedCall {
  uint64_t id;
  std::unique_ptr<flutter::MethodCall<flutter::EncodableValue>> request;
  bool start_if_missing;
};
struct PrivilegedCompletion {
  uint64_t id;
  bool exchanged;
  ExchangeFailure failure;
  DWORD windows_error;
  std::vector<uint8_t> response;
};
std::mutex dispatcher_mutex;
std::condition_variable dispatcher_ready;
std::deque<PendingPrivilegedCall> dispatcher_requests;
std::deque<PrivilegedCompletion> dispatcher_completions;
std::map<uint64_t,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>> platform_results;
std::thread dispatcher_worker;
HWND dispatcher_window = nullptr;
bool dispatcher_stopping = false;
uint64_t next_call_id = 0;

void RunPrivilegedCallWorker() {
  CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  while (true) {
    PendingPrivilegedCall call{};
    {
      std::unique_lock<std::mutex> lock(dispatcher_mutex);
      dispatcher_ready.wait(lock, [] {
        return dispatcher_stopping || !dispatcher_requests.empty();
      });
      if (dispatcher_stopping) break;
      call = std::move(dispatcher_requests.front());
      dispatcher_requests.pop_front();
    }
    PrivilegedCompletion completed{
        call.id, false, ExchangeFailure::kNone, ERROR_SUCCESS, {}};
    completed.exchanged = Exchange(*call.request, call.start_if_missing,
        &completed.response, true, &completed.failure, &completed.windows_error);
    {
      std::lock_guard<std::mutex> lock(dispatcher_mutex);
      if (dispatcher_stopping) {
        Wipe(&completed.response);
        break;
      }
      dispatcher_completions.push_back(std::move(completed));
      // No pointer or reply handle travels through the message queue. All
      // Flutter reply objects stay on the platform thread until completion.
      PostMessageW(dispatcher_window, kPrivilegedCallCompletedMessage, 0, 0);
    }
  }
  CoUninitialize();
}
#endif
}  // namespace

#ifndef FUZEVPN_SERVICE_PROCESS
bool InitializePrivilegedCallDispatcher(HWND window) {
  if (window == nullptr || dispatcher_worker.joinable()) return false;
  client_cancel_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (client_cancel_event == nullptr) return false;
  dispatcher_window = window;
  dispatcher_stopping = false;
  dispatcher_worker = std::thread(RunPrivilegedCallWorker);
  return true;
}

void ProcessPrivilegedCallCompletions() {
  std::deque<PrivilegedCompletion> completed;
  {
    std::lock_guard<std::mutex> lock(dispatcher_mutex);
    completed.swap(dispatcher_completions);
  }
  for (auto& completion : completed) {
    auto found = platform_results.find(completion.id);
    if (found == platform_results.end()) {
      Wipe(&completion.response);
      continue;
    }
    auto result = std::move(found->second);
    platform_results.erase(found);
    CompletePrivilegedCall(std::move(result), completion.exchanged,
                            completion.failure, &completion.response,
                            completion.windows_error);
  }
}

void ShutdownPrivilegedCallDispatcher() {
  {
    std::lock_guard<std::mutex> lock(dispatcher_mutex);
    dispatcher_stopping = true;
    dispatcher_window = nullptr;
    dispatcher_requests.clear();
    if (client_cancel_event != nullptr) SetEvent(client_cancel_event);
  }
  dispatcher_ready.notify_all();
  if (dispatcher_worker.joinable()) dispatcher_worker.join();
  // Called before engine destruction, on its platform thread. No worker may
  // retain a Flutter result or race the engine shutdown.
  for (auto& pending : platform_results) {
    pending.second->Error("operation_cancelled", "The application is closing.");
  }
  platform_results.clear();
  for (auto& completion : dispatcher_completions) Wipe(&completion.response);
  dispatcher_completions.clear();
  if (client_cancel_event != nullptr) CloseHandle(client_cancel_event);
  client_cancel_event = nullptr;
}
#endif

void ForwardPrivilegedCall(
    const std::string& scope,
    const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result,
    bool start_if_missing) {
  auto arguments = call.arguments() == nullptr ? nullptr :
      std::make_unique<flutter::EncodableValue>(*call.arguments());
  auto request = std::make_unique<flutter::MethodCall<flutter::EncodableValue>>(
      scope + "." + call.method_name(), std::move(arguments));
#ifndef FUZEVPN_SERVICE_PROCESS
  if (dispatcher_window != nullptr) {
    if (scope == "diagnostics" && !platform_results.empty()) {
      // Do not queue a passive poll behind an active VPN mutation. It can be
      // retried by a later manual diagnostic without delaying that command.
      result->Error("runtime_status_unavailable", "The VPN runtime is busy.");
      return;
    }
    if (platform_results.size() >= 64) {
      result->Error("broker_busy", "Too many VPN operations are pending.");
      return;
    }
    const uint64_t id = ++next_call_id;
    platform_results.emplace(id, std::move(result));
    {
      std::lock_guard<std::mutex> lock(dispatcher_mutex);
      dispatcher_requests.push_back({id, std::move(request), start_if_missing});
    }
    dispatcher_ready.notify_one();
    return;
  }
#endif
  // Native shutdown cleanup runs after the window/message loop has ended and
  // uses native-only result objects. Normal GUI calls always use the worker.
  std::vector<uint8_t> response;
  ExchangeFailure failure = ExchangeFailure::kNone;
  DWORD windows_error = ERROR_SUCCESS;
  const bool exchanged = Exchange(*request, start_if_missing, &response, true,
                                   &failure, &windows_error);
  CompletePrivilegedCall(std::move(result), exchanged, failure, &response,
                          windows_error);
}

std::optional<bool> PrivilegedRuntimePresence(bool* detection_failed) {
  if (detection_failed != nullptr) *detection_failed = false;
  const auto mode = fuzevpn_distribution::CurrentMode();
  if (mode == fuzevpn_distribution::Mode::unavailable) {
    if (detection_failed != nullptr) *detection_failed = true;
    return std::nullopt;
  }
  if (mode == fuzevpn_distribution::Mode::installed) {
    const auto service_pid = QueryServiceProcessId();
    if (!service_pid.has_value()) return std::nullopt;
    if (*service_pid != 0) return true;
  }
  const DWORD pid = launched_broker_pid.load();
  if (pid == 0) return false;
  HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
  if (process == nullptr) return std::nullopt;
  const DWORD state = WaitForSingleObject(process, 0);
  const DWORD wait_error = state == WAIT_FAILED ? GetLastError() : ERROR_INVALID_DATA;
  CloseHandle(process);
  if (state == WAIT_OBJECT_0) return false;
  if (state == WAIT_TIMEOUT) return true;
  SetLastError(wait_error);
  return std::nullopt;
}

void CompleteRuntimeStatusFailure(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result,
    bool detection_failed) {
  CompleteRuntimeStatusFailure(result.get(), detection_failed);
}

void CompleteRuntimeStatusFailure(
    flutter::MethodResult<flutter::EncodableValue>* result,
    bool detection_failed) {
  const DWORD windows_error = GetLastError();
  const char* code = detection_failed ? "runtime_detection_failed" :
                                        "runtime_status_unavailable";
  const flutter::EncodableValue details(flutter::EncodableMap{
      {flutter::EncodableValue("win32_error"),
       flutter::EncodableValue(static_cast<int64_t>(windows_error))}});
  AppendNativeDiagnostic("runtime", code, std::to_string(windows_error));
  result->Error(code, detection_failed
      ? "Windows could not identify this FuzeVPN copy."
      : "Windows could not read the VPN runtime status.", details);
}

bool IsPrivilegedBrokerRunning() {
  // Existing channel guards use false only for confirmed absence. Unknown
  // status must attempt authenticated IPC and report an error, never a false
  // disconnected bit or an unexecuted successful Disconnect.
  return PrivilegedRuntimePresence().value_or(true);
}

bool IsPersistentVpnServiceRunning() {
  if (fuzevpn_distribution::CurrentMode() == fuzevpn_distribution::Mode::portable)
    return false;
  const auto pid = QueryServiceProcessId();
  // At GUI shutdown, uncertainty must not tear down a service-owned tunnel.
  return !pid.has_value() || *pid != 0;
}

void ShutdownPrivilegedBroker() {
  if (launched_broker_pid.load() == 0) return;
  flutter::MethodCall<flutter::EncodableValue> call("broker.shutdown", nullptr);
  std::vector<uint8_t> response;
  Exchange(call, false, &response, false);
  Wipe(&response);
  std::lock_guard<std::mutex> lock(client_mutex);
  if (launched_broker_process != nullptr) CloseHandle(launched_broker_process);
  launched_broker_process = nullptr;
  launched_portable_engine.clear();
  launched_broker_pid.store(0);
}
