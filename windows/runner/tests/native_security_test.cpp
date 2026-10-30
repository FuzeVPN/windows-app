// Isolated Win32 regression tests: no VPN, SCM mutation, UAC or user store I/O.
// Including this translation unit exercises the actual private IPC boundary.
#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include "../distribution_mode.h"
#include "../service_pipe_endpoint.h"

namespace fuzevpn_distribution {
Mode test_distribution_mode = Mode::installed;
unsigned test_distribution_queries = 0;
Mode TestCurrentMode() { ++test_distribution_queries; return test_distribution_mode; }
}

namespace {
enum class ScmScenario {
  real, manager_denied, service_denied, absent, query_failed, stopped,
  starting_without_pid, running
};
ScmScenario scm_scenario = ScmScenario::real;
unsigned scm_manager_queries = 0;
bool inspect_pipe_connections = false;
bool inspect_service_status = false;
unsigned inspected_service_status_updates = 0;
DWORD inspected_service_state = SERVICE_RUNNING;
BOOL WINAPI ObserveSetServiceStatus(SERVICE_STATUS_HANDLE handle, LPSERVICE_STATUS status) {
  if (!inspect_service_status) return SetServiceStatus(handle, status);
  ++inspected_service_status_updates;
  inspected_service_state = status->dwCurrentState;
  return TRUE;
}
DWORD transport_open_error = ERROR_PIPE_BUSY;
unsigned transport_open_attempts = 0;
unsigned transport_trust_queries = 0;
ULONGLONG transport_ticks = 0;
ULONGLONG transport_cancel_at = 0;
bool transport_cancelled = false;
bool test_diagnostic_changes_error = false;
bool inspect_presence_wait_failure = false;
HANDLE presence_process_handle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(109));
HANDLE WINAPI ObserveOpenProcess(DWORD access, BOOL inherit, DWORD process) {
  if (!inspect_presence_wait_failure) return OpenProcess(access, inherit, process);
  return access == SYNCHRONIZE ? presence_process_handle : nullptr;
}
HANDLE transport_cancel_handle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(107));
HANDLE WINAPI ObserveCreateFile(LPCWSTR name, DWORD access, DWORD sharing,
    LPSECURITY_ATTRIBUTES attributes, DWORD disposition, DWORD flags, HANDLE template_file) {
  if (!inspect_pipe_connections)
    return CreateFileW(name, access, sharing, attributes, disposition, flags, template_file);
  ++transport_open_attempts;
  SetLastError(transport_open_error);
  return INVALID_HANDLE_VALUE;
}
ULONGLONG WINAPI ObserveTicks() {
  return inspect_pipe_connections ? transport_ticks : GetTickCount64();
}
DWORD WINAPI ObserveTransportWait(HANDLE handle, DWORD milliseconds) {
  if (inspect_presence_wait_failure && handle == presence_process_handle) {
    SetLastError(ERROR_NOT_SUPPORTED); return WAIT_FAILED;
  }
  if (!inspect_pipe_connections || handle != transport_cancel_handle)
    return WaitForSingleObject(handle, milliseconds);
  transport_ticks += milliseconds;
  if (transport_cancelled || (transport_cancel_at != 0 && transport_ticks >= transport_cancel_at))
    return WAIT_OBJECT_0;
  // A wait may change the thread error; callers must retain the pipe error.
  SetLastError(ERROR_SUCCESS);
  return WAIT_TIMEOUT;
}
LONG WINAPI ObserveTransportTrust(HWND window, GUID* action, LPVOID data) {
  if (!inspect_pipe_connections) return WinVerifyTrust(window, action, data);
  ++transport_trust_queries;
  SetLastError(ERROR_SUCCESS);
  return ERROR_SUCCESS;
}
bool inspect_acl_writes = false;
DWORD inspected_interactive_mask = 0;
bool inspected_preserved_system_ace = false;
bool inspect_privilege_adjustments = false;
bool deny_inspection_token = false;
bool inspected_privilege_enabled = false;
bool inspected_privilege_restored = false;
bool inspected_privilege_handle_closed = false;
DWORD inspection_previous_attributes = 0;
bool inspect_service_repair = false;
bool deny_service_config = false;
unsigned repair_starts = 0;
const wchar_t* repair_binary = L"\"C:\\Program Files\\FuzeVPN\\fuzevpn-service.exe\" --fuzevpn-vpn-service";
const wchar_t* repair_account = L"LocalSystem";
BOOL WINAPI ObserveQueryServiceConfig(SC_HANDLE service, LPQUERY_SERVICE_CONFIGW config,
                                     DWORD size, LPDWORD needed) {
  if (!inspect_service_repair) return QueryServiceConfigW(service, config, size, needed);
  *needed = sizeof(QUERY_SERVICE_CONFIGW);
  if (deny_service_config) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  if (config == nullptr || size < *needed) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
  ZeroMemory(config, sizeof(*config));
  config->dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  config->lpBinaryPathName = const_cast<LPWSTR>(repair_binary);
  config->lpServiceStartName = const_cast<LPWSTR>(repair_account);
  return TRUE;
}
BOOL WINAPI ObserveStartService(SC_HANDLE service, DWORD count, LPCWSTR* args) {
  if (!inspect_service_repair) return StartServiceW(service, count, args);
  ++repair_starts;
  return TRUE;
}
BOOL WINAPI ObserveOpenProcessToken(HANDLE process, DWORD access, PHANDLE token) {
  if (!inspect_privilege_adjustments) return OpenProcessToken(process, access, token);
  if (deny_inspection_token) {
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
  }
  if (access != (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)) return FALSE;
  *token = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(104));
  return TRUE;
}
BOOL WINAPI ObserveAdjustTokenPrivileges(HANDLE token, BOOL disable_all,
    PTOKEN_PRIVILEGES requested, DWORD size, PTOKEN_PRIVILEGES previous,
    PDWORD returned) {
  if (!inspect_privilege_adjustments) return AdjustTokenPrivileges(token,
      disable_all, requested, size, previous, returned);
  if (disable_all || requested == nullptr || requested->PrivilegeCount != 1)
    return FALSE;
  if (previous != nullptr) {
    inspected_privilege_enabled =
        requested->Privileges[0].Attributes == SE_PRIVILEGE_ENABLED;
    *previous = *requested;
    previous->Privileges[0].Attributes = inspection_previous_attributes;
    *returned = sizeof(*previous);
  } else {
    inspected_privilege_restored = requested->Privileges[0].Attributes ==
        inspection_previous_attributes;
  }
  SetLastError(ERROR_SUCCESS);
  return TRUE;
}
BOOL WINAPI ObserveCloseHandle(HANDLE handle) {
  if (inspect_presence_wait_failure && handle == presence_process_handle) {
    SetLastError(ERROR_INVALID_HANDLE); return TRUE;
  }
  if (!inspect_privilege_adjustments) return CloseHandle(handle);
  inspected_privilege_handle_closed = handle ==
      reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(104));
  return inspected_privilege_handle_closed;
}
DWORD WINAPI ObserveGetSecurityInfo(HANDLE object, SE_OBJECT_TYPE type,
    SECURITY_INFORMATION information, PSID* owner, PSID* group, PACL* dacl,
    PACL* sacl, PSECURITY_DESCRIPTOR* descriptor) {
  if (!inspect_acl_writes) return GetSecurityInfo(object, type, information,
      owner, group, dacl, sacl, descriptor);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;;GA;;;SY)", SDDL_REVISION_1, descriptor, nullptr))
    return GetLastError();
  BOOL present = FALSE, defaulted = FALSE;
  return GetSecurityDescriptorDacl(*descriptor, &present, dacl, &defaulted) ?
      ERROR_SUCCESS : ERROR_INVALID_SECURITY_DESCR;
}
DWORD WINAPI ObserveSetSecurityInfo(HANDLE object, SE_OBJECT_TYPE type,
    SECURITY_INFORMATION information, PSID owner, PSID group, PACL dacl,
    PACL sacl) {
  if (!inspect_acl_writes) return SetSecurityInfo(object, type, information,
      owner, group, dacl, sacl);
  if (type != SE_KERNEL_OBJECT || information != DACL_SECURITY_INFORMATION ||
      dacl == nullptr) return ERROR_INVALID_PARAMETER;
  inspected_interactive_mask = 0;
  inspected_preserved_system_ace = false;
  for (DWORD i = 0; i < dacl->AceCount; ++i) {
    void* raw = nullptr;
    if (!GetAce(dacl, i, &raw)) continue;
    const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
    if (IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinInteractiveSid))
      inspected_interactive_mask |= ace->Mask;
    if (IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinLocalSystemSid) &&
        ace->Mask == GENERIC_ALL) inspected_preserved_system_ace = true;
  }
  return ERROR_SUCCESS;
}
SC_HANDLE WINAPI ObserveOpenManager(LPCWSTR machine, LPCWSTR database, DWORD access) {
  ++scm_manager_queries;
  if (scm_scenario == ScmScenario::real)
    return OpenSCManagerW(machine, database, access);
  if (scm_scenario == ScmScenario::manager_denied) {
    SetLastError(ERROR_ACCESS_DENIED);
    return nullptr;
  }
  return reinterpret_cast<SC_HANDLE>(static_cast<ULONG_PTR>(101));
}
SC_HANDLE WINAPI ObserveOpenService(SC_HANDLE manager, LPCWSTR name, DWORD access) {
  if (scm_scenario == ScmScenario::real) return OpenServiceW(manager, name, access);
  if (scm_scenario == ScmScenario::service_denied ||
      scm_scenario == ScmScenario::absent) {
    SetLastError(scm_scenario == ScmScenario::absent ?
                 ERROR_SERVICE_DOES_NOT_EXIST : ERROR_ACCESS_DENIED);
    return nullptr;
  }
  return reinterpret_cast<SC_HANDLE>(static_cast<ULONG_PTR>(102));
}
BOOL WINAPI ObserveQueryService(SC_HANDLE service, SC_STATUS_TYPE type,
                                LPBYTE buffer, DWORD size, LPDWORD needed) {
  if (scm_scenario == ScmScenario::real)
    return QueryServiceStatusEx(service, type, buffer, size, needed);
  if (scm_scenario == ScmScenario::query_failed) {
    SetLastError(ERROR_ACCESS_DENIED);
    return FALSE;
  }
  if (size < sizeof(SERVICE_STATUS_PROCESS)) return FALSE;
  auto* status = reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer);
  ZeroMemory(status, sizeof(*status));
  *needed = sizeof(*status);
  status->dwCurrentState = scm_scenario == ScmScenario::stopped ? SERVICE_STOPPED :
      scm_scenario == ScmScenario::starting_without_pid ? SERVICE_START_PENDING :
                                                       SERVICE_RUNNING;
  status->dwProcessId = scm_scenario == ScmScenario::running ? 500 : 0;
  return TRUE;
}
BOOL WINAPI ObserveCloseService(SC_HANDLE handle) {
  return scm_scenario == ScmScenario::real ? CloseServiceHandle(handle) : TRUE;
}
}
namespace fuzevpn_ipc {
bool ObserveReadServicePipeName(DWORD expected_process, std::wstring* name) {
  if (expected_process == 0) { SetLastError(ERROR_FILE_NOT_FOUND); return false; }
  endpoint_detail::Record record;
  record.process_id = expected_process;
  record.nonce.fill(7);
  *name = endpoint_detail::PipeName(record);
  return true;
}
}
#define ReadServicePipeName ObserveReadServicePipeName
#define OpenSCManagerW ObserveOpenManager
#define OpenServiceW ObserveOpenService
#define QueryServiceStatusEx ObserveQueryService
#define QueryServiceConfigW ObserveQueryServiceConfig
#define StartServiceW ObserveStartService
#define SetServiceStatus ObserveSetServiceStatus
#define CloseServiceHandle ObserveCloseService
#define GetSecurityInfo ObserveGetSecurityInfo
#define SetSecurityInfo ObserveSetSecurityInfo
#define OpenProcessToken ObserveOpenProcessToken
#define AdjustTokenPrivileges ObserveAdjustTokenPrivileges
#define CloseHandle ObserveCloseHandle
#define OpenProcess ObserveOpenProcess
#define ProtectedStoreUserId TestProtectedStoreUserId
#define WriteUserDiagnostic TestWriteUserDiagnostic
#define CurrentMode TestCurrentMode
#define CreateFileW ObserveCreateFile
#define GetTickCount64 ObserveTicks
#define WaitForSingleObject ObserveTransportWait
#define WinVerifyTrust ObserveTransportTrust
#include "../privileged_broker.cpp"
#undef OpenSCManagerW
#undef OpenServiceW
#undef QueryServiceStatusEx
#undef QueryServiceConfigW
#undef StartServiceW
#undef SetServiceStatus
#undef CloseServiceHandle
#undef GetSecurityInfo
#undef SetSecurityInfo
#undef OpenProcessToken
#undef AdjustTokenPrivileges
#undef CloseHandle
#undef OpenProcess
#undef ProtectedStoreUserId
#undef WriteUserDiagnostic
#undef CurrentMode
#undef CreateFileW
#undef GetTickCount64
#undef WaitForSingleObject
#undef WinVerifyTrust
#undef ReadServicePipeName

#include <iostream>
#include <stdexcept>
#include "../wireguard_endpoint.h"
#include "installation_security_path_test.h"
#include "broker_passive_connect_test.h"
#include "runtime_namespace_test.h"
#include "service_pipe_endpoint_test.h"
#include "legacy_runtime_guard_test.h"

bool IsWireGuardTunnelConnected() { return false; }
bool IsOpenVpnTunnelConnected() { return false; }
std::string test_runtime_user = "S-1-5-21-1-2-3-1001";
std::optional<bool> test_wireguard_stopped = true;
bool test_openvpn_stopped = true;
bool test_wireguard_protection = false;
bool test_openvpn_protection = false;
bool test_protection_known = true;
unsigned test_openvpn_exception = 0;
unsigned test_native_mutations = 0;
unsigned test_snapshot_queries = 0;
std::string TestProtectedStoreUserId() { return test_runtime_user; }
std::string test_written_diagnostic;
bool TestWriteUserDiagnostic(const std::string&, const std::string& text, bool) {
  test_written_diagnostic = text;
  if (test_diagnostic_changes_error) SetLastError(ERROR_INVALID_DATA);
  return true;
}
std::optional<bool> IsWireGuardTunnelStopped() { return test_wireguard_stopped; }
bool IsOpenVpnTunnelStopped() { return test_openvpn_stopped; }
bool IsNetworkProtectionActive(NetworkProtectionOwner owner) {
  return owner == NetworkProtectionOwner::wire_guard ? test_wireguard_protection :
                                                     test_openvpn_protection;
}
bool IsNetworkProtectionStateKnown() { return test_protection_known; }
// Persistent filtering is exercised by network_filter_test's mocked WFP engine.
// The broker boundary test must never read or write the machine policy store.
bool SetNetworkProtectionUser(const std::string&) { return true; }
bool RestoreNetworkProtection(std::string* user) { user->clear(); return true; }
bool PrepareNetworkProtectionForInternalStop() { return true; }
ScopedNetworkProtectionRetention::ScopedNetworkProtectionRetention() = default;
ScopedNetworkProtectionRetention::~ScopedNetworkProtectionRetention() = default;
namespace fuzevpn_diagnostics {
// Keep this IPC test independent of live network/driver observations. The
// snapshot encoder and redaction rules have their own synthetic test suite.
flutter::EncodableMap RequestRuntimeSnapshot(const std::string& user, bool owned, bool other_user) {
  ++test_snapshot_queries;
  return {
      {flutter::EncodableValue("test_user"), flutter::EncodableValue(user)},
      {flutter::EncodableValue("test_owned"), flutter::EncodableValue(owned)},
      {flutter::EncodableValue("test_other_user"), flutter::EncodableValue(other_user)},
  };
}
void InvalidateRuntimeSnapshots() {}
void ShutdownRuntimeSnapshots() {}
}
// WFP path semantics are covered separately by network_filter_test's simulated
// production filters; this IPC executable must never create a WFP session.
bool SetAuthenticatedBrokerUiPath(std::wstring) { return true; }
void ClearAuthenticatedBrokerUiPath() {}
void RemoveWireGuardTunnelService() {}
void HandleWireGuardPrivilegedCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    flutter::MethodResult<flutter::EncodableValue>* result) {
  if (call.method_name() == "networkProtectionStatus") {
    result->Success(flutter::EncodableValue(flutter::EncodableMap{
        {flutter::EncodableValue("active"), flutter::EncodableValue(test_wireguard_protection)},
        {flutter::EncodableValue("phase"), flutter::EncodableValue("prepared")},
        {flutter::EncodableValue("killSwitch"), flutter::EncodableValue(true)},
    }));
    return;
  }
  ++test_native_mutations;
  if (call.method_name() == "prepareConnection") test_wireguard_protection = true;
  if (call.method_name() == "disconnect") test_wireguard_protection = false;
  result->Success(flutter::EncodableValue(false));
}
void HandleOpenVpnPrivilegedCall(
    const flutter::MethodCall<flutter::EncodableValue>&,
    flutter::MethodResult<flutter::EncodableValue>* result) {
  ++test_native_mutations;
  if (test_openvpn_exception == 1) throw std::runtime_error("private-openvpn-profile-detail");
  if (test_openvpn_exception == 2) throw 17;
  result->Success(flutter::EncodableValue(false));
}
bool TestProtectedStoreTokenRouting();
bool TestProtectedDiagnosticRouting();
bool TestProtectedStoreReadFailures();
bool TestProtectedStoreWriteFailures();
bool TestMaintenanceRecovery();
bool TestMaintenanceNetworkRecovery();
bool TestPortableServiceLease();

namespace {
int failures = 0;
void Check(bool condition, const char* message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAIL: " << message << " (Windows " << GetLastError() << ")\n";
  }
}

struct PipePair {
  HANDLE server = INVALID_HANDLE_VALUE;
  HANDLE client = INVALID_HANDLE_VALUE;
  explicit PipePair(unsigned index) {
    const auto name = L"\\\\.\\pipe\\FuzeAuditSecurityTest-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(index);
    server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX |
        FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
        256, 256, 0, nullptr);
    Check(server != INVALID_HANDLE_VALUE, "create isolated test pipe");
    client = CreateFileW(name.c_str(), fuzevpn_ipc::kPipeClientAccess,
        0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED |
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    Check(client != INVALID_HANDLE_VALUE, "connect using minimal client rights");
    OVERLAPPED connection{};
    connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const bool connected = ConnectNamedPipe(server, &connection) != FALSE ||
                           GetLastError() == ERROR_PIPE_CONNECTED;
    Check(connected, "connect isolated test pair");
    CloseHandle(connection.hEvent);
  }
  ~PipePair() {
    if (client != INVALID_HANDLE_VALUE) CloseHandle(client);
    if (server != INVALID_HANDLE_VALUE) CloseHandle(server);
  }
};

void CheckInteractiveRights(const wchar_t* sddl, DWORD required,
                            DWORD forbidden) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
      SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "parse production DACL");
  if (descriptor == nullptr) return;
  PACL acl = nullptr;
  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  Check(GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) &&
        present && acl != nullptr, "production DACL present");
  bool found = false;
  if (acl != nullptr) {
    for (DWORD i = 0; i < acl->AceCount; ++i) {
      void* raw = nullptr;
      if (!GetAce(acl, i, &raw)) continue;
      const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
          IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinInteractiveSid)) {
        found = true;
        Check((ace->Mask & required) == required,
              "interactive rights include required access");
        Check((ace->Mask & forbidden) == 0,
              "interactive rights exclude privileged access");
      }
    }
  }
  Check(found, "interactive ACE exists");
  LocalFree(descriptor);
}

void TestInstallationPolicy() {
  TestInstallationPathSecurity();
  using fuzevpn_installation::IsCanonicalLocalAbsolutePath;
  Check(IsCanonicalLocalAbsolutePath(L"D:\\Applications\\FuzeVPN") &&
        IsCanonicalLocalAbsolutePath(L"c:\\Dossier avec espaces\\\u00c9quipe VPN"),
        "custom local paths preserve ordinary spaces, Unicode and drive case");
  for (const auto* path : {L"C:\\", L"C:FuzeVPN", L"FuzeVPN", L"\\\\server\\share\\FuzeVPN",
       L"\\\\?\\C:\\FuzeVPN", L"C:/Apps/FuzeVPN", L"C:\\Apps\\..\\FuzeVPN", L"C:\\Apps\\.\\FuzeVPN",
       L"C:\\Apps\\\\FuzeVPN", L"C:\\Apps\\FuzeVPN\\", L"C:\\Apps\\FuzeVPN.", L"C:\\Apps\\FuzeVPN ",
       L"C:\\Apps\\FuzeVPN:stream", L"C:\\Apps\\NUL.exe", L"C:\\Apps\\LPT1", L"C:\\Apps\\a*b"}) {
    Check(!IsCanonicalLocalAbsolutePath(path), "ambiguous or nonlocal install path is rejected");
  }
  Check(!IsCanonicalLocalAbsolutePath(std::wstring(L"C:\\Apps\\Fuze\0VPN", 16)),
        "embedded NUL cannot truncate a validated installation path");
  auto permitted = [](const wchar_t* sddl, bool ancestor = false) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &descriptor, nullptr)) return false;
    const bool result = fuzevpn_installation::IsProtectedDescriptor(
        descriptor, true, ancestor);
    LocalFree(descriptor);
    return result;
  };
  Check(permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)"),
        "protected installer ACL admits SYSTEM/admin writes and user read/execute");
  Check(!permitted(L"O:S-1-5-21-1-2-3-1001G:SYD:P(A;;FA;;;SY)(A;;GRGX;;;BU)"),
        "ordinary owner cannot regain writes through WRITE_DAC");
  Check(!permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x00000002;;;BU)"),
        "ordinary write-data grant is rejected");
  Check(!permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x00040000;;;AU)"),
        "ordinary WRITE_DAC grant is rejected");
  Check(!permitted(L"O:SYG:SYD:NO_ACCESS_CONTROL"), "null DACL is rejected");
  Check(permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;IO;FA;;;CO)(A;;GRGX;;;BU)"),
        "inherit-only creator grant does not affect the checked directory");
  Check(permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x00000004;;;AU)", true),
        "volume creation rights alone cannot replace the protected child");
  Check(!permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;0x00000040;;;AU)", true),
        "volume delete-child grant prevents secure installation");
  Check(!permitted(L"O:SYG:SYD:P(A;;FA;;;SY)(A;;SD;;;AU)", true),
        "an ancestor cannot be renamed through its own ordinary DELETE grant");
  const std::filesystem::path root(L"C:\\Program Files");
  Check(fuzevpn_installation::IsDescendant(L"c:\\program files\\FuzeVPN", root),
        "installation containment uses case-insensitive directory boundary");
  Check(!fuzevpn_installation::IsDescendant(L"C:\\Program Files-other\\FuzeVPN", root) &&
        !fuzevpn_installation::IsDescendant(root, root),
        "sibling prefix and the Program Files root are not app directories");
  fuzevpn_installation::ProtectedInstallation untrusted;
  Check(!untrusted.Validate(L"C:\\Users\\Untrusted\\fuzevpn-service.exe"),
        "a user-profile bundle is refused before any elevation can be requested");
}

void TestExclusiveRuntime() {
  const auto name = L"Local\\FuzeVpnRuntimeLockTest-" + std::to_wstring(GetCurrentProcessId());
  {
    fuzevpn_ipc::ExclusiveRuntimeLock first;
    Check(first.Acquire(name.c_str(), nullptr), "first isolated runtime reserves its machine resource");
    bool second_owned = true;
    std::thread contender([&]() {
      fuzevpn_ipc::ExclusiveRuntimeLock second;
      second_owned = second.Acquire(name.c_str(), nullptr);
    });
    contender.join();
    Check(!second_owned, "another runtime cannot enter owner cleanup while the first is alive");
  }
  fuzevpn_ipc::ExclusiveRuntimeLock recovered;
  Check(recovered.Acquire(name.c_str(), nullptr), "runtime reservation releases after owner cleanup");
}

void TestPortableDevelopmentPolicy() {
  using fuzevpn_broker::CanSkipProtectedInstallation;
  Check(!CanSkipProtectedInstallation<false>(TRUST_E_NOSIGNATURE, TRUST_E_NOSIGNATURE),
        "default production build still requires a protected installation for unsigned files");
  Check(CanSkipProtectedInstallation<true>(TRUST_E_NOSIGNATURE, TRUST_E_NOSIGNATURE),
        "explicit portable test build admits only a paired unsigned bundle");
  for (const LONG other : {static_cast<LONG>(ERROR_SUCCESS), TRUST_E_BAD_DIGEST,
                          CERT_E_UNTRUSTEDROOT, CERT_E_EXPIRED,
                          static_cast<LONG>(ERROR_ACCESS_DENIED)}) {
    Check(!CanSkipProtectedInstallation<true>(other, TRUST_E_NOSIGNATURE) &&
          !CanSkipProtectedInstallation<true>(TRUST_E_NOSIGNATURE, other) &&
          !CanSkipProtectedInstallation<true>(other, other),
          "signed, mixed, invalid or unreadable bundles never use the portable exception");
  }
  Check(CanSkipProtectedInstallation(TRUST_E_NOSIGNATURE, TRUST_E_NOSIGNATURE) ==
        fuzevpn_broker::kAllowPortableDevelopment,
        "actual broker policy follows the explicit compile-time option");
}

void TestServiceRepair() {
  inspect_service_repair = true;
  repair_starts = 0;
  const std::wstring expected(repair_binary);
  Check(StartExistingExpectedVpnService(nullptr, expected) && repair_starts == 1,
        "an existing stopped registration is reused without service deletion");
  Check(!StartExistingExpectedVpnService(nullptr, L"other.exe") && repair_starts == 1,
        "a different installation is preserved for an explicit installer migration");
  Check(GetLastError() == ERROR_BAD_CONFIGURATION,
        "configuration mismatch has an explicit installer result");
  repair_account = L"LocalService";
  Check(!StartExistingExpectedVpnService(nullptr, expected) && repair_starts == 1,
        "an unexpected service identity cannot be adopted");
  Check(GetLastError() == ERROR_BAD_CONFIGURATION,
        "unexpected service identity is distinguished from unavailable SCM");
  repair_account = L"LocalSystem";
  deny_service_config = true;
  Check(!StartExistingExpectedVpnService(nullptr, expected) && repair_starts == 1,
        "unreadable existing configuration is preserved");
  Check(GetLastError() == ERROR_ACCESS_DENIED,
        "SCM read refusal is not relabeled as a configuration mismatch");
  Check(ServiceInstallerFailureCode(ERROR_SUCCESS) == nullptr &&
        ServiceInstallerFailureCode(STILL_ACTIVE) == nullptr &&
        std::string(ServiceInstallerFailureCode(ERROR_BAD_CONFIGURATION)) ==
            "service_configuration_mismatch" &&
        std::string(ServiceInstallerFailureCode(ERROR_ACCESS_DENIED)) ==
            "service_install_failed",
        "installer process result maps to a precise non-sensitive parent diagnostic");
  deny_service_config = false;
  inspect_service_repair = false;
}

void TestWireGuardCandidates() {
  using namespace fuzevpn;
  std::vector<std::string> endpoints;
  Check(PrepareWireGuardEndpoints("vpn.example:51820", [] { return true; },
      [] { return true; }, [](const std::string&, std::vector<std::string>* addresses) {
        *addresses = {"192.0.2.1", "2001:db8::2", "192.0.2.1"}; return true;
      }, &endpoints) == WireGuardEndpointResult::ready &&
      endpoints == std::vector<std::string>{"192.0.2.1:51820", "[2001:db8::2]:51820"},
      "all validated DNS candidates are formatted and deduplicated");
  std::uint64_t now = 0;
  unsigned attempts = 0;
  Check(TryWireGuardEndpoints(endpoints, 70000, [&] { return now; },
      [&](const std::string&, std::uint64_t deadline, size_t index) {
        Check(index == attempts, "each attempt receives its candidate index");
        ++attempts;
        if (attempts == 1) { Check(deadline == 35000, "first address gets a bounded share"); now = deadline; return WireGuardAttemptResult::retry; }
        Check(deadline == 70000, "remaining address retains the rest of the shared budget");
        return WireGuardAttemptResult::connected;
      }) && attempts == 2, "a failed first handshake permits a reachable second address");
  attempts = 0;
  now = 70000;
  Check(!TryWireGuardEndpoints(endpoints, 70000, [&] { return now; },
      [&](const std::string&, std::uint64_t, size_t) { ++attempts; return WireGuardAttemptResult::connected; }) &&
      attempts == 0, "expired overall deadline never starts another tunnel attempt");
}

// Simulated clock: the real loop, with a scripted driver handshake and SCM.
struct HandshakeWait {
  std::uint64_t now = 0;
  std::uint64_t handshake_at = UINT64_MAX;
  std::uint64_t stopped_at = UINT64_MAX;
  std::vector<std::uint64_t> probes;
  bool Run(std::uint64_t window, std::uint64_t attempt_deadline) {
    return fuzevpn::WaitForWireGuardHandshake(window, attempt_deadline, [&] { return now; },
        [&] { probes.push_back(now); }, [&] { return now >= handshake_at; },
        [&] { return now < stopped_at; }, [&](std::uint64_t milliseconds) {
          Check(milliseconds >= 1 && milliseconds <= 100, "handshake polling stays bounded");
          now += milliseconds;
        });
  }
};

void TestWireGuardHandshakeWait() {
  using namespace fuzevpn;
  // Four initiations, each up to REKEY_TIMEOUT plus jitter apart, must fit.
  Check(kWireGuardFinalHandshakeWaitMs >= 3 * 5333 + 1000 &&
        kWireGuardFailoverHandshakeWaitMs >= 5333 + 1000 &&
        kWireGuardFailoverHandshakeWaitMs < kWireGuardFinalHandshakeWaitMs,
        "handshake windows cover the intended WireGuard initiations");
  Check(WireGuardHandshakeWindow(0, 1) == kWireGuardFinalHandshakeWaitMs &&
        WireGuardHandshakeWindow(0, 2) == kWireGuardFailoverHandshakeWaitMs &&
        WireGuardHandshakeWindow(1, 2) == kWireGuardFinalHandshakeWaitMs &&
        WireGuardHandshakeWindow(6, 8) == kWireGuardFailoverHandshakeWaitMs &&
        WireGuardHandshakeWindow(7, 8) == kWireGuardFinalHandshakeWaitMs,
        "only the last or only candidate gets the long handshake window");
  HandshakeWait late;
  late.handshake_at = 15400;  // Third retransmission after a relocated peer.
  Check(late.Run(WireGuardHandshakeWindow(0, 1), 70000) && late.now == 15400,
        "the only candidate tolerates two unanswered initiations");
  Check(!late.probes.empty() && late.probes.front() == 0 && late.probes.size() == 16,
        "tunneled traffic is solicited once per second while waiting");
  HandshakeWait failover;
  failover.handshake_at = 15400;
  Check(!failover.Run(WireGuardHandshakeWindow(0, 2), 35000) && failover.now == 8000,
        "an earlier address still fails over after the short window");
  HandshakeWait silent;
  Check(!silent.Run(kWireGuardFinalHandshakeWaitMs, 70000) &&
        silent.now == kWireGuardFinalHandshakeWaitMs,
        "an unanswered last candidate gives up exactly at its window");
  HandshakeWait bounded;
  bounded.now = 61250;
  Check(!bounded.Run(kWireGuardFinalHandshakeWaitMs, 70000) && bounded.now == 70000,
        "the long window never exceeds the attempt deadline");
  HandshakeWait expired;
  expired.now = 70000;
  Check(!expired.Run(kWireGuardFinalHandshakeWaitMs, 70000) && expired.probes.empty(),
        "an expired attempt neither solicits nor waits");
  HandshakeWait stopped;
  stopped.stopped_at = 3000;
  Check(!stopped.Run(kWireGuardFinalHandshakeWaitMs, 70000) && stopped.now == 3000,
        "a stopped tunnel service ends the wait at once");
  HandshakeWait immediate;
  immediate.handshake_at = 0;
  Check(immediate.Run(kWireGuardFinalHandshakeWaitMs, 70000) && immediate.now == 0 &&
        immediate.probes.size() == 1, "an existing handshake succeeds without waiting");

  WireGuardAttemptSnapshot snapshot;
  snapshot.candidates = 2;
  snapshot.candidate_index = 1;
  snapshot.stage = WireGuardAttemptStage::peer_ready;
  snapshot.elapsed_ms = 21543;
  snapshot.budget_ms = 61200;
  snapshot.service_start_ms = 402;
  snapshot.handshake_wait_ms = 20000;
  snapshot.stop_ms = 1100;
  snapshot.tx_bytes = 592;
  snapshot.stats_reads = 197;
  Check(FormatWireGuardAttemptSnapshot(snapshot) ==
        "candidates=2 candidate_index=1 stage=peer_ready handshake=0 success=0 elapsed_ms=21543 "
        "budget_ms=61200 service_start_ms=402 handshake_wait_ms=20000 stop_ms=1100 "
        "tx_bytes=592 rx_bytes=0 stats_reads=197", "attempt snapshot is numeric with a closed stage");
  snapshot.stage = WireGuardAttemptStage::adapter_open;
  Check(FormatWireGuardAttemptSnapshot(snapshot).find("stage=adapter_open ") != std::string::npos,
        "adapter-open failure is distinguishable from the handshake wait");
  Check(FormatWireGuardAttemptSnapshot(WireGuardAttemptSnapshot{}).ends_with(
            " tx_bytes=0 rx_bytes=0 stats_reads=0"),
        "an attempt without a driver reading says so instead of claiming nothing was sent");

  // Only a successful driver reading replaces the counters and is counted.
  WireGuardPeerStats observed;
  std::uint64_t reads = 0;
  const auto unreadable = [](WireGuardPeerStats* stats) { stats->tx = 999; return false; };
  Check(!ObserveWireGuardPeer(unreadable, &observed, &reads) && reads == 0 && observed.tx == 0,
        "a failed driver reading is neither counted nor recorded");
  Check(!ObserveWireGuardPeer([](WireGuardPeerStats* stats) { stats->tx = 592; return true; },
                              &observed, &reads) && reads == 1 && observed.tx == 592,
        "an unanswered driver reading is counted with its counters");
  Check(!ObserveWireGuardPeer(unreadable, &observed, &reads) && reads == 1 && observed.tx == 592,
        "a later failed reading keeps the last driver counters");
  Check(ObserveWireGuardPeer([](WireGuardPeerStats* stats) {
          stats->tx = 740; stats->rx = 92; stats->handshake = 1; return true;
        }, &observed, &reads) && reads == 2 && observed.rx == 92,
        "an authenticated driver reading ends the wait");
  // Polled every 100 ms until the handshake at 15.4 s: 155 readings, of which
  // the 15 at x.5 s are refused by the driver and must not be counted.
  std::uint64_t wait_now = 0;
  std::uint64_t counted_reads = 0;
  WireGuardPeerStats last;
  Check(WaitForWireGuardHandshake(kWireGuardFinalHandshakeWaitMs, 70000,
            [&] { return wait_now; }, [] {},
            [&] {
              return ObserveWireGuardPeer([&](WireGuardPeerStats* stats) {
                if (wait_now % 1000 == 500) return false;
                stats->tx = wait_now / 100;
                stats->handshake = wait_now >= 15400 ? 1u : 0u;
                return true;
              }, &last, &counted_reads);
            },
            [] { return true; }, [&](std::uint64_t milliseconds) { wait_now += milliseconds; }) &&
        wait_now == 15400 && counted_reads == 140 && last.handshake == 1 && last.tx == 154,
        "the wait counts exactly its successful driver readings");

  // service_start_ms covers the SCM start alone, not the configuration write.
  std::uint64_t fake_ticks = 700;
  std::uint64_t service_start_ms = 0;
  Check(TimeWireGuardServiceStart([&] { return fake_ticks; }, [&] { fake_ticks += 402; return true; },
                                  &service_start_ms) && service_start_ms == 402,
        "service start time excludes configuration generation and write");
  Check(!TimeWireGuardServiceStart([&] { return fake_ticks; }, [&] { fake_ticks += 35; return false; },
                                   &service_start_ms) && service_start_ms == 35,
        "a failed service start still reports its own duration");
}

// Breadcrumb operations are fixed camelCase identifiers; the writer must
// persist them for the local reader and still reject field separators.
void TestNativeDiagnosticIdentifiers() {
  test_written_diagnostic.clear();
  WriteSafeOperation("openvpn.importAndConnect", "started");
  Check(test_written_diagnostic.find(" area=openvpn event=importAndConnect_started\r\n") !=
        std::string::npos, "OpenVPN connect breadcrumb reaches the native log");
  WriteSafeOperation("openvpn.prepareConnection", "succeeded");
  Check(test_written_diagnostic.find(" area=openvpn event=prepareConnection_succeeded\r\n") !=
        std::string::npos, "OpenVPN preparation breadcrumb reaches the native log");
  WriteSafeOperation("wireguard.prepareIdentityForAccount", "failed");
  Check(test_written_diagnostic.find(" area=wireguard event=prepareIdentityForAccount_failed\r\n") !=
        std::string::npos, "WireGuard identity breadcrumb reaches the native log");
  for (const char* forged : {"importAndConnect_started code=other", "importAndConnect\r\nx",
                             "event=connect_started", "", "import/connect"}) {
    test_written_diagnostic.clear();
    AppendNativeDiagnostic("openvpn", forged);
    Check(test_written_diagnostic.empty(), "diagnostic identifiers cannot forge fields or lines");
  }
  test_written_diagnostic.clear();
  AppendNativeDiagnostic("openvpn", std::string(81, 'A'));
  Check(test_written_diagnostic.empty(), "diagnostic identifiers stay bounded");
}

std::vector<uint8_t> EncodedCall(const std::string& method,
                               const flutter::EncodableValue* arguments = nullptr) {
  flutter::MethodCall<flutter::EncodableValue> call(method,
      arguments == nullptr ? nullptr : std::make_unique<flutter::EncodableValue>(*arguments));
  return *flutter::StandardMethodCodec::GetInstance().EncodeMethodCall(call);
}

void TestProtocolValidation() {
  auto accepted = [](const std::vector<uint8_t>& bytes) {
    return fuzevpn_ipc::ValidateMethodRequest(bytes.data(), bytes.size());
  };
  for (const char* method : {"wireguard.disconnect", "openvpn.disconnect",
       "wireguard.suspendForMigration", "openvpn.suspendForMigration",
       "wireguard.networkProtectionStatus", "openvpn.networkProtectionStatus",
       "wireguard.resolveApiAddresses", "wireguard.reconnect", "openvpn.reconnect"}) {
    Check(accepted(EncodedCall(method)), "valid no-argument application method accepted");
  }
  const flutter::EncodableValue protection(flutter::EncodableMap{
      {flutter::EncodableValue("killSwitch"), flutter::EncodableValue(true)},
      {flutter::EncodableValue("dnsProtection"), flutter::EncodableValue(false)},
  });
  const auto valid = EncodedCall("wireguard.prepareConnection", &protection);
  Check(accepted(valid), "valid typed options accepted before decoding");
  bool all_truncations_rejected = true;
  for (size_t length = 0; length < valid.size(); ++length)
    all_truncations_rejected &= !fuzevpn_ipc::ValidateMethodRequest(valid.data(), length);
  Check(all_truncations_rejected, "every truncation rejected before codec access");
  auto extra = valid;
  extra.push_back(0);
  Check(!accepted(extra), "trailing bytes rejected");
  const flutter::EncodableValue wrong_type(flutter::EncodableMap{
      {flutter::EncodableValue("killSwitch"), flutter::EncodableValue("true")},
  });
  Check(!accepted(EncodedCall("wireguard.prepareConnection", &wrong_type)),
        "wrong option type cannot silently select a default");
  const flutter::EncodableValue unknown_field(flutter::EncodableMap{
      {flutter::EncodableValue("unrecognized"), flutter::EncodableValue(true)},
  });
  Check(!accepted(EncodedCall("wireguard.prepareConnection", &unknown_field)),
        "unknown fields rejected");
  Check(!accepted(EncodedCall("wireguard.unknown")), "unknown methods rejected");
  const flutter::EncodableValue too_long(flutter::EncodableMap{
      {flutter::EncodableValue("accountId"), flutter::EncodableValue(std::string(129, 'x'))},
  });
  Check(!accepted(EncodedCall("wireguard.prepareIdentityForAccount", &too_long)),
        "field length budget enforced");
  const auto& codec = flutter::StandardMethodCodec::GetInstance();
  const auto response = codec.EncodeSuccessEnvelope(&protection);
  Check(fuzevpn_ipc::ValidateResponseEnvelope(response->data(), response->size()),
        "valid bounded status map response accepted");
  const auto error = codec.EncodeErrorEnvelope("storage_error", "Unavailable");
  Check(fuzevpn_ipc::ValidateResponseEnvelope(error->data(), error->size()),
        "valid error envelope accepted");
  // These fixed-size fixtures go only through the allocation-free validator.
  const uint8_t excessive_string[] = {0, 7, 255, 255, 255, 255, 255};
  Check(!fuzevpn_ipc::ValidateResponseEnvelope(excessive_string, sizeof(excessive_string)),
        "declared lengths cannot request allocation from the general codec");
  const uint8_t wrong_error_type[] = {1, 1, 0, 0};
  Check(!fuzevpn_ipc::ValidateResponseEnvelope(wrong_error_type, sizeof(wrong_error_type)),
        "typed error fields checked before std::get in response codec");
  std::vector<uint8_t> deep{0};
  for (int depth = 0; depth < 10; ++depth) { deep.push_back(12); deep.push_back(1); }
  deep.push_back(0);
  Check(!fuzevpn_ipc::ValidateResponseEnvelope(deep.data(), deep.size()),
        "nested response complexity bounded");
}

void TestRuntimePresence() {
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
  for (auto scenario : {ScmScenario::manager_denied, ScmScenario::service_denied,
                        ScmScenario::query_failed,
                        ScmScenario::starting_without_pid}) {
    scm_scenario = scenario;
    Check(!PrivilegedRuntimePresence().has_value(),
          "SCM query error remains unknown, never disconnected");
    Check(IsPrivilegedBrokerRunning(),
          "legacy absence guard does not discard a command on SCM error");
    Check(IsPersistentVpnServiceRunning(),
          "GUI shutdown preserves service ownership when SCM is uncertain");
  }
  for (auto scenario : {ScmScenario::absent, ScmScenario::stopped}) {
    scm_scenario = scenario;
    Check(PrivilegedRuntimePresence() == std::optional<bool>(false),
          "missing or stopped service is confirmed absent");
  }
  scm_scenario = ScmScenario::running;
  Check(PrivilegedRuntimePresence() == std::optional<bool>(true),
        "running service is present");
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::portable;
  const unsigned prior_queries = scm_manager_queries;
  Check(PrivilegedRuntimePresence() == std::optional<bool>(false) &&
        !IsPersistentVpnServiceRunning() && scm_manager_queries == prior_queries,
        "portable runtime does not adopt or query an installed service");
  inspect_presence_wait_failure = true;
  launched_broker_pid.store(109);
  const auto failed_presence = PrivilegedRuntimePresence();
  const auto failed_presence_code = GetLastError();
  launched_broker_pid.store(0);
  inspect_presence_wait_failure = false;
  Check(!failed_presence.has_value() && failed_presence_code == ERROR_NOT_SUPPORTED,
        "runtime process wait retains Windows 50 before closing its handle");
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::unavailable;
  Check(!PrivilegedRuntimePresence().has_value() && scm_manager_queries == prior_queries,
        "unavailable distribution state remains unknown without querying SCM");
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
  scm_scenario = ScmScenario::real;
}

void TestServerInspectionRights() {
  // Intercept the OS descriptor write. No real process, token, or application's
  // security descriptor is changed by this test.
  inspect_acl_writes = true;
  HANDLE fake = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(103));
  Check(GrantInteractiveInspection(fake,
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
        "server process descriptor permits minimal identity inspection");
  Check(inspected_preserved_system_ace && inspected_interactive_mask ==
        (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
        "process ACL preserves SYSTEM and excludes write/injection access");
  Check(GrantInteractiveInspection(fake, TOKEN_QUERY),
        "server token descriptor permits query");
  Check(inspected_preserved_system_ace && inspected_interactive_mask == TOKEN_QUERY,
        "token ACL preserves SYSTEM and excludes duplication/impersonation");
  inspect_acl_writes = false;
}

void TestScopedInspectionPrivilege() {
  // Inject the token operations: this test never adjusts a real token.
  inspect_privilege_adjustments = true;
  for (DWORD initial : {DWORD(0), DWORD(SE_PRIVILEGE_ENABLED)}) {
    inspection_previous_attributes = initial;
    inspected_privilege_enabled = false;
    inspected_privilege_restored = false;
    inspected_privilege_handle_closed = false;
    {
      ScopedProcessInspectionPrivilege inspection;
      Check(inspected_privilege_enabled && !inspected_privilege_restored,
            "inspection privilege is enabled only inside its scope");
    }
    Check(inspected_privilege_restored && inspected_privilege_handle_closed,
          "inspection restores original privilege and closes token");
  }
  deny_inspection_token = true;
  inspected_privilege_enabled = false;
  inspected_privilege_restored = false;
  inspected_privilege_handle_closed = false;
  { ScopedProcessInspectionPrivilege inspection; }
  Check(!inspected_privilege_enabled && !inspected_privilege_restored &&
        !inspected_privilege_handle_closed,
        "failed token acquisition makes no privilege change");
  deny_inspection_token = false;
  inspect_privilege_adjustments = false;
}

void TestIoAndAuthentication() {
  PipePair pipes(1);
  const uint8_t sent[] = {7, 2, 9, 0};
  uint8_t received[sizeof(sent)]{};
  Check(WriteExactOverlapped(pipes.client, nullptr, sent, sizeof(sent)),
        "overlapped write with minimal rights");
  Check(ReadExactOverlapped(pipes.server, nullptr, received, sizeof(received)) &&
        std::memcmp(sent, received, sizeof(sent)) == 0, "exact bytes round trip");
  Check(!AuthenticatePipeServer(pipes.client, true),
        "an arbitrary local process cannot impersonate the SCM service");
  Check(!AuthenticatePipeServer(pipes.client, false),
        "an unlaunched peer cannot impersonate the elevated broker");

  const auto read_started = GetTickCount64();
  BYTE byte = 0;
  Check(!ReadExactOverlapped(pipes.server, nullptr, &byte, 1,
                             read_started + 40) &&
        GetLastError() == ERROR_TIMEOUT, "idle read has a deadline");
  Check(GetTickCount64() - read_started < 3000, "read cancellation is bounded");
  // Reuse the pipe immediately after the cancelled operation. Windows must
  // have finished writing the earlier OVERLAPPED and buffer before we return.
  Check(WriteExactOverlapped(pipes.client, nullptr, sent, sizeof(sent)),
        "pipe usable after cancellation drain");
  Check(ReadExactOverlapped(pipes.server, nullptr, received, sizeof(received)),
        "read usable after cancellation drain");

  std::vector<uint8_t> large(2 * 1024 * 1024, 0);
  const auto write_started = GetTickCount64();
  Check(!WriteExactOverlapped(pipes.client, nullptr, large.data(),
      static_cast<DWORD>(large.size()), write_started + 40) &&
      GetLastError() == ERROR_TIMEOUT, "blocked write has a deadline");
  Check(GetTickCount64() - write_started < 3000, "write cancellation is bounded");

  PipePair cancelled_pipes(2);
  HANDLE cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::thread canceller([cancel] { Sleep(30); SetEvent(cancel); });
  Check(!ReadExactOverlapped(cancelled_pipes.server, cancel, &byte, 1) &&
        GetLastError() == ERROR_OPERATION_ABORTED,
        "shutdown signal cancels a pending I/O and drains completion");
  canceller.join();
  CloseHandle(cancel);
}

struct ReplyState {
  bool replied = false;
  DWORD callback_thread = 0;
  std::string code;
  std::optional<flutter::EncodableValue> value;
};
class RecordingResult final : public flutter::MethodResult<flutter::EncodableValue> {
 public:
  explicit RecordingResult(ReplyState* state) : state_(state) {}
 protected:
  void SuccessInternal(const flutter::EncodableValue* value) override {
    if (value != nullptr) state_->value = *value;
    Record("success");
  }
  void ErrorInternal(const std::string& code, const std::string&,
                     const flutter::EncodableValue* details) override {
    if (details != nullptr) state_->value = *details;
    Record(code);
  }
  void NotImplementedInternal() override { Record("not_implemented"); }
 private:
  void Record(const std::string& code) {
    state_->replied = true;
    state_->callback_thread = GetCurrentThreadId();
    state_->code = code;
  }
  ReplyState* state_;
};

void CheckBrokerFailureDetails(const ReplyState& reply, const char* expected_code,
                              const char* expected_stage, DWORD expected_error) {
  Check(reply.replied && reply.code == expected_code,
        "IPC failure keeps its existing public error code");
  const auto* details = reply.value
      ? std::get_if<flutter::EncodableMap>(&*reply.value) : nullptr;
  Check(details != nullptr &&
        details->size() == (expected_error == ERROR_SUCCESS ? 1u : 2u),
        "IPC failure details contain only stage and a nonzero Windows code");
  if (details == nullptr) return;
  const auto stage = details->find(flutter::EncodableValue("stage"));
  Check(stage != details->end() &&
        std::holds_alternative<std::string>(stage->second) &&
        std::get<std::string>(stage->second) == expected_stage,
        "IPC failure stage is the exact bounded transport phase");
  const auto error = details->find(flutter::EncodableValue("win32_error"));
  if (expected_error == ERROR_SUCCESS) {
    Check(error == details->end(), "zero Windows code is omitted");
  } else {
    Check(error != details->end() &&
          std::holds_alternative<int64_t>(error->second) &&
          std::get<int64_t>(error->second) == static_cast<int64_t>(expected_error),
          "DWORD keeps its full unsigned range in the codec's int64 field");
  }
}

void TestBrokerFailureDetails() {
  struct Case {
    ExchangeFailure failure;
    const char* code;
    const char* stage;
  };
  const Case cases[] = {
      {ExchangeFailure::kNone, "broker_unavailable", "broker_connection"},
      {ExchangeFailure::kBrokerUnavailable, "broker_unavailable", "broker_connection"},
      {ExchangeFailure::kInstallationRequired, "installation_required", "broker_connection"},
      {ExchangeFailure::kRequestWriteFailed, "broker_write_failed", "broker_write"},
      {ExchangeFailure::kResponseUnavailable, "broker_response_timeout", "broker_response"}};
  for (const auto& item : cases) {
    for (const DWORD original_error : {DWORD{ERROR_SUCCESS}, DWORD{ERROR_NOT_SUPPORTED},
                                       DWORD{0xf1234567u}}) {
      ReplyState reply;
      std::vector<uint8_t> response{0x61, 0x62, 0x63};
      // Completion must use the snapshot, never this platform-thread errno.
      SetLastError(ERROR_ACCESS_DENIED);
      CompletePrivilegedCall(std::make_unique<RecordingResult>(&reply), false,
                            item.failure, &response, original_error);
      CheckBrokerFailureDetails(reply, item.code, item.stage, original_error);
      Check(response.empty(), "failed IPC response is wiped before delivery");
      if (!reply.value) continue;
      const auto& codec = flutter::StandardMethodCodec::GetInstance();
      const auto envelope = codec.EncodeErrorEnvelope(reply.code, "", &*reply.value);
      ReplyState decoded;
      RecordingResult receiver(&decoded);
      Check(envelope != nullptr && codec.DecodeAndProcessResponseEnvelope(
                envelope->data(), envelope->size(), &receiver),
            "actual StandardMethodCodec error envelope preserves structured details");
      CheckBrokerFailureDetails(decoded, item.code, item.stage, original_error);
    }
  }
  for (const DWORD closed_pipe : {DWORD{ERROR_BROKEN_PIPE},
                                  DWORD{ERROR_PIPE_NOT_CONNECTED}, DWORD{ERROR_NO_DATA}}) {
    ReplyState reply;
    std::vector<uint8_t> response;
    CompletePrivilegedCall(std::make_unique<RecordingResult>(&reply), false,
        ExchangeFailure::kResponseUnavailable, &response, closed_pipe);
    CheckBrokerFailureDetails(reply, "broker_unavailable", "broker_response", closed_pipe);
  }
  ReplyState timeout;
  std::vector<uint8_t> response;
  CompletePrivilegedCall(std::make_unique<RecordingResult>(&timeout), false,
      ExchangeFailure::kResponseUnavailable, &response, ERROR_TIMEOUT);
  CheckBrokerFailureDetails(timeout, "broker_response_timeout", "broker_response", ERROR_TIMEOUT);
}

void TestBrokerFailureCapture() {
  const auto old_mode = fuzevpn_distribution::test_distribution_mode;
  const auto old_scm = scm_scenario;
  HANDLE old_cancel = client_cancel_event;
  inspect_pipe_connections = true;
  test_diagnostic_changes_error = true;
  client_cancel_event = nullptr;
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
  scm_scenario = ScmScenario::running;
  scm_manager_queries = transport_open_attempts = transport_trust_queries = 0;
  transport_cancelled = false;
  transport_open_error = ERROR_NOT_SUPPORTED;
  std::vector<uint8_t> response;
  ExchangeFailure failure = ExchangeFailure::kNone;
  DWORD windows_error = 0xffffffffu;
  flutter::MethodCall<flutter::EncodableValue> call("wireguard.isConnected", nullptr);
  Check(!Exchange(call, false, &response, true, &failure, &windows_error) &&
        failure == ExchangeFailure::kBrokerUnavailable &&
        windows_error == ERROR_NOT_SUPPORTED && GetLastError() == ERROR_INVALID_DATA,
        "actual Exchange snapshots the connection error before diagnostic changes errno");
  Check(scm_manager_queries == 1 && transport_open_attempts == 1,
        "failure capture queries only simulated SCM identity and never retries a terminal pipe error");
  flutter::MethodCall<flutter::EncodableValue> oversized("wireguard.isConnected",
      std::make_unique<flutter::EncodableValue>(std::string(2 * 1024 * 1024, 'x')));
  SetLastError(ERROR_NOT_SUPPORTED);
  windows_error = 0xffffffffu;
  Check(!Exchange(oversized, false, &response, true, &failure, &windows_error) &&
        failure == ExchangeFailure::kRequestWriteFailed &&
        windows_error == ERROR_SUCCESS && transport_open_attempts == 1,
        "local request rejection clears stale Windows state and never opens a pipe");
  test_diagnostic_changes_error = false;
  inspect_pipe_connections = false;
  client_cancel_event = old_cancel;
  scm_scenario = old_scm;
  fuzevpn_distribution::test_distribution_mode = old_mode;
}

void TestPassiveBrokerTransport() {
  const auto old_scm = scm_scenario;
  const auto old_mode = fuzevpn_distribution::test_distribution_mode;
  HANDLE old_cancel = client_cancel_event;
  inspect_pipe_connections = true;
  client_cancel_event = transport_cancel_handle;
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
  const auto reset = [] {
    scm_scenario = ScmScenario::running;
    scm_manager_queries = transport_open_attempts = transport_trust_queries = 0;
    transport_ticks = transport_cancel_at = 0;
    transport_cancelled = false;
    transport_open_error = ERROR_PIPE_BUSY;
  };
  const auto connect = [](bool diagnostic = false) {
    bool installation = true;
    HANDLE pipe = ConnectToBroker(false, true, &installation, diagnostic);
    const auto error = GetLastError();
    Check(!installation, "passive pipe connection never requests installation");
    SetLastError(error);
    return pipe;
  };
  reset();
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY &&
      transport_ticks == 2000 && transport_open_attempts > 1 && transport_trust_queries == 0,
      "actual passive ConnectToBroker retries a running service for exactly two virtual seconds");
  reset();
  Check(connect(true) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY &&
      transport_ticks == 0 && transport_open_attempts == 1 && scm_manager_queries == 1 &&
      transport_trust_queries == 0,
      "diagnostic single-attempt connection verifies identity without waiting or starting the service");
  reset(); transport_open_error = ERROR_ACCESS_DENIED;
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED &&
      transport_open_attempts == 1 && transport_ticks == 0 && scm_manager_queries == 1,
      "actual pipe authentication/access denial is terminal before retries");
  reset(); transport_cancelled = true;
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_CANCELLED &&
      transport_open_attempts == 0 && scm_manager_queries == 0,
      "pre-cancelled passive transport performs no connection or service query");
  reset(); transport_cancel_at = 75;
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_CANCELLED &&
      transport_ticks == 75 && transport_open_attempts == 2,
      "passive transport cancellation interrupts its first wait without a new pipe request");
  reset(); scm_scenario = ScmScenario::query_failed;
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED &&
      transport_open_attempts == 0 && transport_trust_queries == 0 && transport_ticks == 0,
      "unknown SCM status remains explicit and cannot launch an installed or portable fallback");
  reset(); scm_scenario = ScmScenario::absent;
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND &&
      transport_open_attempts == 0 && transport_trust_queries > 0 && transport_ticks == 0,
      "confirmed absent service never connects to a stale endpoint or static fallback");
  reset(); transport_open_error = ERROR_INVALID_PARAMETER;
  Check(connect() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER &&
      transport_open_attempts == 1 && transport_trust_queries > 0 && scm_manager_queries == 1,
      "nonretryable pipe error is preserved across unsigned-development detection");
  inspect_pipe_connections = false;
  client_cancel_event = old_cancel;
  scm_scenario = old_scm;
  fuzevpn_distribution::test_distribution_mode = old_mode;
}

void TestRuntimeStatusFailures() {
  for (const auto mode : {fuzevpn_distribution::Mode::unavailable,
                         fuzevpn_distribution::Mode::installed}) {
    fuzevpn_distribution::test_distribution_mode = mode;
    bool detection_failed = false;
    if (mode == fuzevpn_distribution::Mode::unavailable) {
      Check(!PrivilegedRuntimePresence(&detection_failed).has_value() && detection_failed,
          "presence captures an unavailable distribution before reporting it");
    }
    // A later successful discovery must never relabel the original failure.
    fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
    const auto discovery_queries = fuzevpn_distribution::test_distribution_queries;
    ReplyState reply;
    SetLastError(ERROR_ACCESS_DENIED);
    CompleteRuntimeStatusFailure(std::make_unique<RecordingResult>(&reply), detection_failed);
    Check(fuzevpn_distribution::test_distribution_queries == discovery_queries,
          "reporting a runtime failure never repeats discovery or masks its origin");
    Check(reply.replied && reply.code == (mode == fuzevpn_distribution::Mode::unavailable
        ? "runtime_detection_failed" : "runtime_status_unavailable"),
        "unknown distribution and runtime reads have distinct error codes");
    const auto* details = reply.value ? std::get_if<flutter::EncodableMap>(&*reply.value) : nullptr;
    const auto found = details ? details->find(flutter::EncodableValue("win32_error")) :
                                flutter::EncodableMap::const_iterator{};
    Check(details && details->size() == 1 && found != details->end() &&
        std::get<int64_t>(found->second) == ERROR_ACCESS_DENIED,
        "failure details retain the Windows code and disclose no paths or account data");
    Check(test_written_diagnostic.find("code=5") != std::string::npos,
        "diagnostic retains the original failure without writing the user's store");
  }
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
}

void TestServiceIdleHandoff() {
  const auto previous_status_handle = service_status_handle;
  service_status_handle = reinterpret_cast<SERVICE_STATUS_HANDLE>(static_cast<ULONG_PTR>(108));
  inspect_service_status = true;
  const auto confirm_yield = +[](DWORD*) { return true; };
  service_yield_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  service_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  const auto reset = [&]() {
    runtime_ownership = fuzevpn::RuntimeOwnership{};
    service_idle_request.Clear(); service_accepts_yield.store(true);
    test_protection_known = true; test_wireguard_stopped = true;
    test_openvpn_stopped = true; test_wireguard_protection = test_openvpn_protection = false;
    inspected_service_status_updates = 0; inspected_service_state = SERVICE_RUNNING;
    ResetEvent(service_yield_event); ResetEvent(service_stop_event);
  };
  reset();
  Check(VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr) == NO_ERROR &&
      WaitForSingleObject(service_yield_event, 0) == WAIT_OBJECT_0 &&
      WaitForSingleObject(service_stop_event, 0) == WAIT_TIMEOUT,
      "SCM idle command queues a distinct wake without requesting service STOP");
  Check(ConsumeServiceIdleHandoff(confirm_yield) && !service_accepts_yield.load(),
      "serialized worker accepts confirmed idle service and forbids further handoff requests");
  reset();
  VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr);
  Check(!ConsumeServiceIdleHandoff(+[](DWORD* error) {
        if (error != nullptr) *error = ERROR_ACCESS_DENIED;
        return false;
      }) && service_accepts_yield.load() && inspected_service_status_updates == 0 &&
      inspected_service_state == SERVICE_RUNNING &&
      WaitForSingleObject(service_stop_event, 0) == WAIT_TIMEOUT,
      "failed durable confirmation preserves RUNNING service without publishing STOP_PENDING");
  reset();
  VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr);
  runtime_ownership.AuthorizeMutation("another-user", true);
  Check(!ConsumeServiceIdleHandoff(confirm_yield) && service_accepts_yield.load(),
      "concurrent prepare reservation prevents yield even before a tunnel or filters exist");
  SetEvent(service_yield_event);
  Check(!ConsumeServiceIdleHandoff(confirm_yield) && WaitForSingleObject(service_yield_event, 0) == WAIT_TIMEOUT,
      "late wake after a consumed request is cleared without a busy loop");
  reset(); test_wireguard_stopped = false;
  VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr);
  Check(!ConsumeServiceIdleHandoff(confirm_yield), "active tunnel cannot yield service");
  reset(); test_wireguard_protection = true;
  VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr);
  Check(!ConsumeServiceIdleHandoff(confirm_yield), "retained protection cannot yield service");
  reset(); test_protection_known = false;
  VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr);
  Check(!ConsumeServiceIdleHandoff(confirm_yield), "unknown filtering policy cannot yield service");
  reset(); service_accepts_yield.store(false);
  Check(VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr) == ERROR_SERVICE_CANNOT_ACCEPT_CTRL &&
      !service_idle_request.Pending(), "service not ready refuses control");
  reset();
  Check(service_idle_request.Queue(1) && !service_idle_request.Consume(1 + fuzevpn_handoff::kRequestLifetimeMs,
      false, true), "expired request cannot stop service after helper abandonment");
  reset();
  VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr);
  Check(VpnServiceControlHandler(fuzevpn_handoff::kYieldIdleControl, 0, nullptr, nullptr) == ERROR_BUSY,
      "duplicate queued request is refused");
  reset(); service_accepts_yield.store(false);
  CloseHandle(service_yield_event); CloseHandle(service_stop_event);
  service_yield_event = service_stop_event = nullptr;
  service_status_handle = previous_status_handle;
  inspect_service_status = false;
}

void TestRuntimeOwnership() {
  using Ownership = fuzevpn::RuntimeOwnership;
  using Authorization = Ownership::Authorization;
  Ownership owner;
  Check(owner.AuthorizeMutation("account-a", std::nullopt) ==
            Authorization::state_unavailable && !owner.HasOwner(),
        "unknown runtime cannot be adopted by a client");
  Check(owner.AuthorizeMutation("account-a", false) ==
            Authorization::state_unavailable && !owner.HasOwner(),
        "orphaned active runtime cannot be adopted by a client");
  Check(owner.AuthorizeMutation("account-a", true) == Authorization::allowed,
        "first account reserves confirmed idle runtime");
  Check(owner.AuthorizeMutation("account-b", true) == Authorization::another_user,
        "idle preparation reservation remains bound to its account");
  owner.ReleaseIfIdle(std::nullopt);
  owner.ReleaseIfIdle(false);
  Check(owner.OwnedByAnotherUser("account-b") &&
        owner.AuthorizeMutation("account-a", std::nullopt) == Authorization::allowed,
        "owner may recover while another account cannot mutate uncertain state");
  owner.ReleaseIfIdle(true);
  Check(!owner.HasOwner() &&
        owner.AuthorizeMutation("account-b", true) == Authorization::allowed,
        "confirmed explicit release allows a new account to reserve runtime");

  // Exercise the production dispatcher with tunnel stubs. No service, WFP,
  // real account token or diagnostic file is touched by this integration test.
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::vpn_service);
  runtime_ownership = Ownership();
  test_runtime_user = "account-a";
  test_wireguard_stopped = true;
  test_openvpn_stopped = true;
  test_wireguard_protection = false;
  test_openvpn_protection = false;
  test_native_mutations = 0;
  auto dispatch = [](const std::string& method,
                     const flutter::EncodableValue* arguments = nullptr) {
    bool shutdown = false;
    const auto response = Dispatch(EncodedCall(method, arguments), &shutdown,
                                   nullptr, nullptr, false);
    ReplyState state;
    RecordingResult result(&state);
    const bool decoded = flutter::StandardMethodCodec::GetInstance()
        .DecodeAndProcessResponseEnvelope(response.data(), response.size(), &result);
    Check(decoded, "production dispatcher response remains a valid envelope");
    return state;
  };
  auto diagnostic = [&](bool expected_owned, bool expected_other) {
    const auto queries = test_snapshot_queries;
    const auto mutations = test_native_mutations;
    const auto managers = scm_manager_queries;
    const auto response = dispatch("diagnostics.collectSnapshot");
    const flutter::EncodableValue expected(flutter::EncodableMap{
        {flutter::EncodableValue("test_user"), flutter::EncodableValue(test_runtime_user)},
        {flutter::EncodableValue("test_owned"), flutter::EncodableValue(expected_owned)},
        {flutter::EncodableValue("test_other_user"), flutter::EncodableValue(expected_other)},
    });
    Check(response.code == "success" && response.value && *response.value == expected &&
          test_snapshot_queries == queries + 1 && test_native_mutations == mutations &&
          scm_manager_queries == managers,
        "diagnostics dispatch performs only one synthetic observation with exact ownership flags");
  };
  diagnostic(false, false);
  Check(!runtime_ownership.HasOwner(), "diagnostics does not reserve an idle runtime");
  test_wireguard_stopped = std::nullopt;
  test_protection_known = false;
  diagnostic(false, false);
  Check(!runtime_ownership.HasOwner(), "diagnostics observes uncertain orphan state without mutation authorization or ownership");
  test_wireguard_stopped = true;
  test_protection_known = true;
  const flutter::EncodableValue options(flutter::EncodableMap{});
  Check(dispatch("wireguard.prepareConnection", &options).code == "success" &&
        test_wireguard_protection, "first account prepares mocked protected runtime");
  diagnostic(true, false);
  Check(runtime_ownership.HasOwner() && !runtime_ownership.OwnedByAnotherUser("account-a"),
        "diagnostics preserves the caller's existing reservation");
  test_runtime_user = "account-b";
  diagnostic(false, true);
  Check(runtime_ownership.HasOwner() && runtime_ownership.OwnedByAnotherUser("account-b") && test_wireguard_protection,
        "another account may obtain redacted diagnostics without taking or releasing ownership");
  const unsigned before = test_native_mutations;
  Check(dispatch("wireguard.disconnect").code == "runtime_owned_by_another_user" &&
        dispatch("openvpn.disconnect").code == "runtime_owned_by_another_user" &&
        dispatch("wireguard.reconnect").code == "runtime_owned_by_another_user" &&
        test_native_mutations == before && test_wireguard_protection,
        "other account rejected before either native handler or reconnect cache is touched");
  const auto status = dispatch("wireguard.networkProtectionStatus");
  const auto* map = status.value ? std::get_if<flutter::EncodableMap>(&*status.value) : nullptr;
  bool other_owner = false;
  if (map != nullptr) {
    const auto found = map->find(flutter::EncodableValue("ownedByAnotherUser"));
    const auto* flag = found == map->end() ? nullptr : std::get_if<bool>(&found->second);
    other_owner = flag != nullptr && *flag;
  }
  Check(status.code == "success" && other_owner,
        "status discloses only another-account ownership, without exposing its SID");
  test_runtime_user = "account-a";
  test_wireguard_stopped = std::nullopt;
  Check(dispatch("wireguard.disconnect").code == "success" && runtime_ownership.HasOwner(),
        "unknown stop confirmation cannot release account ownership");
  test_wireguard_stopped = true;
  Check(dispatch("wireguard.disconnect").code == "success" && !runtime_ownership.HasOwner(),
        "owner release requires confirmed absence of both tunnels and all protections");
  test_runtime_user = "account-b";
  Check(dispatch("wireguard.prepareConnection", &options).code == "success",
        "second account can reserve after explicit confirmed release");
  dispatch("wireguard.disconnect");

  test_runtime_user = "account-a";
  const flutter::EncodableValue account(flutter::EncodableMap{
      {flutter::EncodableValue("accountId"), flutter::EncodableValue("web-account-a")},
  });
  const flutter::EncodableValue identity(flutter::EncodableMap{
      {flutter::EncodableValue("accountId"), flutter::EncodableValue("web-account-a")},
      {flutter::EncodableValue("deviceId"), flutter::EncodableValue("device-a")},
  });
  Check(dispatch("wireguard.getOrCreatePublicKey", &account).code == "success" &&
        !runtime_ownership.HasOwner(),
        "standalone identity request releases its temporary idle reservation");
  Check(dispatch("wireguard.reconnect").code == "success" &&
        !runtime_ownership.HasOwner(),
        "standalone reconnect without a cached tunnel releases an idle reservation");
  dispatch("wireguard.prepareConnection", &options);
  // Model a preparation with every WFP option disabled. The enrolment still
  // owns its sequence while asynchronous API work follows key/CSR generation.
  test_wireguard_protection = false;
  Check(dispatch("wireguard.getOrCreatePublicKey", &account).code == "success" &&
        dispatch("openvpn.getOrCreateCsr", &identity).code == "success" &&
        dispatch("wireguard.reconnect").code == "success" &&
        runtime_ownership.HasOwner(),
        "identity work cannot release an existing idle enrolment reservation");
  test_runtime_user = "account-b";
  Check(dispatch("wireguard.disconnect").code == "runtime_owned_by_another_user" &&
        dispatch("wireguard.resolveApiAddresses").code == "runtime_owned_by_another_user",
        "another account cannot interrupt enrolment with all WFP options disabled");
  test_runtime_user = "account-a";
  Check(dispatch("wireguard.disconnect").code == "success" && !runtime_ownership.HasOwner(),
        "explicit cancellation releases the idle enrolment reservation");
  runtime_ownership = Ownership();
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::user_interface);
}

void TestOpenVpnExceptionDispatch() {
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::vpn_service);
  runtime_ownership = fuzevpn::RuntimeOwnership{};
  test_runtime_user = "account-openvpn-exception";
  test_wireguard_stopped = test_openvpn_stopped = true;
  test_wireguard_protection = false;
  test_openvpn_protection = false;
  test_protection_known = true;
  Check(runtime_ownership.AuthorizeMutation(test_runtime_user, true) ==
        fuzevpn::RuntimeOwnership::Authorization::allowed, "reserve synthetic OpenVPN owner");
  test_openvpn_protection = true;
  for (const auto mode : {1u, 2u}) {
    test_openvpn_exception = mode;
    bool shutdown = false;
    std::vector<uint8_t> response;
    try {
      response = Dispatch(EncodedCall("openvpn.reconnect"),
                          &shutdown, nullptr, nullptr, false);
    } catch (...) {
      Check(false, "OpenVPN exception escaped the dispatcher and would terminate the service");
      continue;
    }
    ReplyState reply;
    RecordingResult receiver(&reply);
    Check(flutter::StandardMethodCodec::GetInstance().DecodeAndProcessResponseEnvelope(
        response.data(), response.size(), &receiver), "exception produces a complete broker response");
    CheckBrokerFailureDetails(reply, "openvpn_connection_failed", "openvpn_native_exception", ERROR_SUCCESS);
    Check(std::string(response.begin(), response.end()).find("private-openvpn-profile-detail") == std::string::npos,
          "native exception text never leaves the service");
    Check(!shutdown && test_openvpn_protection && runtime_ownership.HasOwner(),
          "exception retains filtering and ownership instead of claiming successful cleanup");
  }
  test_openvpn_exception = 0;
  bool shutdown = false;
  const auto next = Dispatch(EncodedCall("openvpn.isConnected"), &shutdown, nullptr, nullptr, false);
  Check(fuzevpn_ipc::ValidateResponseEnvelope(next.data(), next.size()),
        "the broker remains able to answer the next request after an OpenVPN exception");
  test_openvpn_protection = false;
  runtime_ownership.ReleaseIfIdle(true);
  test_runtime_user = "S-1-5-21-1-2-3-1001";
}
LRESULT CALLBACK TestWindowProc(HWND window, UINT message, WPARAM wparam,
                                LPARAM lparam) {
  if (message == kPrivilegedCallCompletedMessage) {
    ProcessPrivilegedCallCompletions();
    return 0;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}
void TestPlatformDelivery() {
  WNDCLASSW window_class{};
  window_class.lpfnWndProc = TestWindowProc;
  window_class.hInstance = GetModuleHandleW(nullptr);
  window_class.lpszClassName = L"FuzeAuditSecurityMessageWindow";
  Check(RegisterClassW(&window_class) != 0, "register test message window");
  HWND window = CreateWindowExW(0, window_class.lpszClassName, L"", 0,
      0, 0, 0, 0, HWND_MESSAGE, nullptr, window_class.hInstance, nullptr);
  Check(window != nullptr && InitializePrivilegedCallDispatcher(window),
        "initialize real platform dispatcher");
  ReplyState reply;
  // A locally rejected oversized request never opens the application's pipe,
  // contacts a service or requests elevation.
  flutter::MethodCall<flutter::EncodableValue> call("isConnected",
      std::make_unique<flutter::EncodableValue>(std::string(2 * 1024 * 1024, 'x')));
  const DWORD platform_thread = GetCurrentThreadId();
  ForwardPrivilegedCall("wireguard", call,
                        std::make_unique<RecordingResult>(&reply), false);
  Check(!reply.replied, "ForwardPrivilegedCall returns before the reply");
  const auto deadline = GetTickCount64() + 3000;
  while (!reply.replied && GetTickCount64() < deadline) {
    MSG message{};
    while (PeekMessageW(&message, window, 0, 0, PM_REMOVE)) {
      DispatchMessageW(&message);
    }
    Sleep(1);
  }
  Check(reply.replied && reply.code == "broker_write_failed",
        "worker reports locally rejected request");
  Check(reply.callback_thread == platform_thread,
        "Flutter reply delivered only on the platform thread");
  CheckBrokerFailureDetails(reply, "broker_write_failed", "broker_write", ERROR_SUCCESS);

  // Exercise the real dispatcher with a terminal, simulated connection failure.
  // No real pipe/service/UAC is accessed; the worker's errno differs from GUI.
  const auto old_mode = fuzevpn_distribution::test_distribution_mode;
  const auto old_scm = scm_scenario;
  inspect_pipe_connections = true;
  test_diagnostic_changes_error = true;
  fuzevpn_distribution::test_distribution_mode = fuzevpn_distribution::Mode::installed;
  scm_scenario = ScmScenario::running;
  transport_cancelled = false;
  transport_open_error = ERROR_NOT_SUPPORTED;
  transport_open_attempts = scm_manager_queries = 0;
  ReplyState failed_connection;
  flutter::MethodCall<flutter::EncodableValue> status_call("isConnected", nullptr);
  ForwardPrivilegedCall("wireguard", status_call,
      std::make_unique<RecordingResult>(&failed_connection), false);
  const auto failure_deadline = GetTickCount64() + 3000;
  while (!failed_connection.replied && GetTickCount64() < failure_deadline) {
    MSG message{};
    while (PeekMessageW(&message, window, 0, 0, PM_REMOVE)) {
      SetLastError(ERROR_ACCESS_DENIED);
      DispatchMessageW(&message);
    }
    Sleep(1);
  }
  CheckBrokerFailureDetails(failed_connection, "broker_unavailable",
                           "broker_connection", ERROR_NOT_SUPPORTED);
  Check(failed_connection.callback_thread == platform_thread &&
         transport_open_attempts == 1 && scm_manager_queries == 1,
        "worker Windows code crosses threads without reading GUI errno or real SCM");
  test_diagnostic_changes_error = false;
  inspect_pipe_connections = false;
  scm_scenario = old_scm;
  fuzevpn_distribution::test_distribution_mode = old_mode;
  ReplyState closing;
  ForwardPrivilegedCall("wireguard", call,
                        std::make_unique<RecordingResult>(&closing), false);
  ShutdownPrivilegedCallDispatcher();
  Check(closing.replied && closing.code == "operation_cancelled" &&
        closing.callback_thread == platform_thread,
        "shutdown drains worker and completes replies before engine destruction");
  DestroyWindow(window);
  UnregisterClassW(window_class.lpszClassName, window_class.hInstance);
}
}  // namespace

int main() {
  TestPortableDevelopmentPolicy();
  Check(TestMaintenanceRecovery(), "maintenance failures preserve protection and never overwrite another transaction");
  Check(TestMaintenanceNetworkRecovery(), "historical service errors require independent read-only network proof");
  Check(TestPortableServiceLease(), "portable service lease preserves active and unknown runtime state");
  Check(TestProtectedStoreReadFailures(), "missing values remain distinct from storage failures without real store I/O");
  Check(TestProtectedStoreWriteFailures(),
        "protected-store writes report a fixed stage and Win32 error and retry only transient replace/delete locks");
  TestExclusiveRuntime();
  Check(fuzevpn_runtime_namespace_test::TestRuntimeNamespace(),
        "private runtime namespace resists public-name squatting and preserves exclusion");
  Check(fuzevpn_service_endpoint_test::TestServicePipeEndpoint(),
        "random live endpoints are published after pipe creation through protected 64-bit registry fixtures");
  Check(fuzevpn_legacy_runtime_test::TestLegacyRuntimeGuard(),
        "legitimate legacy runtime detection never acquires an attacker-controlled public mutex");
  TestServiceRepair();
  TestWireGuardCandidates();
  TestWireGuardHandshakeWait();
  TestNativeDiagnosticIdentifiers();
  Check(TestProtectedStoreTokenRouting(),
        "protected storage explicitly routes and restores the user's folder token");
  Check(TestProtectedDiagnosticRouting(),
        "diagnostics use selected short impersonation and never fall back on failure");
  CheckInteractiveRights(fuzevpn_ipc::kServiceEventSddl, SYNCHRONIZE,
                         EVENT_MODIFY_STATE | WRITE_DAC | WRITE_OWNER);
  CheckInteractiveRights(fuzevpn_ipc::kServicePipeSddl,
      fuzevpn_ipc::kPipeClientAccess,
      FILE_CREATE_PIPE_INSTANCE | WRITE_DAC | WRITE_OWNER);
  TestRuntimePresence();
  TestRuntimeStatusFailures();
  TestBrokerFailureDetails();
  TestBrokerFailureCapture();
  TestPassiveBrokerTransport();
  Check(TestPassiveServicePipeRetry(), "passive authenticated service retry handles bounded recovery and terminal failures");
  TestServiceIdleHandoff();
  TestInstallationPolicy();
  TestProtocolValidation();
  TestRuntimeOwnership();
  TestOpenVpnExceptionDispatch();
  TestServerInspectionRights();
  TestScopedInspectionPrivilege();
  TestIoAndAuthentication();
  TestPlatformDelivery();
  std::cout << (failures == 0 ? "PASS" : "FAIL")
            << ": native security IPC, ACL, cancellation and platform delivery\n";
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
