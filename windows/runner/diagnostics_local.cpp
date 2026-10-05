// SPDX-License-Identifier: MPL-2.0
#include "diagnostics_local.h"
#include "diagnostics_async.h"
#include "distribution_mode.h"
#include "openvpn_diagnostic_state.h"
#include "privileged_broker.h"
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

namespace fuzevpn_diagnostics {
using Value = flutter::EncodableValue;
using Map = flutter::EncodableMap;
using List = flutter::EncodableList;
namespace {
constexpr size_t kMaximumNativeBytes = 64 * 1024;
constexpr size_t kMaximumNativeEvents = 128;
bool Is(std::string_view value, std::initializer_list<const char*> values) {
  return std::any_of(values.begin(), values.end(), [value](const char* candidate) {
    return value == candidate;
  });
}
std::optional<int64_t> Number(std::string_view value) {
  if (value.empty() || value.size() > 10) return std::nullopt;
  uint64_t number = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), number);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
      number > 0xffffffffULL) return std::nullopt;
  return static_cast<int64_t>(number);
}
bool Timestamp(std::string_view value) {
  if (value.size() != 24) return false;
  for (size_t i = 0; i < value.size(); ++i) {
    const char separator = i == 4 || i == 7 ? '-' : i == 10 ? 'T' :
        i == 13 || i == 16 ? ':' : i == 19 ? '.' : i == 23 ? 'Z' : '\0';
    if (separator ? value[i] != separator : value[i] < '0' || value[i] > '9')
      return false;
  }
  return true;
}
bool Event(std::string_view area, std::string_view value) {
  if (area == "broker") return Is(value, {
      "broker_ready", "client_connected", "request_read", "client_authenticated",
      "request_decoded", "wireguard_dispatch", "wireguard_complete", "openvpn_dispatch",
      "openvpn_complete", "response_acknowledged", "shutdown_pending", "shutdown_unconfirmed",
      "shutdown_complete", "service_install_failed", "connection_failed", "request_write_failed",
      "response_unavailable", "response_ack_failed"});
  if (area == "runtime") return Is(value, {"runtime_detection_failed", "runtime_status_unavailable"});
  if (area != "wireguard" && area != "openvpn") return false;
  if (value == "native_error" || (area == "openvpn" && Is(value,
      {"connection_attempt_snapshot", "cleanup_snapshot"}))) return true;
  for (const char* operation : {"connect", "prepareConnection", "disconnect",
      "prepareIdentityForAccount", "recreateIdentityForAccount", "resetIdentity",
      "importAndConnect", "suspendForMigration"}) {
    for (const char* suffix : {"started", "succeeded", "failed"})
      if (value == std::string(operation) + "_" + suffix) return true;
  }
  return false;
}
bool ErrorCode(std::string_view value) {
  if (value == "other" || value == fuzevpn::SafeOpenVpnFailure(value)) return true;
  return Is(value, {"runtime_unavailable", "runtime_status_unavailable", "runtime_detection_failed",
      "key_unavailable", "storage_failure", "storage_error", "permission_denied",
      "invalid_configuration", "tunnel_failure", "tunnel_handshake_timeout",
      "endpoint_resolution_failed", "api_bootstrap_unavailable", "openvpn_signer_unavailable",
      "maintenance_in_progress", "runtime_owned_by_another_user", "service_configuration_mismatch",
      "service_install_failed", "network_protection_release_failed"});
}
bool Action(std::string_view value) {
  return Is(value, {"none", "unknown", "command_other", "command_route_add", "command_route_delete",
      "command_address_set", "command_address_delete", "command_interface", "command_dns_set",
      "command_dns_add", "command_dns_delete", "command_dns_flush", "route_lookup", "route_create",
      "route_remove", "setup_actions", "postcondition_adapter", "postcondition_address",
      "postcondition_route", "postcondition_dns", "postcondition_read_adapter",
      "postcondition_read_routes", "postcondition_read_nrpt", "dns_manager_open", "dns_service_open",
      "dns_notify", "dns_gpo_notify"});
}
bool CoreEvent(std::string_view value) {
  return Is(value, {"none", "RESOLVE", "WAIT", "WAIT_PROXY", "CONNECTING", "GET_CONFIG",
      "ASSIGN_IP", "ADD_ROUTES", "CONNECTED", "RECONNECTING", "AUTH_PENDING", "DISCONNECTED",
      "PAUSE", "RESUME", "TRANSPORT_ERROR", "TUN_ERROR", "AUTH_FAILED", "CERT_VERIFY_FAIL",
      "TLS_ALERT_HANDSHAKE_FAILURE", "TUN_SETUP_FAILED", "CONNECTION_TIMEOUT", "CLIENT_SETUP"});
}
std::optional<Map> ParseLine(std::string_view line) {
  if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
  if (line.size() > 4096 || line.size() < 25 || !Timestamp(line.substr(0, 24)) || line[24] != ' ')
    return std::nullopt;
  Map result{{Value("timestamp"), Value(std::string(line.substr(0, 24)))}};
  line.remove_prefix(25);
  while (!line.empty()) {
    const auto space = line.find(' ');
    auto token = line.substr(0, space);
    if (space == line.npos) line = {}; else line.remove_prefix(space + 1);
    const auto equal = token.find('=');
    if (equal == token.npos || equal == 0 || equal == token.size() - 1) return std::nullopt;
    const auto key = token.substr(0, equal), value = token.substr(equal + 1);
    if (key.size() > 40 || result.contains(Value(std::string(key)))) return std::nullopt;
    if (key == "area") {
      if (!Is(value, {"broker", "runtime", "wireguard", "openvpn"})) return std::nullopt;
      result[Value("area")] = Value(std::string(value));
    } else if (key == "event") {
      // The closed area-specific vocabulary is checked after the complete line.
      if (value.size() > 80) return std::nullopt;
      result[Value("event")] = Value(std::string(value));
    } else if (key == "code") {
      if (const auto number = Number(value)) result[Value("code")] = Value(*number);
      else if (ErrorCode(value)) result[Value("code")] = Value(std::string(value));
      else result[Value("code")] = Value("unknown_error");
    } else if (Is(key, {"peer_ready", "send_attempts", "send_ok", "send_failed", "received",
        "reconnects", "command_failed", "success", "engine_connect_ms", "setup_commands_ms",
        "setup_validation_ms", "first_failed_code", "postcondition_failures", "address_expected",
        "address_matched", "address_tentative", "address_duplicate", "complete", "last_code",
        "failure_count", "pending_groups", "elapsed_ms", "budget_ms"})) {
      if (const auto number = Number(value)) result[Value(std::string(key))] = Value(*number);
    } else if (key == "stage") {
      if (Is(value, {"starting", "adapter_open", "peer_ready", "packet_received", "tls_active",
          "assign_ip", "add_routes", "connected"})) result[Value("stage")] = Value(std::string(value));
    } else if (Is(key, {"first_error", "last_error", "failure_before_stop"})) {
      result[Value(std::string(key))] = Value(ErrorCode(value) ? std::string(value) : "unknown_error");
    } else if (Is(key, {"first_failed_action", "last_action"})) {
      result[Value(std::string(key))] = Value(Action(value) ? std::string(value) : "unknown");
    } else if (key == "last_event") {
      result[Value("last_event")] = Value(CoreEvent(value) ? std::string(value) : "unknown");
    }
    // Unknown fields have no path into the export, including messages and paths.
  }
  const auto area = result.find(Value("area")), event = result.find(Value("event"));
  if (area == result.end() || event == result.end() || !Event(std::get<std::string>(area->second),
      std::get<std::string>(event->second))) return std::nullopt;
  return result;
}
Map Error(const char* status, DWORD code) {
  return {{Value("status"), Value(status)}, {Value("win32_error"), Value(static_cast<int64_t>(code))},
      {Value("truncated"), Value(false)}, {Value("discarded_lines"), Value(int64_t(0))},
      {Value("events"), Value(List{})}};
}
Map ReadNativeLog(const std::filesystem::path& path) {
  // Never follow a redirect to another user's profile or an arbitrary file.
  HANDLE directory = CreateFileW(path.parent_path().c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (directory == INVALID_HANDLE_VALUE) {
    const auto code = GetLastError();
    return Error(code == ERROR_PATH_NOT_FOUND || code == ERROR_FILE_NOT_FOUND ? "absent" : "read_failed", code);
  }
  BY_HANDLE_FILE_INFORMATION directory_info{};
  const bool safe_directory = GetFileInformationByHandle(directory, &directory_info) &&
      !(directory_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
      (directory_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
  CloseHandle(directory);
  if (!safe_directory) return Error("rejected", ERROR_ACCESS_DENIED);
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    const auto code = GetLastError();
    return Error(code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ? "absent" : "read_failed", code);
  }
  BY_HANDLE_FILE_INFORMATION info{};
  if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info) ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
    CloseHandle(file); return Error("rejected", ERROR_ACCESS_DENIED);
  }
  const uint64_t length = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
  const auto count = static_cast<DWORD>((std::min)(length, static_cast<uint64_t>(kMaximumNativeBytes)));
  const bool truncated = length > count;
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(length - count);
  if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN)) {
    const auto code = GetLastError(); CloseHandle(file); return Error("read_failed", code);
  }
  std::string bytes(count, '\0');
  DWORD read = 0;
  const bool complete = ReadFile(file, bytes.data(), count, &read, nullptr) != FALSE;
  const auto code = complete ? ERROR_SUCCESS : GetLastError();
  CloseHandle(file);
  if (!complete) return Error("read_failed", code);
  bytes.resize(read);
  auto result = SanitizeNativeDiagnosticTail(bytes, truncated);
  if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
  return result;
}
Map ReadUserNativeLog() {
  PWSTR directory = nullptr;
  const auto status = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &directory);
  if (FAILED(status)) return Error("read_failed", HRESULT_FACILITY(status) == FACILITY_WIN32 ?
      HRESULT_CODE(status) : ERROR_PATH_NOT_FOUND);
  const auto path = std::filesystem::path(directory) / L"FuzeVPN" / L"native_diagnostic.log";
  CoTaskMemFree(directory);
  return ReadNativeLog(path);
}
const char* ServiceState(DWORD state) {
  switch (state) {
    case SERVICE_STOPPED: return "stopped";
    case SERVICE_START_PENDING: return "start_pending";
    case SERVICE_STOP_PENDING: return "stop_pending";
    case SERVICE_RUNNING: return "running";
    case SERVICE_CONTINUE_PENDING: return "continue_pending";
    case SERVICE_PAUSE_PENDING: return "pause_pending";
    case SERVICE_PAUSED: return "paused";
    default: return "unknown";
  }
}
std::string BinaryVersion(const std::filesystem::path& path) {
  if (path.empty()) return {};
  DWORD ignored = 0;
  const auto length = GetFileVersionInfoSizeW(path.c_str(), &ignored);
  if (!length || length > 1024 * 1024) return {};
  std::vector<BYTE> bytes(length);
  if (!GetFileVersionInfoW(path.c_str(), 0, length, bytes.data())) return {};
  VS_FIXEDFILEINFO* version = nullptr;
  UINT size = 0;
  if (!VerQueryValueW(bytes.data(), L"\\", reinterpret_cast<void**>(&version), &size) ||
      size < sizeof(VS_FIXEDFILEINFO) || version->dwSignature != 0xfeef04bd) return {};
  return std::to_string(HIWORD(version->dwFileVersionMS)) + "." +
      std::to_string(LOWORD(version->dwFileVersionMS)) + "." +
      std::to_string(HIWORD(version->dwFileVersionLS)) + "." +
      std::to_string(LOWORD(version->dwFileVersionLS));
}
std::filesystem::path ImagePath() {
  std::wstring image(32768, L'\0');
  const DWORD size = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
  if (!size || size >= image.size()) return {};
  image.resize(size); return image;
}
Map ObserveService(const std::string& application_version) {
  Map result{{Value("name"), Value("FuzeVPNService")}, {Value("state"), Value("unknown")},
      {Value("query_stage"), Value("scm_open")}};
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) {
    result[Value("win32_error")] = Value(static_cast<int64_t>(GetLastError())); return result;
  }
  result[Value("query_stage")] = Value("service_open");
  // Status requires no administrator privileges. Config/version inspection is
  // optional and separately reports an access denial without losing status.
  SC_HANDLE service = OpenServiceW(manager, L"FuzeVPNService", SERVICE_QUERY_STATUS);
  if (!service) {
    const auto code = GetLastError(); CloseServiceHandle(manager);
    result[Value("win32_error")] = Value(static_cast<int64_t>(code));
    if (code == ERROR_SERVICE_DOES_NOT_EXIST) {
      result[Value("state")] = Value("absent"); result[Value("query_stage")] = Value("completed");
    }
    return result;
  }
  result[Value("query_stage")] = Value("service_status");
  SERVICE_STATUS_PROCESS status{};
  DWORD needed = 0;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status),
      sizeof(status), &needed)) {
    result[Value("state")] = Value(ServiceState(status.dwCurrentState));
    result[Value("query_stage")] = Value("completed");
    result[Value("win32_exit_code")] = Value(static_cast<int64_t>(status.dwWin32ExitCode));
    result[Value("service_exit_code")] = Value(static_cast<int64_t>(status.dwServiceSpecificExitCode));
    result[Value("process_present")] = Value(status.dwProcessId != 0);
  } else result[Value("win32_error")] = Value(static_cast<int64_t>(GetLastError()));
  CloseServiceHandle(service);
  service = OpenServiceW(manager, L"FuzeVPNService", SERVICE_QUERY_CONFIG);
  if (service) {
    DWORD length = 0;
    QueryServiceConfigW(service, nullptr, 0, &length);
    if (length >= sizeof(QUERY_SERVICE_CONFIGW) && length <= 65536) {
      std::vector<BYTE> bytes(length);
      auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
      if (QueryServiceConfigW(service, config, length, &length) && config->lpBinaryPathName) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(config->lpBinaryPathName, &argc);
        if (argv && argc > 0) {
          const std::filesystem::path path(argv[0]);
          const auto& native = path.native();
          // Metadata never causes a UNC access or exposes the stored path.
          if (native.size() > 3 && native[1] == L':' && native[2] == L'\\' &&
              GetDriveTypeW(path.root_path().c_str()) == DRIVE_FIXED) {
            const auto version = BinaryVersion(path);
            if (!version.empty()) {
              result[Value("binary_version")] = Value(version);
              if (!application_version.empty()) result[Value("service_binary_matches_application")] =
                  Value(version == application_version);
            }
          }
        }
        if (argv) LocalFree(argv);
      } else result[Value("configuration_win32_error")] = Value(static_cast<int64_t>(GetLastError()));
    }
    CloseServiceHandle(service);
  } else result[Value("configuration_win32_error")] = Value(static_cast<int64_t>(GetLastError()));
  CloseServiceHandle(manager);
  return result;
}
Map Collect(const AsyncSnapshot<Map>::Request&) {
  const auto mode = fuzevpn_distribution::CurrentMode();
  const auto mode_error = GetLastError();
  const auto image = ImagePath();
  const auto application_version = BinaryVersion(image);
  Map environment{{Value("installation_mode"), Value(fuzevpn_distribution::ModeName(mode))}};
  if (mode == fuzevpn_distribution::Mode::unavailable)
    environment[Value("win32_error")] = Value(static_cast<int64_t>(mode_error));
  if (!application_version.empty()) environment[Value("binary_version")] = Value(application_version);
  for (const auto& sibling : {std::pair{L"fuzevpn-service.exe", "service_executable_present"},
                             std::pair{L"fuzevpn-runtime.exe", "runtime_executable_present"}}) {
    const auto attributes = image.empty() ? INVALID_FILE_ATTRIBUTES :
        GetFileAttributesW((image.parent_path() / sibling.first).c_str());
    environment[Value(sibling.second)] = Value(attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)));
  }
  bool detection_failed = false;
  SetLastError(ERROR_SUCCESS);
  const auto presence = PrivilegedRuntimePresence(&detection_failed);
  const auto runtime_error = GetLastError();
  Map runtime{{Value("presence"), Value(!presence ? "unknown" : *presence ? "present" : "absent")},
      {Value("detection_failed"), Value(detection_failed)}};
  if (!presence) runtime[Value("win32_error")] = Value(static_cast<int64_t>(runtime_error));
  return {{Value("schema_version"), Value(int64_t(1))}, {Value("collection_pending"), Value(false)},
      {Value("environment"), Value(environment)}, {Value("runtime"), Value(runtime)},
      {Value("service"), Value(ObserveService(application_version))}, {Value("native_log"), Value(ReadUserNativeLog())}};
}
AsyncSnapshot<Map>& Cache() { static AsyncSnapshot<Map> cache(Collect); return cache; }
}  // namespace
Map SanitizeNativeDiagnosticTail(std::string_view bytes, bool starts_midline) {
  bool truncated = starts_midline;
  int64_t discarded = 0;
  List events;
  if (bytes.size() > kMaximumNativeBytes) {
    bytes.remove_prefix(bytes.size() - kMaximumNativeBytes);
    starts_midline = true; truncated = true;
  }
  if (starts_midline) {
    const auto first = bytes.find('\n');
    if (first == bytes.npos) bytes = {}; else bytes.remove_prefix(first + 1);
    ++discarded;
  }
  while (!bytes.empty()) {
    const auto end = bytes.find('\n');
    // A partially written final record cannot be mistaken for complete evidence.
    if (end == bytes.npos) { ++discarded; break; }
    const auto parsed = ParseLine(bytes.substr(0, end));
    bytes.remove_prefix(end + 1);
    if (!parsed) { ++discarded; continue; }
    if (events.size() == kMaximumNativeEvents) { events.erase(events.begin()); truncated = true; ++discarded; }
    events.emplace_back(*parsed);
  }
  return {{Value("status"), Value("ok")}, {Value("truncated"), Value(truncated)},
      {Value("discarded_lines"), Value(discarded)}, {Value("events"), Value(events)}};
}
Map RequestLocalDiagnostics() {
  const auto result = Cache().Poll("local", false, false);
  return result ? *result : Map{{Value("schema_version"), Value(int64_t(1))},
      {Value("collection_pending"), Value(true)}};
}
void ShutdownLocalDiagnostics() { Cache().Stop(); }
}  // namespace fuzevpn_diagnostics
