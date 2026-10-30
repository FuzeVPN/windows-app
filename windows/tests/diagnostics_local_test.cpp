// SPDX-License-Identifier: MPL-2.0
// Isolated read-only SCM and sanitized log regression suite. No UAC, service
// changes, VPN operations, network access or real user profile reads.
#include <windows.h>
#include "diagnostics_local.h"
#include "distribution_mode.h"
#include "privileged_broker.h"
#include "wireguard_endpoint.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
enum class Scenario { manager_denied, absent, service_denied, status_failed, stopped, running, starting };
Scenario scenario = Scenario::running;
unsigned manager_access = 0, status_queries = 0;
SC_HANDLE WINAPI TestOpenManager(LPCWSTR, LPCWSTR, DWORD access) {
  manager_access = access;
  if (scenario == Scenario::manager_denied) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
  return reinterpret_cast<SC_HANDLE>(static_cast<uintptr_t>(101));
}
SC_HANDLE WINAPI TestOpenService(SC_HANDLE, LPCWSTR name, DWORD access) {
  if (std::wstring_view(name) != L"FuzeVPNService") return nullptr;
  if (access == SERVICE_QUERY_CONFIG) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
  if (access != SERVICE_QUERY_STATUS) return nullptr;
  if (scenario == Scenario::absent || scenario == Scenario::service_denied) {
    SetLastError(scenario == Scenario::absent ? ERROR_SERVICE_DOES_NOT_EXIST : ERROR_ACCESS_DENIED);
    return nullptr;
  }
  return reinterpret_cast<SC_HANDLE>(static_cast<uintptr_t>(102));
}
BOOL WINAPI TestQueryStatus(SC_HANDLE, SC_STATUS_TYPE, LPBYTE buffer, DWORD length, LPDWORD needed) {
  ++status_queries;
  if (scenario == Scenario::status_failed) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
  if (length != sizeof(SERVICE_STATUS_PROCESS)) return FALSE;
  auto* status = reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer);
  *status = {};
  status->dwCurrentState = scenario == Scenario::stopped ? SERVICE_STOPPED :
      scenario == Scenario::starting ? SERVICE_START_PENDING : SERVICE_RUNNING;
  status->dwProcessId = scenario == Scenario::running ? 500 : 0;
  status->dwWin32ExitCode = scenario == Scenario::stopped ? ERROR_NOT_SUPPORTED : ERROR_SUCCESS;
  status->dwServiceSpecificExitCode = scenario == Scenario::stopped ? 123 : 0;
  *needed = sizeof(*status);
  return TRUE;
}
BOOL WINAPI TestCloseService(SC_HANDLE) { return TRUE; }
}  // namespace
namespace fuzevpn_distribution {
Mode CurrentMode() { SetLastError(ERROR_SUCCESS); return Mode::portable; }
const char* ModeName(Mode mode) { return mode == Mode::portable ? "portable" : "unavailable"; }
}
std::optional<bool> PrivilegedRuntimePresence(bool* detection_failed) {
  *detection_failed = false;
  SetLastError(ERROR_NOT_SUPPORTED);
  return std::nullopt;
}
#define OpenSCManagerW TestOpenManager
#define OpenServiceW TestOpenService
#define QueryServiceStatusEx TestQueryStatus
#define CloseServiceHandle TestCloseService
#include "../runner/diagnostics_local.cpp"
#undef OpenSCManagerW
#undef OpenServiceW
#undef QueryServiceStatusEx
#undef CloseServiceHandle

namespace {
using namespace fuzevpn_diagnostics;
void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
const Map& Child(const Map& map, const char* key) { return std::get<Map>(map.at(Value(key))); }
const List& Events(const Map& map) { return std::get<List>(map.at(Value("events"))); }
std::string Text(const Map& map, const char* key) { return std::get<std::string>(map.at(Value(key))); }
int64_t Integer(const Map& map, const char* key) { return std::get<int64_t>(map.at(Value(key))); }
bool Flag(const Map& map, const char* key) { return std::get<bool>(map.at(Value(key))); }
std::string Line(std::string_view fields) {
  return "2026-10-05T20:12:11.932Z " + std::string(fields) + "\r\n";
}
void ParserChecks() {
  const auto normal = SanitizeNativeDiagnosticTail(
      Line("area=broker event=connection_failed code=50") +
      Line("area=broker event=response_acknowledged") +
      Line("area=runtime event=runtime_status_unavailable code=5") +
      Line("area=openvpn event=connection_attempt_snapshot peer_ready=1 send_failed=2 "
           "stage=tls_active last_event=TLS_ALERT_HANDSHAKE_FAILURE first_error=none "
           "last_error=openvpn_tls_handshake_failed first_failed_action=command_dns_set "
           "first_failed_code=50 success=0"));
  Check(Events(normal).size() == 4 && !Flag(normal, "truncated"), "native chronology preserved");
  Check(Integer(std::get<Map>(Events(normal)[0]), "code") == 50, "exact Windows 50 retained");
  const auto& openvpn = std::get<Map>(Events(normal)[3]);
  Check(Text(openvpn, "last_error") == "openvpn_tls_handshake_failed" &&
      Integer(openvpn, "first_failed_code") == 50, "structured engine details retained");
  const auto private_fields = SanitizeNativeDiagnosticTail(
      Line("area=broker event=connection_failed code=access_token_value account=secret token=secret "
           "path=C:\\Users\\Other message=private email=person@example.com") +
      Line("area=openvpn event=connection_attempt_snapshot first_error=secret last_action=secret "
           "last_event=secret stage=secret send_failed=4294967296 password=secret"));
  Check(Events(private_fields).size() == 2, "safe event survives dropped private fields");
  const auto& broker = std::get<Map>(Events(private_fields)[0]);
  Check(broker.size() == 4 && Text(broker, "code") == "unknown_error", "unregistered code and fields cannot leak");
  const auto& filtered = std::get<Map>(Events(private_fields)[1]);
  Check(Text(filtered, "first_error") == "unknown_error" && Text(filtered, "last_action") == "unknown" &&
      Text(filtered, "last_event") == "unknown" && !filtered.contains(Value("stage")) &&
      !filtered.contains(Value("send_failed")), "closed values and bounded numbers enforced");
  const auto malformed = SanitizeNativeDiagnosticTail(
      Line("area=private event=request_decoded") + Line("area=broker event=secret") +
      Line("area=broker event=request_decoded area=broker") +
      "private exception\r\n" + Line("area=broker event=request_decoded") +
      "2026-10-05T20:12:11.932Z area=broker event=connection_failed code=5");
  Check(Events(malformed).size() == 1 && Integer(malformed, "discarded_lines") == 5,
      "malformed and partial records excluded");
  std::string many;
  for (unsigned i = 0; i < 180; ++i) many += Line("area=broker event=connection_failed code=" + std::to_string(i));
  const auto bounded = SanitizeNativeDiagnosticTail(many);
  Check(Events(bounded).size() == 128 && Flag(bounded, "truncated") &&
      Integer(std::get<Map>(Events(bounded)[0]), "code") == 52 &&
      Integer(std::get<Map>(Events(bounded).back()), "code") == 179, "bounded latest events retained");
  const auto oversized = SanitizeNativeDiagnosticTail(std::string(70000, 'x') +
      "\n" + Line("area=broker event=connection_failed code=50"));
  Check(Flag(oversized, "truncated") && Events(oversized).size() == 1, "64KB tail cap and partial prefix enforced");
}
void WireGuardSnapshotChecks() {
  fuzevpn::WireGuardAttemptSnapshot written;
  written.candidates = 1;
  written.stage = fuzevpn::WireGuardAttemptStage::peer_ready;
  written.elapsed_ms = 21543;
  written.budget_ms = 69870;
  written.service_start_ms = 402;
  written.handshake_wait_ms = 20000;
  written.stop_ms = 1100;
  written.tx_bytes = 592;
  written.stats_reads = 197;
  const auto parsed = SanitizeNativeDiagnosticTail(
      Line("area=wireguard event=connection_attempt_snapshot " +
           fuzevpn::FormatWireGuardAttemptSnapshot(written)) +
      Line("area=wireguard event=connection_attempt_snapshot candidates=2 candidate_index=1 "
           "stage=handshake_wait endpoint=192.0.2.1:51820 public_key=secret tx_bytes=4294967296 "
           "stats_reads=4294967296 handshake=1 success=1"));
  Check(Events(parsed).size() == 2, "WireGuard attempt snapshots are retained");
  const auto& snapshot = std::get<Map>(Events(parsed)[0]);
  Check(Text(snapshot, "stage") == "peer_ready" && Integer(snapshot, "candidates") == 1 &&
      Integer(snapshot, "candidate_index") == 0 && Integer(snapshot, "handshake") == 0 &&
      Integer(snapshot, "success") == 0 && Integer(snapshot, "elapsed_ms") == 21543 &&
      Integer(snapshot, "budget_ms") == 69870 && Integer(snapshot, "service_start_ms") == 402 &&
      Integer(snapshot, "handshake_wait_ms") == 20000 && Integer(snapshot, "stop_ms") == 1100 &&
      Integer(snapshot, "tx_bytes") == 592 && Integer(snapshot, "rx_bytes") == 0 &&
      Integer(snapshot, "stats_reads") == 197 &&
      snapshot.size() == 16, "every numeric handshake field survives the reader");
  const auto& hostile = std::get<Map>(Events(parsed)[1]);
  Check(!hostile.contains(Value("stage")) && !hostile.contains(Value("endpoint")) &&
      !hostile.contains(Value("public_key")) && !hostile.contains(Value("tx_bytes")) &&
      !hostile.contains(Value("stats_reads")) &&
      Integer(hostile, "handshake") == 1, "unknown stages, endpoints, keys and overflow are dropped");
  // The writers' shared timestamp is exactly the shape the reader accepts.
  SYSTEMTIME written_at{};
  written_at.wYear = 2026; written_at.wMonth = 1; written_at.wDay = 2; written_at.wHour = 3;
  written_at.wMinute = 4; written_at.wSecond = 5; written_at.wMilliseconds = 7;
  const auto stamp = FormatNativeDiagnosticTimestamp(written_at);
  const auto stamped = SanitizeNativeDiagnosticTail(stamp +
      " area=wireguard event=connection_attempt_snapshot " +
      fuzevpn::FormatWireGuardAttemptSnapshot(written) + "\r\n");
  Check(stamp == "2026-01-02T03:04:05.007Z" && Events(stamped).size() == 1 &&
      Text(std::get<Map>(Events(stamped)[0]), "timestamp") == stamp,
      "native writers' timestamp is accepted by the local reader");
  const auto adapter = SanitizeNativeDiagnosticTail(Line(
      "area=wireguard event=connection_attempt_snapshot stage=adapter_open handshake=0 success=0"));
  Check(Events(adapter).size() == 1 &&
      Text(std::get<Map>(Events(adapter)[0]), "stage") == "adapter_open",
      "adapter-open failure stays distinct from the handshake wait");
  const auto operations = SanitizeNativeDiagnosticTail(
      Line("area=openvpn event=importAndConnect_started") +
      Line("area=openvpn event=prepareConnection_succeeded") +
      Line("area=wireguard event=prepareIdentityForAccount_failed") +
      Line("area=wireguard event=recreateIdentityForAccount_started") +
      Line("area=openvpn event=ImportAndConnect_started") +
      Line("area=openvpn event=importAndConnect_Started") +
      Line("area=wireguard event=cleanup_snapshot") +
      Line("area=broker event=connection_attempt_snapshot"));
  Check(Events(operations).size() == 4 && Integer(operations, "discarded_lines") == 4 &&
      Text(std::get<Map>(Events(operations)[0]), "event") == "importAndConnect_started" &&
      Text(std::get<Map>(Events(operations)[2]), "event") == "prepareIdentityForAccount_failed",
      "camelCase operation breadcrumbs are read; unknown spellings and areas are not");
}
void ServiceChecks() {
  scenario = Scenario::manager_denied;
  auto service = ObserveService({});
  Check(Text(service, "state") == "unknown" && Text(service, "query_stage") == "scm_open" &&
      Integer(service, "win32_error") == ERROR_ACCESS_DENIED, "SCM permission failure precise");
  scenario = Scenario::absent; service = ObserveService({});
  Check(Text(service, "state") == "absent" && Integer(service, "win32_error") == ERROR_SERVICE_DOES_NOT_EXIST,
      "missing installed service observed automatically");
  scenario = Scenario::service_denied; service = ObserveService({});
  Check(Text(service, "state") == "unknown" && Text(service, "query_stage") == "service_open",
      "service permission denial differs from absence");
  scenario = Scenario::status_failed; service = ObserveService({});
  Check(Text(service, "state") == "unknown" && Text(service, "query_stage") == "service_status" &&
      Integer(service, "win32_error") == ERROR_INVALID_HANDLE, "query error retained");
  scenario = Scenario::stopped; service = ObserveService({});
  Check(Text(service, "state") == "stopped" && Integer(service, "win32_exit_code") == 50 &&
      Integer(service, "service_exit_code") == 123 && !Flag(service, "process_present"),
      "stopped service exit codes retained without PowerShell");
  scenario = Scenario::starting; service = ObserveService({});
  Check(Text(service, "state") == "start_pending" && !Flag(service, "process_present"),
      "start pending not falsely absent");
  scenario = Scenario::running; service = ObserveService({});
  Check(Text(service, "state") == "running" && Flag(service, "process_present") &&
      Integer(service, "configuration_win32_error") == ERROR_ACCESS_DENIED &&
      manager_access == SC_MANAGER_CONNECT, "minimal read permissions preserve status when config denied");
}
void PartialCollectionChecks() {
  const auto valid = [] { return Map{{Value("fixture"), Value(true)}}; };
  for (unsigned failed = 0; failed < 4; ++failed) {
    unsigned called = 0;
    const auto reader = [&]() -> Map {
      if (called++ == failed) throw std::runtime_error("private exception text");
      return valid();
    };
    const auto result = CollectSources(reader, reader, reader, reader);
    Check(called == 4 && result.size() == 6 &&
        Integer(result, "collection_error") == ERROR_UNHANDLED_EXCEPTION,
        "a reader failure retains three independent observations and an explicit code");
  }
}
void FileChecks(const std::filesystem::path& directory) {
  std::filesystem::create_directories(directory);
  const auto missing = ReadNativeLog(directory / L"missing.log");
  Check(Text(missing, "status") == "absent", "absent native log exported explicitly");
  const auto path = directory / L"native_diagnostic.log";
  {
    std::ofstream file(path, std::ios::binary);
    file << std::string(70000, 'x') << '\n' << Line("area=broker event=connection_failed code=50");
  }
  const auto read = ReadNativeLog(path);
  Check(Text(read, "status") == "ok" && Flag(read, "truncated") && Events(read).size() == 1,
      "on-disk collector reads bounded file tail");
  const auto folder = ReadNativeLog(directory);
  Check(Text(folder, "status") == "rejected" || Text(folder, "status") == "read_failed",
      "directory cannot become log input");
  const auto linked = directory / L"native-link.log";
  // Symbolic-link creation may be unavailable on stock Windows. If available,
  // exercise actual reparse-point rejection, without reading the target.
  if (CreateSymbolicLinkW(linked.c_str(), path.c_str(), SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
    Check(Text(ReadNativeLog(linked), "status") == "rejected", "reparse log rejected");
    DeleteFileW(linked.c_str());
  }
}
}  // namespace
int wmain(int argc, wchar_t** argv) {
  try {
    Check(argc == 2, "isolated fixture directory required");
    ParserChecks(); WireGuardSnapshotChecks(); ServiceChecks(); PartialCollectionChecks();
    FileChecks(argv[1]);
    std::cout << "native local diagnostics: parser, privacy, bounds, automatic SCM evidence passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
  }
}
