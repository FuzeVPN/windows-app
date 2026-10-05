// Exercises the production maintenance finalizer with in-memory registry and
// SCM adapters. No service or machine registry operation is performed.
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <shlobj.h>
#include <cstring>
#include <iostream>
#include <string>
#include "../broker_security.h"
#include "../maintenance_network_policy.h"
#include "../installation_security.h"
#include "../service_handoff_mutex.h"

namespace {
const std::wstring fixture_token = L"01234567-89ab-cdef-0123-456789abcdef";
const std::wstring other_token = L"11234567-89ab-cdef-0123-456789abcdef";
std::wstring fixture_directory;
std::wstring fixture_command;
std::wstring gate_token;
std::wstring gate_directory;
bool gate_exists = true;
bool clear_denied = false;
bool create_denied = false;
bool disable_denied = false;
bool config_denied = false;
bool replace_gate_during_start = false;
bool protected_creation = false;
DWORD fixture_start_error = ERROR_SUCCESS;
DWORD start_type = SERVICE_DISABLED;
DWORD clean_stop = 1;
unsigned start_calls = 0;
unsigned disable_calls = 0;
unsigned writes = 0;
bool fixture_service_exists = true;
bool fixture_wireguard_running = false;
bool fixture_lock_available = true;
DWORD fixture_network_error = ERROR_SUCCESS;
DWORD fixture_state = SERVICE_STOPPED;
DWORD fixture_exit = ERROR_SUCCESS;
DWORD fixture_specific_exit = 0;
DWORD fixture_pid = 0;
DWORD fixture_status_error = ERROR_SUCCESS;
DWORD fixture_parent_create_error = ERROR_SUCCESS;
DWORD fixture_service_open_error = ERROR_SUCCESS;
DWORD fixture_process_open_error = ERROR_SUCCESS;
bool fixture_target_valid = true;
DWORD fixture_snapshot_error = ERROR_SUCCESS;
DWORD fixture_snapshot_first_error = ERROR_SUCCESS;
DWORD fixture_snapshot_next_error = ERROR_SUCCESS;
bool fixture_snapshot_initial_present = false;
bool fixture_snapshot_self_present = true;
ULONGLONG fixture_now = 10000;
unsigned stop_calls = 0;
unsigned network_checks = 0;
HKEY GateKey() { return reinterpret_cast<HKEY>(static_cast<ULONG_PTR>(10)); }
HKEY ParentKey() { return reinterpret_cast<HKEY>(static_cast<ULONG_PTR>(11)); }

LSTATUS WINAPI MaintenanceOpenKey(HKEY, LPCWSTR path, DWORD, REGSAM, PHKEY result) {
  if (std::wstring(path) == L"SOFTWARE\\FuzeVPN") { *result = ParentKey(); return ERROR_SUCCESS; }
  if (!gate_exists) return ERROR_FILE_NOT_FOUND;
  *result = GateKey(); return ERROR_SUCCESS;
}
LSTATUS WINAPI MaintenanceCreateKey(HKEY, LPCWSTR path, DWORD, LPWSTR, DWORD,
    REGSAM, const LPSECURITY_ATTRIBUTES attributes, PHKEY result, LPDWORD disposition) {
  if (std::wstring(path) == L"SOFTWARE\\FuzeVPN") {
    if (fixture_parent_create_error) return fixture_parent_create_error;
    *result = ParentKey(); return ERROR_SUCCESS;
  }
  if (create_denied) return ERROR_ACCESS_DENIED;
  LPWSTR sddl = nullptr;
  if (attributes && ConvertSecurityDescriptorToStringSecurityDescriptorW(
      attributes->lpSecurityDescriptor, SDDL_REVISION_1,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sddl, nullptr)) {
    const std::wstring value(sddl); LocalFree(sddl);
    protected_creation = value.find(L"O:BA") != std::wstring::npos &&
        value.find(L"D:P") != std::wstring::npos;
  }
  if (disposition) *disposition = gate_exists ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
  gate_exists = true; *result = GateKey(); return ERROR_SUCCESS;
}
LSTATUS WINAPI MaintenanceCloseKey(HKEY) { return ERROR_SUCCESS; }
LSTATUS WINAPI MaintenanceFlushKey(HKEY) { return ERROR_SUCCESS; }
LSTATUS WINAPI MaintenanceDeleteKey(HKEY, LPCWSTR, REGSAM, DWORD) {
  if (clear_denied) return ERROR_ACCESS_DENIED;
  gate_exists = false; gate_token.clear(); gate_directory.clear(); return ERROR_SUCCESS;
}
LSTATUS WINAPI MaintenanceReadValue(HKEY, LPCWSTR, LPCWSTR name, DWORD,
    LPDWORD, PVOID value, LPDWORD bytes) {
  const std::wstring* selected = nullptr;
  if (std::wstring(name) == L"Transaction") selected = &gate_token;
  if (std::wstring(name) == L"Directory") selected = &gate_directory;
  if (!gate_exists || !selected) return ERROR_FILE_NOT_FOUND;
  const DWORD required = static_cast<DWORD>((selected->size() + 1) * sizeof(wchar_t));
  if (*bytes < required) { *bytes = required; return ERROR_MORE_DATA; }
  std::memcpy(value, selected->c_str(), required); *bytes = required; return ERROR_SUCCESS;
}
LSTATUS WINAPI MaintenanceWriteValue(HKEY, LPCWSTR name, DWORD, DWORD type,
    const BYTE* value, DWORD bytes) {
  ++writes;
  if (type == REG_SZ) {
    const std::wstring text(reinterpret_cast<const wchar_t*>(value), bytes / sizeof(wchar_t) - 1);
    if (std::wstring(name) == L"Transaction") gate_token = text;
    if (std::wstring(name) == L"Directory") gate_directory = text;
  } else if (std::wstring(name) == L"CleanStopConfirmed" && bytes == sizeof(DWORD)) {
    std::memcpy(&clean_stop, value, sizeof(clean_stop));
  }
  return ERROR_SUCCESS;
}
LSTATUS WINAPI MaintenanceKeySecurity(HKEY, SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR output, LPDWORD bytes) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", SDDL_REVISION_1,
      &descriptor, nullptr)) return ERROR_INVALID_SECURITY_DESCR;
  const DWORD required = GetSecurityDescriptorLength(descriptor);
  const bool enough = output && *bytes >= required;
  if (enough) std::memcpy(output, descriptor, required);
  *bytes = required; LocalFree(descriptor);
  return enough ? ERROR_SUCCESS : ERROR_INSUFFICIENT_BUFFER;
}
SC_HANDLE WINAPI MaintenanceOpenManager(LPCWSTR, LPCWSTR, DWORD) {
  return reinterpret_cast<SC_HANDLE>(static_cast<ULONG_PTR>(12));
}
SC_HANDLE WINAPI MaintenanceOpenService(SC_HANDLE, LPCWSTR name, DWORD) {
  if (std::wstring(name) == L"WireGuardTunnel$FuzeVPN") {
    if (fixture_wireguard_running) return reinterpret_cast<SC_HANDLE>(static_cast<ULONG_PTR>(14));
    SetLastError(ERROR_SERVICE_DOES_NOT_EXIST); return nullptr;
  }
  if (!fixture_service_exists) { SetLastError(ERROR_SERVICE_DOES_NOT_EXIST); return nullptr; }
  if (fixture_service_open_error) { SetLastError(fixture_service_open_error); return nullptr; }
  return reinterpret_cast<SC_HANDLE>(static_cast<ULONG_PTR>(13));
}
BOOL WINAPI MaintenanceCloseService(SC_HANDLE) { return TRUE; }
BOOL WINAPI MaintenanceQueryConfig(SC_HANDLE, LPQUERY_SERVICE_CONFIGW output,
    DWORD bytes, LPDWORD required) {
  *required = sizeof(QUERY_SERVICE_CONFIGW);
  if (!output || bytes < *required) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
  *output = {};
  output->dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  output->lpBinaryPathName = fixture_command.data();
  output->lpServiceStartName = const_cast<LPWSTR>(L"LocalSystem");
  return TRUE;
}
BOOL WINAPI MaintenanceConfig(SC_HANDLE, DWORD, DWORD type, DWORD, LPCWSTR,
    LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR) {
  if (type == SERVICE_DISABLED) {
    ++disable_calls;
    if (disable_denied) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  }
  start_type = type; return TRUE;
}
BOOL WINAPI MaintenanceConfig2(SC_HANDLE, DWORD, LPVOID) {
  if (config_denied) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  return TRUE;
}
BOOL WINAPI MaintenanceStart(SC_HANDLE, DWORD, LPCWSTR*) {
  ++start_calls;
  if (replace_gate_during_start) { gate_exists = true; gate_token = other_token; }
  if (fixture_start_error != ERROR_SUCCESS) { SetLastError(fixture_start_error); return FALSE; }
  return TRUE;
}
BOOL WINAPI MaintenanceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE output, DWORD bytes, LPDWORD required) {
  *required = sizeof(SERVICE_STATUS_PROCESS);
  if (fixture_status_error != ERROR_SUCCESS) { SetLastError(fixture_status_error); return FALSE; }
  if (bytes < *required) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
  auto* state = reinterpret_cast<SERVICE_STATUS_PROCESS*>(output);
  *state = {};
  state->dwCurrentState = fixture_state;
  state->dwWin32ExitCode = fixture_exit;
  state->dwServiceSpecificExitCode = fixture_specific_exit;
  state->dwProcessId = fixture_pid;
  return TRUE;
}
BOOL WINAPI MaintenanceStatus(SC_HANDLE, LPSERVICE_STATUS state) {
  *state = {}; state->dwCurrentState = SERVICE_RUNNING; return TRUE;
}
BOOL WINAPI MaintenanceStop(SC_HANDLE, DWORD, LPSERVICE_STATUS) {
  ++stop_calls; fixture_state = SERVICE_STOPPED; fixture_pid = 0; return TRUE;
}
HANDLE WINAPI MaintenanceProcess(DWORD, BOOL, DWORD) {
  if (fixture_process_open_error) { SetLastError(fixture_process_open_error); return nullptr; }
  return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(15));
}
DWORD WINAPI MaintenanceWait(HANDLE, DWORD) { return WAIT_OBJECT_0; }
BOOL WINAPI MaintenanceCloseHandle(HANDLE) { return TRUE; }
HANDLE WINAPI MaintenanceSnapshot(DWORD flags, DWORD pid) {
  if (flags != TH32CS_SNAPPROCESS || pid != 0) { SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
  if (fixture_snapshot_error) { SetLastError(fixture_snapshot_error); return INVALID_HANDLE_VALUE; }
  return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(17));
}
BOOL WINAPI MaintenanceFirst(HANDLE, LPPROCESSENTRY32W process) {
  if (fixture_snapshot_first_error) { SetLastError(fixture_snapshot_first_error); return FALSE; }
  process->th32ProcessID = fixture_snapshot_self_present ? 404 : 405; return TRUE;
}
BOOL WINAPI MaintenanceNext(HANDLE, LPPROCESSENTRY32W process) {
  if (fixture_snapshot_next_error) { SetLastError(fixture_snapshot_next_error); return FALSE; }
  if (fixture_snapshot_initial_present && process->th32ProcessID != 123) {
    process->th32ProcessID = 123; return TRUE;
  }
  SetLastError(ERROR_NO_MORE_FILES); return FALSE;
}
DWORD WINAPI MaintenanceSelfPid() { return 404; }
ULONGLONG WINAPI MaintenanceTick() { return fixture_now; }
void WINAPI MaintenanceSleep(DWORD value) { fixture_now += value; }
void ResetMaintenance() {
  gate_exists = true; gate_token = fixture_token; gate_directory = fixture_directory;
  clear_denied = create_denied = disable_denied = config_denied = false;
  replace_gate_during_start = protected_creation = false;
  fixture_start_error = ERROR_SUCCESS; start_type = SERVICE_DISABLED; clean_stop = 1;
  start_calls = disable_calls = writes = 0;
  fixture_service_exists = fixture_lock_available = true;
  fixture_wireguard_running = false;
  fixture_network_error = fixture_status_error = ERROR_SUCCESS;
  fixture_parent_create_error = fixture_service_open_error = fixture_process_open_error = ERROR_SUCCESS;
  fixture_target_valid = true;
  fixture_snapshot_error = fixture_snapshot_first_error = fixture_snapshot_next_error = ERROR_SUCCESS;
  fixture_snapshot_initial_present = false; fixture_snapshot_self_present = true; fixture_now = 10000;
  fixture_state = SERVICE_STOPPED; fixture_exit = fixture_specific_exit = fixture_pid = 0;
  stop_calls = network_checks = 0;
}
bool VerifyMaintenance(bool condition, const char* message) {
  if (!condition) std::cerr << "Maintenance regression: " << message << '\n';
  return condition;
}
}  // namespace

namespace fuzevpn_ipc_maintenance_test {
class ExclusiveRuntimeLock {
 public:
  bool AcquireMachineRuntime() { return fixture_lock_available; }
};
}
namespace fuzevpn_handoff_maintenance_test {
class Reservation {
 public:
  bool Acquire(const wchar_t* name) {
    if (std::wstring(name) != L"Global\\FuzeVPN-ExclusiveRuntime-v1") { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    if (!fixture_lock_available) SetLastError(ERROR_BUSY);
    return fixture_lock_available;
  }
};
}

namespace fuzevpn_installation {
bool TestMaintenanceTarget(const std::filesystem::path&) { return fixture_target_valid; }
}

namespace fuzevpn_maintenance_test {
bool ConfirmStoppedNetworkState(const std::wstring&, DWORD* error) {
  ++network_checks;
  if (error) *error = fixture_network_error;
  return fixture_network_error == ERROR_SUCCESS;
}
}

#define fuzevpn_maintenance fuzevpn_maintenance_test
#define fuzevpn_ipc fuzevpn_ipc_maintenance_test
#define fuzevpn_handoff fuzevpn_handoff_maintenance_test
#define RegOpenKeyExW MaintenanceOpenKey
#define RegCreateKeyExW MaintenanceCreateKey
#define RegCloseKey MaintenanceCloseKey
#define RegFlushKey MaintenanceFlushKey
#define RegDeleteKeyExW MaintenanceDeleteKey
#define RegGetValueW MaintenanceReadValue
#define RegSetValueExW MaintenanceWriteValue
#define RegGetKeySecurity MaintenanceKeySecurity
#define OpenSCManagerW MaintenanceOpenManager
#define OpenServiceW MaintenanceOpenService
#define CloseServiceHandle MaintenanceCloseService
#define QueryServiceConfigW MaintenanceQueryConfig
#define ChangeServiceConfigW MaintenanceConfig
#define ChangeServiceConfig2W MaintenanceConfig2
#define StartServiceW MaintenanceStart
#define QueryServiceStatusEx MaintenanceStatusEx
#define QueryServiceStatus MaintenanceStatus
#define ControlService MaintenanceStop
#define OpenProcess MaintenanceProcess
#define WaitForSingleObject MaintenanceWait
#define CloseHandle MaintenanceCloseHandle
#define ValidateInstallationTarget TestMaintenanceTarget
#define CreateToolhelp32Snapshot MaintenanceSnapshot
#define Process32FirstW MaintenanceFirst
#define Process32NextW MaintenanceNext
#define GetCurrentProcessId MaintenanceSelfPid
#define GetTickCount64 MaintenanceTick
#define Sleep MaintenanceSleep
#include "../maintenance_state.cpp"
#undef ValidateInstallationTarget
#undef fuzevpn_maintenance
#undef fuzevpn_ipc
#undef fuzevpn_handoff

bool TestMaintenanceRecovery() {
  fixture_directory = L"D:\\Applications prot\u00e9g\u00e9es\\FuzeVPN";
  fixture_command = L"\"" + fixture_directory + L"\\fuzevpn-service.exe\" --fuzevpn-vpn-service";
  DWORD error = ERROR_SUCCESS; bool attempted = false;
  const auto finish = [&]() { return fuzevpn_maintenance_test::EndInstallerMaintenance(fixture_token, true, &error, &attempted); };
  ResetMaintenance();
  if (!VerifyMaintenance(finish() && attempted && start_calls == 1 &&
      !gate_exists && start_type == SERVICE_AUTO_START, "successful relaunch")) return false;
  ResetMaintenance(); fixture_start_error = ERROR_SERVICE_REQUEST_TIMEOUT;
  if (!VerifyMaintenance(!finish() && attempted && error == ERROR_SERVICE_REQUEST_TIMEOUT &&
      gate_exists && gate_token == fixture_token && gate_directory == fixture_directory && clean_stop == 0 &&
      protected_creation && start_type == SERVICE_DISABLED, "ambiguous start restores protected gate and disables SCM")) return false;
  ResetMaintenance(); fixture_start_error = ERROR_SERVICE_REQUEST_TIMEOUT; replace_gate_during_start = true;
  if (!VerifyMaintenance(!finish() && attempted && error == ERROR_INSTALL_ALREADY_RUNNING &&
      gate_token == other_token && writes == 0 && start_type == SERVICE_DISABLED,
      "concurrent transaction must never be overwritten")) return false;
  ResetMaintenance(); fixture_start_error = ERROR_SERVICE_REQUEST_TIMEOUT; create_denied = true;
  if (!VerifyMaintenance(!finish() && attempted && error == ERROR_ACCESS_DENIED &&
      disable_calls == 1 && start_type == SERVICE_DISABLED,
      "SCM disable still runs when registry recovery fails")) return false;
  ResetMaintenance(); fixture_start_error = ERROR_SERVICE_REQUEST_TIMEOUT; disable_denied = true;
  if (!VerifyMaintenance(!finish() && attempted && error == ERROR_ACCESS_DENIED &&
      gate_exists && gate_token == fixture_token && protected_creation,
      "registry protection survives SCM disable failure")) return false;
  ResetMaintenance(); clear_denied = true;
  if (!VerifyMaintenance(!finish() && !attempted && start_calls == 0 && gate_exists &&
      start_type == SERVICE_DISABLED, "failed gate removal cannot leave AUTO_START enabled")) return false;
  ResetMaintenance(); config_denied = true;
  if (!VerifyMaintenance(!finish() && !attempted && start_calls == 0 && gate_exists &&
      start_type == SERVICE_DISABLED, "configuration failure does not enable startup")) return false;
  ResetMaintenance(); gate_directory = L"D:\\Applications\\..\\FuzeVPN";
  if (!VerifyMaintenance(!finish() && !attempted && error == ERROR_ACCESS_DENIED &&
      start_calls == 0 && gate_exists, "noncanonical maintenance directory remains blocked")) return false;
  ResetMaintenance(); fixture_command = L"\"D:\\Other\\fuzevpn-service.exe\" --fuzevpn-vpn-service";
  if (!VerifyMaintenance(!finish() && !attempted && error == ERROR_BAD_CONFIGURATION &&
      start_calls == 0 && gate_exists, "custom directory cannot authorize a different installed service")) return false;

  fixture_command = L"\"" + fixture_directory + L"\\fuzevpn-service.exe\" --fuzevpn-vpn-service";
  const auto stop = [&]() { error = ERROR_SUCCESS;
    return fuzevpn_maintenance_test::StopConfirmed(fixture_directory, false, &error); };
  const auto begin = [&]() { error = ERROR_SUCCESS;
    return fuzevpn_maintenance_test::BeginInstallerMaintenance(fixture_token, fixture_directory, &error); };
  ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; start_type = SERVICE_AUTO_START;
  if (!VerifyMaintenance(begin() && stop_calls == 1 && start_type == SERVICE_DISABLED && clean_stop == 1 &&
      std::wstring(fuzevpn_maintenance_test::LastInstallerMaintenanceStage()) == L"complete",
      "complete healthy running service upgrade disables and confirms stop before file replacement")) return false;
  if (!VerifyMaintenance(finish() && start_calls == 1 && start_type == SERVICE_AUTO_START && !gate_exists,
      "healthy service transaction restores automatic startup and clears gate")) return false;
  ResetMaintenance(); fixture_parent_create_error = ERROR_INVALID_OWNER;
  if (!VerifyMaintenance(!begin() && error == ERROR_INVALID_OWNER && stop_calls == 0 &&
      std::wstring(fuzevpn_maintenance_test::LastInstallerMaintenanceStage()) == L"parent_key_open",
      "parent registry API error is preserved with its exact diagnostic stage")) return false;
  ResetMaintenance(); fixture_target_valid = false;
  if (!VerifyMaintenance(!begin() && error == ERROR_ACCESS_DENIED && stop_calls == 0 &&
      std::wstring(fuzevpn_maintenance_test::LastInstallerMaintenanceStage()) == L"target_security",
      "target security refusal is diagnosed before service mutation")) return false;
  ResetMaintenance(); fixture_service_open_error = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(!begin() && error == ERROR_ACCESS_DENIED && disable_calls == 0 && stop_calls == 0 &&
      std::wstring(fuzevpn_maintenance_test::LastInstallerMaintenanceStage()) == L"service_open",
      "SCM access refusal is distinct from target and registry security")) return false;
  ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123;
  fixture_process_open_error = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(begin() && stop_calls == 1 && network_checks == 1 && clean_stop == 1,
      "restricted MSI token upgrades a healthy service via complete process disappearance and network proof")) return false;
  if (!VerifyMaintenance(finish() && start_type == SERVICE_AUTO_START && !gate_exists,
      "successful restricted-token transaction restores service configuration")) return false;
  for (const DWORD open_error : {ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER}) {
    ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; fixture_process_open_error = open_error;
    fixture_snapshot_initial_present = true;
    if (!VerifyMaintenance(!begin() && error == ERROR_TIMEOUT && stop_calls == 1 && network_checks == 0 && writes == 2,
        "original or recycled PID still present after SCM STOPPED cannot authorize replacement")) return false;
  }
  ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; fixture_process_open_error = ERROR_ACCESS_DENIED;
  fixture_snapshot_error = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(!begin() && error == ERROR_ACCESS_DENIED && network_checks == 0 &&
      std::wstring(fuzevpn_maintenance_test::LastInstallerMaintenanceStage()) == L"service_process_snapshot",
      "snapshot failure is explicit and cannot confirm cleanup")) return false;
  for (const bool first : {true, false}) {
    ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; fixture_process_open_error = ERROR_ACCESS_DENIED;
    if (first) fixture_snapshot_first_error = ERROR_ACCESS_DENIED;
    else fixture_snapshot_next_error = ERROR_ACCESS_DENIED;
    if (!VerifyMaintenance(!begin() && error == ERROR_ACCESS_DENIED && network_checks == 0,
        "incomplete process enumeration cannot prove absence")) return false;
  }
  ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; fixture_process_open_error = ERROR_ACCESS_DENIED;
  fixture_snapshot_self_present = false;
  if (!VerifyMaintenance(!begin() && error == ERROR_INVALID_DATA && network_checks == 0,
      "snapshot omitting the current live CA is not accepted as process proof")) return false;
  for (const DWORD proof_error : {ERROR_BUSY, ERROR_ACCESS_DENIED}) {
    ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; fixture_process_open_error = ERROR_ACCESS_DENIED;
    fixture_network_error = proof_error;
    if (!VerifyMaintenance(!begin() && error == proof_error && network_checks == 1,
        "process absence still requires independent clean network state")) return false;
  }
  ResetMaintenance(); fixture_exit = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(stop() && network_checks == 1 && stop_calls == 0 &&
      start_type == SERVICE_DISABLED && gate_exists,
      "cached startup error is accepted only after independent proof")) return false;
  for (const DWORD proof_error : {ERROR_BUSY, ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE}) {
    ResetMaintenance(); fixture_exit = ERROR_ACCESS_DENIED; fixture_network_error = proof_error;
    if (!VerifyMaintenance(!stop() && error == proof_error && network_checks == 1 && gate_exists,
        "surviving or inaccessible network state remains blocking")) return false;
  }
  ResetMaintenance(); fixture_specific_exit = 1;
  if (!VerifyMaintenance(stop() && network_checks == 1,
      "historical service-specific error also requires proof")) return false;
  ResetMaintenance(); fixture_state = SERVICE_RUNNING; fixture_pid = 123; fixture_exit = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(!stop() && error == ERROR_SERVICE_SPECIFIC_ERROR &&
      stop_calls == 1 && network_checks == 0,
      "new stop failure cannot use historical-error fallback")) return false;
  ResetMaintenance(); fixture_pid = 123; fixture_exit = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(!stop() && error == ERROR_SERVICE_SPECIFIC_ERROR && network_checks == 0,
      "STOPPED with a process ID cannot use historical fallback")) return false;
  for (const DWORD open_error : {ERROR_SUCCESS, ERROR_ACCESS_DENIED}) {
    ResetMaintenance(); fixture_pid = 123; fixture_process_open_error = open_error;
    if (!VerifyMaintenance(!stop() && error == ERROR_TIMEOUT && network_checks == 0,
        "STOPPED with a nonzero SCM PID cannot authorize replacement even with zero exit codes")) return false;
  }
  ResetMaintenance(); fixture_exit = ERROR_ACCESS_DENIED; fixture_wireguard_running = true;
  if (!VerifyMaintenance(!stop() && error == ERROR_BUSY && network_checks == 0,
      "surviving WireGuard service remains blocking")) return false;
  ResetMaintenance(); fixture_exit = ERROR_ACCESS_DENIED; fixture_lock_available = false;
  if (!VerifyMaintenance(!stop() && error == ERROR_BUSY && network_checks == 0,
      "surviving broker blocks independent proof")) return false;
  ResetMaintenance(); fixture_status_error = ERROR_ACCESS_DENIED;
  if (!VerifyMaintenance(!stop() && error == ERROR_ACCESS_DENIED && network_checks == 0,
      "unknown SCM state cannot authorize repair")) return false;
  ResetMaintenance();
  if (!VerifyMaintenance(stop() && network_checks == 0,
      "normal clean stop retains its established cleanup contract")) return false;
  using namespace fuzevpn_maintenance_policy;
  if (!VerifyMaintenance(
      !ActiveVpnAdapter(L"OpenVPN Data Channel Offload", L"ovpn-dco", false, true, true) &&
      ActiveVpnAdapter(L"OpenVPN Data Channel Offload", L"ovpn-dco", true, true, true) &&
      ActiveVpnAdapter(L"FuzeVPN", L"WireGuard Tunnel", true, false, true) &&
      !ActiveVpnAdapter(L"vEthernet (FuzeVPN-Lab)", L"Hyper-V Virtual Ethernet Adapter", true, true, true) &&
      !ActiveVpnAdapter(L"FuzeVPN-Lab", L"Hyper-V Virtual Ethernet Adapter", true, true, true),
      "disconnected DCO and unrelated lab interfaces do not prevent repair")) return false;
  if (!VerifyMaintenance(FuzeName(L"FuzeVPN — DNS") && !FuzeName(L"FuzeVPN-Lab") &&
      VpnFilterName(L"OpenVPN") && VpnFilterName(L"OpenVPN DNS block") &&
      !VpnFilterName(L"Corporate firewall") &&
      FuzeExecutable(L"\\device\\harddiskvolume3\\program files\\FuzeVPN\\FUzeVPN-service.exe") &&
      !FuzeExecutable(L"\\device\\fuzevpn-service.exe.backup") &&
      VpnNrptRule(L"FuzeVPNDNSRoutingV1-123-456-0") &&
      VpnNrptRule(L"OpenVPNDNSRouting-123") && !VpnNrptRule(L"CorporateDNS"),
      "network ownership matching covers current and legacy rules")) return false;
  return true;
}
