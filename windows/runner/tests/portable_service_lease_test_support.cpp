// The actual lease implementation runs against injected Win32 adapters. No
// SCM command, process operation, named mutex or protected-file read is real.
#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <cstring>
#include <iostream>
#include "../broker_security.h"
#include "../installation_security.h"
#include "../update_security.h"

namespace {
ULONGLONG fixture_now = 10000;
ULONGLONG fixture_yield_at = 0;
ULONGLONG fixture_pending_at = 0;
ULONGLONG fixture_old_exit_at = 0;
DWORD fixture_control_delay = 0;
DWORD fixture_state = SERVICE_RUNNING;
DWORD fixture_query_error = ERROR_SUCCESS;
DWORD fixture_control_error = ERROR_SUCCESS;
DWORD fixture_start_error = ERROR_SUCCESS;
DWORD fixture_duplicate_error = ERROR_SUCCESS;
bool fixture_missing = false;
bool fixture_validate = true;
bool fixture_requested = false;
bool fixture_parent_alive = true;
bool fixture_old_exited = true;
bool fixture_runtime_free = true;
bool fixture_mutex_busy = false;
unsigned fixture_controls = 0;
unsigned fixture_starts = 0;
unsigned fixture_validation_calls = 0;
std::wstring fixture_config;
std::wstring fixture_mutex_sddl;
std::string fixture_order;
HANDLE FixtureHandle(ULONG_PTR number) { return reinterpret_cast<HANDLE>(number); }
SC_HANDLE WINAPI LeaseOpenManager(LPCWSTR, LPCWSTR, DWORD) { return reinterpret_cast<SC_HANDLE>(41); }
SC_HANDLE WINAPI LeaseOpenService(SC_HANDLE, LPCWSTR, DWORD access) {
  if (access & (SERVICE_STOP | DELETE | SERVICE_CHANGE_CONFIG)) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
  if (fixture_missing) { SetLastError(ERROR_SERVICE_DOES_NOT_EXIST); return nullptr; }
  return reinterpret_cast<SC_HANDLE>(42);
}
BOOL WINAPI LeaseCloseService(SC_HANDLE) { return TRUE; }
BOOL WINAPI LeaseQuery(SC_HANDLE, SC_STATUS_TYPE, LPBYTE buffer, DWORD, LPDWORD bytes) {
  if (fixture_query_error) { SetLastError(fixture_query_error); return FALSE; }
  if (fixture_requested && fixture_pending_at && fixture_now >= fixture_pending_at) fixture_state = SERVICE_STOP_PENDING;
  if (fixture_requested && fixture_yield_at && fixture_now >= fixture_yield_at) fixture_state = SERVICE_STOPPED;
  auto* state = reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer); *state = {};
  state->dwCurrentState = fixture_state;
  state->dwProcessId = fixture_state == SERVICE_STOPPED ? 0 : 123;
  *bytes = sizeof(*state); return TRUE;
}
BOOL WINAPI LeaseControl(SC_HANDLE, DWORD command, LPSERVICE_STATUS) {
  ++fixture_controls;
  if (command != 128 || fixture_control_error) {
    SetLastError(fixture_control_error ? fixture_control_error : ERROR_ACCESS_DENIED); return FALSE;
  }
  fixture_requested = true;
  fixture_now += fixture_control_delay;
  if (!fixture_yield_at) fixture_state = SERVICE_STOPPED;
  return TRUE;
}
BOOL WINAPI LeaseStart(SC_HANDLE, DWORD, LPCWSTR*) {
  ++fixture_starts; fixture_order += 'S';
  if (fixture_start_error) { SetLastError(fixture_start_error); return FALSE; }
  fixture_state = SERVICE_RUNNING; return TRUE;
}
BOOL WINAPI LeaseConfig(SC_HANDLE, LPQUERY_SERVICE_CONFIGW config, DWORD bytes, LPDWORD required) {
  *required = sizeof(QUERY_SERVICE_CONFIGW);
  if (!config || bytes < *required) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
  *config = {}; config->dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  config->lpServiceStartName = const_cast<LPWSTR>(L"LocalSystem"); config->lpBinaryPathName = fixture_config.data();
  return TRUE;
}
HANDLE WINAPI LeaseProcess(DWORD access, BOOL, DWORD) {
  if (access != SYNCHRONIZE) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
  return FixtureHandle(44);
}
HANDLE WINAPI LeaseMutex(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) { return FixtureHandle(43); }
DWORD WINAPI LeaseSecurity(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID* owner, PSID*,
    PACL* acl, PACL*, PSECURITY_DESCRIPTOR* descriptor) {
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(fixture_mutex_sddl.c_str(), SDDL_REVISION_1,
      descriptor, nullptr)) return GetLastError();
  BOOL defaulted = FALSE, present = FALSE;
  GetSecurityDescriptorOwner(*descriptor, owner, &defaulted);
  GetSecurityDescriptorDacl(*descriptor, &present, acl, &defaulted);
  return ERROR_SUCCESS;
}
DWORD WINAPI LeaseWait(HANDLE handle, DWORD timeout) {
  if (handle == FixtureHandle(43)) return fixture_mutex_busy ? WAIT_TIMEOUT : WAIT_OBJECT_0;
  if (handle == FixtureHandle(44)) return fixture_old_exited ||
      (fixture_old_exit_at && fixture_now >= fixture_old_exit_at) ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
  if (handle == FixtureHandle(46)) return fixture_parent_alive ? WAIT_TIMEOUT : WAIT_OBJECT_0;
  if (handle == FixtureHandle(45) && timeout == INFINITE) { fixture_order += 'E'; return WAIT_OBJECT_0; }
  return WAIT_OBJECT_0;
}
BOOL WINAPI LeaseRelease(HANDLE) { return TRUE; }
BOOL WINAPI LeaseCloseHandle(HANDLE) { return TRUE; }
BOOL WINAPI LeaseDuplicate(HANDLE, HANDLE, HANDLE, LPHANDLE target, DWORD, BOOL, DWORD) {
  if (fixture_duplicate_error) { SetLastError(fixture_duplicate_error); return FALSE; }
  *target = FixtureHandle(45); return TRUE;
}
ULONGLONG WINAPI LeaseNow() { return fixture_now; }
void WINAPI LeaseSleep(DWORD value) { fixture_now += value; }
void ResetLease() {
  fixture_now = 10000; fixture_yield_at = fixture_pending_at = fixture_old_exit_at = 0;
  fixture_control_delay = 0; fixture_state = SERVICE_RUNNING;
  fixture_query_error = fixture_control_error = fixture_start_error = fixture_duplicate_error = ERROR_SUCCESS;
  fixture_missing = fixture_requested = fixture_mutex_busy = false;
  fixture_validate = fixture_parent_alive = fixture_old_exited = fixture_runtime_free = true;
  fixture_controls = fixture_starts = fixture_validation_calls = 0; fixture_order.clear();
  fixture_config = L"\"C:\\Program Files\\FuzeVPN\\fuzevpn-service.exe\" --fuzevpn-vpn-service";
  fixture_mutex_sddl = L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";
}
}
namespace fuzevpn_ipc_lease_test {
class ExclusiveRuntimeLock { public: bool AcquireMachineRuntime() { return fixture_runtime_free; } };
}
#define fuzevpn_handoff fuzevpn_handoff_lease_test
#define fuzevpn_ipc fuzevpn_ipc_lease_test
#define OpenSCManagerW LeaseOpenManager
#define OpenServiceW LeaseOpenService
#define CloseServiceHandle LeaseCloseService
#define QueryServiceStatusEx LeaseQuery
#define ControlService LeaseControl
#define StartServiceW LeaseStart
#define QueryServiceConfigW LeaseConfig
#define OpenProcess LeaseProcess
#define CreateMutexW LeaseMutex
#define GetSecurityInfo LeaseSecurity
#define WaitForSingleObject LeaseWait
#define ReleaseMutex LeaseRelease
#define CloseHandle LeaseCloseHandle
#define DuplicateHandle LeaseDuplicate
#define GetTickCount64 LeaseNow
#define Sleep LeaseSleep
#include "../portable_service_lease.cpp"
#undef fuzevpn_handoff
#undef fuzevpn_ipc

namespace {
bool LeaseValidate(SC_HANDLE, const fuzevpn_update::PinnedFile&, fuzevpn_update::PinnedFile*,
    fuzevpn_installation::ProtectedInstallation*, std::wstring* command, DWORD* error) {
  ++fixture_validation_calls; *command = fixture_config;
  if (!fixture_validate) { if (error) *error = ERROR_ACCESS_DENIED; return false; }
  return true;
}
}
bool TestPortableServiceLease() {
  using fuzevpn_handoff_lease_test::InstalledServiceLease;
  fuzevpn_update::PinnedFile helper; DWORD error = ERROR_SUCCESS;
  const auto check = [](bool condition, const char* message) {
    if (!condition) std::cerr << "Portable service lease: " << message << '\n';
    return condition;
  };
  ResetLease();
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(lease.Acquire(helper, FixtureHandle(46), &error) && fixture_controls == 1 &&
        lease.TrackEngine(FixtureHandle(47), &error), "idle service yields before private engine")) return false;
  }
  if (!check(fixture_starts == 1 && fixture_order == "ES", "engine actually exits before service restoration")) return false;
  for (const auto* failure : {"cache", "environment", "process", "response", "ack", "resume"}) {
    ResetLease();
    { InstalledServiceLease lease(LeaseValidate);
      if (!check(lease.Acquire(helper, FixtureHandle(46), &error), failure)) return false;
      if (std::string(failure) == "ack" || std::string(failure) == "resume")
        if (!check(lease.TrackEngine(FixtureHandle(47), &error), failure)) return false;
    }
    if (!check(fixture_starts == 1, "every bootstrap exit after accepted yield restores service")) return false;
  }
  ResetLease(); fixture_control_error = ERROR_INVALID_SERVICE_CONTROL;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && error == ERROR_INVALID_SERVICE_CONTROL,
        "unsupported control never falls back to service STOP")) return false;
  }
  if (!check(fixture_starts == 0 && fixture_controls == 1, "refused control never starts or stops service")) return false;
  ResetLease(); fixture_yield_at = fixture_now + 999999;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && error == ERROR_BUSY,
        "busy service yields no engine within bounded wait")) return false;
  }
  if (!check(fixture_starts == 0, "rejected expired yield leaves running service untouched")) return false;
  ResetLease(); fixture_yield_at = fixture_now + 7000; fixture_parent_alive = false;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && error == ERROR_CANCELLED,
        "cancelled bootstrap is reported")) return false;
  }
  if (!check(fixture_starts == 1 && fixture_now >= 17000,
      "cancellation waits for queued lease resolution before restoring")) return false;
  ResetLease(); fixture_old_exited = false; fixture_old_exit_at = fixture_now + 20000;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error), "STOPPED before old process exit is not sufficient")) return false;
  }
  if (!check(fixture_starts == 1 && fixture_now >= 30000,
      "restoration waits for actual old service process exit even past bootstrap timeout")) return false;
  ResetLease(); fixture_pending_at = fixture_now + 1000; fixture_yield_at = fixture_now + 20000;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && error == ERROR_BUSY,
        "slow accepted stop prevents private engine bootstrap past deadline")) return false;
  }
  if (!check(fixture_starts == 1 && fixture_now >= 30000,
      "accepted STOP_PENDING is restored after its eventual completion")) return false;
  ResetLease(); fixture_control_delay = 10000; fixture_yield_at = fixture_now + 18000;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(lease.Acquire(helper, FixtureHandle(46), &error),
        "delayed control delivery starts helper deadline after successful queue")) return false;
  }
  if (!check(fixture_starts == 1 && fixture_now >= 28000,
      "delayed delivery still completes before the helper deadline")) return false;
  ResetLease(); fixture_validate = false;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && fixture_controls == 0,
        "untrusted/configuration mismatch never sends control")) return false;
  }
  ResetLease(); fixture_query_error = ERROR_ACCESS_DENIED;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && fixture_controls == 0,
        "unknown service state never sends control")) return false;
  }
  for (const bool missing : {false, true}) {
    ResetLease(); fixture_missing = missing; fixture_state = SERVICE_STOPPED;
    { InstalledServiceLease lease(LeaseValidate);
      if (!check(lease.Acquire(helper, FixtureHandle(46), &error) && fixture_controls == 0,
          "absent/already stopped service is never changed")) return false;
    }
    if (!check(fixture_starts == 0, "pre-existing service stop is preserved")) return false;
  }
  ResetLease(); fixture_runtime_free = false;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(lease.Acquire(helper, FixtureHandle(46), &error) && !lease.Restore(&error) && error == ERROR_BUSY,
        "another surviving runtime prevents restart")) return false;
  }
  if (!check(fixture_starts == 0, "busy machine runtime remains untouched")) return false;
  ResetLease(); fixture_mutex_busy = true;
  { InstalledServiceLease lease(LeaseValidate);
    if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && error == ERROR_BUSY && fixture_controls == 0,
        "second helper cannot adopt a lease")) return false;
  }
  for (const auto* sddl : {L"O:BUG:BUD:P(A;;GA;;;BU)", L"O:BAG:BAD:P(A;;GA;;;BA)(A;;GA;;;BU)",
      L"O:BAG:BAD:(A;;GA;;;SY)(A;;GA;;;BA)"}) {
    ResetLease(); fixture_mutex_sddl = sddl;
    { InstalledServiceLease lease(LeaseValidate);
      if (!check(!lease.Acquire(helper, FixtureHandle(46), &error) && error == ERROR_ACCESS_DENIED && fixture_controls == 0,
          "pre-created permissive, untrusted-owner or unprotected mutex is rejected")) return false;
    }
  }
  return true;
}
