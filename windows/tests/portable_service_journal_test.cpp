// SPDX-License-Identifier: MPL-2.0
// Production process identity reader against synthetic Win32 adapters only.
#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <iostream>
#include "../runner/installation_security.h"
#include "../runner/update_security.h"
namespace {
DWORD open_error = ERROR_SUCCESS, query_error = ERROR_SUCCESS, wait_state = WAIT_TIMEOUT;
DWORD actual_pid = 123, actual_session = 7;
std::uint64_t actual_created = 456;
unsigned opened = 0, closed = 0;
bool invalid_access = false;
HANDLE WINAPI ProbeOpen(DWORD access, BOOL inherit, DWORD pid) {
  ++opened;
  invalid_access |= access != (SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION) || inherit || pid != 123;
  if (open_error) { SetLastError(open_error); return nullptr; }
  return reinterpret_cast<HANDLE>(19);
}
DWORD WINAPI ProbePid(HANDLE) { return actual_pid; }
BOOL WINAPI ProbeTimes(HANDLE, LPFILETIME created, LPFILETIME, LPFILETIME, LPFILETIME) {
  if (query_error) { SetLastError(query_error); return FALSE; }
  created->dwLowDateTime = static_cast<DWORD>(actual_created);
  created->dwHighDateTime = static_cast<DWORD>(actual_created >> 32);
  return TRUE;
}
BOOL WINAPI ProbeSession(DWORD, DWORD* session) { *session = actual_session; return TRUE; }
DWORD WINAPI ProbeWait(HANDLE, DWORD timeout) {
  invalid_access |= timeout != 0;
  if (wait_state == WAIT_FAILED) SetLastError(ERROR_ACCESS_DENIED);
  return wait_state;
}
BOOL WINAPI ProbeClose(HANDLE) { ++closed; return TRUE; }
void Reset() {
  open_error = query_error = ERROR_SUCCESS; wait_state = WAIT_TIMEOUT;
  actual_pid = 123; actual_session = 7; actual_created = 456;
  opened = closed = 0; invalid_access = false;
}
}
#define OpenProcess ProbeOpen
#define GetProcessId ProbePid
#define GetProcessTimes ProbeTimes
#define ProcessIdToSessionId ProbeSession
#define WaitForSingleObject ProbeWait
#define CloseHandle ProbeClose
#include "../runner/portable_service_lease_journal.h"
#undef OpenProcess
#undef GetProcessId
#undef GetProcessTimes
#undef ProcessIdToSessionId
#undef WaitForSingleObject
#undef CloseHandle

int main() {
  using namespace fuzevpn_handoff;
  ProtectedLeaseJournal journal;
  const LeaseProcessIdentity original{123, 7, 456};
  DWORD error = ERROR_SUCCESS;
  unsigned passed = 0;
  const auto check = [&](LeaseProcessState expected, const char* message) {
    if (journal.ProcessState(original, &error) != expected || invalid_access || opened != 1 ||
        closed != (open_error ? 0u : 1u)) {
      std::cerr << "Portable journal identity: " << message << '\n'; return false;
    }
    ++passed; return true;
  };
  Reset(); if (!check(LeaseProcessState::alive, "same live PID/session/creation blocks recovery")) return 1;
  Reset(); wait_state = WAIT_OBJECT_0;
  if (!check(LeaseProcessState::dead, "signaled process proves exit")) return 1;
  Reset(); actual_created = 789;
  if (!check(LeaseProcessState::dead, "recycled PID is a different original process")) return 1;
  Reset(); actual_session = 8;
  if (!check(LeaseProcessState::dead, "recycled PID in another session is not adopted")) return 1;
  Reset(); open_error = ERROR_INVALID_PARAMETER;
  if (!check(LeaseProcessState::dead, "nonexistent PID proves absence")) return 1;
  Reset(); open_error = ERROR_ACCESS_DENIED;
  if (!check(LeaseProcessState::unknown, "access denied never proves absence")) return 1;
  Reset(); query_error = ERROR_ACCESS_DENIED;
  if (!check(LeaseProcessState::unknown, "creation time query failure is unknown")) return 1;
  Reset(); actual_pid = 0;
  if (!check(LeaseProcessState::unknown, "PID query failure is unknown")) return 1;
  Reset(); wait_state = WAIT_FAILED;
  if (!check(LeaseProcessState::unknown, "wait failure is unknown")) return 1;
  Reset();
  if (journal.ProcessState({}, &error) != LeaseProcessState::unknown || opened) return 1;
  ++passed;
  LeaseRecord record;
  record.token = std::string(32, 'a'); record.command = L"service";
  record.helper = record.parent = record.service = original;
  record.service.session = 0;
  if (!lease_journal_detail::ValidRecord(record)) return 1;
  ++passed;
  record.phase = LeasePhase::engine;
  if (lease_journal_detail::ValidRecord(record)) return 1;
  ++passed;
  record.engine = original;
  if (!lease_journal_detail::ValidRecord(record)) return 1;
  ++passed;
  std::cout << passed << " portable journal identity/record cases passed; synthetic process APIs only.\n";
  return 0;
}
