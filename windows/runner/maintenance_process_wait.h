// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_MAINTENANCE_PROCESS_WAIT_H_
#define RUNNER_MAINTENANCE_PROCESS_WAIT_H_
#include <windows.h>
#include <tlhelp32.h>
#include <optional>

namespace fuzevpn_maintenance {
// A restricted MSI SYSTEM token can lack SeDebugPrivilege and cannot obtain a
// SYNCHRONIZE handle to a service process. Process-only Toolhelp enumeration
// proves its original SCM PID is gone without any process/ACL/privilege write.
// A recycled PID remains blocking, and incomplete/empty snapshots never prove
// absence: our own live process must also appear in the complete enumeration.
inline std::optional<bool> ServiceProcessExitedBySnapshot(DWORD initial_pid, DWORD* error) {
  const auto reject = [&](DWORD status) -> std::optional<bool> {
    if (error) *error = status;
    return std::nullopt;
  };
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return reject(GetLastError());
  struct Snapshot { HANDLE value; ~Snapshot() { CloseHandle(value); } } scoped{snapshot};
  PROCESSENTRY32W process{}; process.dwSize = sizeof(process);
  if (!Process32FirstW(snapshot, &process)) return reject(GetLastError());
  bool initial_present = false, self_present = false;
  const DWORD self_pid = GetCurrentProcessId();
  do {
    initial_present |= process.th32ProcessID == initial_pid;
    self_present |= process.th32ProcessID == self_pid;
  } while (Process32NextW(snapshot, &process));
  const DWORD final_error = GetLastError();
  if (final_error != ERROR_NO_MORE_FILES) return reject(final_error);
  if (!self_present || !initial_pid) return reject(ERROR_INVALID_DATA);
  if (error) *error = ERROR_SUCCESS;
  return !initial_present;
}
}  // namespace fuzevpn_maintenance
#endif
