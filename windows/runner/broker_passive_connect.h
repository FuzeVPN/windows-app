// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_BROKER_PASSIVE_CONNECT_H_
#define RUNNER_BROKER_PASSIVE_CONNECT_H_

#include <windows.h>
#include <algorithm>

namespace fuzevpn_ipc {
inline bool RetryableServicePipeError(DWORD error) {
  return error == ERROR_PIPE_BUSY || error == ERROR_FILE_NOT_FOUND ||
      error == ERROR_PATH_NOT_FOUND || error == ERROR_SEM_TIMEOUT ||
      error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_NO_DATA;
}

// Every opener must authenticate the pipe. Query returns zero unless the same
// installed service is RUNNING; unknown status preserves its own Windows error.
// The clock/pause boundary keeps this policy testable without touching a service.
template <typename Open, typename Query, typename Cancelled, typename Clock, typename Pause>
HANDLE RetryRunningServicePipe(DWORD expected_pid, DWORD initial_error,
    Open&& open, Query&& query, Cancelled&& cancelled, Clock&& clock, Pause&& pause) {
  DWORD pipe_error = initial_error;
  const ULONGLONG deadline = clock() + 2000;
  if (expected_pid == 0 || !RetryableServicePipeError(pipe_error)) {
    SetLastError(pipe_error);
    return INVALID_HANDLE_VALUE;
  }
  while (true) {
    if (cancelled()) { SetLastError(ERROR_CANCELLED); return INVALID_HANDLE_VALUE; }
    if (clock() >= deadline) { SetLastError(pipe_error); return INVALID_HANDLE_VALUE; }
    const auto pid = query();
    if (!pid.has_value()) return INVALID_HANDLE_VALUE;
    if (*pid != expected_pid) {
      SetLastError(ERROR_SERVICE_NOT_ACTIVE);
      return INVALID_HANDLE_VALUE;
    }
    if (cancelled()) { SetLastError(ERROR_CANCELLED); return INVALID_HANDLE_VALUE; }
    if (clock() >= deadline) { SetLastError(pipe_error); return INVALID_HANDLE_VALUE; }
    HANDLE pipe = open();
    if (pipe != INVALID_HANDLE_VALUE) return pipe;
    pipe_error = GetLastError();
    if (!RetryableServicePipeError(pipe_error)) {
      SetLastError(pipe_error);
      return INVALID_HANDLE_VALUE;
    }
    const ULONGLONG now = clock();
    if (now >= deadline) { SetLastError(pipe_error); return INVALID_HANDLE_VALUE; }
    pause(static_cast<DWORD>(std::min<ULONGLONG>(75, deadline - now)));
  }
}
}  // namespace fuzevpn_ipc
#endif
