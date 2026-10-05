// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_BROKER_IO_H_
#define RUNNER_BROKER_IO_H_

#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <limits>

namespace fuzevpn_ipc {

// CancelIoEx only requests cancellation. OVERLAPPED, its event and the data
// buffer remain owned by this call until Windows confirms completion.
inline bool AwaitOperation(HANDLE pipe, HANDLE cancel, OVERLAPPED* operation,
                           DWORD* transferred, ULONGLONG deadline) {
  HANDLE waits[2]{operation->hEvent, cancel};
  const ULONGLONG now = GetTickCount64();
  const DWORD timeout = deadline == 0 ? INFINITE :
      static_cast<DWORD>((std::min)(deadline > now ? deadline - now : 0,
                                   static_cast<ULONGLONG>(INFINITE - 1)));
  const DWORD waited = WaitForMultipleObjects(cancel == nullptr ? 1 : 2,
                                              waits, FALSE, timeout);
  if (waited == WAIT_OBJECT_0) {
    return GetOverlappedResult(pipe, operation, transferred, FALSE) != FALSE;
  }
  const DWORD reason = waited == WAIT_TIMEOUT ? ERROR_TIMEOUT :
                       waited == WAIT_OBJECT_0 + 1 ? ERROR_OPERATION_ABORTED :
                       GetLastError();
  CancelIoEx(pipe, operation);
  // This blocking drain concerns only a cancelled Windows named-pipe I/O,
  // never an unbounded wait for the peer to send application data.
  GetOverlappedResult(pipe, operation, transferred, TRUE);
  SetLastError(reason);
  return false;
}

inline bool Transfer(HANDLE pipe, HANDLE cancel, void* buffer, DWORD size,
                     bool writing, ULONGLONG deadline) {
  auto* cursor = static_cast<BYTE*>(buffer);
  DWORD remaining = size;
  while (remaining != 0) {
    if ((cancel != nullptr && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) ||
        (deadline != 0 && GetTickCount64() >= deadline)) {
      SetLastError(cancel != nullptr &&
          WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0 ?
          ERROR_OPERATION_ABORTED : ERROR_TIMEOUT);
      return false;
    }
    OVERLAPPED operation{};
    operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (operation.hEvent == nullptr) return false;
    DWORD transferred = 0;
    bool ok = (writing ? WriteFile(pipe, cursor, remaining, &transferred,
                                   &operation) :
                         ReadFile(pipe, cursor, remaining, &transferred,
                                  &operation)) != FALSE;
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
      ok = AwaitOperation(pipe, cancel, &operation, &transferred, deadline);
    }
    const DWORD error = GetLastError();
    CloseHandle(operation.hEvent);
    if (!ok || transferred == 0) {
      SetLastError(ok ? ERROR_BROKEN_PIPE : error);
      return false;
    }
    cursor += transferred;
    remaining -= transferred;
  }
  return true;
}

}  // namespace fuzevpn_ipc
#endif  // RUNNER_BROKER_IO_H_
