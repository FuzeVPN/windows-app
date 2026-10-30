// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_BROKER_SECURITY_H_
#define RUNNER_BROKER_SECURITY_H_

#include <windows.h>
#include <sddl.h>

#include "runtime_namespace.h"
#include "legacy_runtime_guard.h"

namespace fuzevpn_ipc {
// Grant the client only byte I/O, server-PID inspection and synchronization.
// In particular, FILE_CREATE_PIPE_INSTANCE must never be granted to clients.
constexpr DWORD kPipeClientAccess =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
constexpr wchar_t kServicePipeSddl[] =
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100083;;;IU)S:(ML;;NW;;;ME)";
constexpr wchar_t kServiceEventSddl[] =
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;IU)S:(ML;;NW;;;ME)";

// WireGuard's tunnel service and filtering policy are machine resources.
// Only their exclusive runtime may perform startup recovery or exit cleanup.
class ExclusiveRuntimeLock final {
 public:
  ~ExclusiveRuntimeLock() {
    if (owned_) ReleaseMutex(handle_);
    if (handle_ != nullptr) CloseHandle(handle_);
  }
  bool Acquire(const wchar_t* name, SECURITY_ATTRIBUTES* security) {
    if (handle_ != nullptr) { SetLastError(ERROR_INVALID_HANDLE); return false; }
    handle_ = CreateMutexW(security, FALSE, name);
    if (handle_ == nullptr) return false;
    const DWORD state = WaitForSingleObject(handle_, 0);
    owned_ = state == WAIT_OBJECT_0 || state == WAIT_ABANDONED;
    if (!owned_ && state != WAIT_FAILED) SetLastError(ERROR_BUSY);
    return owned_;
  }
  bool AcquireMachineRuntime() {
    if (!CanStartAlongsideLegacyRuntime()) return false;
    if (!BindMachineRuntimeNamespace()) return false;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
        &descriptor, nullptr)) return false;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const bool acquired = Acquire(kMachineRuntimeMutex, &security);
    const DWORD error = acquired ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    if (!acquired) SetLastError(error);
    return acquired;
  }
  ExclusiveRuntimeLock() = default;
  ExclusiveRuntimeLock(const ExclusiveRuntimeLock&) = delete;
  ExclusiveRuntimeLock& operator=(const ExclusiveRuntimeLock&) = delete;
 private:
  HANDLE handle_ = nullptr;
  bool owned_ = false;
};
}  // namespace fuzevpn_ipc
#endif  // RUNNER_BROKER_SECURITY_H_
