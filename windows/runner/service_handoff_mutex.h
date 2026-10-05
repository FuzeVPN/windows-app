// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SERVICE_HANDOFF_MUTEX_H_
#define RUNNER_SERVICE_HANDOFF_MUTEX_H_
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include "service_idle_handoff.h"

namespace fuzevpn_handoff {
class Reservation final {
 public:
  ~Reservation() { if (owned_) ReleaseMutex(handle_); if (handle_) CloseHandle(handle_); }
  Reservation() = default;
  Reservation(const Reservation&) = delete;
  Reservation& operator=(const Reservation&) = delete;
  bool Acquire(const wchar_t* name = kHelperMutex) {
    if (handle_) { SetLastError(ERROR_INVALID_HANDLE); return false; }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    handle_ = CreateMutexW(&attributes, FALSE, name);
    const DWORD created = GetLastError();
    LocalFree(descriptor);
    if (!handle_) { SetLastError(created); return false; }
    PSID owner = nullptr; PACL acl = nullptr; descriptor = nullptr;
    const DWORD status = GetSecurityInfo(handle_, SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &acl, nullptr, &descriptor);
    bool secure = status == ERROR_SUCCESS && owner && acl &&
        (IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    secure = secure && GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0;
    for (DWORD index = 0; secure && index < acl->AceCount; ++index) {
      void* raw = nullptr;
      if (!GetAce(acl, index, &raw)) { secure = false; break; }
      const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
          (ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) != 0 ||
          !(IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinLocalSystemSid) ||
            IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinBuiltinAdministratorsSid))) secure = false;
    }
    if (descriptor) LocalFree(descriptor);
    if (!secure) { SetLastError(status == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : status); return false; }
    const DWORD waited = WaitForSingleObject(handle_, 0);
    owned_ = waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
    if (!owned_ && waited != WAIT_FAILED) SetLastError(ERROR_BUSY);
    return owned_;
  }
 private:
  HANDLE handle_ = nullptr;
  bool owned_ = false;
};
}  // namespace fuzevpn_handoff
#endif
