// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_LEGACY_RUNTIME_GUARD_H_
#define RUNNER_LEGACY_RUNTIME_GUARD_H_

#include <windows.h>
#include <aclapi.h>

namespace fuzevpn_ipc {
namespace legacy_runtime_detail {

inline bool PrivilegedSid(PSID sid) {
  return sid != nullptr && IsValidSid(sid) &&
      (IsWellKnownSid(sid, WinLocalSystemSid) ||
       IsWellKnownSid(sid, WinBuiltinAdministratorsSid));
}
inline bool TrustedDescriptor(PSECURITY_DESCRIPTOR descriptor) {
  PSID owner = nullptr;
  PACL acl = nullptr;
  BOOL defaulted = FALSE, present = FALSE;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  if (descriptor == nullptr || !IsValidSecurityDescriptor(descriptor) ||
      !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !PrivilegedSid(owner) ||
      !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) ||
      !present || acl == nullptr || !IsValidAcl(acl) ||
      !GetSecurityDescriptorControl(descriptor, &control, &revision) ||
      (control & SE_DACL_PROTECTED) == 0) return false;
  for (DWORD index = 0; index < acl->AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(acl, index, &raw)) return false;
    const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
        ace->Header.AceSize < sizeof(ACCESS_ALLOWED_ACE) ||
        (ace->Header.AceFlags & (INHERITED_ACE | INHERIT_ONLY_ACE)) != 0 ||
        !PrivilegedSid(const_cast<DWORD*>(&ace->SidStart))) return false;
  }
  return true;
}

struct Win32Api {
  static HANDLE Open(const wchar_t* name) {
    // Inspection only: never create, acquire, or wait on the public object.
    return OpenMutexW(READ_CONTROL, FALSE, name);
  }
  static DWORD Security(HANDLE handle, PSECURITY_DESCRIPTOR* descriptor) {
    return GetSecurityInfo(handle, SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, descriptor);
  }
  static void Close(HANDLE handle) { CloseHandle(handle); }
  static void Free(PSECURITY_DESCRIPTOR descriptor) { LocalFree(descriptor); }
};

template <typename Api = Win32Api>
bool CanStart(const wchar_t* legacy_name, DWORD* error) {
  HANDLE handle = Api::Open(legacy_name);
  if (handle == nullptr) {
    const DWORD cause = GetLastError();
    // An ordinary process can reserve or deny the old name. Such an object is
    // not evidence of a legitimate v1 runtime and must not block the new one.
    if (cause == ERROR_FILE_NOT_FOUND || cause == ERROR_ACCESS_DENIED ||
        cause == ERROR_INVALID_HANDLE) return true;
    if (error != nullptr) *error = cause;
    return false;
  }
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD queried = Api::Security(handle, &descriptor);
  const bool trusted = queried == ERROR_SUCCESS && TrustedDescriptor(descriptor);
  if (descriptor != nullptr) Api::Free(descriptor);
  Api::Close(handle);
  if (trusted) { if (error != nullptr) *error = ERROR_BUSY; return false; }
  if (queried != ERROR_SUCCESS && queried != ERROR_ACCESS_DENIED) {
    if (error != nullptr) *error = queried;
    return false;
  }
  return true;
}

}  // namespace legacy_runtime_detail

inline bool CanStartAlongsideLegacyRuntime() {
  DWORD error = ERROR_SUCCESS;
  const bool allowed = legacy_runtime_detail::CanStart(
      L"Global\\FuzeVPN-ExclusiveRuntime-v1", &error);
  if (!allowed) SetLastError(error);
  return allowed;
}

}  // namespace fuzevpn_ipc
#endif  // RUNNER_LEGACY_RUNTIME_GUARD_H_
