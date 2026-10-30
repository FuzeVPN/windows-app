// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RUNTIME_NAMESPACE_H_
#define RUNNER_RUNTIME_NAMESPACE_H_

#include <windows.h>
#include <sddl.h>

#include <mutex>

namespace fuzevpn_ipc {
namespace detail {

// A boundary is part of the kernel namespace's identity. An ordinary process
// cannot reserve the administrators' boundary, even before the service starts.
// Do not include a user, logon or session SID: SYSTEM and elevated brokers from
// different accounts/sessions must all see the same machine runtime.
struct RuntimeNamespaceApi {
  static HANDLE Boundary(const wchar_t* name) {
    return CreateBoundaryDescriptorW(name, 0);
  }
  static bool AddAdministrators(HANDLE* boundary) {
    BYTE sid[SECURITY_MAX_SID_SIZE]{};
    DWORD size = sizeof(sid);
    return CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &size) &&
        AddSIDToBoundaryDescriptor(boundary, sid);
  }
  static HANDLE Create(SECURITY_ATTRIBUTES* security, HANDLE boundary,
                       const wchar_t* alias) {
    return CreatePrivateNamespaceW(security, boundary, alias);
  }
  static HANDLE Open(HANDLE boundary, const wchar_t* alias) {
    return OpenPrivateNamespaceW(boundary, alias);
  }
  static void DeleteBoundary(HANDLE boundary) {
    DeleteBoundaryDescriptor(boundary);
  }
  static void Close(HANDLE handle) {
    // Never DESTROY a shared namespace: peers may still own its runtime mutex.
    // Windows keeps it reachable while another process has a namespace handle.
    ClosePrivateNamespace(handle, 0);
  }
};

template <typename Api = RuntimeNamespaceApi>
class RuntimeNamespaceBinding final {
 public:
  ~RuntimeNamespaceBinding() {
    if (handle_ != nullptr) Api::Close(handle_);
  }
  RuntimeNamespaceBinding() = default;
  RuntimeNamespaceBinding(const RuntimeNamespaceBinding&) = delete;
  RuntimeNamespaceBinding& operator=(const RuntimeNamespaceBinding&) = delete;

  bool Bind(const wchar_t* boundary_name, const wchar_t* alias) {
    if (handle_ != nullptr) return true;
    HANDLE boundary = Api::Boundary(boundary_name);
    if (boundary == nullptr) return false;
    if (!Api::AddAdministrators(&boundary)) {
      const DWORD error = GetLastError();
      Api::DeleteBoundary(boundary);
      SetLastError(error);
      return false;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
        &descriptor, nullptr)) {
      const DWORD error = GetLastError();
      Api::DeleteBoundary(boundary);
      SetLastError(error);
      return false;
    }
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    DWORD error = ERROR_SUCCESS;
    // A creator can exit between CREATE's collision and OPEN. Retry only this
    // disappearance race, with a finite bound and no public-name fallback.
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
      handle_ = Api::Create(&security, boundary, alias);
      if (handle_ != nullptr) break;
      error = GetLastError();
      if (error != ERROR_ALREADY_EXISTS) break;
      handle_ = Api::Open(boundary, alias);
      if (handle_ != nullptr) break;
      error = GetLastError();
      if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) break;
    }
    LocalFree(descriptor);
    Api::DeleteBoundary(boundary);
    if (handle_ == nullptr) SetLastError(error);
    return handle_ != nullptr;
  }

 private:
  HANDLE handle_ = nullptr;
};

}  // namespace detail

inline constexpr wchar_t kMachineRuntimeNamespace[] = L"FuzeVPNPrivilegedRuntimeV2";
inline constexpr wchar_t kMachineRuntimeBoundary[] = L"FuzeVPN-MachineRuntime-v2";
inline constexpr wchar_t kMachineRuntimeMutex[] =
    L"FuzeVPNPrivilegedRuntimeV2\\ExclusiveRuntime";

inline bool BindMachineRuntimeNamespace() {
  // An alias is process-local. Bind it once and retain it past every local lock
  // object's lifetime, including a failed acquisition by a competing thread.
  static std::mutex binding_mutex;
  static detail::RuntimeNamespaceBinding<> binding;
  std::lock_guard<std::mutex> guard(binding_mutex);
  return binding.Bind(kMachineRuntimeBoundary, kMachineRuntimeNamespace);
}

}  // namespace fuzevpn_ipc
#endif  // RUNNER_RUNTIME_NAMESPACE_H_
