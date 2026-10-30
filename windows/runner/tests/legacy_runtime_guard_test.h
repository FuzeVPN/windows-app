// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_TESTS_LEGACY_RUNTIME_GUARD_TEST_H_
#define RUNNER_TESTS_LEGACY_RUNTIME_GUARD_TEST_H_

#include "../legacy_runtime_guard.h"
#include <sddl.h>
#include <iostream>
#include <string>

namespace fuzevpn_legacy_runtime_test {
struct Api {
  static inline DWORD open_error = ERROR_SUCCESS, query_error = ERROR_SUCCESS;
  static inline unsigned opened = 0, closed = 0;
  static inline std::wstring descriptor;
  static void Reset() {
    open_error = query_error = ERROR_SUCCESS; opened = closed = 0;
    descriptor = L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)";
  }
  static HANDLE Open(const wchar_t*) {
    ++opened;
    if (open_error != ERROR_SUCCESS) { SetLastError(open_error); return nullptr; }
    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(801));
  }
  static DWORD Security(HANDLE, PSECURITY_DESCRIPTOR* value) {
    if (query_error != ERROR_SUCCESS) return query_error;
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(),
        SDDL_REVISION_1, value, nullptr) ? ERROR_SUCCESS : GetLastError();
  }
  static void Close(HANDLE) { ++closed; SetLastError(ERROR_INVALID_HANDLE); }
  static void Free(PSECURITY_DESCRIPTOR value) { LocalFree(value); }
  // Deliberately no Create/Wait/Release adapters: compatibility is inspection.
};
inline bool Check(bool condition, const char* description) {
  if (!condition) std::cerr << "Legacy runtime guard: " << description << '\n';
  return condition;
}
inline bool TestLegacyRuntimeGuard() {
  bool passed = true;
  DWORD error = ERROR_SUCCESS;
  Api::Reset();
  passed &= Check(!fuzevpn_ipc::legacy_runtime_detail::CanStart<Api>(L"fixture", &error) &&
      error == ERROR_BUSY && Api::opened == 1 && Api::closed == 1,
      "a privileged protected legacy runtime object refuses new startup without waiting");
  for (DWORD missing : {DWORD{ERROR_FILE_NOT_FOUND}, DWORD{ERROR_ACCESS_DENIED}, DWORD{ERROR_INVALID_HANDLE}}) {
    Api::Reset(); Api::open_error = missing;
    passed &= Check(fuzevpn_ipc::legacy_runtime_detail::CanStart<Api>(L"fixture", &error) && Api::closed == 0,
        "absent, denied and wrong-type public squats cannot deny the new private runtime");
  }
  for (const wchar_t* hostile : {
      L"O:S-1-5-21-1-2-3-1001G:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
      L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
      L"O:SYG:SYD:NO_ACCESS_CONTROL",
      L"O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)"}) {
    Api::Reset(); Api::descriptor = hostile;
    passed &= Check(fuzevpn_ipc::legacy_runtime_detail::CanStart<Api>(L"fixture", &error) && Api::closed == 1,
        "ordinary ownership, interactive grants, null and inheritable ACLs are not legacy-runtime evidence");
  }
  Api::Reset(); Api::query_error = ERROR_ACCESS_DENIED;
  passed &= Check(fuzevpn_ipc::legacy_runtime_detail::CanStart<Api>(L"fixture", &error),
      "a hostile object denying inspection does not recover the original public-name DoS");
  Api::Reset(); Api::open_error = ERROR_NOT_ENOUGH_MEMORY;
  passed &= Check(!fuzevpn_ipc::legacy_runtime_detail::CanStart<Api>(L"fixture", &error) &&
      error == ERROR_NOT_ENOUGH_MEMORY, "unexpected inspection failure stays explicit");
  return passed;
}
}  // namespace fuzevpn_legacy_runtime_test
#endif  // RUNNER_TESTS_LEGACY_RUNTIME_GUARD_TEST_H_
