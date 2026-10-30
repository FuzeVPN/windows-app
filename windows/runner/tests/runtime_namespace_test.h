// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_TESTS_RUNTIME_NAMESPACE_TEST_H_
#define RUNNER_TESTS_RUNTIME_NAMESPACE_TEST_H_

#include "../broker_security.h"
#include <objbase.h>

#include <iostream>
#include <string>
#include <thread>

namespace fuzevpn_runtime_namespace_test {

inline bool Check(bool condition, const char* description) {
  if (!condition) std::cerr << "Runtime namespace: " << description << '\n';
  return condition;
}

struct FakeApi {
  static inline unsigned creates = 0, opens = 0, closes = 0, deletes = 0;
  static inline unsigned disappearances = 0;
  static inline DWORD create_error = ERROR_SUCCESS, open_error = ERROR_SUCCESS;
  static inline bool boundary_failed = false, sid_failed = false;
  static inline bool restricted_security = false;
  static void Reset() {
    creates = opens = closes = deletes = disappearances = 0;
    create_error = open_error = ERROR_SUCCESS;
    boundary_failed = sid_failed = restricted_security = false;
  }
  static HANDLE Handle(ULONG_PTR value) { return reinterpret_cast<HANDLE>(value); }
  static HANDLE Boundary(const wchar_t*) {
    if (boundary_failed) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return nullptr; }
    return Handle(501);
  }
  static bool AddAdministrators(HANDLE*) {
    if (sid_failed) SetLastError(ERROR_INVALID_SID);
    return !sid_failed;
  }
  static HANDLE Create(SECURITY_ATTRIBUTES* security, HANDLE, const wchar_t*) {
    ++creates;
    PSID owner = nullptr;
    BOOL defaulted = FALSE, present = FALSE;
    PACL acl = nullptr;
    auto* descriptor = security->lpSecurityDescriptor;
    restricted_security = security->bInheritHandle == FALSE &&
        GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) &&
        IsWellKnownSid(owner, WinBuiltinAdministratorsSid) &&
        GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) &&
        present && acl != nullptr && acl->AceCount == 2;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    restricted_security = restricted_security &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0;
    bool system = false, administrators = false;
    for (DWORD index = 0; restricted_security && index < acl->AceCount; ++index) {
      void* raw = nullptr;
      restricted_security = GetAce(acl, index, &raw) != FALSE;
      if (!restricted_security) break;
      const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      restricted_security = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
          ace->Mask == GENERIC_ALL;
      auto* sid = const_cast<DWORD*>(&ace->SidStart);
      system |= IsWellKnownSid(sid, WinLocalSystemSid) != FALSE;
      administrators |= IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != FALSE;
    }
    restricted_security = restricted_security && system && administrators;
    if (create_error != ERROR_SUCCESS) { SetLastError(create_error); return nullptr; }
    return Handle(502);
  }
  static HANDLE Open(HANDLE, const wchar_t*) {
    ++opens;
    if (opens <= disappearances) { SetLastError(ERROR_PATH_NOT_FOUND); return nullptr; }
    if (open_error != ERROR_SUCCESS) { SetLastError(open_error); return nullptr; }
    return Handle(502);
  }
  static void DeleteBoundary(HANDLE) { ++deletes; SetLastError(ERROR_INVALID_HANDLE); }
  static void Close(HANDLE) { ++closes; }
};

// Exercise the same binding algorithm and actual Windows namespace lifetime
// without requesting elevation. Only these test adapters replace the required
// administrators SID and ACL with the current user's ordinary test namespace.
struct UserNamespaceApi : fuzevpn_ipc::detail::RuntimeNamespaceApi {
  static bool AddAdministrators(HANDLE* boundary) {
    BYTE sid[SECURITY_MAX_SID_SIZE]{};
    DWORD size = sizeof(sid);
    return CreateWellKnownSid(WinWorldSid, nullptr, sid, &size) &&
        AddSIDToBoundaryDescriptor(boundary, sid);
  }
  static HANDLE Create(SECURITY_ATTRIBUTES*, HANDLE boundary, const wchar_t* alias) {
    return CreatePrivateNamespaceW(nullptr, boundary, alias);
  }
};

inline bool TestRuntimeNamespace() {
  using fuzevpn_ipc::detail::RuntimeNamespaceBinding;
  bool passed = true;
  FakeApi::Reset();
  {
    RuntimeNamespaceBinding<FakeApi> binding;
    passed &= Check(binding.Bind(L"test-boundary", L"test-alias") &&
        FakeApi::restricted_security && FakeApi::creates == 1 && FakeApi::opens == 0,
        "new namespace restricts both creation boundary and SYSTEM/admin ACL");
    passed &= Check(binding.Bind(L"test-boundary", L"test-alias") && FakeApi::creates == 1,
        "a process binding is idempotent instead of remapping its alias");
  }
  passed &= Check(FakeApi::closes == 1 && FakeApi::deletes == 1,
      "namespace handle and boundary are released exactly once");

  FakeApi::Reset();
  FakeApi::create_error = ERROR_ALREADY_EXISTS;
  {
    RuntimeNamespaceBinding<FakeApi> binding;
    passed &= Check(binding.Bind(L"test-boundary", L"test-alias") &&
        FakeApi::creates == 1 && FakeApi::opens == 1,
        "an existing privileged namespace is opened, not replaced");
  }
  FakeApi::Reset();
  FakeApi::create_error = ERROR_ALREADY_EXISTS;
  FakeApi::disappearances = 2;
  {
    RuntimeNamespaceBinding<FakeApi> binding;
    passed &= Check(binding.Bind(L"test-boundary", L"test-alias") &&
        FakeApi::creates == 3 && FakeApi::opens == 3,
        "creator-exit race retries CREATE/OPEN within its finite budget");
  }
  FakeApi::Reset();
  FakeApi::create_error = ERROR_ALREADY_EXISTS;
  FakeApi::disappearances = 4;
  {
    RuntimeNamespaceBinding<FakeApi> binding;
    passed &= Check(!binding.Bind(L"test-boundary", L"test-alias") &&
        GetLastError() == ERROR_PATH_NOT_FOUND && FakeApi::creates == 3 && FakeApi::opens == 3,
        "persistent churn fails safely without spinning or a public fallback");
  }
  for (bool fail_on_open : {false, true}) {
    FakeApi::Reset();
    FakeApi::create_error = fail_on_open ? ERROR_ALREADY_EXISTS : ERROR_ACCESS_DENIED;
    FakeApi::open_error = ERROR_ACCESS_DENIED;
    RuntimeNamespaceBinding<FakeApi> binding;
    passed &= Check(!binding.Bind(L"test-boundary", L"test-alias") &&
        GetLastError() == ERROR_ACCESS_DENIED && FakeApi::creates == 1 &&
        FakeApi::opens == (fail_on_open ? 1u : 0u),
        "access denial preserves its error and cannot select an unprotected name");
  }
  for (bool fail_sid : {false, true}) {
    FakeApi::Reset();
    FakeApi::sid_failed = fail_sid;
    FakeApi::boundary_failed = !fail_sid;
    RuntimeNamespaceBinding<FakeApi> binding;
    passed &= Check(!binding.Bind(L"test-boundary", L"test-alias") &&
        GetLastError() == static_cast<DWORD>(fail_sid ? ERROR_INVALID_SID : ERROR_NOT_ENOUGH_MEMORY) &&
        FakeApi::creates == 0 && FakeApi::deletes == (fail_sid ? 1u : 0u),
        "failed boundary construction never creates a namespace and retains the cause");
  }

  GUID identifier{};
  wchar_t identifier_text[40]{};
  const bool unique_name = SUCCEEDED(CoCreateGuid(&identifier)) &&
      StringFromGUID2(identifier, identifier_text, 40) != 0;
  passed &= Check(unique_name, "random isolated test namespace name is available");
  if (!unique_name) return false;
  const std::wstring unique = L"FuzeRuntimeNamespaceTest-" + std::wstring(identifier_text);
  BYTE admin_sid[SECURITY_MAX_SID_SIZE]{};
  DWORD sid_size = sizeof(admin_sid);
  BOOL administrator = FALSE;
  const bool membership_known =
      CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin_sid, &sid_size) &&
      CheckTokenMembership(nullptr, admin_sid, &administrator);
  passed &= Check(membership_known, "current token membership is available");
  if (membership_known && !administrator) {
    RuntimeNamespaceBinding<> privileged;
    passed &= Check(!privileged.Bind((unique + L"BoundaryDenied").c_str(),
                                    (unique + L"Denied").c_str()) &&
        GetLastError() == ERROR_ACCESS_DENIED,
        "actual Windows denies privileged-boundary precreation by an ordinary token");
  }

  // A public object with the same alias cannot squat the private namespace.
  HANDLE public_collision = CreateMutexW(nullptr, TRUE, (L"Global\\" + unique).c_str());
  passed &= Check(public_collision != nullptr, "create an isolated public-name collision");
  {
    RuntimeNamespaceBinding<UserNamespaceApi> binding;
    const bool bound = binding.Bind((unique + L"Boundary").c_str(), unique.c_str());
    passed &= Check(bound, "private binding is independent of a public-name collision");
    if (bound) {
      const std::wstring name = unique + L"\\ExclusiveRuntime";
      {
        fuzevpn_ipc::ExclusiveRuntimeLock first;
        passed &= Check(first.Acquire(name.c_str(), nullptr), "reserve actual isolated namespace mutex");
        bool contender_acquired = true;
        DWORD contender_error = ERROR_SUCCESS;
        std::thread contender([&]() {
          fuzevpn_ipc::ExclusiveRuntimeLock second;
          contender_acquired = second.Acquire(name.c_str(), nullptr);
          contender_error = GetLastError();
        });
        contender.join();
        passed &= Check(!contender_acquired && contender_error == ERROR_BUSY,
            "another thread cannot enter cleanup while a runtime owns the mutex");
      }
      {
        fuzevpn_ipc::ExclusiveRuntimeLock next;
        passed &= Check(next.Acquire(name.c_str(), nullptr), "normal exit permits a later runtime");
      }
      HANDLE abandoned = nullptr;
      bool worker_owned = false;
      std::thread owner([&]() {
        abandoned = CreateMutexW(nullptr, FALSE, name.c_str());
        worker_owned = abandoned != nullptr &&
            WaitForSingleObject(abandoned, 0) == WAIT_OBJECT_0;
        // Leave this test mutex owned when its thread exits. Keep its handle
        // open so Windows can deliver WAIT_ABANDONED to the recovery runtime.
      });
      owner.join();
      passed &= Check(worker_owned, "test owner holds mutex before thread exit");
      {
        fuzevpn_ipc::ExclusiveRuntimeLock recovery;
        passed &= Check(recovery.Acquire(name.c_str(), nullptr), "abandoned ownership permits safe recovery");
      }
      if (abandoned != nullptr) CloseHandle(abandoned);
    }
  }
  if (public_collision != nullptr) { ReleaseMutex(public_collision); CloseHandle(public_collision); }
  return passed;
}

}  // namespace fuzevpn_runtime_namespace_test
#endif  // RUNNER_TESTS_RUNTIME_NAMESPACE_TEST_H_
