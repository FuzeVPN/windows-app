// SPDX-License-Identifier: MPL-2.0
// Includes the real identity implementation. All SCM, store and DLL operations
// below are strict in-memory doubles; no service, key file, driver or WFP object
// on the test machine is touched.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define FUZEVPN_SERVICE_PROCESS
#include <winsock2.h>
#include <windows.h>
#include <winsvc.h>
#include <array>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include "network_protection.h"
#include "protected_store.h"
#include "privileged_runtime.h"

namespace fixture {
std::map<std::string, std::string> store;
std::set<std::string> failed_reads;
std::deque<std::optional<bool>> runtime;
std::deque<DWORD> tunnel_states;
bool service_present = false, manager_denied = false, query_denied = false;
bool delete_failed = false, load_failed = false;
int write_fail_at = 0, reads = 0, deletes = 0, writes = 0, loads = 0;
int privileged_scm = 0, wfp = 0, failures = 0;
void Reset() {
  store.clear(); failed_reads.clear(); runtime = {false};
  tunnel_states = {SERVICE_STOPPED};
  service_present = manager_denied = query_denied = delete_failed = load_failed = false;
  write_fail_at = reads = deletes = writes = loads = privileged_scm = wfp = 0;
}
void Check(bool condition, const char* message) {
  if (!condition) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}
void CheckLocalOnly() {
  Check(privileged_scm == 0, "identity preparation requested privileged SCM access");
  Check(wfp == 0, "identity preparation attempted a WFP mutation");
  Check(!CanManageNetworkProtection(), "fixture accidentally runs as a privileged runtime");
}
}

SC_HANDLE WINAPI IdentityOpenSCManagerW(LPCWSTR, LPCWSTR, DWORD access) {
  if (access != SC_MANAGER_CONNECT) ++fixture::privileged_scm;
  if (fixture::manager_denied) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
  return reinterpret_cast<SC_HANDLE>(1);
}
SC_HANDLE WINAPI IdentityOpenServiceW(SC_HANDLE, LPCWSTR, DWORD access) {
  if (access != SERVICE_QUERY_STATUS) ++fixture::privileged_scm;
  if (!fixture::service_present) { SetLastError(ERROR_SERVICE_DOES_NOT_EXIST); return nullptr; }
  if (access != SERVICE_QUERY_STATUS || fixture::query_denied) {
    SetLastError(ERROR_ACCESS_DENIED); return nullptr;
  }
  return reinterpret_cast<SC_HANDLE>(2);
}
BOOL WINAPI IdentityQueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS status) {
  status->dwCurrentState = fixture::tunnel_states.front();
  if (fixture::tunnel_states.size() > 1) fixture::tunnel_states.pop_front();
  return TRUE;
}
BOOL WINAPI IdentityCloseServiceHandle(SC_HANDLE) { return TRUE; }
BOOL WINAPI IdentityControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS) {
  ++fixture::privileged_scm; SetLastError(ERROR_ACCESS_DENIED); return FALSE;
}
HMODULE WINAPI IdentityLoadLibraryExW(LPCWSTR, HANDLE, DWORD) {
  ++fixture::loads;
  return fixture::load_failed ? nullptr : reinterpret_cast<HMODULE>(3);
}
BOOL __cdecl IdentityTunnelService(LPCWSTR) { return FALSE; }
void __cdecl IdentityGenerateKeypair(BYTE* public_key, BYTE* private_key) {
  for (int index = 0; index < 32; ++index) {
    public_key[index] = static_cast<BYTE>(index + 17);
    private_key[index] = static_cast<BYTE>(index + 129);
  }
}
FARPROC WINAPI IdentityGetProcAddress(HMODULE, LPCSTR name) {
  if (std::strcmp(name, "WireGuardGenerateKeypair") == 0)
    return reinterpret_cast<FARPROC>(IdentityGenerateKeypair);
  if (std::strcmp(name, "WireGuardTunnelService") == 0)
    return reinterpret_cast<FARPROC>(IdentityTunnelService);
  return nullptr;
}
BOOL WINAPI IdentityFreeLibrary(HMODULE) { return TRUE; }
BOOL WINAPI IdentitySetDllDirectoryW(LPCWSTR) { return TRUE; }

#define OpenSCManagerW IdentityOpenSCManagerW
#define OpenServiceW IdentityOpenServiceW
#define QueryServiceStatus IdentityQueryServiceStatus
#define CloseServiceHandle IdentityCloseServiceHandle
#define ControlService IdentityControlService
#define LoadLibraryExW IdentityLoadLibraryExW
#define GetProcAddress IdentityGetProcAddress
#define FreeLibrary IdentityFreeLibrary
#define SetDllDirectoryW IdentitySetDllDirectoryW
#include "../runner/wireguard_tunnel.cpp"
#undef OpenSCManagerW
#undef OpenServiceW
#undef QueryServiceStatus
#undef CloseServiceHandle
#undef ControlService
#undef LoadLibraryExW
#undef GetProcAddress
#undef FreeLibrary
#undef SetDllDirectoryW

std::optional<bool> PrivilegedRuntimePresence(bool* detection_failed) {
  if (detection_failed) *detection_failed = false;
  const auto current = fixture::runtime.front();
  if (fixture::runtime.size() > 1) fixture::runtime.pop_front();
  if (!current) SetLastError(ERROR_ACCESS_DENIED);
  return current;
}
ProtectedValueReadStatus ReadProtectedValueStatus(const std::string& key,
                                                 std::string* value) {
  ++fixture::reads; value->clear();
  if (fixture::failed_reads.count(key)) return ProtectedValueReadStatus::decryption_failed;
  const auto found = fixture::store.find(key);
  if (found == fixture::store.end()) return ProtectedValueReadStatus::not_found;
  *value = found->second; return ProtectedValueReadStatus::found;
}
bool WriteProtectedValue(const std::string& key, const std::string& value) {
  ++fixture::writes;
  if (fixture::write_fail_at == fixture::writes) return false;
  fixture::store[key] = value; return true;
}
bool DeleteProtectedValue(const std::string& key) {
  ++fixture::deletes;
  if (fixture::delete_failed) return false;
  fixture::store.erase(key); return true;
}
bool DisableNetworkProtection(NetworkProtectionOwner) {
  ++fixture::wfp;
  fixture::Check(!CanManageNetworkProtection(), "regression proof must remain an ordinary UI runtime");
  return false;
}
bool PrepareNetworkProtection(NetworkProtectionOwner, const NetworkProtectionOptions&) {
  ++fixture::wfp; return false;
}
bool IsNetworkProtectionActive(NetworkProtectionOwner) { ++fixture::wfp; return false; }
bool IsTunnelNetworkProtectionActive(NetworkProtectionOwner) { ++fixture::wfp; return false; }
NetworkProtectionStatus GetNetworkProtectionStatus(NetworkProtectionOwner) {
  ++fixture::wfp; return {};
}
bool ReadProtectedValue(const std::string& key, std::string* value) {
  return ReadProtectedValueStatus(key, value) == ProtectedValueReadStatus::found;
}
std::string ProtectedStoreUserId() { return "synthetic-user"; }
bool ResolveApiBootstrapAddresses(std::vector<std::string>*) {
  fixture::Check(false, "identity preparation invoked API DNS"); return false;
}
bool ResolveWireGuardEndpointAddresses(const std::string&, std::uint64_t,
                                      std::vector<std::string>*) {
  fixture::Check(false, "identity preparation invoked tunnel DNS"); return false;
}
void CompleteRuntimeStatusFailure(flutter::MethodResult<flutter::EncodableValue>*, bool) {
  fixture::Check(false, "unexpected privileged channel dispatch");
}
namespace fuzevpn_diagnostics {
NetworkObservation ReadNetworkObservation(const NetworkExpectation&) {
  fixture::Check(false, "identity preparation invoked network diagnostics"); return {};
}
}

void SeedIdentity(const std::string& account) {
  std::array<BYTE, 32> bytes{};
  for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<BYTE>(i + 1);
  fixture::store[kPrivateKeyStoreKey] = EncodeKey(bytes);
  fixture::store[kPublicKeyStoreKey] = EncodeKey(bytes);
  fixture::store[kAccountBindingStoreKey] = account;
}

int main() {
  using fixture::Check;
  TunnelFailure failure = TunnelFailure::kNone;
  fixture::Reset();
  Check(!PrepareIdentityForAccount("account-b", &failure) &&
      failure == TunnelFailure::kNetworkProtectionFailure && fixture::wfp == 1,
      "previous privileged identity path must reproduce the ordinary UI failure");
  Check(fixture::store.empty(), "regression proof must not touch protected keys");

  fixture::Reset(); failure = TunnelFailure::kNone;
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::ready,
      "first sign-in cannot create its local identity");
  Check(fixture::store[kAccountBindingStoreKey] == "account-b" && fixture::writes == 3,
      "fresh identity must bind its generated pair to the account");
  fixture::CheckLocalOnly();

  fixture::Reset(); SeedIdentity("account-a");
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::ready &&
      fixture::store[kAccountBindingStoreKey] == "account-b" && fixture::writes == 3,
      "account change cannot replace its local identity");
  fixture::CheckLocalOnly();

  fixture::Reset(); SeedIdentity("account-b");
  fixture::service_present = true; // A stopped registration is queryable without SERVICE_STOP.
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::ready &&
      fixture::deletes == 0 && fixture::writes == 0 && fixture::loads == 0,
      "matching stored identity must be reused without mutation");
  fixture::CheckLocalOnly();

  for (const auto state : {SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOP_PENDING}) {
    fixture::Reset(); SeedIdentity("account-a"); fixture::service_present = true;
    fixture::tunnel_states = {static_cast<DWORD>(state)};
    Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::runtime_required &&
        fixture::reads == 0 && fixture::deletes == 0, "active tunnel must require the runtime");
    fixture::CheckLocalOnly();
  }
  fixture::Reset(); fixture::runtime = {true};
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::runtime_required &&
      fixture::reads == 0 && fixture::deletes == 0, "active runtime must authorize identity work");
  fixture::CheckLocalOnly();

  for (int unknown = 0; unknown != 3; ++unknown) {
    fixture::Reset(); SeedIdentity("account-a");
    if (unknown == 0) fixture::runtime = {std::nullopt};
    if (unknown == 1) fixture::manager_denied = true;
    if (unknown == 2) {fixture::service_present = true; fixture::query_denied = true;}
    Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::runtime_unknown &&
        fixture::deletes == 0 && fixture::writes == 0, "unknown runtime state must preserve identity");
    fixture::CheckLocalOnly();
  }
  fixture::Reset(); SeedIdentity("account-a"); fixture::runtime = {false, true};
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::runtime_required &&
      fixture::deletes == 0, "runtime appearing during reads must prevent identity replacement");
  fixture::CheckLocalOnly();
  fixture::Reset(); SeedIdentity("account-a"); fixture::service_present = true;
  fixture::tunnel_states = {SERVICE_STOPPED, SERVICE_RUNNING};
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::runtime_required &&
      fixture::deletes == 0, "tunnel starting during reads must prevent identity replacement");
  fixture::CheckLocalOnly();

  for (const auto* key : {kPrivateKeyStoreKey, kPublicKeyStoreKey, kAccountBindingStoreKey}) {
    fixture::Reset(); SeedIdentity("account-a"); fixture::failed_reads.insert(key);
    Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::failed &&
        failure == TunnelFailure::kStorageFailure && fixture::deletes == 0 && fixture::writes == 0,
        "failed protected read must not erase or recreate an identity");
    fixture::CheckLocalOnly();
  }
  fixture::Reset(); SeedIdentity("account-a"); fixture::store[kPrivateKeyStoreKey] = "corrupt";
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::failed &&
      fixture::deletes == 0, "malformed protected identity must be preserved for explicit recovery");
  fixture::CheckLocalOnly();
  fixture::Reset(); SeedIdentity("account-a"); fixture::delete_failed = true;
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::failed &&
      fixture::writes == 0, "failed delete must not create another identity");
  fixture::CheckLocalOnly();
  for (int write = 1; write != 4; ++write) {
    fixture::Reset(); fixture::write_fail_at = write;
    Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::failed &&
        failure == TunnelFailure::kStorageFailure && fixture::store.empty(),
        "failed protected write must clean only its incomplete synthetic identity");
    fixture::CheckLocalOnly();
  }
  fixture::Reset(); fixture::load_failed = true;
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::failed &&
      failure == TunnelFailure::kRuntimeUnavailable && fixture::writes == 0,
      "missing key generator must not report a successful identity");
  fixture::CheckLocalOnly();
  fixture::Reset(); SeedIdentity("account-b"); fixture::service_present = true;
  Check(ResetLocalIdentity(&failure) == LocalIdentityPreparation::ready &&
      fixture::store.empty() && fixture::deletes == 3 && fixture::writes == 0,
      "explicit idle identity reset must delete only the current user's keys");
  fixture::CheckLocalOnly();
  for (int blocked = 0; blocked != 4; ++blocked) {
    fixture::Reset(); SeedIdentity("account-b");
    auto expected = LocalIdentityPreparation::runtime_required;
    if (blocked == 0) fixture::runtime = {true};
    if (blocked == 1) {fixture::service_present = true; fixture::tunnel_states = {SERVICE_RUNNING};}
    if (blocked == 2) {fixture::runtime = {std::nullopt}; expected = LocalIdentityPreparation::runtime_unknown;}
    if (blocked == 3) {fixture::manager_denied = true; expected = LocalIdentityPreparation::runtime_unknown;}
    Check(ResetLocalIdentity(&failure) == expected && fixture::store.size() == 3 &&
        fixture::deletes == 0 && fixture::writes == 0,
        "active or unknown identity reset must preserve the current user's keys");
    fixture::CheckLocalOnly();
  }
  fixture::Reset(); SeedIdentity("account-b"); fixture::delete_failed = true;
  Check(ResetLocalIdentity(&failure) == LocalIdentityPreparation::failed &&
      failure == TunnelFailure::kStorageFailure && fixture::store.size() == 3,
      "failed explicit reset must remain a storage failure");
  fixture::CheckLocalOnly();
  std::cout << "Real WireGuard local identity regression: " << fixture::failures << " failures\n";
  return fixture::failures == 0 ? 0 : 1;
}
