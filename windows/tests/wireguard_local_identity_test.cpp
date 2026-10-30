// SPDX-License-Identifier: MPL-2.0
// Includes the real identity implementation. All SCM, store, DLL, CSPRNG and
// known-folder operations below are strict in-memory doubles; no service, key
// file, driver or WFP object on the test machine is touched.
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
#include <bcrypt.h>
#include <shlobj.h>
#include <openssl/evp.h>
#include <array>
#include <cstring>
#include <deque>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include "network_protection.h"
#include "protected_store.h"
#include "privileged_runtime.h"

namespace fixture {
// RFC 7748 section 6.1: Alice's X25519 private scalar and public key.
constexpr std::array<BYTE, 32> kRandomPrivate{
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
constexpr std::array<BYTE, 32> kExpectedPublic{
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
const HMODULE kTunnelModule = reinterpret_cast<HMODULE>(static_cast<ULONG_PTR>(3));
const HMODULE kDriverModule = reinterpret_cast<HMODULE>(static_cast<ULONG_PTR>(4));
std::map<std::string, std::string> store;
std::set<std::string> failed_reads;
std::deque<std::optional<bool>> runtime;
std::deque<DWORD> tunnel_states;
bool service_present = false, manager_denied = false, query_denied = false;
bool delete_failed = false, load_failed = false, random_failed = false, export_missing = false;
int write_fail_at = 0, reads = 0, deletes = 0, writes = 0, loads = 0;
int privileged_scm = 0, wfp = 0, failures = 0;
int tunnel_loads = 0, tunnel_frees = 0, keypair_exports = 0, randoms = 0, pins = 0;
int events = 0, pin_event = 0, export_event = 0;
DWORD pin_flags = 0;
LPCWSTR pin_address = nullptr;
bool random_policy = true;
void Reset() {
  store.clear(); failed_reads.clear(); runtime = {false};
  tunnel_states = {SERVICE_STOPPED};
  service_present = manager_denied = query_denied = delete_failed = load_failed = false;
  random_failed = export_missing = false;
  write_fail_at = reads = deletes = writes = loads = privileged_scm = wfp = 0;
  tunnel_loads = tunnel_frees = keypair_exports = randoms = pins = 0;
  events = pin_event = export_event = 0;
  pin_flags = 0; pin_address = nullptr; random_policy = true;
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
HMODULE WINAPI IdentityLoadLibraryExW(LPCWSTR path, HANDLE, DWORD) {
  ++fixture::loads;
  const bool tunnel = std::filesystem::path(path).filename() == L"tunnel.dll";
  if (tunnel) ++fixture::tunnel_loads;
  if (fixture::load_failed) return nullptr;
  return tunnel ? fixture::kTunnelModule : fixture::kDriverModule;
}
BOOL __cdecl IdentityTunnelService(LPCWSTR) { return FALSE; }
FARPROC WINAPI IdentityGetProcAddress(HMODULE, LPCSTR name) {
  // A Go-hosted key generator must never be requested again.
  if (std::strcmp(name, "WireGuardGenerateKeypair") == 0) ++fixture::keypair_exports;
  if (std::strcmp(name, "WireGuardTunnelService") == 0) {
    fixture::export_event = ++fixture::events;
    if (!fixture::export_missing) return reinterpret_cast<FARPROC>(IdentityTunnelService);
  }
  return nullptr;
}
BOOL WINAPI IdentityFreeLibrary(HMODULE library) {
  if (library == fixture::kTunnelModule) ++fixture::tunnel_frees;
  return TRUE;
}
BOOL WINAPI IdentitySetDllDirectoryW(LPCWSTR) { return TRUE; }
BOOL WINAPI IdentityGetModuleHandleExW(DWORD flags, LPCWSTR address, HMODULE* pinned) {
  ++fixture::pins;
  fixture::pin_event = ++fixture::events;
  fixture::pin_flags = flags;
  fixture::pin_address = address;
  *pinned = fixture::kTunnelModule;
  return TRUE;
}
NTSTATUS WINAPI IdentityBCryptGenRandom(BCRYPT_ALG_HANDLE algorithm, PUCHAR buffer,
                                        ULONG size, ULONG flags) {
  ++fixture::randoms;
  fixture::random_policy = fixture::random_policy && algorithm == nullptr &&
      flags == BCRYPT_USE_SYSTEM_PREFERRED_RNG && size == fixture::kRandomPrivate.size();
  if (fixture::random_failed || size != fixture::kRandomPrivate.size())
    return static_cast<NTSTATUS>(0xC0000001L);
  std::memcpy(buffer, fixture::kRandomPrivate.data(), fixture::kRandomPrivate.size());
  return 0;
}
// Keeps RemoveRestrictedConfiguration away from the machine's ProgramData.
HRESULT WINAPI IdentitySHGetKnownFolderPath(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR* path) {
  *path = nullptr;
  return E_ACCESSDENIED;
}

#define OpenSCManagerW IdentityOpenSCManagerW
#define OpenServiceW IdentityOpenServiceW
#define QueryServiceStatus IdentityQueryServiceStatus
#define CloseServiceHandle IdentityCloseServiceHandle
#define ControlService IdentityControlService
#define LoadLibraryExW IdentityLoadLibraryExW
#define GetProcAddress IdentityGetProcAddress
#define FreeLibrary IdentityFreeLibrary
#define SetDllDirectoryW IdentitySetDllDirectoryW
#define GetModuleHandleExW IdentityGetModuleHandleExW
#define BCryptGenRandom IdentityBCryptGenRandom
#define SHGetKnownFolderPath IdentitySHGetKnownFolderPath
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
#undef GetModuleHandleExW
#undef BCryptGenRandom
#undef SHGetKnownFolderPath

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
bool WriteUserDiagnostic(const std::string&, const std::string&, bool) {
  fixture::Check(false, "identity preparation wrote a tunnel connection diagnostic"); return false;
}
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

std::array<BYTE, 32> StoredKey(const char* key) {
  std::array<BYTE, 32> bytes{};
  const auto& value = fixture::store[key];
  DWORD size = static_cast<DWORD>(bytes.size());
  if (!IsWireGuardKey(value) ||
      !CryptStringToBinaryA(value.data(), static_cast<DWORD>(value.size()), CRYPT_STRING_BASE64,
                            bytes.data(), &size, nullptr, nullptr) ||
      size != bytes.size()) {
    bytes.fill(0);
  }
  return bytes;
}

// The stored pair must be exactly WireGuardGenerateKeypair's: the CSPRNG
// scalar with WireGuard clamping and its X25519 public key, both base64.
void CheckGeneratedIdentity(const std::string& account, const char* message) {
  auto expected_private = fixture::kRandomPrivate;
  expected_private[0] = static_cast<BYTE>(expected_private[0] & 248);
  expected_private[31] = static_cast<BYTE>((expected_private[31] & 127) | 64);
  const auto private_key = StoredKey(kPrivateKeyStoreKey);
  fixture::Check(private_key == expected_private && (private_key[0] & 7) == 0 &&
      (private_key[31] & 0xc0) == 0x40 && StoredKey(kPublicKeyStoreKey) == fixture::kExpectedPublic &&
      fixture::store[kAccountBindingStoreKey] == account && fixture::randoms == 1 &&
      fixture::random_policy, message);
}

// A Go c-shared runtime cannot be unloaded: the GUI, FuzeVPNService and the
// portable engine must create identities without ever mapping tunnel.dll.
void CheckNoTunnelRuntime(const char* message) {
  fixture::Check(fixture::loads == 0 && fixture::tunnel_frees == 0 &&
      fixture::keypair_exports == 0 && fixture::pins == 0, message);
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
  CheckGeneratedIdentity("account-b", "first sign-in must store a clamped X25519 pair");
  CheckNoTunnelRuntime("first portable sign-in loaded the Go tunnel runtime in the GUI");
  fixture::CheckLocalOnly();

  fixture::Reset(); SeedIdentity("account-a");
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::ready &&
      fixture::store[kAccountBindingStoreKey] == "account-b" && fixture::writes == 3,
      "account change cannot replace its local identity");
  CheckGeneratedIdentity("account-b", "account change must store a clamped X25519 pair");
  CheckNoTunnelRuntime("account change loaded the Go tunnel runtime in the GUI");
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
  fixture::Reset(); fixture::random_failed = true;
  Check(PrepareLocalIdentityForAccount("account-b", &failure) == LocalIdentityPreparation::failed &&
      failure == TunnelFailure::kRuntimeUnavailable && fixture::writes == 0 &&
      fixture::store.empty() && fixture::randoms == 1,
      "failed key generation must not report a successful identity");
  CheckNoTunnelRuntime("failed key generation fell back to the Go tunnel runtime");
  fixture::CheckLocalOnly();

  // FuzeVPNService and the portable engine create identities on these paths.
  std::string public_key;
  fixture::Reset(); failure = TunnelFailure::kNone;
  Check(GetOrCreatePublicKey("account-b", &public_key, &failure, false) &&
      public_key == EncodeKey(fixture::kExpectedPublic) && fixture::writes == 3 &&
      fixture::wfp == 0, "missing connection identity must be created without releasing protection");
  CheckGeneratedIdentity("account-b", "service connection identity must be a clamped X25519 pair");
  CheckNoTunnelRuntime("service key creation loaded the Go tunnel runtime");
  fixture::Reset(); SeedIdentity("account-a"); failure = TunnelFailure::kNone;
  Check(RecreateIdentityForAccount("account-b", &failure) && fixture::deletes == 3 &&
      fixture::writes == 3 && fixture::wfp == 0, "revoked identity must be recreated in one operation");
  CheckGeneratedIdentity("account-b", "recreated identity must be a clamped X25519 pair");
  CheckNoTunnelRuntime("identity recreation loaded the Go tunnel runtime");
  fixture::Reset(); failure = TunnelFailure::kNone; public_key.clear();
  Check(CreateIdentityForAccount("account-b", &public_key, &failure) &&
      public_key == EncodeKey(fixture::kExpectedPublic), "direct identity creation must succeed");
  CheckNoTunnelRuntime("direct identity creation loaded the Go tunnel runtime");
  fixture::Reset(); fixture::random_failed = true; failure = TunnelFailure::kNone; public_key.clear();
  Check(!GetOrCreatePublicKey("account-b", &public_key, &failure, false) &&
      failure == TunnelFailure::kRuntimeUnavailable && public_key.empty() &&
      fixture::writes == 0 && fixture::store.empty(),
      "service key generation failure keeps the public runtime_unavailable code");
  CheckNoTunnelRuntime("service key generation failure fell back to the Go tunnel runtime");
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

  // Only the dedicated tunnel service process loads tunnel.dll. The loader
  // keeps process-wide state, so its policy is exercised last.
  fixture::Reset(); fixture::load_failed = true;
  Check(TunnelRuntime::LoadTunnelService() == nullptr && fixture::tunnel_loads == 1 &&
      fixture::pins == 0, "failed tunnel runtime load must expose no entry point");
  fixture::load_failed = false; fixture::export_missing = true;
  Check(TunnelRuntime::LoadTunnelService() == nullptr && fixture::tunnel_loads == 2 &&
      fixture::pins == 1, "failed tunnel runtime load must be retried, not cached");
  Check(fixture::pin_flags == static_cast<DWORD>(
          GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) &&
      fixture::pin_address == reinterpret_cast<LPCWSTR>(fixture::kTunnelModule) &&
      fixture::pin_event < fixture::export_event,
      "Go runtime must be pinned from its module base before any export lookup");
  fixture::export_missing = false;
  Check(TunnelRuntime::LoadTunnelService() == IdentityTunnelService &&
      fixture::tunnel_loads == 2 && fixture::pins == 1,
      "pinned tunnel runtime must be reused, never loaded twice");
  Check(fixture::tunnel_frees == 0 && fixture::keypair_exports == 0,
      "Go tunnel runtime must never be freed, even with a missing export");
  std::cout << "Real WireGuard local identity regression: " << fixture::failures << " failures\n";
  return fixture::failures == 0 ? 0 : 1;
}
