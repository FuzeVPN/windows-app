// SPDX-License-Identifier: MPL-2.0
// Production recovery authorization with in-memory adapters only. Never opens
// a real process token, file, mutex, WFP engine or service and sends no packets.
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include "runtime_network_recovery.h"
#include "broker_security.h"
#include "maintenance_network_state.h"
#include "network_protection_persistence.h"
#include "update_security.h"

namespace fixture {
bool token = true, elevated = true, pinned = true, locked = true;
LONG signature = ERROR_SUCCESS;
DWORD proof = ERROR_SUCCESS, removal = ERROR_SUCCESS;
unsigned signature_calls = 0, lock_calls = 0, proof_calls = 0, removal_calls = 0;
void Check(bool result, const char* message) {
  if (!result) { std::cerr << message << '\n'; std::exit(EXIT_FAILURE); }
}
void Reset() {
  token = elevated = pinned = locked = true;
  signature = ERROR_SUCCESS; proof = removal = ERROR_SUCCESS;
  signature_calls = lock_calls = proof_calls = removal_calls = 0;
}
}
BOOL WINAPI RecoveryOpenToken(HANDLE, DWORD access, PHANDLE result) {
  fixture::Check(access == TOKEN_QUERY, "recovery only queries current elevation");
  if (!fixture::token) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  *result = reinterpret_cast<HANDLE>(20); return TRUE;
}
BOOL WINAPI RecoveryTokenInfo(HANDLE, TOKEN_INFORMATION_CLASS type, LPVOID value, DWORD, PDWORD size) {
  fixture::Check(type == TokenElevation, "only token elevation read");
  static_cast<TOKEN_ELEVATION*>(value)->TokenIsElevated = fixture::elevated ? 1 : 0;
  *size = sizeof(TOKEN_ELEVATION); return TRUE;
}
BOOL WINAPI RecoveryClose(HANDLE) { return TRUE; }
LONG WINAPI RecoveryTrust(HWND, GUID*, LPVOID raw) {
  auto* trust = static_cast<WINTRUST_DATA*>(raw);
  fixture::Check(trust->dwUIChoice == WTD_UI_NONE &&
      (trust->dwProvFlags & WTD_CACHE_ONLY_URL_RETRIEVAL) && trust->pFile &&
      trust->pFile->hFile == reinterpret_cast<HANDLE>(21),
      "recovery verifies pinned helper offline without UI or network retrieval");
  ++fixture::signature_calls;
  return fixture::signature;
}
namespace recovery_update {
std::filesystem::path CurrentExecutable() { return L"D:\\Recovered copy\\fuzevpn-runtime.exe"; }
class PinnedFile {
 public:
  bool Open(const std::filesystem::path&, bool ancestors) {
    fixture::Check(ancestors, "recovery pins executable ancestors"); return fixture::pinned;
  }
  HANDLE get() const { return reinterpret_cast<HANDLE>(21); }
};
}
namespace recovery_ipc {
class ExclusiveRuntimeLock {
 public:
  bool AcquireMachineRuntime() {
    ++fixture::lock_calls;
    if (!fixture::locked) SetLastError(ERROR_BUSY);
    return fixture::locked;
  }
};
}
namespace recovery_maintenance {
bool ConfirmStoppedNetworkState(const std::wstring& directory, DWORD* error) {
  fixture::Check(directory == L"D:\\Recovered copy", "no old frontend path required");
  ++fixture::proof_calls; *error = fixture::proof; return fixture::proof == ERROR_SUCCESS;
}
}
namespace recovery_persistence {
DWORD RemoveForMaintenance() { ++fixture::removal_calls; return fixture::removal; }
}

#define OpenProcessToken RecoveryOpenToken
#define GetTokenInformation RecoveryTokenInfo
#define CloseHandle RecoveryClose
#define WinVerifyTrust RecoveryTrust
#define fuzevpn_update recovery_update
#define fuzevpn_ipc recovery_ipc
#define fuzevpn_maintenance recovery_maintenance
#define fuzevpn_network_persistence recovery_persistence
#include "../runner/runtime_network_recovery.cpp"

int main() {
  using namespace fixture;
  Reset(); token = false;
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_ACCESS_DENIED && !signature_calls && !removal_calls,
        "token query failure cannot mutate network");
  Reset(); elevated = false;
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_ACCESS_DENIED && !signature_calls && !removal_calls,
        "unelevated recovery is refused before file or WFP operations");
  Reset(); pinned = false;
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_ACCESS_DENIED && !signature_calls && !removal_calls,
        "unverifiable helper path cannot recover");
  Reset(); signature = TRUST_E_NOSIGNATURE;
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_ACCESS_DENIED && signature_calls == 2 && !lock_calls && !removal_calls,
        "unsigned helper never acquires runtime ownership or alters WFP");
  Reset(); locked = false;
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_BUSY && lock_calls == 1 && !proof_calls && !removal_calls,
        "live runtime mutex prevents recovery");
  for (const DWORD error : {DWORD(ERROR_BUSY), DWORD(ERROR_ACCESS_DENIED), DWORD(ERROR_INVALID_DATA)}) {
    Reset(); proof = error;
    Check(RecoverStoppedNetworkFromRuntime() == error && proof_calls == 1 && !removal_calls,
          "active or unobservable network state cannot be erased");
  }
  Reset(); removal = ERROR_ACCESS_DENIED;
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_ACCESS_DENIED && removal_calls == 1,
        "transaction failure reaches administrator without false success");
  Reset();
  Check(RecoverStoppedNetworkFromRuntime() == ERROR_SUCCESS && signature_calls == 2 &&
        lock_calls == 1 && proof_calls == 1 && removal_calls == 1,
        "signed elevated standalone helper recovers only after complete idle proof");
  std::cout << "Runtime network recovery authorization tests passed (all OS operations mocked)\n";
  return EXIT_SUCCESS;
}
