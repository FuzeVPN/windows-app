// SPDX-License-Identifier: MPL-2.0
#include "runtime_network_recovery.h"

#include <softpub.h>
#include <wintrust.h>
#include "broker_security.h"
#include "maintenance_network_state.h"
#include "network_protection_persistence.h"
#include "update_security.h"

DWORD RecoverStoppedNetworkFromRuntime() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return GetLastError();
  TOKEN_ELEVATION elevation{};
  DWORD bytes = 0;
  const bool elevated = GetTokenInformation(token, TokenElevation, &elevation,
      sizeof(elevation), &bytes) && elevation.TokenIsElevated != 0;
  CloseHandle(token);
  if (!elevated) return ERROR_ACCESS_DENIED;

  // This entry point belongs to the static-CRT, OS-import-only runtime helper,
  // never the service which imports VPN/OpenSSL DLLs before main. Hold the
  // verified image and its ancestors against replacement throughout recovery.
  const auto executable = fuzevpn_update::CurrentExecutable();
  fuzevpn_update::PinnedFile self;
  if (executable.empty() || !self.Open(executable, true)) return ERROR_ACCESS_DENIED;
  WINTRUST_FILE_INFO file{};
  file.cbStruct = sizeof(file);
  file.pcwszFilePath = executable.c_str();
  file.hFile = self.get();
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust);
  trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust.dwUnionChoice = WTD_CHOICE_FILE;
  trust.pFile = &file;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  // Recovery must work while the guard blocks network access. Validate the
  // signature/root trust using the local trust store; never download evidence.
  trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG signature = WinVerifyTrust(nullptr, &policy, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policy, &trust);
  if (signature != ERROR_SUCCESS) return ERROR_ACCESS_DENIED;

  fuzevpn_ipc::ExclusiveRuntimeLock runtime_lock;
  if (!runtime_lock.AcquireMachineRuntime()) return GetLastError();
  DWORD error = ERROR_SUCCESS;
  if (!fuzevpn_maintenance::ConfirmStoppedNetworkState(executable.parent_path().wstring(), &error)) return error;
  return fuzevpn_network_persistence::RemoveForMaintenance();
}
