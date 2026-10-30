// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NETWORK_PROTECTION_PERSISTENCE_H_
#define RUNNER_NETWORK_PROTECTION_PERSISTENCE_H_

#include <windows.h>
#include <fwpmu.h>
#include <sddl.h>
#include <cstdint>
#include <string>
#include <vector>
#include "network_protection_failure.h"

// Shared with the elevated installer recovery path. Ownership is identified by
// stable GUIDs, never display names or an executable path which an update moves.
namespace fuzevpn_network_persistence {
struct SecurityDescriptor {
  PSECURITY_DESCRIPTOR value = nullptr;
  SecurityDescriptor() {
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)",
        SDDL_REVISION_1, &value, nullptr);
  }
  ~SecurityDescriptor() { if (value) LocalFree(value); }
};
inline constexpr GUID kProvider = {0x455a55a4, 0xba48, 0x4a67,
    {0xa0, 0x1b, 0x97, 0x96, 0x26, 0x19, 0x70, 0x41}};
inline constexpr GUID kSublayer = {0xe8641624, 0x3149, 0x4f84,
    {0x99, 0xb1, 0xa2, 0x2b, 0x51, 0x84, 0x25, 0xce}};
inline constexpr GUID kIntentFilter = {0x38c16e47, 0x0883, 0x4bf9,
    {0x87, 0xcf, 0x8a, 0x65, 0x0a, 0x42, 0x6c, 0x27}};

struct Intent {
  bool wireguard = true;
  bool kill_switch = true;
  bool dns = true;
  bool web_rtc = true;
  std::string user;
};

inline bool ValidUser(const std::string& user) {
  if (user.size() < 5 || user.size() > 184 || user.rfind("S-1-", 0) != 0) return false;
  bool digit = false;
  for (size_t i = 4; i < user.size(); ++i) {
    if (user[i] >= '0' && user[i] <= '9') digit = true;
    else if (user[i] == '-' && digit) digit = false;
    else return false;
  }
  return digit;
}

inline std::vector<UINT8> Encode(const Intent& intent) {
  if (!ValidUser(intent.user)) return {};
  std::vector<UINT8> bytes{'F', 'Z', 'N', 'P', 1,
      static_cast<UINT8>(intent.wireguard ? 0 : 1),
      static_cast<UINT8>((intent.kill_switch ? 1 : 0) |
          (intent.dns ? 2 : 0) | (intent.web_rtc ? 4 : 0)),
      static_cast<UINT8>(intent.user.size())};
  bytes.insert(bytes.end(), intent.user.begin(), intent.user.end());
  return bytes;
}

inline bool Decode(const FWP_BYTE_BLOB& blob, Intent* intent) {
  if (!blob.data || blob.size < 8 || blob.size > 192 ||
      blob.data[0] != 'F' || blob.data[1] != 'Z' || blob.data[2] != 'N' ||
      blob.data[3] != 'P' || blob.data[4] != 1 || blob.data[5] > 1 ||
      (blob.data[6] & ~7U) || blob.size != 8U + blob.data[7]) return false;
  Intent candidate;
  candidate.wireguard = blob.data[5] == 0;
  candidate.kill_switch = (blob.data[6] & 1) != 0;
  candidate.dns = (blob.data[6] & 2) != 0;
  candidate.web_rtc = (blob.data[6] & 4) != 0;
  candidate.user.assign(reinterpret_cast<const char*>(blob.data + 8), blob.data[7]);
  if (!ValidUser(candidate.user)) return false;
  *intent = std::move(candidate);
  return true;
}

// Caller owns the engine and, for writes, an active WFP transaction.
inline DWORD Read(HANDLE engine, Intent* intent, bool* present) {
  *present = false;
  FWPM_FILTER0* filter = nullptr;
  const DWORD status = FwpmFilterGetByKey0(engine, &kIntentFilter, &filter);
  if (status == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) return ERROR_SUCCESS;
  if (status != ERROR_SUCCESS) return status;
  const bool valid = filter && (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) &&
      filter->providerKey && IsEqualGUID(*filter->providerKey, kProvider) &&
      Decode(filter->providerData, intent);
  if (filter) FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
  if (!valid) return ERROR_INVALID_DATA;
  *present = true;
  return ERROR_SUCCESS;
}

inline bool ProviderEnforced(HANDLE engine) {
  FWPM_PROVIDER0* provider = nullptr;
  const DWORD status = FwpmProviderGetByKey0(engine, &kProvider, &provider);
  const bool enforced = status == ERROR_SUCCESS && provider &&
      !(provider->flags & FWPM_PROVIDER_FLAG_DISABLED);
  if (provider) FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
  return enforced;
}

inline DWORD RemoveInTransaction(HANDLE engine, bool persistent_only = false) {
  using fuzevpn_network_failure::Capture;
  using fuzevpn_network_failure::Stage;
  // A non-null template requires an actual layer GUID. GUID_NULL is not an
  // all-layers selector (Windows returns FWP_E_LAYER_NOT_FOUND). The documented
  // null template returns all filters, including boot-time/disabled objects.
  // Restrict ownership explicitly below, BEFORE collecting any deletion IDs.
  HANDLE enumeration = nullptr;
  DWORD status = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration);
  if (status == static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND)) return ERROR_SUCCESS;
  if (status != ERROR_SUCCESS) return Capture(Stage::filter_enum_create, status);
  std::vector<UINT64> identifiers;
  for (;;) {
    FWPM_FILTER0** filters = nullptr;
    UINT32 count = 0;
    status = FwpmFilterEnum0(engine, enumeration, 256, &filters, &count);
    if (status == ERROR_SUCCESS) {
      for (UINT32 i = 0; i < count; ++i) {
        const auto* filter = filters[i];
        if (filter && filter->providerKey && IsEqualGUID(*filter->providerKey, kProvider) &&
            IsEqualGUID(filter->subLayerKey, kSublayer) &&
            (!persistent_only || (filter->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME))))
          identifiers.push_back(filter->filterId);
      }
    }
    if (filters) FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
    if (status != ERROR_SUCCESS || count == 0) break;
  }
  const DWORD destroyed = FwpmFilterDestroyEnumHandle0(engine, enumeration);
  if (status != ERROR_SUCCESS) return Capture(Stage::filter_enum, status);
  if (destroyed != ERROR_SUCCESS) return Capture(Stage::filter_enum_destroy, destroyed);
  for (const auto id : identifiers) {
    status = FwpmFilterDeleteById0(engine, id);
    if (status != ERROR_SUCCESS) return Capture(Stage::filter_delete, status);
  }
  if (persistent_only) return ERROR_SUCCESS;
  status = FwpmSubLayerDeleteByKey0(engine, &kSublayer);
  if (status != ERROR_SUCCESS && status != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND))
    return Capture(Stage::sublayer_delete, status);
  status = FwpmProviderDeleteByKey0(engine, &kProvider);
  return status == static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND) ? ERROR_SUCCESS :
      Capture(Stage::provider_delete, status);
}

inline DWORD EnsureProvider(HANDLE engine) {
  SecurityDescriptor security;
  if (!security.value) return ERROR_ACCESS_DENIED;
  FWPM_PROVIDER0 provider{};
  provider.providerKey = kProvider;
  provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
  provider.displayData.name = const_cast<wchar_t*>(L"FuzeVPN — protection persistante");
  const DWORD status = FwpmProviderAdd0(engine, &provider, security.value);
  return status == static_cast<DWORD>(FWP_E_ALREADY_EXISTS) ? ERROR_SUCCESS : status;
}

// Only call after the installer has acquired its protected maintenance gate,
// stopped every runtime, and acquired the machine runtime mutex. This is also
// the recovery route if the previous portable copy was moved or deleted.
inline DWORD RemoveForMaintenance() {
  HANDLE engine = nullptr;
  DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine);
  if (status != ERROR_SUCCESS) return status;
  status = FwpmTransactionBegin0(engine, 0);
  if (status == ERROR_SUCCESS) {
    status = RemoveInTransaction(engine);
    if (status == ERROR_SUCCESS) status = FwpmTransactionCommit0(engine);
    if (status != ERROR_SUCCESS) FwpmTransactionAbort0(engine);
  }
  FwpmEngineClose0(engine);
  return status;
}
}  // namespace fuzevpn_network_persistence
#endif  // RUNNER_NETWORK_PROTECTION_PERSISTENCE_H_
