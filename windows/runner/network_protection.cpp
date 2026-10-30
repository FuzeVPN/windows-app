// SPDX-License-Identifier: MPL-2.0
#include "network_protection.h"
#include "network_protection_lifecycle.h"

#include "privileged_runtime.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <rpc.h>
#include <softpub.h>
#include <wintrust.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <memory>
#include <map>
#include <set>
#include <mutex>
#include <string>
#include <vector>

#include "installation_security.h"
#include "network_protection_persistence.h"

namespace {
using fuzevpn_network_failure::Capture;
using fuzevpn_network_failure::Stage;

std::mutex protection_mutex;
HANDLE engine_handle = nullptr;
HANDLE transient_engine_handle = nullptr;
std::set<HANDLE> transient_engines;
std::map<HANDLE, std::vector<UINT64>> installed_filter_ids;
std::map<HANDLE, fuzevpn_network_persistence::Intent> installing_intents;
fuzevpn::NetworkProtectionLifecycle protection_lifecycle;
std::uint64_t protected_tunnel_luid = 0;
std::wstring authenticated_broker_ui_path;
std::uint64_t protection_generation = 1;
fuzevpn_network_persistence::Intent protection_intent;
thread_local unsigned internal_stop_depth = 0;

constexpr wchar_t kUiExecutableName[] = L"fuzevpn_windows.exe";
constexpr wchar_t kServiceExecutableName[] = L"fuzevpn-service.exe";

struct FwpmMemoryDeleter {
  void operator()(FWP_BYTE_BLOB* value) const {
    if (value != nullptr) {
      void* memory = value;
      FwpmFreeMemory0(&memory);
    }
  }
};

using AppId = std::unique_ptr<FWP_BYTE_BLOB, FwpmMemoryDeleter>;

void CloseEngine(HANDLE* handle) {
  if (handle != nullptr && *handle != nullptr) {
    FwpmEngineClose0(*handle);
    installed_filter_ids.erase(*handle);
    installing_intents.erase(*handle);
    transient_engines.erase(*handle);
    *handle = nullptr;
  }
}

bool CloseEngineLocked() {
  ++protection_generation;
  // Remove ephemeral exceptions first. If persistent removal fails, only the
  // conservative prepared baseline remains; never claim a live tunnel permit.
  CloseEngine(&transient_engine_handle);
  if (engine_handle) {
    protection_lifecycle.ActivatePrepared(
        protection_intent.wireguard ? NetworkProtectionOwner::wire_guard : NetworkProtectionOwner::open_vpn,
        {protection_intent.kill_switch, protection_intent.dns, protection_intent.web_rtc});
    protected_tunnel_luid = 0;
  }
  if (engine_handle != nullptr) {
    if (FwpmTransactionBegin0(engine_handle, 0) != ERROR_SUCCESS) return false;
    const DWORD removed = fuzevpn_network_persistence::RemoveInTransaction(engine_handle);
    if (removed != ERROR_SUCCESS || FwpmTransactionCommit0(engine_handle) != ERROR_SUCCESS) {
      FwpmTransactionAbort0(engine_handle);
      return false;
    }
  }
  CloseEngine(&engine_handle);
  protected_tunnel_luid = 0;
  protection_lifecycle.Clear();
  return true;
}

bool ExecutablePath(std::wstring* path) {
  std::wstring value(MAX_PATH, L'\0');
  while (true) {
    const DWORD length = GetModuleFileNameW(
        nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (length == 0) {
      return false;
    }
    if (length < value.size() - 1) {
      value.resize(length);
      *path = std::move(value);
      return true;
    }
    value.resize(value.size() * 2);
  }
}

bool IsFileTrusted(const std::wstring& path) {
  WINTRUST_FILE_INFO file{};
  file.cbStruct = sizeof(file);
  file.pcwszFilePath = path.c_str();
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust);
  trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust.dwUnionChoice = WTD_CHOICE_FILE;
  trust.pFile = &file;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  const LONG status = WinVerifyTrust(nullptr, &policy, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policy, &trust);
  return status == ERROR_SUCCESS;
}

bool PreConnectUiPath(const std::wstring& current_executable,
                      std::wstring* ui_path) {
  // Called under protection_mutex. Services retain their installed sibling;
  // only a broker with a pinned, authenticated frontend may override it.
  if (!IsVpnServiceRuntime() && !authenticated_broker_ui_path.empty()) {
    *ui_path = authenticated_broker_ui_path;
    return true;
  }
  const std::filesystem::path current(current_executable);
  const std::filesystem::path candidate =
      current.parent_path() / kUiExecutableName;
  const std::wstring candidate_text = candidate.wstring();

  // Production runs in the dedicated signed service. Unsigned development
  // launches the fixed sibling service executable as an elevated broker; its
  // IPC bootstrap has already authenticated that exact unsigned pair.
  if (IsVpnServiceRuntime()) {
    if (!IsFileTrusted(candidate_text)) {
      return false;
    }
  } else {
    const std::wstring current_name = current.filename().wstring();
    if (_wcsicmp(current_name.c_str(), kServiceExecutableName) != 0) {
      return false;
    }
  }
  *ui_path = candidate_text;
  return true;
}

bool SystemExecutablePath(const wchar_t* executable_name,
                          std::wstring* executable_path) {
  std::wstring system_directory(MAX_PATH, L'\0');
  while (true) {
    const UINT length = GetSystemDirectoryW(
        system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (length == 0) {
      return false;
    }
    if (length < system_directory.size()) {
      system_directory.resize(length);
      *executable_path =
          (std::filesystem::path(system_directory) / executable_name).wstring();
      return true;
    }
    system_directory.resize(static_cast<std::size_t>(length) + 1);
  }
}

bool AddFilter(HANDLE engine, const FWPM_FILTER0& filter) {
  FWPM_FILTER0 persistent = filter;
  persistent.providerKey = const_cast<GUID*>(&fuzevpn_network_persistence::kProvider);
  std::vector<UINT8> bytes;
  if (transient_engines.find(engine) == transient_engines.end()) {
    if (!(persistent.flags & FWPM_FILTER_FLAG_BOOTTIME)) persistent.flags |= FWPM_FILTER_FLAG_PERSISTENT;
    if (installed_filter_ids[engine].empty()) {
      persistent.filterKey = fuzevpn_network_persistence::kIntentFilter;
      bytes = fuzevpn_network_persistence::Encode(installing_intents.at(engine));
      if (bytes.empty()) return false;
      persistent.providerData = {static_cast<UINT32>(bytes.size()), bytes.data()};
    }
  }
  fuzevpn_network_persistence::SecurityDescriptor security;
  if (!security.value) return false;
  UINT64 id = 0;
  if (Capture(Stage::filter_add, FwpmFilterAdd0(engine, &persistent, security.value, &id)) != ERROR_SUCCESS)
    return false;
  installed_filter_ids[engine].push_back(id);
  return true;
}

bool VerifyFiltersLocked() {
  if (engine_handle == nullptr) return true;
  if (!fuzevpn_network_persistence::ProviderEnforced(engine_handle)) return false;
  const auto found = installed_filter_ids.find(engine_handle);
  if (found == installed_filter_ids.end() || found->second.empty()) return false;
  for (const UINT64 id : found->second) {
    FWPM_FILTER0* filter = nullptr;
    const DWORD status = FwpmFilterGetById0(engine_handle, id, &filter);
    const bool enforced = filter && (!(filter->flags & FWPM_FILTER_FLAG_DISABLED) ||
                                    (filter->flags & FWPM_FILTER_FLAG_BOOTTIME));
    if (filter != nullptr) FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
    if (status != ERROR_SUCCESS || !enforced) return false;
  }
  if (transient_engine_handle) {
    const auto transient = installed_filter_ids.find(transient_engine_handle);
    if (transient == installed_filter_ids.end() || transient->second.empty()) return false;
    for (const auto id : transient->second) {
      FWPM_FILTER0* filter = nullptr;
      const DWORD status = FwpmFilterGetById0(transient_engine_handle, id, &filter);
      const bool enforced = filter && !(filter->flags & FWPM_FILTER_FLAG_DISABLED);
      if (filter) FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
      if (status != ERROR_SUCCESS || !enforced) return false;
    }
  }
  return true;
}

bool AddPermitFilter(HANDLE engine, const GUID& layer, const GUID& sublayer,
                     FWPM_FILTER_CONDITION0* conditions,
                     UINT32 condition_count,
                     const wchar_t* name) {
  FWPM_FILTER0 filter{};
  filter.layerKey = layer;
  filter.subLayerKey = sublayer;
  filter.displayData.name = const_cast<wchar_t*>(name);
  filter.action.type = FWP_ACTION_PERMIT;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0xF;
  filter.numFilterConditions = condition_count;
  filter.filterCondition = conditions;
  return AddFilter(engine, filter);
}

bool AddPermitFilter(HANDLE engine, const GUID& layer, const GUID& sublayer,
                     const FWPM_FILTER_CONDITION0& condition,
                     const wchar_t* name) {
  return AddPermitFilter(
      engine, layer, sublayer,
      const_cast<FWPM_FILTER_CONDITION0*>(&condition), 1, name);
}

bool AddBlockFilter(HANDLE engine, const GUID& layer, const GUID& sublayer,
                    FWPM_FILTER_CONDITION0* conditions,
                    UINT32 condition_count, const wchar_t* name) {
  FWPM_FILTER0 filter{};
  filter.layerKey = layer;
  filter.subLayerKey = sublayer;
  filter.displayData.name = const_cast<wchar_t*>(name);
  filter.action.type = FWP_ACTION_BLOCK;
  filter.weight.type = FWP_EMPTY;
  filter.numFilterConditions = condition_count;
  filter.filterCondition = conditions;
  return AddFilter(engine, filter);
}

bool AddDnsBlocks(HANDLE engine, const GUID& layer, const GUID& sublayer,
                  const FWPM_FILTER_CONDITION0& not_loopback) {
  for (const UINT16 port : std::array<UINT16, 2>{53, 853}) {
    FWPM_FILTER_CONDITION0 conditions[2]{};
    conditions[0] = not_loopback;
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT16;
    conditions[1].conditionValue.uint16 = port;
    if (!AddBlockFilter(engine, layer, sublayer, conditions, 2,
                        L"FuzeVPN — protection DNS")) {
      return false;
    }
  }
  return true;
}

bool AddWebRtcUdpBlock(HANDLE engine, const GUID& layer,
                       const GUID& sublayer,
                       const FWPM_FILTER_CONDITION0& not_loopback,
                       const wchar_t* name) {
  FWPM_FILTER_CONDITION0 conditions[2]{};
  conditions[0] = not_loopback;
  conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
  conditions[1].matchType = FWP_MATCH_EQUAL;
  conditions[1].conditionValue.type = FWP_UINT8;
  conditions[1].conditionValue.uint8 = IPPROTO_UDP;
  return AddBlockFilter(engine, layer, sublayer, conditions, 2, name);
}

FWPM_FILTER_CONDITION0 NumberCondition(const GUID& field, UINT16 value) {
  FWPM_FILTER_CONDITION0 condition{};
  condition.fieldKey = field;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_UINT16;
  condition.conditionValue.uint16 = value;
  return condition;
}

FWPM_FILTER_CONDITION0 ProtocolCondition(UINT8 value) {
  FWPM_FILTER_CONDITION0 condition{};
  condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_UINT8;
  condition.conditionValue.uint8 = value;
  return condition;
}

bool AddControlTrafficPermits(HANDLE engine, const GUID& sublayer,
                              FWP_BYTE_BLOB* system_app_id) {
  FWPM_FILTER_CONDITION0 system_app{};
  system_app.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  system_app.matchType = FWP_MATCH_EQUAL;
  system_app.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  system_app.conditionValue.byteBlob = system_app_id;
  // Only the system service executable using the DHCP client/server port pair
  // may perform address assignment. Unicast renewals are required as well as
  // broadcast discovery. This does not admit application UDP or DNS.
  for (const GUID& layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
    FWPM_FILTER_CONDITION0 conditions[]{system_app, ProtocolCondition(IPPROTO_UDP),
        NumberCondition(FWPM_CONDITION_IP_LOCAL_PORT, 68),
        NumberCondition(FWPM_CONDITION_IP_REMOTE_PORT, 67)};
    if (!AddPermitFilter(engine, layer, sublayer, conditions,
                          static_cast<UINT32>(std::size(conditions)),
                          L"FuzeVPN — configuration DHCP IPv4")) return false;
  }
  FWP_V6_ADDR_AND_MASK link_local{};
  link_local.addr[0] = 0xfe;
  link_local.addr[1] = 0x80;
  link_local.prefixLength = 10;
  FWPM_FILTER_CONDITION0 local_link{};
  local_link.fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
  local_link.matchType = FWP_MATCH_EQUAL;
  local_link.conditionValue.type = FWP_V6_ADDR_MASK;
  local_link.conditionValue.v6AddrMask = &link_local;
  auto remote_link = local_link;
  remote_link.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  FWP_BYTE_ARRAY16 dhcp_multicast{};
  dhcp_multicast.byteArray16[0] = 0xff;
  dhcp_multicast.byteArray16[1] = 0x02;
  dhcp_multicast.byteArray16[13] = 1;
  dhcp_multicast.byteArray16[15] = 2;
  FWPM_FILTER_CONDITION0 remote_multicast{};
  remote_multicast.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  remote_multicast.matchType = FWP_MATCH_EQUAL;
  remote_multicast.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
  remote_multicast.conditionValue.byteArray16 = &dhcp_multicast;
  for (unsigned variant = 0; variant < 3; ++variant) {
    const bool inbound = variant == 2;
    FWPM_FILTER_CONDITION0 conditions[]{system_app, ProtocolCondition(IPPROTO_UDP),
        NumberCondition(FWPM_CONDITION_IP_LOCAL_PORT, 546),
        NumberCondition(FWPM_CONDITION_IP_REMOTE_PORT, 547), local_link,
        variant == 0 ? remote_multicast : remote_link};
    if (!AddPermitFilter(engine, inbound ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
                                        : FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                          sublayer, conditions, static_cast<UINT32>(std::size(conditions)),
                          L"FuzeVPN — configuration DHCP IPv6")) return false;
  }
  FWP_BYTE_ARRAY16 routers{};
  routers.byteArray16[0] = 0xff;
  routers.byteArray16[1] = 0x02;
  routers.byteArray16[15] = 2;
  auto router_multicast = remote_multicast;
  router_multicast.conditionValue.byteArray16 = &routers;
  // ALE exposes ICMP type/code through the port condition aliases. Router
  // requests are link-local multicast; advertisements/redirects must originate
  // link-local. Neighbour discovery is restricted to its two type/code pairs.
  // Windows validates the NDP hop-limit and message format in the IPv6 stack.
  for (const UINT16 type : {UINT16(133), UINT16(134), UINT16(135), UINT16(136), UINT16(137)}) {
    for (const bool inbound : {false, true}) {
      if ((type == 133 && inbound) || ((type == 134 || type == 137) && !inbound)) continue;
      std::vector<FWPM_FILTER_CONDITION0> conditions{
          ProtocolCondition(IPPROTO_ICMPV6), NumberCondition(FWPM_CONDITION_ICMP_TYPE, type),
          NumberCondition(FWPM_CONDITION_ICMP_CODE, 0)};
      if (type == 133) conditions.push_back(router_multicast);
      if (type == 134 || type == 137) conditions.push_back(remote_link);
      if (!AddPermitFilter(engine, inbound ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
                                          : FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            sublayer, conditions.data(), static_cast<UINT32>(conditions.size()),
                            L"FuzeVPN — découverte des voisins IPv6")) return false;
    }
  }
  return true;
}

bool InstallFiltersLocked(bool prepared, NET_LUID interface_luid,
                           NetworkProtectionOwner owner,
                           const NetworkProtectionOptions& options,
                           HANDLE* installed_engine, HANDLE* installed_transient,
                           bool enable_transient = true, bool reset_provider = false) {
  const auto plan =
      fuzevpn::BuildNetworkProtectionFilterPlan(prepared, options);
  *installed_engine = nullptr;
  *installed_transient = nullptr;
  FWPM_SESSION0 session{};
  // Persistent objects outlive process crashes. Their BFE/boot enforcement is
  // an integration-test requirement (see network-protection-recovery.md). A
  // normal session is required: dynamic sessions cannot own persistent filters.
  session.displayData.name = const_cast<wchar_t*>(L"FuzeVPN");
  HANDLE candidate_engine = nullptr;
  if (Capture(Stage::engine_open, FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session,
                      &candidate_engine)) != ERROR_SUCCESS) {
    return false;
  }

  const GUID& sublayer = fuzevpn_network_persistence::kSublayer;

  if (Capture(Stage::transaction_begin, FwpmTransactionBegin0(candidate_engine, 0)) != ERROR_SUCCESS) {
    CloseEngine(&candidate_engine);
    return false;
  }
  bool transaction_open = true;
  auto fail = [&]() {
    if (transaction_open) {
      FwpmTransactionAbort0(candidate_engine);
    }
    CloseEngine(&candidate_engine);
    return false;
  };

  auto intent = protection_intent;
  intent.wireguard = owner == NetworkProtectionOwner::wire_guard;
  intent.kill_switch = options.kill_switch;
  intent.dns = options.dns_protection;
  intent.web_rtc = options.web_rtc_protection;
  // Removal and replacement are one transaction. Failure or termination before
  // commit leaves the complete previous policy and its intent in BFE intact.
  installing_intents[candidate_engine] = intent;
  if (reset_provider &&
      fuzevpn_network_persistence::RemoveInTransaction(candidate_engine) != ERROR_SUCCESS) return fail();
  if (Capture(Stage::provider_add, fuzevpn_network_persistence::EnsureProvider(candidate_engine)) != ERROR_SUCCESS ||
      fuzevpn_network_persistence::RemoveInTransaction(candidate_engine, true) != ERROR_SUCCESS) {
    return fail();
  }

  FWPM_SUBLAYER0 layer{};
  layer.subLayerKey = sublayer;
  layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
  layer.providerKey = const_cast<GUID*>(&fuzevpn_network_persistence::kProvider);
  layer.displayData.name = const_cast<wchar_t*>(L"FuzeVPN");
  layer.displayData.description =
      const_cast<wchar_t*>(L"Protection contre les fuites réseau");
  layer.weight = 0x100;
  fuzevpn_network_persistence::SecurityDescriptor security;
  if (!security.value) return fail();
  const DWORD layer_status = FwpmSubLayerAdd0(candidate_engine, &layer, security.value);
  if (layer_status != ERROR_SUCCESS && layer_status != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) {
    Capture(Stage::sublayer_add, layer_status);
    return fail();
  }

  if (!prepared) {
    NET_IFINDEX interface_index = 0;
    if (interface_luid.Value == 0 ||
        ConvertInterfaceLuidToIndex(&interface_luid, &interface_index) !=
            NO_ERROR ||
        interface_index == 0) {
      return fail();
    }
  }

  std::wstring executable;
  if (!ExecutablePath(&executable)) {
    return fail();
  }
  FWP_BYTE_BLOB* raw_app_id = nullptr;
  if (Capture(Stage::app_id, FwpmGetAppIdFromFileName0(executable.c_str(), &raw_app_id)) !=
      ERROR_SUCCESS) {
    return fail();
  }
  AppId app_id(raw_app_id);

  AppId ui_app_id;
  if (plan.permit_ui && enable_transient) {
    std::wstring ui_executable;
    if (!PreConnectUiPath(executable, &ui_executable)) {
      return fail();
    }
    FWP_BYTE_BLOB* raw_ui_app_id = nullptr;
    if (Capture(Stage::app_id, FwpmGetAppIdFromFileName0(ui_executable.c_str(), &raw_ui_app_id)) !=
        ERROR_SUCCESS) {
      return fail();
    }
    ui_app_id.reset(raw_ui_app_id);
  }

  AppId control_app_id;
  {
    std::wstring control_executable;
    if (!SystemExecutablePath(L"svchost.exe", &control_executable)) {
      return fail();
    }
    FWP_BYTE_BLOB* raw_control_app_id = nullptr;
    if (Capture(Stage::app_id, FwpmGetAppIdFromFileName0(control_executable.c_str(),
                                  &raw_control_app_id)) != ERROR_SUCCESS) {
      return fail();
    }
    control_app_id.reset(raw_control_app_id);
  }

  FWPM_FILTER_CONDITION0 match_app{};
  match_app.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  match_app.matchType = FWP_MATCH_EQUAL;
  match_app.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  match_app.conditionValue.byteBlob = app_id.get();

  FWPM_FILTER_CONDITION0 match_ui{};
  if (plan.permit_ui && enable_transient) {
    match_ui.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    match_ui.matchType = FWP_MATCH_EQUAL;
    match_ui.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    match_ui.conditionValue.byteBlob = ui_app_id.get();
  }

  FWPM_FILTER_CONDITION0 match_interface{};
  if (plan.permit_tunnel) {
    match_interface.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
    match_interface.matchType = FWP_MATCH_EQUAL;
    match_interface.conditionValue.type = FWP_UINT64;
    match_interface.conditionValue.uint64 = &interface_luid.Value;
  }

  FWPM_FILTER_CONDITION0 not_loopback{};
  not_loopback.fieldKey = FWPM_CONDITION_FLAGS;
  not_loopback.matchType = FWP_MATCH_FLAGS_NONE_SET;
  not_loopback.conditionValue.type = FWP_UINT32;
  not_loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

  // Address assignment and neighbour discovery must survive a closed policy.
  // DNS is deliberately absent: API bootstrap uses a bounded direct resolver
  // in the permitted engine, never the shared DNS Client process.
  if (!AddControlTrafficPermits(candidate_engine, sublayer, control_app_id.get())) {
    return fail();
  }

  if (options.kill_switch) {
    // Persistent ALE filters are loaded when BFE initializes. Boot-time packet
    // blocks request coverage of the earlier TCP/IP startup interval. Windows
    // switches these to the persistent policy; that handoff requires VM packet
    // validation. They carry no app or
    // tunnel exception and are removed with the same provider on disconnect.
    for (const GUID& packet_layer :
         {FWPM_LAYER_INBOUND_IPPACKET_V4, FWPM_LAYER_INBOUND_IPPACKET_V6,
          FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWPM_LAYER_OUTBOUND_IPPACKET_V6}) {
      FWPM_FILTER0 boot{};
      boot.flags = FWPM_FILTER_FLAG_BOOTTIME;
      boot.layerKey = packet_layer;
      boot.subLayerKey = sublayer;
      boot.displayData.name = const_cast<wchar_t*>(L"FuzeVPN — protection au démarrage");
      boot.action.type = FWP_ACTION_BLOCK;
      boot.weight.type = FWP_EMPTY;
      boot.numFilterConditions = 1;
      boot.filterCondition = &not_loopback;
      if (!AddFilter(candidate_engine, boot)) return fail();
    }
  }

  for (const GUID& connect_layer :
       std::array<GUID, 4>{FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                          FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                          FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                          FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    if (plan.permit_engine &&
        !AddPermitFilter(candidate_engine, connect_layer, sublayer, match_app,
                         L"FuzeVPN — moteur VPN")) {
      return fail();
    }
  }

  // ALE flows keep the authorization layer of their initiating packet. Both
  // directions must be filtered: replies on accepted inbound sockets otherwise
  // bypass AUTH_CONNECT, including flows established before VPN activation.
  for (const GUID& ipv4_layer :
       std::array<GUID, 2>{FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                          FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4}) {
    if (plan.block_ipv4 &&
        !AddBlockFilter(candidate_engine, ipv4_layer, sublayer, &not_loopback, 1,
                        L"FuzeVPN — kill switch IPv4")) {
      return fail();
    }
    if (plan.block_dns &&
        !AddDnsBlocks(candidate_engine, ipv4_layer, sublayer, not_loopback)) {
      return fail();
    }
    // The selective setting blocks UDP on arbitrary ports. TURN over TCP/TLS
    // requires the full kill switch; its scope is stated in settings. The
    // higher-priority permits preserve VPN-interface and engine UDP.
    if (plan.block_udp &&
        !AddWebRtcUdpBlock(candidate_engine, ipv4_layer, sublayer, not_loopback,
                          L"FuzeVPN — protection WebRTC UDP IPv4")) {
      return fail();
    }
  }
  for (const GUID& ipv6_layer :
       std::array<GUID, 2>{FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                          FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    if (plan.block_ipv6 &&
        !AddBlockFilter(candidate_engine, ipv6_layer, sublayer, &not_loopback,
                        1, L"FuzeVPN — protection IPv6 obligatoire")) {
      return fail();
    }
  }

  if (Capture(Stage::transaction_commit, FwpmTransactionCommit0(candidate_engine)) != ERROR_SUCCESS) {
    return fail();
  }
  transaction_open = false;
  protection_intent = std::move(intent);
  *installed_engine = candidate_engine;
  if (!enable_transient) return true;
  FWPM_SESSION0 transient_session{};
  transient_session.flags = FWPM_SESSION_FLAG_DYNAMIC;
  HANDLE transient = nullptr;
  if (Capture(Stage::engine_open, FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &transient_session,
                     &transient)) != ERROR_SUCCESS) return false;
  transient_engines.insert(transient);
  if (Capture(Stage::transaction_begin, FwpmTransactionBegin0(transient, 0)) != ERROR_SUCCESS) {
    CloseEngine(&transient);
    return false;
  }
  bool success = true;
  for (const GUID& connect_layer :
       {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    if (plan.permit_ui) success = success && AddPermitFilter(transient, connect_layer,
        sublayer, match_ui, L"FuzeVPN — préparation de l’application");
    if (plan.permit_tunnel) success = success && AddPermitFilter(transient, connect_layer,
        sublayer, match_interface, L"FuzeVPN — interface VPN");
  }
  if (!success || Capture(Stage::transaction_commit, FwpmTransactionCommit0(transient)) != ERROR_SUCCESS) {
    FwpmTransactionAbort0(transient);
    CloseEngine(&transient);
    return false;
  }
  *installed_transient = transient;
  return true;
}

void SwapProtectionLocked(HANDLE candidate_engine, HANDLE candidate_transient,
                          NetworkProtectionOwner owner,
                          const NetworkProtectionOptions& options,
                          bool prepared,
                          std::uint64_t tunnel_luid) {
  // The WFP transaction replaced all persistent objects atomically. Publish
  // local metadata only after commit; closing a query handle removes no rule.
  HANDLE previous_engine = engine_handle;
  HANDLE previous_transient = transient_engine_handle;
  engine_handle = candidate_engine;
  transient_engine_handle = candidate_transient;
  ++protection_generation;
  if (prepared) {
    protection_lifecycle.ActivatePrepared(owner, options);
  } else {
    protection_lifecycle.ActivateTunnel(owner, options);
    protected_tunnel_luid = tunnel_luid;
  }
  CloseEngine(&previous_engine);
  CloseEngine(&previous_transient);
}

}  // namespace

bool SetNetworkProtectionUser(const std::string& user) {
  if (!CanManageNetworkProtection() || !fuzevpn_network_persistence::ValidUser(user)) return false;
  std::lock_guard<std::mutex> lock(protection_mutex);
  if (engine_handle && !protection_intent.user.empty() && protection_intent.user != user) return false;
  protection_intent.user = user;
  return true;
}

bool RestoreNetworkProtection(std::string* recovered_user) {
  if (!recovered_user || !CanManageNetworkProtection()) return false;
  recovered_user->clear();
  std::lock_guard<std::mutex> lock(protection_mutex);
  if (engine_handle || transient_engine_handle) return false;
  HANDLE query = nullptr;
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &query) != ERROR_SUCCESS) return false;
  fuzevpn_network_persistence::Intent intent;
  bool present = false;
  const DWORD status = fuzevpn_network_persistence::Read(query, &intent, &present);
  CloseEngine(&query);
  if (status != ERROR_SUCCESS) return false;
  if (!present) return true;
  protection_intent = intent;
  NetworkProtectionOptions options{intent.kill_switch, intent.dns, intent.web_rtc};
  const auto owner = intent.wireguard ? NetworkProtectionOwner::wire_guard : NetworkProtectionOwner::open_vpn;
  HANDLE restored = nullptr;
  NET_LUID none{};
  // Never trust a tunnel LUID left by an earlier process or boot. Revoke its
  // exception before stopping orphaned tunnels or accepting frontend requests.
  HANDLE transient = nullptr;
  if (!InstallFiltersLocked(true, none, owner, options, &restored, &transient, false, true)) return false;
  SwapProtectionLocked(restored, transient, owner, options, true, 0);
  protected_tunnel_luid = 0;
  *recovered_user = intent.user;
  return true;
}

bool PrepareNetworkProtectionForInternalStop() {
  std::lock_guard<std::mutex> lock(protection_mutex);
  if (!engine_handle) return true;
  const auto retained_owner = protection_intent.wireguard ? NetworkProtectionOwner::wire_guard : NetworkProtectionOwner::open_vpn;
  if (!transient_engine_handle &&
      protection_lifecycle.Status(retained_owner).phase == NetworkProtectionStatus::Phase::prepared)
    return VerifyFiltersLocked();
  NetworkProtectionOptions options{protection_intent.kill_switch, protection_intent.dns, protection_intent.web_rtc};
  const auto owner = protection_intent.wireguard ? NetworkProtectionOwner::wire_guard : NetworkProtectionOwner::open_vpn;
  HANDLE prepared = nullptr;
  NET_LUID none{};
  HANDLE transient = nullptr;
  if (!InstallFiltersLocked(true, none, owner, options, &prepared, &transient, false)) return false;
  SwapProtectionLocked(prepared, transient, owner, options, true, 0);
  protected_tunnel_luid = 0;
  return true;
}

ScopedNetworkProtectionRetention::ScopedNetworkProtectionRetention() { ++internal_stop_depth; }
ScopedNetworkProtectionRetention::~ScopedNetworkProtectionRetention() { --internal_stop_depth; }

bool SetAuthenticatedBrokerUiPath(std::wstring path) {
  if (!CanManageNetworkProtection() || IsVpnServiceRuntime() ||
      !fuzevpn_installation::IsCanonicalLocalAbsolutePath(path) ||
      !fuzevpn_installation::SamePath(std::filesystem::path(path).filename().wstring(),
                                     kUiExecutableName)) return false;
  std::lock_guard<std::mutex> lock(protection_mutex);
  if (engine_handle != nullptr) return false;
  authenticated_broker_ui_path = std::move(path);
  return true;
}

void ClearAuthenticatedBrokerUiPath() {
  std::lock_guard<std::mutex> lock(protection_mutex);
  // Do not invalidate the pinning contract while its path is still permitted.
  if (engine_handle == nullptr) authenticated_broker_ui_path.clear();
}

bool PrepareNetworkProtection(NetworkProtectionOwner owner,
                              const NetworkProtectionOptions& options) {
  fuzevpn_network_failure::Clear();
  if (!options.kill_switch) {
    return true;
  }
  // The Flutter process is never allowed to own WFP state. In production the
  // persistent VPN service owns the policy, so UI termination cannot
  // remove the kill switch. The elevated broker is retained only for unsigned
  // local development builds.
  if (!CanManageNetworkProtection()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(protection_mutex);

  // Rebuild even when the owner/options are unchanged. Candidate-first
  // replacement preserves the active policy through each reconnect attempt.
  NET_LUID no_interface{};
  HANDLE candidate_engine = nullptr;
  HANDLE candidate_transient = nullptr;
  if (!InstallFiltersLocked(true, no_interface, owner, options, &candidate_engine, &candidate_transient)) {
    if (candidate_engine) SwapProtectionLocked(candidate_engine, nullptr, owner, options, true, 0);
    return false;
  }
  SwapProtectionLocked(candidate_engine, candidate_transient, owner, options, true, 0);
  return true;
}

bool PromoteNetworkProtection(NetworkProtectionOwner owner,
                              std::uint64_t tunnel_interface_luid,
                              const NetworkProtectionOptions& options) {
  fuzevpn_network_failure::Clear();
  if (!CanManageNetworkProtection()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(protection_mutex);
  if ((engine_handle == nullptr || !VerifyFiltersLocked()) && options.kill_switch) {
    return false;
  }
  if (!protection_lifecycle.CanPromote(owner, options)) {
    return false;
  }

  NET_LUID interface_luid{};
  interface_luid.Value = tunnel_interface_luid;
  HANDLE candidate_engine = nullptr;
  HANDLE candidate_transient = nullptr;
  if (!InstallFiltersLocked(false, interface_luid, owner, options,
                            &candidate_engine, &candidate_transient)) {
    if (candidate_engine) SwapProtectionLocked(candidate_engine, nullptr, owner, options, true, 0);
    return false;
  }

  SwapProtectionLocked(candidate_engine, candidate_transient, owner, options, false,
                       tunnel_interface_luid);
  return true;
}

bool DisableNetworkProtection(NetworkProtectionOwner owner) {
  if (!CanManageNetworkProtection()) {
    return false;
  }
  if (internal_stop_depth != 0) return true;
  std::lock_guard<std::mutex> lock(protection_mutex);
  if (protection_lifecycle.IsActive(owner)) {
    return CloseEngineLocked();
  }
  return true;
}

bool IsNetworkProtectionActive(NetworkProtectionOwner owner) {
  if (!CanManageNetworkProtection()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(protection_mutex);
  return engine_handle != nullptr &&
         protection_lifecycle.IsActive(owner) && VerifyFiltersLocked();
}

bool IsTunnelNetworkProtectionActive(NetworkProtectionOwner owner) {
  if (!CanManageNetworkProtection()) {
    return false;
  }
  std::lock_guard<std::mutex> lock(protection_mutex);
  return engine_handle != nullptr &&
         protection_lifecycle.IsTunnel(owner) && VerifyFiltersLocked();
}

NetworkProtectionStatus GetNetworkProtectionStatus(NetworkProtectionOwner owner) {
  if (!CanManageNetworkProtection()) return {};
  std::lock_guard<std::mutex> lock(protection_mutex);
  return engine_handle && VerifyFiltersLocked() ? protection_lifecycle.Status(owner)
                        : NetworkProtectionStatus{};
}

bool IsNetworkProtectionStateKnown() {
  std::lock_guard<std::mutex> lock(protection_mutex);
  return VerifyFiltersLocked();
}

bool IsNetworkProtectionObservationCurrent(const NetworkProtectionObservation& observation) {
  std::unique_lock<std::mutex> lock(protection_mutex, std::try_to_lock);
  return lock.owns_lock() && observation.generation != 0 &&
         observation.generation == protection_generation;
}

NetworkProtectionObservation ObserveNetworkProtection() {
  NetworkProtectionObservation observation;
  if (!CanManageNetworkProtection()) return observation;
  std::vector<UINT64> identifiers;
  {
    std::unique_lock<std::mutex> lock(protection_mutex, std::try_to_lock);
    if (!lock.owns_lock()) return observation;
    observation.generation = protection_generation;
    if (engine_handle == nullptr) {
      observation.known = true;
      return observation;
    }
    const auto found = installed_filter_ids.find(engine_handle);
    if (found == installed_filter_ids.end() || found->second.empty()) return observation;
    identifiers = found->second;
    if (transient_engine_handle) {
      const auto transient = installed_filter_ids.find(transient_engine_handle);
      if (transient == installed_filter_ids.end()) return observation;
      identifiers.insert(identifiers.end(), transient->second.begin(), transient->second.end());
    }
    observation.wireguard = protection_lifecycle.Status(NetworkProtectionOwner::wire_guard);
    observation.openvpn = protection_lifecycle.Status(NetworkProtectionOwner::open_vpn);
  }
  // Never borrow engine_handle: disconnect can close the owning dynamic
  // session concurrently. This session performs only read operations.
  struct QuerySession {
    HANDLE handle = nullptr;
    ~QuerySession() { if (handle) FwpmEngineClose0(handle); }
  } query;
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &query.handle) != ERROR_SUCCESS)
    return observation;
  if (!fuzevpn_network_persistence::ProviderEnforced(query.handle)) return observation;
  for (const UINT64 id : identifiers) {
    if (!IsNetworkProtectionObservationCurrent(observation)) return observation;
    FWPM_FILTER0* filter = nullptr;
    const DWORD status = FwpmFilterGetById0(query.handle, id, &filter);
    const bool enforced = filter && (!(filter->flags & FWPM_FILTER_FLAG_DISABLED) ||
                                    (filter->flags & FWPM_FILTER_FLAG_BOOTTIME));
    if (filter) FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
    if (status != ERROR_SUCCESS || !enforced) return observation;
  }
  observation.known = IsNetworkProtectionObservationCurrent(observation);
  return observation;
}

std::uint64_t NetworkProtectionBootstrapTunnelLuid() {
  std::lock_guard<std::mutex> lock(protection_mutex);
  return VerifyFiltersLocked() ? protected_tunnel_luid : 0;
}
