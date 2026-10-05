// SPDX-License-Identifier: MPL-2.0
// Production WFP construction, intercepted entirely in memory. No engine,
// filter, interface or network connection is created on the test machine.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <rpc.h>
#include <softpub.h>
#include <wintrust.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "privileged_runtime.h"

namespace capture {
struct Condition {
  GUID field;
  FWP_MATCH_TYPE match;
  FWP_DATA_TYPE type;
  UINT64 integer = 0;
  std::wstring app;
  std::array<UINT8, 16> address{};
  UINT8 prefix = 128;
};
struct Filter {
  GUID layer;
  FWP_ACTION_TYPE action;
  bool permit_priority;
  std::vector<Condition> conditions;
};
struct Session { bool committed = false; std::vector<Filter> filters; bool query_only = false; };
std::map<HANDLE, Session> sessions;
std::vector<std::string> events;
ULONG_PTR next_handle = 0;
bool fail_commit = false;
bool missing_filter = false;
bool service_runtime = false;
std::set<void*> filter_queries;
int fail_filter_after = -1;
std::function<void()> before_query;
void Check(bool condition, const char* message) {
  if (!condition) { std::cerr << message << '\n'; std::exit(EXIT_FAILURE); }
}
}

bool CanManageNetworkProtection() { return true; }
bool IsVpnServiceRuntime() { return capture::service_runtime; }
LONG WINAPI FakeWinVerifyTrust(HWND, GUID*, LPVOID) { return ERROR_SUCCESS; }
DWORD WINAPI FakeGetModuleFileNameW(HMODULE, LPWSTR path, DWORD count) {
  const wchar_t fixed[] = L"C:\\Program Files\\FuzeVPN\\fuzevpn-service.exe";
  if (count < std::size(fixed)) return 0;
  std::memcpy(path, fixed, sizeof(fixed));
  return static_cast<DWORD>(std::size(fixed) - 1);
}
NETIO_STATUS WINAPI FakeConvertInterfaceLuidToIndex(const NET_LUID* luid, PNET_IFINDEX index) {
  *index = static_cast<NET_IFINDEX>(luid->Value);
  return *index ? NO_ERROR : ERROR_INVALID_PARAMETER;
}
DWORD WINAPI FakeFwpmEngineOpen0(const wchar_t*, UINT32, SEC_WINNT_AUTH_IDENTITY_W*,
                                const FWPM_SESSION0* session, HANDLE* out) {
  capture::Check(session == nullptr || session->flags == FWPM_SESSION_FLAG_DYNAMIC, "crash-lifetime remains explicit");
  *out = reinterpret_cast<HANDLE>(++capture::next_handle);
  capture::sessions[*out] = {};
  capture::sessions[*out].query_only = session == nullptr;
  capture::events.emplace_back("open");
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmEngineClose0(HANDLE engine) {
  capture::Check(capture::sessions.erase(engine) == 1, "known WFP session closed once");
  capture::events.emplace_back("close");
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmTransactionBegin0(HANDLE, UINT32) { return ERROR_SUCCESS; }
DWORD WINAPI FakeFwpmTransactionCommit0(HANDLE engine) {
  capture::events.emplace_back("commit");
  if (capture::fail_commit) return ERROR_ACCESS_DENIED;
  capture::sessions.at(engine).committed = true;
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmTransactionAbort0(HANDLE) {
  capture::events.emplace_back("abort");
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmSubLayerAdd0(HANDLE, const FWPM_SUBLAYER0*, PSECURITY_DESCRIPTOR) {
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmGetAppIdFromFileName0(PCWSTR path, FWP_BYTE_BLOB** out) {
  const auto bytes = (wcslen(path) + 1) * sizeof(wchar_t);
  auto* blob = new FWP_BYTE_BLOB{};
  blob->size = static_cast<UINT32>(bytes);
  blob->data = new UINT8[bytes];
  std::memcpy(blob->data, path, bytes);
  *out = blob;
  return ERROR_SUCCESS;
}
void WINAPI FakeFwpmFreeMemory0(void** memory) {
  if (capture::filter_queries.erase(*memory) != 0) {
    delete static_cast<FWPM_FILTER0*>(*memory);
    *memory = nullptr;
    return;
  }
  auto* blob = static_cast<FWP_BYTE_BLOB*>(*memory);
  delete[] blob->data; delete blob; *memory = nullptr;
}
DWORD WINAPI FakeFwpmFilterAdd0(HANDLE engine, const FWPM_FILTER0* filter,
                               PSECURITY_DESCRIPTOR, UINT64* id) {
  if (capture::fail_filter_after == 0) return ERROR_ACCESS_DENIED;
  if (capture::fail_filter_after > 0) --capture::fail_filter_after;
  capture::Filter copy{filter->layerKey, filter->action.type,
                       filter->weight.type == FWP_UINT8, {}};
  for (UINT32 i = 0; i < filter->numFilterConditions; ++i) {
    const auto& source = filter->filterCondition[i];
    const auto& value = source.conditionValue;
    capture::Condition condition{source.fieldKey, source.matchType, value.type};
    if (value.type == FWP_UINT8) condition.integer = value.uint8;
    else if (value.type == FWP_UINT16) condition.integer = value.uint16;
    else if (value.type == FWP_UINT32) condition.integer = value.uint32;
    else if (value.type == FWP_UINT64) condition.integer = *value.uint64;
    else if (value.type == FWP_BYTE_BLOB_TYPE)
      condition.app = reinterpret_cast<wchar_t*>(value.byteBlob->data);
    else if (value.type == FWP_BYTE_ARRAY16_TYPE)
      std::copy_n(value.byteArray16->byteArray16, 16, condition.address.begin());
    else if (value.type == FWP_V6_ADDR_MASK) {
      std::copy_n(value.v6AddrMask->addr, 16, condition.address.begin());
      condition.prefix = value.v6AddrMask->prefixLength;
    } else capture::Check(false, "unhandled condition type in test");
    copy.conditions.push_back(condition);
  }
  capture::sessions.at(engine).filters.push_back(copy);
  if (id) *id = capture::sessions.at(engine).filters.size();
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmFilterGetById0(HANDLE engine, UINT64 id, FWPM_FILTER0** filter) {
  if (capture::before_query) {
    const auto callback = std::move(capture::before_query);
    capture::before_query = {};
    callback();
  }
  if (capture::missing_filter)
    return static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND);
  const auto found = capture::sessions.find(engine);
  if (found == capture::sessions.end()) return ERROR_INVALID_HANDLE;
  if (found->second.query_only) {
    const bool present = std::any_of(capture::sessions.begin(), capture::sessions.end(),
        [id](const auto& entry) { return entry.second.committed && id != 0 && id <= entry.second.filters.size(); });
    if (!present) return static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND);
  } else if (!found->second.committed || id == 0 || id > found->second.filters.size()) return ERROR_INVALID_HANDLE;
  *filter = new FWPM_FILTER0{};
  capture::filter_queries.insert(*filter);
  return ERROR_SUCCESS;
}

#define GetModuleFileNameW FakeGetModuleFileNameW
#define ConvertInterfaceLuidToIndex FakeConvertInterfaceLuidToIndex
#define FwpmEngineOpen0 FakeFwpmEngineOpen0
#define FwpmEngineClose0 FakeFwpmEngineClose0
#define FwpmTransactionBegin0 FakeFwpmTransactionBegin0
#define FwpmTransactionCommit0 FakeFwpmTransactionCommit0
#define FwpmTransactionAbort0 FakeFwpmTransactionAbort0
#define FwpmSubLayerAdd0 FakeFwpmSubLayerAdd0
#define FwpmGetAppIdFromFileName0 FakeFwpmGetAppIdFromFileName0
#define FwpmFreeMemory0 FakeFwpmFreeMemory0
#define FwpmFilterAdd0 FakeFwpmFilterAdd0
#define FwpmFilterGetById0 FakeFwpmFilterGetById0
#define WinVerifyTrust FakeWinVerifyTrust
#include "../runner/network_protection.cpp"

namespace capture {
struct Flow {
  GUID layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  std::wstring app = L"ordinary-app.exe";
  UINT64 luid = 11;
  UINT64 protocol = IPPROTO_UDP;
  UINT64 local_port = 12345;
  UINT64 remote_port = 53;
  std::array<UINT8, 16> local_address{}, remote_address{};
};
bool AddressMatches(const std::array<UINT8, 16>& address, const Condition& condition) {
  for (unsigned bit = 0; bit < condition.prefix; ++bit) {
    const UINT8 mask = static_cast<UINT8>(0x80 >> (bit % 8));
    if ((address[bit / 8] & mask) != (condition.address[bit / 8] & mask)) return false;
  }
  return true;
}
bool Permitted(const Flow& flow) {
  // This models only our own sublayer's priority and conditions. It does not
  // claim to emulate Windows packet classification or other providers.
  for (const auto& entry : sessions) {
    if (!entry.second.committed) continue;
    bool matched = false;
    for (bool priority : {true, false}) {
      for (const auto& filter : entry.second.filters) {
        if (filter.permit_priority != priority || filter.layer != flow.layer) continue;
        bool matches = true;
        for (const auto& c : filter.conditions) {
          if (c.field == FWPM_CONDITION_ALE_APP_ID) matches &= c.app == flow.app;
          else if (c.field == FWPM_CONDITION_IP_LOCAL_INTERFACE) matches &= c.integer == flow.luid;
          else if (c.field == FWPM_CONDITION_IP_PROTOCOL) matches &= c.integer == flow.protocol;
          else if (c.field == FWPM_CONDITION_IP_REMOTE_PORT) matches &= c.integer == flow.remote_port;
          else if (c.field == FWPM_CONDITION_IP_LOCAL_PORT) matches &= c.integer == flow.local_port;
          else if (c.field == FWPM_CONDITION_IP_REMOTE_ADDRESS) matches &= AddressMatches(flow.remote_address, c);
          else if (c.field == FWPM_CONDITION_IP_LOCAL_ADDRESS) matches &= AddressMatches(flow.local_address, c);
          else if (c.field == FWPM_CONDITION_FLAGS) matches &= c.match == FWP_MATCH_FLAGS_NONE_SET;
          else Check(false, "unhandled condition field in test");
        }
        if (matches) {
          if (filter.action == FWP_ACTION_BLOCK) return false;
          matched = true;
          break;
        }
      }
      if (matched) break;
    }
  }
  return true;
}
void ControlTrafficAndDns() {
  wchar_t directory[MAX_PATH]{};
  GetSystemDirectoryW(directory, MAX_PATH);
  Flow flow;
  flow.app = std::wstring(directory) + L"\\svchost.exe";
  for (const GUID& layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    flow.layer = layer;
    for (auto protocol : {IPPROTO_TCP, IPPROTO_UDP}) {
      flow.protocol = protocol;
      for (auto port : {53, 853}) {
        flow.remote_port = port;
        Check(!Permitted(flow), "shared DNS service cannot cross physical interface");
      }
    }
  }
  flow.layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  flow.protocol = IPPROTO_UDP; flow.local_port = 68; flow.remote_port = 67;
  Check(Permitted(flow), "system DHCPv4 client permitted");
  flow.layer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
  Check(Permitted(flow), "system DHCPv4 reply permitted");
  flow.local_port = 12345;
  Check(!Permitted(flow), "arbitrary UDP to DHCP server port rejected");
  flow.local_port = 68; flow.app = L"ordinary-app.exe";
  Check(!Permitted(flow), "another executable cannot use DHCP exception");
  flow.app = std::wstring(directory) + L"\\svchost.exe";
  flow.layer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
  flow.local_port = 546; flow.remote_port = 547;
  flow.local_address[0] = 0xfe; flow.local_address[1] = 0x80;
  flow.remote_address[0] = 0xff; flow.remote_address[1] = 2;
  flow.remote_address[13] = 1; flow.remote_address[15] = 2;
  Check(Permitted(flow), "system DHCPv6 link-local discovery permitted");
  flow.remote_address[0] = 0x20;
  Check(!Permitted(flow), "DHCPv6 exception cannot contact global destination");
  flow.remote_address = {}; flow.remote_address[0] = 0xfe; flow.remote_address[1] = 0x80;
  Check(Permitted(flow), "DHCPv6 unicast renewal permitted");
  flow.layer = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
  Check(Permitted(flow), "DHCPv6 link-local reply permitted");
  flow.app = L"System"; flow.protocol = IPPROTO_ICMPV6; flow.remote_port = 0;
  flow.local_port = 134;
  Check(Permitted(flow), "link-local router advertisement permitted");
  flow.remote_address[0] = 0x20;
  Check(!Permitted(flow), "off-link router advertisement rejected");
  for (auto type : {135, 136}) {
    flow.local_port = type;
    Check(Permitted(flow), "neighbour discovery type/code permitted");
    flow.remote_port = 1;
    Check(!Permitted(flow), "wrong NDP code rejected");
    flow.remote_port = 0;
  }
  flow.local_port = 128;
  Check(!Permitted(flow), "general physical ICMPv6 echo remains blocked");
}
}

int main() {
  using namespace capture;
  const auto owner = NetworkProtectionOwner::open_vpn;
  const NetworkProtectionOptions options;
  Check(PrepareNetworkProtection(owner, options), "prepare production filters");
  Check(sessions.size() == 1, "one committed prepared session");
  ControlTrafficAndDns();
  Flow engine;
  engine.app = L"C:\\Program Files\\FuzeVPN\\fuzevpn-service.exe";
  Check(Permitted(engine), "native API resolver can send fixed bootstrap question");
  const auto original = sessions.begin()->first;
  fail_filter_after = 2;
  Check(!PromoteNetworkProtection(owner, 42, options), "injected filter failure rejects candidate");
  Check(sessions.size() == 1 && sessions.begin()->first == original &&
        GetNetworkProtectionStatus(owner).phase == NetworkProtectionStatus::Phase::prepared,
        "failed filter candidate preserves previous prepared policy");
  fail_filter_after = -1; fail_commit = true;
  Check(!PromoteNetworkProtection(owner, 42, options), "injected commit failure rejects candidate");
  Check(sessions.size() == 1 && sessions.begin()->first == original,
        "failed commit preserves previous session");
  fail_commit = false; events.clear();
  Check(PromoteNetworkProtection(owner, 42, options), "initial promotion succeeds");
  Check(events == std::vector<std::string>{"open", "commit", "close"},
        "actual production replacement commits candidate before closing old session");
  ControlTrafficAndDns();
  Flow tunnel;
  tunnel.luid = 42;
  Check(Permitted(tunnel), "ordinary DNS allowed over tunnel interface");
  events.clear();
  Check(PromoteNetworkProtection(owner, 43, options), "internal OpenVPN reconnect may repromote");
  Check(events == std::vector<std::string>{"open", "commit", "close"},
        "repeat promotion preserves replacement ordering");
  Check(!Permitted(tunnel), "old interface loses permit after reconnect");
  tunnel.luid = 43;
  Check(Permitted(tunnel), "replacement interface receives permit");
  Check(!PromoteNetworkProtection(NetworkProtectionOwner::wire_guard, 44, options),
        "another protocol cannot steal active prepared policy");
  Check(IsNetworkProtectionStateKnown() && IsNetworkProtectionActive(owner),
        "committed filter IDs are verified against the engine");
  const auto observation = ObserveNetworkProtection();
  Check(observation.known && observation.openvpn.active && !observation.wireguard.active &&
        IsNetworkProtectionObservationCurrent(observation) && sessions.size() == 1,
        "passive observation verifies IDs through an independent query session and closes it");
  {
    std::lock_guard<std::mutex> lock(protection_mutex);
    const auto contended = std::async(std::launch::async, [] { return ObserveNetworkProtection(); }).get();
    Check(!contended.known && contended.generation == 0,
          "passive observation returns unknown immediately when policy lock is busy");
  }
  missing_filter = true;
  Check(!ObserveNetworkProtection().known && sessions.size() == 1,
        "missing BFE filter yields unknown without closing the owning protection session");
  Check(!IsNetworkProtectionStateKnown() && !IsNetworkProtectionActive(owner) &&
        !IsTunnelNetworkProtectionActive(owner) && NetworkProtectionBootstrapTunnelLuid() == 0,
        "lost BFE filters cannot be reported active from retained metadata");
  Check(!PromoteNetworkProtection(owner, 44, options),
        "promotion cannot trust a prepared policy that BFE has lost");
  missing_filter = false;
  Check(IsNetworkProtectionStateKnown(), "transient inspection failure preserves retryable metadata");
  Check(filter_queries.empty(), "filter inspection releases every queried WFP allocation");
  DisableNetworkProtection(owner);
  Check(sessions.empty(), "explicit disconnect closes final dynamic session");
  Check(!IsNetworkProtectionObservationCurrent(observation) && ObserveNetworkProtection().known,
        "disconnect invalidates old samples while confirmed local absence is observable");
  Check(PrepareNetworkProtection(owner, options), "prepare concurrent diagnostic fixture");
  before_query = [&] {
    // This would deadlock if the observer held the policy mutex across the WFP
    // call; it models a disconnect completing while the system call is pending.
    DisableNetworkProtection(owner);
  };
  const auto interrupted = ObserveNetworkProtection();
  Check(!interrupted.known && !IsNetworkProtectionObservationCurrent(interrupted) && sessions.empty(),
        "concurrent disconnect is not blocked and invalidates the diagnostic result");
  const std::wstring portable_ui = L"D:\\Portable FuzeVPN\\fuzevpn_windows.exe";
  Check(!SetAuthenticatedBrokerUiPath(L"relative\\fuzevpn_windows.exe") &&
        !SetAuthenticatedBrokerUiPath(L"D:\\Portable FuzeVPN\\other.exe"),
        "broker frontend override requires a canonical GUI executable path");
  Check(SetAuthenticatedBrokerUiPath(portable_ui), "authenticated portable frontend path accepted before filters");
  Check(PrepareNetworkProtection(owner, options), "portable preparation keeps production filtering");
  Flow frontend; frontend.app = portable_ui;
  Check(Permitted(frontend), "prepared broker policy permits the authenticated portable GUI");
  frontend.app = L"C:\\Program Files\\FuzeVPN\\fuzevpn_windows.exe";
  Check(!Permitted(frontend), "portable broker does not grant an obsolete sibling GUI exception");
  Check(!SetAuthenticatedBrokerUiPath(L"D:\\Another\\fuzevpn_windows.exe"),
        "active policy cannot change its pinned frontend identity");
  ClearAuthenticatedBrokerUiPath();
  std::wstring retained;
  Check(PreConnectUiPath(engine.app, &retained) && retained == portable_ui,
        "cleanup cannot clear the authenticated path while filters remain active");
  ControlTrafficAndDns();
  DisableNetworkProtection(owner);
  ClearAuthenticatedBrokerUiPath();
  Check(SetAuthenticatedBrokerUiPath(portable_ui), "broker path can be set for another isolated runtime");
  service_runtime = true;
  Check(!SetAuthenticatedBrokerUiPath(portable_ui), "persistent service cannot take a portable path override");
  Check(PrepareNetworkProtection(owner, options), "installed service preparation still succeeds");
  Check(Permitted(frontend), "installed service retains its installed sibling GUI");
  frontend.app = portable_ui;
  Check(!Permitted(frontend), "installed service ignores a broker-only frontend path");
  DisableNetworkProtection(owner);
  service_runtime = false;
  ClearAuthenticatedBrokerUiPath();
  std::cout << "Production network filter construction tests passed (no packets or WFP changes)\n";
  return EXIT_SUCCESS;
}
