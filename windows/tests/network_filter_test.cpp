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
#include <memory>
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
  UINT64 id = 0;
  UINT32 flags = 0;
  GUID key{};
  std::vector<UINT8> metadata;
  HANDLE dynamic_owner = nullptr;
  GUID provider{};
  GUID sublayer{};
};
struct Session {
  bool committed = false;
  std::vector<Filter> filters;
  bool dynamic = false;
  std::vector<UINT64> deleted;
  bool remove_provider = false;
  bool add_provider = false;
  bool add_layer = false;
};
std::map<HANDLE, Session> sessions;
std::map<UINT64, Filter> active_filters;
bool provider_present = false, layer_present = false;
bool disabled_provider = false;
UINT64 next_filter_id = 0;
struct QueryAllocation { FWPM_FILTER0 filter{}; GUID provider{}; std::vector<UINT8> metadata; };
std::map<void*, std::unique_ptr<QueryAllocation>> query_allocations;
std::map<void*, std::vector<std::unique_ptr<QueryAllocation>>> enum_allocations;
std::map<HANDLE, std::pair<std::vector<UINT64>, size_t>> enumerations;
std::vector<std::string> events;
ULONG_PTR next_handle = 0;
bool fail_commit = false;
int fail_commit_after = -1;
bool missing_filter = false;
bool disabled_filter = false;
bool service_runtime = false;
std::set<void*> filter_queries;
std::set<void*> provider_queries;
int fail_filter_after = -1;
int fail_enum_after = -1;
std::function<void()> before_query;
void Check(bool condition, const char* message) {
  if (!condition) { std::cerr << message << '\n'; std::exit(EXIT_FAILURE); }
}
void CheckManagementAcl(PSECURITY_DESCRIPTOR descriptor) {
  Check(descriptor != nullptr, "explicit management ACL is present");
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  Check(GetSecurityDescriptorControl(descriptor, &control, &revision) && (control & SE_DACL_PROTECTED),
        "WFP ACL does not inherit weaker rights");
  PACL acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
  Check(GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) && present && acl,
        "WFP ACL contains explicit permissions");
  for (DWORD index = 0; index < acl->AceCount; ++index) {
    void* raw = nullptr;
    Check(GetAce(acl, index, &raw) != FALSE, "inspect every WFP ACL entry");
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
    Check(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "known ACL entry type");
    if (ace->Mask & (GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER)) {
      PSID sid = const_cast<DWORD*>(&ace->SidStart);
      Check(IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid),
            "only SYSTEM or elevated administrators may mutate protection");
    }
  }
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
  capture::Check(session == nullptr || session->flags == 0 || session->flags == FWPM_SESSION_FLAG_DYNAMIC,
                 "persistent baseline and transient exceptions have separate lifetimes");
  *out = reinterpret_cast<HANDLE>(++capture::next_handle);
  capture::sessions[*out] = {};
  capture::sessions[*out].dynamic = session && (session->flags & FWPM_SESSION_FLAG_DYNAMIC);
  capture::events.emplace_back("open");
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmEngineClose0(HANDLE engine) {
  for (auto it = capture::active_filters.begin(); it != capture::active_filters.end();) {
    if (it->second.dynamic_owner == engine) it = capture::active_filters.erase(it);
    else ++it;
  }
  capture::Check(capture::sessions.erase(engine) == 1, "known WFP session closed once");
  capture::events.emplace_back("close");
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmTransactionBegin0(HANDLE engine, UINT32) {
  auto& session = capture::sessions.at(engine);
  session.filters.clear(); session.deleted.clear();
  session.add_provider = session.add_layer = session.remove_provider = false;
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmTransactionCommit0(HANDLE engine) {
  capture::events.emplace_back("commit");
  if (capture::fail_commit || capture::fail_commit_after == 0) return ERROR_ACCESS_DENIED;
  if (capture::fail_commit_after > 0) --capture::fail_commit_after;
  auto& session = capture::sessions.at(engine);
  for (const auto id : session.deleted) capture::active_filters.erase(id);
  for (const auto& filter : session.filters) capture::active_filters[filter.id] = filter;
  if (session.remove_provider) capture::provider_present = capture::layer_present = false;
  if (session.add_provider) { capture::provider_present = true; capture::disabled_provider = false; }
  if (session.add_layer) capture::layer_present = true;
  session.committed = true;
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmTransactionAbort0(HANDLE engine) {
  auto& session = capture::sessions.at(engine);
  session.filters.clear(); session.deleted.clear();
  session.add_provider = session.add_layer = session.remove_provider = false;
  capture::events.emplace_back("abort");
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmSubLayerAdd0(HANDLE engine, const FWPM_SUBLAYER0* layer, PSECURITY_DESCRIPTOR security) {
  capture::Check(security && (layer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT), "persistent sublayer ACL supplied");
  capture::CheckManagementAcl(security);
  if (capture::layer_present && !capture::sessions.at(engine).remove_provider) return static_cast<DWORD>(FWP_E_ALREADY_EXISTS);
  capture::sessions.at(engine).add_layer = true;
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmProviderAdd0(HANDLE engine, const FWPM_PROVIDER0* provider, PSECURITY_DESCRIPTOR security) {
  capture::Check(security && (provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT), "persistent provider ACL supplied");
  capture::CheckManagementAcl(security);
  if (capture::provider_present && !capture::sessions.at(engine).remove_provider) return static_cast<DWORD>(FWP_E_ALREADY_EXISTS);
  capture::sessions.at(engine).add_provider = true;
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmProviderDeleteByKey0(HANDLE engine, const GUID*) {
  capture::sessions.at(engine).remove_provider = true;
  return capture::provider_present ? ERROR_SUCCESS : static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND);
}
DWORD WINAPI FakeFwpmProviderGetByKey0(HANDLE, const GUID*, FWPM_PROVIDER0** result) {
  if (!capture::provider_present) return static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND);
  *result = new FWPM_PROVIDER0{};
  (*result)->flags = FWPM_PROVIDER_FLAG_PERSISTENT | (capture::disabled_provider ? FWPM_PROVIDER_FLAG_DISABLED : 0);
  capture::provider_queries.insert(*result);
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmSubLayerDeleteByKey0(HANDLE, const GUID*) {
  return capture::layer_present ? ERROR_SUCCESS : static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND);
}
DWORD WINAPI FakeFwpmFilterDeleteById0(HANDLE engine, UINT64 id) {
  capture::Check(capture::active_filters.at(id).dynamic_owner == nullptr,
                 "another session cannot delete a dynamic exception");
  capture::sessions.at(engine).deleted.push_back(id);
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
  if (capture::provider_queries.erase(*memory)) {
    delete static_cast<FWPM_PROVIDER0*>(*memory); *memory = nullptr; return;
  }
  if (capture::enum_allocations.erase(*memory)) {
    delete[] static_cast<FWPM_FILTER0**>(*memory); *memory = nullptr; return;
  }
  if (capture::filter_queries.erase(*memory) != 0) {
    capture::query_allocations.erase(*memory);
    *memory = nullptr;
    return;
  }
  auto* blob = static_cast<FWP_BYTE_BLOB*>(*memory);
  delete[] blob->data; delete blob; *memory = nullptr;
}
DWORD WINAPI FakeFwpmFilterAdd0(HANDLE engine, const FWPM_FILTER0* filter,
                               PSECURITY_DESCRIPTOR security, UINT64* id) {
  capture::Check(security != nullptr, "each filter has an explicit management ACL");
  capture::CheckManagementAcl(security);
  if (capture::fail_filter_after == 0) return ERROR_ACCESS_DENIED;
  if (capture::fail_filter_after > 0) --capture::fail_filter_after;
  capture::Filter copy{filter->layerKey, filter->action.type,
                       filter->weight.type == FWP_UINT8, {}};
  copy.id = ++capture::next_filter_id;
  copy.flags = filter->flags;
  copy.key = filter->filterKey;
  copy.provider = *filter->providerKey;
  copy.sublayer = filter->subLayerKey;
  if (filter->providerData.size) copy.metadata.assign(filter->providerData.data,
      filter->providerData.data + filter->providerData.size);
  const bool dynamic = capture::sessions.at(engine).dynamic;
  capture::Check(dynamic != ((filter->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME)) != 0) &&
        ((filter->flags & (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME)) !=
          (FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_BOOTTIME)),
                 "only runtime exceptions are dynamic; all baseline filters persist");
  if (dynamic) copy.dynamic_owner = engine;
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
  if (id) *id = copy.id;
  return ERROR_SUCCESS;
}
std::unique_ptr<capture::QueryAllocation> CopyQuery(const capture::Filter& source) {
  auto allocation = std::make_unique<capture::QueryAllocation>();
  allocation->filter.filterId = source.id;
  allocation->filter.filterKey = source.key;
  allocation->filter.flags = source.flags;
  allocation->filter.layerKey = source.layer;
  allocation->filter.subLayerKey = source.sublayer;
  allocation->provider = source.provider;
  allocation->filter.providerKey = &allocation->provider;
  allocation->metadata = source.metadata;
  allocation->filter.providerData = {static_cast<UINT32>(allocation->metadata.size()), allocation->metadata.data()};
  return allocation;
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
  const auto active = capture::active_filters.find(id);
  if (active == capture::active_filters.end()) return static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND);
  auto allocation = CopyQuery(active->second);
  if (capture::disabled_filter) allocation->filter.flags |= FWPM_FILTER_FLAG_DISABLED;
  *filter = &allocation->filter;
  capture::query_allocations[*filter] = std::move(allocation);
  capture::filter_queries.insert(*filter);
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmFilterGetByKey0(HANDLE engine, const GUID* key, FWPM_FILTER0** filter) {
  for (const auto& [id, value] : capture::active_filters)
    if (IsEqualGUID(value.key, *key)) return FakeFwpmFilterGetById0(engine, id, filter);
  return static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND);
}
DWORD WINAPI FakeFwpmFilterCreateEnumHandle0(HANDLE engine, const FWPM_FILTER_ENUM_TEMPLATE0* specification, HANDLE* handle) {
  // Match the real API: a non-null template with GUID_NULL layer is invalid.
  if (specification && IsEqualGUID(specification->layerKey, GUID{}))
    return static_cast<DWORD>(FWP_E_LAYER_NOT_FOUND);
  if (specification && specification->providerKey &&
      !capture::provider_present && !capture::sessions.at(engine).add_provider)
    return static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND);
  *handle = reinterpret_cast<HANDLE>(++capture::next_handle);
  auto& state = capture::enumerations[*handle];
  for (const auto& [id, filter] : capture::active_filters)
    if ((!specification || !specification->providerKey || IsEqualGUID(filter.provider, *specification->providerKey)) &&
        std::find(capture::sessions.at(engine).deleted.begin(), capture::sessions.at(engine).deleted.end(), id) ==
            capture::sessions.at(engine).deleted.end()) state.first.push_back(id);
  return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmFilterDestroyEnumHandle0(HANDLE, HANDLE enumeration) {
  capture::enumerations.erase(enumeration); return ERROR_SUCCESS;
}
DWORD WINAPI FakeFwpmFilterEnum0(HANDLE, HANDLE enumeration, UINT32 requested, FWPM_FILTER0*** filters, UINT32* count) {
  if (capture::fail_enum_after == 0) return ERROR_ACCESS_DENIED;
  if (capture::fail_enum_after > 0) --capture::fail_enum_after;
  auto& [identifiers, offset] = capture::enumerations.at(enumeration);
  *count = static_cast<UINT32>((std::min)(size_t(requested), identifiers.size() - offset));
  if (!*count) { *filters = nullptr; return ERROR_SUCCESS; }
  *filters = new FWPM_FILTER0*[*count];
  auto& allocations = capture::enum_allocations[*filters];
  for (UINT32 i = 0; i < *count; ++i) {
    allocations.push_back(CopyQuery(capture::active_filters.at(identifiers[offset++])));
    (*filters)[i] = &allocations.back()->filter;
  }
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
#define FwpmProviderAdd0 FakeFwpmProviderAdd0
#define FwpmProviderGetByKey0 FakeFwpmProviderGetByKey0
#define FwpmProviderDeleteByKey0 FakeFwpmProviderDeleteByKey0
#define FwpmSubLayerDeleteByKey0 FakeFwpmSubLayerDeleteByKey0
#define FwpmFilterDeleteById0 FakeFwpmFilterDeleteById0
#define FwpmFilterGetByKey0 FakeFwpmFilterGetByKey0
#define FwpmFilterCreateEnumHandle0 FakeFwpmFilterCreateEnumHandle0
#define FwpmFilterDestroyEnumHandle0 FakeFwpmFilterDestroyEnumHandle0
#define FwpmFilterEnum0 FakeFwpmFilterEnum0
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
    for (bool priority : {true, false}) {
      for (const auto& [id, filter] : active_filters) {
        (void)id;
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
          return true;
        }
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
  fuzevpn_network_failure::Clear();
  std::thread diagnostic_worker([] {
    fuzevpn_network_failure::Capture(fuzevpn_network_failure::Stage::filter_enum_create,
        static_cast<DWORD>(FWP_E_LAYER_NOT_FOUND));
  });
  diagnostic_worker.join();
  fuzevpn_network_failure::Capture(fuzevpn_network_failure::Stage::transaction_commit, ERROR_ACCESS_DENIED);
  Check(std::string(fuzevpn_network_failure::Read().stage) == "wfp_filter_enum_create" &&
      fuzevpn_network_failure::Read().status == static_cast<DWORD>(FWP_E_LAYER_NOT_FOUND),
      "broker receives the worker's exact first WFP API error without cleanup replacing it");
  fuzevpn_network_failure::Clear();
  {
    HANDLE inspection = nullptr;
    Check(FakeFwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &inspection) == ERROR_SUCCESS,
          "open isolated cleanup fixture");
    FWPM_FILTER_ENUM_TEMPLATE0 invalid{};
    invalid.providerKey = const_cast<GUID*>(&fuzevpn_network_persistence::kProvider);
    HANDLE enumeration = nullptr;
    Check(FakeFwpmFilterCreateEnumHandle0(inspection, &invalid, &enumeration) ==
              static_cast<DWORD>(FWP_E_LAYER_NOT_FOUND),
          "the regression double rejects a null layer exactly like Windows");
    std::vector<UINT64> fixture_ids;
    for (unsigned kind = 0; kind < 5; ++kind) {
      Filter filter{};
      filter.id = ++next_filter_id;
      filter.layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
      filter.provider = fuzevpn_network_persistence::kProvider;
      filter.sublayer = fuzevpn_network_persistence::kSublayer;
      filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
      if (kind == 0) filter.flags = FWPM_FILTER_FLAG_BOOTTIME;
      if (kind == 1) filter.flags |= FWPM_FILTER_FLAG_DISABLED;
      if (kind == 2) filter.provider.Data1 ^= 1;
      if (kind == 3) filter.sublayer.Data1 ^= 1;
      if (kind == 4) filter.flags = 0;
      fixture_ids.push_back(filter.id);
      active_filters[filter.id] = filter;
    }
    fail_enum_after = 1;
    Check(fuzevpn_network_persistence::RemoveInTransaction(inspection, true) == ERROR_ACCESS_DENIED &&
        sessions.at(inspection).deleted.empty() && enumerations.empty() && enum_allocations.empty(),
        "incomplete enumeration frees resources and deletes no filter");
    Check(std::string(fuzevpn_network_failure::Read().stage) == "wfp_filter_enum" &&
        fuzevpn_network_failure::Read().status == ERROR_ACCESS_DENIED,
        "enumeration failure preserves the exact API and returned Windows status");
    fail_enum_after = -1;
    fuzevpn_network_failure::Clear();
    Check(fuzevpn_network_persistence::RemoveInTransaction(inspection, true) == ERROR_SUCCESS,
          "global enumeration succeeds without an invalid layer template");
    Check(sessions.at(inspection).deleted == std::vector<UINT64>{fixture_ids[0], fixture_ids[1]},
          "only owned persistent/boot filters selected: foreign providers, sublayers and transient filters survive");
    Check(enumerations.empty() && enum_allocations.empty(), "cleanup enumeration resources released");
    FakeFwpmEngineClose0(inspection);
    for (const auto id : fixture_ids) active_filters.erase(id);
  }
  const auto owner = NetworkProtectionOwner::open_vpn;
  const NetworkProtectionOptions options;
  Check(SetNetworkProtectionUser("S-1-5-21-123-456-789-1001"), "authenticated Windows owner bound before persistence");
  Check(PrepareNetworkProtection(owner, options), "prepare production filters");
  Check(sessions.size() == 2, "persistent baseline and dynamic prepared exceptions committed");
  Check(std::count_if(active_filters.begin(), active_filters.end(), [](const auto& entry) {
      return (entry.second.flags & FWPM_FILTER_FLAG_BOOTTIME) && entry.second.action == FWP_ACTION_BLOCK;
    }) == 4, "four boot-time packet blocks cover IPv4 IPv6 inbound and outbound before BFE initializes");
  ControlTrafficAndDns();
  Flow engine;
  engine.app = L"C:\\Program Files\\FuzeVPN\\fuzevpn-service.exe";
  Check(Permitted(engine), "native API resolver can send fixed bootstrap question");
  const auto original = sessions.begin()->first;
  fail_filter_after = 2;
  Check(!PromoteNetworkProtection(owner, 42, options), "injected filter failure rejects candidate");
  Check(std::string(fuzevpn_network_failure::Read().stage) == "wfp_filter_add" &&
      fuzevpn_network_failure::Read().status == ERROR_ACCESS_DENIED,
      "filter setup preserves its first Windows failure through transaction abort");
  Check(sessions.size() == 2 && sessions.begin()->first == original &&
        GetNetworkProtectionStatus(owner).phase == NetworkProtectionStatus::Phase::prepared,
        "failed filter candidate preserves previous prepared policy");
  fail_filter_after = -1; fail_commit = true;
  Check(!PromoteNetworkProtection(owner, 42, options), "injected commit failure rejects candidate");
  Check(std::string(fuzevpn_network_failure::Read().stage) == "wfp_transaction_commit" &&
      fuzevpn_network_failure::Read().status == ERROR_ACCESS_DENIED,
      "next attempt resets previous failure and preserves its own commit status");
  Check(sessions.size() == 2 && sessions.begin()->first == original,
        "failed commit preserves previous session");
  fail_commit = false; events.clear();
  Check(PromoteNetworkProtection(owner, 42, options), "initial promotion succeeds");
  Check(events == std::vector<std::string>{"open", "commit", "open", "commit", "close", "close"},
        "actual production replacement commits candidate before closing old session");
  ControlTrafficAndDns();
  Flow tunnel;
  tunnel.luid = 42;
  Check(Permitted(tunnel), "ordinary DNS allowed over tunnel interface");
  events.clear();
  Check(PromoteNetworkProtection(owner, 43, options), "internal OpenVPN reconnect may repromote");
  Check(events == std::vector<std::string>{"open", "commit", "open", "commit", "close", "close"},
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
        IsNetworkProtectionObservationCurrent(observation) && sessions.size() == 2,
        "passive observation verifies IDs through an independent query session and closes it");
  {
    std::lock_guard<std::mutex> lock(protection_mutex);
    const auto contended = std::async(std::launch::async, [] { return ObserveNetworkProtection(); }).get();
    Check(!contended.known && contended.generation == 0,
          "passive observation returns unknown immediately when policy lock is busy");
  }
  missing_filter = true;
  Check(!ObserveNetworkProtection().known && sessions.size() == 2,
        "missing BFE filter yields unknown without closing the owning protection session");
  Check(!IsNetworkProtectionStateKnown() && !IsNetworkProtectionActive(owner) &&
        !IsTunnelNetworkProtectionActive(owner) && NetworkProtectionBootstrapTunnelLuid() == 0,
        "lost BFE filters cannot be reported active from retained metadata");
  Check(!PromoteNetworkProtection(owner, 44, options),
        "promotion cannot trust a prepared policy that BFE has lost");
  missing_filter = false;
  Check(IsNetworkProtectionStateKnown(), "transient inspection failure preserves retryable metadata");
  disabled_filter = true;
  Check(!IsNetworkProtectionStateKnown() && !ObserveNetworkProtection().known && !IsNetworkProtectionActive(owner),
        "existing disabled filters cannot be reported as enforced protection");
  disabled_filter = false;
  disabled_provider = true;
  Check(!IsNetworkProtectionStateKnown() && !ObserveNetworkProtection().known && !IsNetworkProtectionActive(owner),
        "disabled provider cannot be reported as enforced even if filter IDs still exist");
  Check(protection_lifecycle.IsActive(owner), "unavailable enforcement preserves the Windows owner's retained policy metadata");
  disabled_provider = false;
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
  Check(SetNetworkProtectionUser("S-1-5-21-123-456-789-1001") && PrepareNetworkProtection(owner, options),
        "prepare persistent crash fixture");
  Flow physical;
  physical.protocol = IPPROTO_TCP; physical.remote_port = 443;
  Flow permitted_ui = physical;
  permitted_ui.app = L"C:\\Program Files\\FuzeVPN\\fuzevpn_windows.exe";
  Check(Permitted(permitted_ui), "prepared UI exception exists only while runtime lives");
  // Simulate all process handles disappearing. Persistent BFE objects are a
  // separate database; only the dynamic UI/tunnel exceptions disappear.
  CloseEngine(&engine_handle);
  CloseEngine(&transient_engine_handle);
  protection_lifecycle.Clear();
  protection_intent = {};
  Check(sessions.empty() && !active_filters.empty() && provider_present &&
        !Permitted(physical) && !Permitted(permitted_ui),
        "crash preserves fail-closed baseline and removes the UI exception");
  for (const auto& layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                           FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    for (const auto protocol : {IPPROTO_TCP, IPPROTO_UDP}) {
      for (const UINT64 port : {UINT64(53), UINT64(853), UINT64(443)}) {
        Flow rejected = physical; rejected.layer = layer; rejected.protocol = protocol; rejected.remote_port = port;
        Check(!Permitted(rejected), "crash baseline blocks both families, directions and DNS/HTTPS transports");
      }
    }
  }
  std::string restored_user;
  fail_commit = true;
  Check(!RestoreNetworkProtection(&restored_user) && !Permitted(physical),
        "failed startup restoration never removes surviving baseline");
  fail_commit = false;
  disabled_provider = true;
  Check(RestoreNetworkProtection(&restored_user) && restored_user == "S-1-5-21-123-456-789-1001" &&
        GetNetworkProtectionStatus(owner).phase == NetworkProtectionStatus::Phase::prepared &&
        !Permitted(permitted_ui) && !disabled_provider && NetworkProtectionBootstrapTunnelLuid() == 0,
        "startup recovers SID and conservative prepared policy without stale UI or tunnel permission");
  Check(!SetNetworkProtectionUser("S-1-5-21-123-456-789-1002"),
        "another Windows user cannot take over retained protection");
  fail_commit_after = 1;
  Check(!PromoteNetworkProtection(owner, 70, options) && IsNetworkProtectionActive(owner) &&
        GetNetworkProtectionStatus(owner).phase == NetworkProtectionStatus::Phase::prepared && !Permitted(physical),
        "failed dynamic exception commit publishes only the committed conservative baseline");
  fail_commit_after = -1;
  Check(PromoteNetworkProtection(owner, 71, options), "restore may reconnect under same intent");
  Flow restored_tunnel = physical; restored_tunnel.luid = 71;
  Check(Permitted(restored_tunnel), "live tunnel exception is dynamic");
  CloseEngine(&engine_handle); CloseEngine(&transient_engine_handle); protection_lifecycle.Clear();
  Check(!Permitted(restored_tunnel) && !Permitted(physical),
        "crash cannot retain a tunnel LUID permit that might be reused after reboot");
  Check(RestoreNetworkProtection(&restored_user), "restore after tunnel crash");
  {
    ScopedNetworkProtectionRetention retain_policy;
    Check(DisableNetworkProtection(owner) && IsNetworkProtectionActive(owner),
          "internal runtime stop cannot erase persistent intent");
  }
  fail_commit = true;
  Check(!DisableNetworkProtection(owner) && !Permitted(physical),
        "failed explicit cleanup retains fail-closed policy and reports failure");
  fail_commit = false;
  Check(DisableNetworkProtection(owner) && active_filters.empty() && !provider_present,
        "successful explicit disconnect atomically removes policy and durable intent");
  Check(RestoreNetworkProtection(&restored_user) && restored_user.empty() && active_filters.empty(),
        "a later startup never rearms protection deliberately disconnected");
  Check(SetNetworkProtectionUser("S-1-5-21-123-456-789-1001") && PrepareNetworkProtection(owner, options),
        "prepare explicit administrator recovery fixture");
  CloseEngine(&engine_handle); CloseEngine(&transient_engine_handle); protection_lifecycle.Clear();
  fail_commit = true;
  Check(fuzevpn_network_persistence::RemoveForMaintenance() == ERROR_ACCESS_DENIED && !active_filters.empty() &&
        !Permitted(physical), "failed maintenance transaction leaves orphaned guard intact");
  fail_commit = false;
  Filter unrelated{};
  unrelated.id = ++next_filter_id;
  unrelated.flags = FWPM_FILTER_FLAG_PERSISTENT;
  unrelated.provider.Data1 = 0x87654321;
  active_filters[unrelated.id] = unrelated;
  Check(fuzevpn_network_persistence::RemoveForMaintenance() == ERROR_SUCCESS && active_filters.size() == 1 &&
        active_filters.count(unrelated.id) == 1 &&
        !provider_present, "authorized maintenance can recover an orphaned portable guard");
  active_filters.erase(unrelated.id);
  Check(SetNetworkProtectionUser("S-1-5-21-123-456-789-1001") && PrepareNetworkProtection(owner, options),
        "prepare unknown future metadata fixture");
  for (auto& [id, filter] : active_filters) {
    (void)id;
    if (!filter.metadata.empty()) filter.metadata[4] = 99;
  }
  CloseEngine(&engine_handle); CloseEngine(&transient_engine_handle); protection_lifecycle.Clear();
  Check(!RestoreNetworkProtection(&restored_user) && !Permitted(physical),
        "unsupported persistent intent version stays fail-closed instead of inventing an owner");
  Check(fuzevpn_network_persistence::RemoveForMaintenance() == ERROR_SUCCESS && active_filters.empty(),
        "administrator recovery remains available for unsupported or damaged intent metadata");
  std::cout << "Production network filter construction tests passed (no packets or WFP changes)\n";
  return EXIT_SUCCESS;
}
