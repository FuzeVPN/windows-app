// Executes the production read-only recovery proof against in-memory Windows
// adapters. No network, service, process or machine registry state is changed.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <tlhelp32.h>
#include <cstring>
#include <iostream>
#include <string>

namespace {
DWORD process_error = ERROR_SUCCESS;
DWORD wfp_error = ERROR_SUCCESS;
DWORD filter_error = ERROR_SUCCESS;
DWORD route_error = ERROR_SUCCESS;
DWORD adapter_error = ERROR_SUCCESS;
LSTATUS nrpt_error = ERROR_SUCCESS;
bool runtime_process = false;
bool filter_present = false;
bool layer_present = false;
bool app_condition = false;
bool adapter_up = false;
bool adapter_addresses = false;
bool adapter_routes = false;
bool nrpt_present = false;
std::wstring filter_name;
std::wstring layer_name;
std::wstring adapter_name;
std::wstring adapter_description;
std::wstring nrpt_name;
unsigned filter_calls = 0;
unsigned layer_calls = 0;
unsigned registry_reads = 0;
FWPM_FILTER0 fixture_filter{};
FWPM_SUBLAYER0 fixture_layer{};
FWPM_FILTER_CONDITION0 fixture_condition{};
FWP_BYTE_BLOB fixture_blob{};
MIB_IPFORWARD_TABLE2 fixture_routes{};
IP_ADAPTER_UNICAST_ADDRESS unicast{};

HANDLE WINAPI ProofSnapshot(DWORD, DWORD) {
  if (process_error != ERROR_SUCCESS) { SetLastError(process_error); return INVALID_HANDLE_VALUE; }
  return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(20));
}
BOOL WINAPI ProofProcessFirst(HANDLE, LPPROCESSENTRY32W process) {
  if (!runtime_process) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
  wcscpy_s(process->szExeFile, L"fuzevpn-service.exe"); return TRUE;
}
BOOL WINAPI ProofProcessNext(HANDLE, LPPROCESSENTRY32W) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
BOOL WINAPI ProofCloseHandle(HANDLE) { return TRUE; }
DWORD WINAPI ProofEngineOpen(const wchar_t*, UINT32, SEC_WINNT_AUTH_IDENTITY_W*,
    const FWPM_SESSION0*, HANDLE* engine) {
  *engine = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(21)); return wfp_error;
}
DWORD WINAPI ProofEngineClose(HANDLE) { return ERROR_SUCCESS; }
DWORD WINAPI ProofFilterCreate(HANDLE, const FWPM_FILTER_ENUM_TEMPLATE0*, HANDLE* enumeration) {
  filter_calls = 0; *enumeration = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(22)); return ERROR_SUCCESS;
}
DWORD WINAPI ProofFilterEnum(HANDLE, HANDLE, UINT32, FWPM_FILTER0*** result, UINT32* count) {
  static FWPM_FILTER0* entries[] = {&fixture_filter};
  *result = entries; *count = filter_present && filter_calls++ == 0 ? 1 : 0; return filter_error;
}
DWORD WINAPI ProofFilterDestroy(HANDLE, HANDLE) { return ERROR_SUCCESS; }
DWORD WINAPI ProofLayerCreate(HANDLE, const FWPM_SUBLAYER_ENUM_TEMPLATE0*, HANDLE* enumeration) {
  layer_calls = 0; *enumeration = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(23)); return ERROR_SUCCESS;
}
DWORD WINAPI ProofLayerEnum(HANDLE, HANDLE, UINT32, FWPM_SUBLAYER0*** result, UINT32* count) {
  static FWPM_SUBLAYER0* entries[] = {&fixture_layer};
  *result = entries; *count = layer_present && layer_calls++ == 0 ? 1 : 0; return ERROR_SUCCESS;
}
DWORD WINAPI ProofLayerDestroy(HANDLE, HANDLE) { return ERROR_SUCCESS; }
void WINAPI ProofFreeWfp(void** value) { *value = nullptr; }
NETIO_STATUS WINAPI ProofRoutes(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2* result) {
  fixture_routes = {}; fixture_routes.NumEntries = adapter_routes ? 1 : 0;
  fixture_routes.Table[0].InterfaceLuid.Value = 123;
  *result = &fixture_routes; return route_error;
}
void WINAPI ProofFreeRoutes(void*) {}
ULONG WINAPI ProofAdapters(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES adapter, PULONG bytes) {
  if (adapter_error != ERROR_SUCCESS) return adapter_error;
  if (*bytes < sizeof(*adapter)) { *bytes = sizeof(*adapter); return ERROR_BUFFER_OVERFLOW; }
  *adapter = {};
  adapter->FriendlyName = adapter_name.data(); adapter->Description = adapter_description.data();
  adapter->Luid.Value = 123;
  adapter->OperStatus = adapter_up ? IfOperStatusUp : IfOperStatusDown;
  adapter->FirstUnicastAddress = adapter_addresses ? &unicast : nullptr;
  return ERROR_SUCCESS;
}
LSTATUS WINAPI ProofOpenKey(HKEY, LPCWSTR, DWORD, REGSAM access, PHKEY key) {
  ++registry_reads;
  if (access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE)) return ERROR_ACCESS_DENIED;
  *key = reinterpret_cast<HKEY>(static_cast<ULONG_PTR>(24)); return nrpt_error;
}
LSTATUS WINAPI ProofEnumKey(HKEY, DWORD index, LPWSTR name, LPDWORD characters,
    LPDWORD, LPWSTR, LPDWORD, PFILETIME) {
  if (!nrpt_present || index > 0) return ERROR_NO_MORE_ITEMS;
  if (*characters <= nrpt_name.size()) return ERROR_MORE_DATA;
  std::memcpy(name, nrpt_name.c_str(), (nrpt_name.size() + 1) * sizeof(wchar_t));
  *characters = static_cast<DWORD>(nrpt_name.size()); return ERROR_SUCCESS;
}
LSTATUS WINAPI ProofCloseKey(HKEY) { return ERROR_SUCCESS; }
void ResetProof() {
  process_error = wfp_error = filter_error = route_error = adapter_error = ERROR_SUCCESS;
  nrpt_error = ERROR_SUCCESS;
  runtime_process = filter_present = layer_present = app_condition = false;
  adapter_up = adapter_addresses = adapter_routes = nrpt_present = false;
  filter_name = L"Corporate firewall"; layer_name = L"Corporate firewall";
  adapter_name = L"FuzeVPN"; adapter_description = L"WireGuard Tunnel";
  nrpt_name = L"CorporateDNS"; registry_reads = 0;
  fixture_filter = {}; fixture_layer = {}; fixture_condition = {}; fixture_blob = {};
}
bool VerifyProof(bool condition_result, const char* message) {
  if (!condition_result) std::cerr << "Maintenance network regression: " << message << '\n';
  return condition_result;
}
}  // namespace

#define fuzevpn_maintenance fuzevpn_maintenance_network_test
#define CreateToolhelp32Snapshot ProofSnapshot
#define Process32FirstW ProofProcessFirst
#define Process32NextW ProofProcessNext
#define CloseHandle ProofCloseHandle
#define FwpmEngineOpen0 ProofEngineOpen
#define FwpmEngineClose0 ProofEngineClose
#define FwpmFilterCreateEnumHandle0 ProofFilterCreate
#define FwpmFilterEnum0 ProofFilterEnum
#define FwpmFilterDestroyEnumHandle0 ProofFilterDestroy
#define FwpmSubLayerCreateEnumHandle0 ProofLayerCreate
#define FwpmSubLayerEnum0 ProofLayerEnum
#define FwpmSubLayerDestroyEnumHandle0 ProofLayerDestroy
#define FwpmFreeMemory0 ProofFreeWfp
#define GetIpForwardTable2 ProofRoutes
#define FreeMibTable ProofFreeRoutes
#define GetAdaptersAddresses ProofAdapters
#define RegOpenKeyExW ProofOpenKey
#define RegEnumKeyExW ProofEnumKey
#define RegCloseKey ProofCloseKey
#include "../maintenance_network_state.cpp"
#undef fuzevpn_maintenance

bool TestMaintenanceNetworkRecovery() {
  DWORD error = ERROR_SUCCESS;
  const auto proof = [&]() {
    fixture_filter.displayData.name = filter_name.data(); fixture_layer.displayData.name = layer_name.data();
    if (app_condition) { fixture_filter.numFilterConditions = 1; fixture_filter.filterCondition = &fixture_condition; }
    error = ERROR_SUCCESS;
    return fuzevpn_maintenance_network_test::ConfirmStoppedNetworkState(L"C:\\Program Files\\FuzeVPN", &error);
  };
  ResetProof();
  if (!VerifyProof(proof() && registry_reads == 2, "absence is proven across both NRPT paths")) return false;
  ResetProof(); runtime_process = true;
  if (!VerifyProof(!proof() && error == ERROR_BUSY, "surviving Fuze runtime is blocking")) return false;
  ResetProof(); process_error = ERROR_ACCESS_DENIED;
  if (!VerifyProof(!proof() && error == ERROR_ACCESS_DENIED, "inaccessible process snapshot is blocking")) return false;
  ResetProof(); wfp_error = ERROR_ACCESS_DENIED;
  if (!VerifyProof(!proof() && error == ERROR_ACCESS_DENIED, "inaccessible WFP engine is blocking")) return false;
  ResetProof(); filter_error = ERROR_ACCESS_DENIED;
  if (!VerifyProof(!proof() && error == ERROR_ACCESS_DENIED, "inaccessible WFP enumeration is blocking")) return false;
  for (const auto* name : {L"FuzeVPN — DNS", L"OpenVPN"}) {
    ResetProof(); filter_present = true; filter_name = name;
    if (!VerifyProof(!proof() && error == ERROR_BUSY, "Fuze and legacy OpenVPN block-only filters are blocking")) return false;
    ResetProof(); layer_present = true; layer_name = name;
    if (!VerifyProof(!proof() && error == ERROR_BUSY, "surviving Fuze and legacy OpenVPN sublayers are blocking")) return false;
  }
  ResetProof(); filter_present = true; app_condition = true;
  wchar_t app[] = L"\\device\\harddiskvolume3\\program files\\FuzeVPN\\fuzevpn-service.exe";
  fixture_blob.data = reinterpret_cast<UINT8*>(app); fixture_blob.size = sizeof(app);
  fixture_condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  fixture_condition.conditionValue.type = FWP_BYTE_BLOB_TYPE; fixture_condition.conditionValue.byteBlob = &fixture_blob;
  if (!VerifyProof(!proof() && error == ERROR_BUSY, "unnamed Fuze app-ID policy is blocking")) return false;
  ResetProof(); adapter_name = L"OpenVPN DCO"; adapter_description = L"ovpn-dco";
  adapter_addresses = adapter_routes = true;
  if (!VerifyProof(proof(), "disconnected DCO permits stale addresses/fixture_routes")) return false;
  adapter_up = true;
  if (!VerifyProof(!proof() && error == ERROR_BUSY, "active DCO is blocking")) return false;
  ResetProof(); adapter_name = L"vEthernet (FuzeVPN-Lab)";
  adapter_description = L"Hyper-V Virtual Ethernet Adapter";
  adapter_up = adapter_addresses = adapter_routes = true;
  if (!VerifyProof(proof(), "unrelated lab interface does not block repair")) return false;
  ResetProof(); route_error = ERROR_ACCESS_DENIED;
  if (!VerifyProof(!proof() && error == ERROR_ACCESS_DENIED, "inaccessible route table is blocking")) return false;
  ResetProof(); adapter_error = ERROR_BUFFER_OVERFLOW;
  if (!VerifyProof(!proof() && error == ERROR_BUFFER_OVERFLOW, "unstable adapter inventory is blocking")) return false;
  for (const auto* name : {L"FuzeVPNDNSRoutingV1-123-456-0", L"OpenVPNDNSRouting-123"}) {
    ResetProof(); nrpt_present = true; nrpt_name = name;
    if (!VerifyProof(!proof() && error == ERROR_BUSY, "current and legacy NRPT leftovers are blocking")) return false;
  }
  ResetProof(); nrpt_error = ERROR_ACCESS_DENIED;
  if (!VerifyProof(!proof() && error == ERROR_ACCESS_DENIED, "inaccessible NRPT rules are blocking")) return false;
  ResetProof(); nrpt_error = ERROR_FILE_NOT_FOUND;
  if (!VerifyProof(proof(), "absent NRPT keys are safe")) return false;
  return true;
}
