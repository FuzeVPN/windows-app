// SPDX-License-Identifier: MPL-2.0
#include <winsock2.h>
#include <ws2tcpip.h>
#include "maintenance_network_state.h"

#include <fwpmu.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <tlhelp32.h>
#include <filesystem>
#include <vector>

#include "maintenance_network_policy.h"

namespace fuzevpn_maintenance {
namespace {
bool Reject(DWORD status, DWORD* error) { if (error) *error = status; return false; }
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Key { HKEY value = nullptr; ~Key() { if (value) RegCloseKey(value); } };
struct Engine { HANDLE value = nullptr; ~Engine() { if (value) FwpmEngineClose0(value); } };
struct WfpMemory { void* value = nullptr; ~WfpMemory() { if (value) FwpmFreeMemory0(&value); } };
struct Routes { MIB_IPFORWARD_TABLE2* value = nullptr; ~Routes() { if (value) FreeMibTable(value); } };

bool ProcessesStopped(const std::wstring& directory, DWORD* error) {
  Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
  if (snapshot.value == INVALID_HANDLE_VALUE) return Reject(GetLastError(), error);
  PROCESSENTRY32W process{}; process.dwSize = sizeof(process);
  if (!Process32FirstW(snapshot.value, &process)) {
    const DWORD status = GetLastError();
    return status == ERROR_NO_MORE_FILES || Reject(status, error);
  }
  do {
    const auto name = fuzevpn_maintenance_policy::Fold(process.szExeFile);
    if (name == L"fuzevpn-service.exe") return Reject(ERROR_BUSY, error);
    if (name != L"openvpn.exe" && name != L"wireguard.exe") continue;
    Handle runtime{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.th32ProcessID)};
    if (!runtime.value) {
      // A process may disappear between enumeration and inspection.
      const DWORD status = GetLastError();
      if (status == ERROR_INVALID_PARAMETER) continue;
      return Reject(status, error);
    }
    wchar_t path[32768]{}; DWORD characters = static_cast<DWORD>(std::size(path));
    if (!QueryFullProcessImageNameW(runtime.value, 0, path, &characters)) return Reject(GetLastError(), error);
    const std::filesystem::path executable(path);
    const auto parent = fuzevpn_maintenance_policy::Fold(executable.parent_path().wstring());
    const auto target = fuzevpn_maintenance_policy::Fold(directory);
    if (parent == target || parent.starts_with(target + L"\\")) return Reject(ERROR_BUSY, error);
  } while (Process32NextW(snapshot.value, &process));
  const DWORD status = GetLastError();
  return status == ERROR_NO_MORE_FILES || Reject(status, error);
}

bool FuzeAppCondition(const FWPM_FILTER_CONDITION0& condition) {
  if (!IsEqualGUID(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID) ||
      condition.conditionValue.type != FWP_BYTE_BLOB_TYPE ||
      !condition.conditionValue.byteBlob) return false;
  const FWP_BYTE_BLOB& blob = *condition.conditionValue.byteBlob;
  if (!blob.data || blob.size == 0 || blob.size % sizeof(wchar_t) != 0) return false;
  const auto* text = reinterpret_cast<const wchar_t*>(blob.data);
  size_t characters = blob.size / sizeof(wchar_t);
  while (characters && text[characters - 1] == L'\0') --characters;
  return fuzevpn_maintenance_policy::FuzeExecutable(std::wstring_view(text, characters));
}

bool FiltersStopped(DWORD* error) {
  Engine engine;
  DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.value);
  if (status != ERROR_SUCCESS) return Reject(status, error);
  HANDLE enumeration = nullptr;
  status = FwpmFilterCreateEnumHandle0(engine.value, nullptr, &enumeration);
  if (status != ERROR_SUCCESS) return Reject(status, error);
  bool clear = true;
  for (;;) {
    FWPM_FILTER0** filters = nullptr; UINT32 count = 0;
    status = FwpmFilterEnum0(engine.value, enumeration, 256, &filters, &count);
    WfpMemory memory{filters};
    if (status != ERROR_SUCCESS) { clear = Reject(status, error); break; }
    if (count == 0) break;
    for (UINT32 i = 0; i < count && clear; ++i) {
      const auto& filter = *filters[i];
      if (filter.displayData.name && fuzevpn_maintenance_policy::VpnFilterName(filter.displayData.name))
        clear = Reject(ERROR_BUSY, error);
      for (UINT32 j = 0; j < filter.numFilterConditions && clear; ++j)
        if (FuzeAppCondition(filter.filterCondition[j])) clear = Reject(ERROR_BUSY, error);
    }
    if (!clear) break;
  }
  const DWORD destroyed = FwpmFilterDestroyEnumHandle0(engine.value, enumeration);
  if (!clear) return false;
  if (destroyed != ERROR_SUCCESS) return Reject(destroyed, error);
  enumeration = nullptr;
  status = FwpmSubLayerCreateEnumHandle0(engine.value, nullptr, &enumeration);
  if (status != ERROR_SUCCESS) return Reject(status, error);
  for (;;) {
    FWPM_SUBLAYER0** layers = nullptr; UINT32 count = 0;
    status = FwpmSubLayerEnum0(engine.value, enumeration, 256, &layers, &count);
    WfpMemory memory{layers};
    if (status != ERROR_SUCCESS) { clear = Reject(status, error); break; }
    if (count == 0) break;
    for (UINT32 i = 0; i < count && clear; ++i)
      if (layers[i]->displayData.name && fuzevpn_maintenance_policy::VpnFilterName(layers[i]->displayData.name))
        clear = Reject(ERROR_BUSY, error);
    if (!clear) break;
  }
  status = FwpmSubLayerDestroyEnumHandle0(engine.value, enumeration);
  return clear && (status == ERROR_SUCCESS || Reject(status, error));
}

bool AdaptersStopped(DWORD* error) {
  Routes routes;
  DWORD status = GetIpForwardTable2(AF_UNSPEC, &routes.value);
  if (status != ERROR_SUCCESS) return Reject(status, error);
  ULONG bytes = 16384;
  std::vector<BYTE> storage;
  for (unsigned attempt = 0; attempt < 4; ++attempt) {
    if (bytes == 0 || bytes > 16 * 1024 * 1024) return Reject(ERROR_NOT_ENOUGH_MEMORY, error);
    storage.resize(bytes);
    status = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()), &bytes);
    if (status != ERROR_BUFFER_OVERFLOW) break;
  }
  if (status == ERROR_NO_DATA) return true;
  if (status != ERROR_SUCCESS) return Reject(status, error);
  for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()); adapter; adapter = adapter->Next) {
    bool has_routes = false;
    for (ULONG i = 0; i < routes.value->NumEntries; ++i)
      if (routes.value->Table[i].InterfaceLuid.Value == adapter->Luid.Value) { has_routes = true; break; }
    if (fuzevpn_maintenance_policy::ActiveVpnAdapter(
        adapter->FriendlyName ? adapter->FriendlyName : L"",
        adapter->Description ? adapter->Description : L"",
        adapter->OperStatus == IfOperStatusUp, adapter->FirstUnicastAddress != nullptr, has_routes))
      return Reject(ERROR_BUSY, error);
  }
  return true;
}

bool NrptStopped(DWORD* error) {
  for (const auto* path : {
      L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig",
      L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"}) {
    Key key;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
        KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &key.value);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) continue;
    if (status != ERROR_SUCCESS) return Reject(static_cast<DWORD>(status), error);
    for (DWORD index = 0;; ++index) {
      wchar_t name[32768]{}; DWORD characters = static_cast<DWORD>(std::size(name));
      status = RegEnumKeyExW(key.value, index, name, &characters, nullptr, nullptr, nullptr, nullptr);
      if (status == ERROR_NO_MORE_ITEMS) break;
      if (status != ERROR_SUCCESS) return Reject(static_cast<DWORD>(status), error);
      if (fuzevpn_maintenance_policy::VpnNrptRule(std::wstring_view(name, characters)))
        return Reject(ERROR_BUSY, error);
    }
  }
  return true;
}
}  // namespace

bool ConfirmStoppedNetworkState(const std::wstring& directory, DWORD* error) {
  if (!ProcessesStopped(directory, error) || !FiltersStopped(error) ||
      !AdaptersStopped(error) || !NrptStopped(error)) return false;
  if (error) *error = ERROR_SUCCESS;
  return true;
}
}  // namespace fuzevpn_maintenance
