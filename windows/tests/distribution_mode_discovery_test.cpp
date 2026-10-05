// SPDX-License-Identifier: MPL-2.0
// Exercise CurrentMode itself with injected OS APIs. A denied private key must
// never be queried; no real registry, process or Windows Installer operation runs.
#include <windows.h>
#include <msi.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "installation_security.h"

namespace {
std::wstring fixture_image;
std::vector<std::wstring> component_paths;
DWORD image_error = ERROR_SUCCESS;
DWORD fixture_marker_attributes = INVALID_FILE_ATTRIBUTES;
DWORD fixture_marker_error = ERROR_FILE_NOT_FOUND;
UINT enumeration_error = ERROR_SUCCESS;
INSTALLSTATE component_state = INSTALLSTATE_LOCAL;
MSIINSTALLCONTEXT returned_context = MSIINSTALLCONTEXT_MACHINE;
unsigned private_reads = 0;
unsigned msi_queries = 0;
unsigned component_queries = 0;
bool proper_machine_context = true;
bool malformed_length = false;
bool overflowing_clients = false;
bool enumeration_active = false;
DWORD expected_enumeration_index = 0;
unsigned completed_enumerations = 0;
unsigned enumeration_cursor_errors = 0;
bool lookup_before_enumeration_complete = false;
std::wstring ProductForIndex(DWORD index) {
  wchar_t product[39]{};
  swprintf_s(product, L"{01234567-89AB-CDEF-0123-%012lX}",
      static_cast<unsigned long>(index));
  return product;
}
DWORD WINAPI DiscoveryImage(HMODULE, LPWSTR target, DWORD capacity) {
  if (image_error != ERROR_SUCCESS) { SetLastError(image_error); return 0; }
  if (fixture_image.size() >= capacity) return capacity;
  std::memcpy(target, fixture_image.c_str(), (fixture_image.size() + 1) * sizeof(wchar_t));
  return static_cast<DWORD>(fixture_image.size());
}
DWORD WINAPI DiscoveryMarker(LPCWSTR) { SetLastError(fixture_marker_error); return fixture_marker_attributes; }
UINT WINAPI DiscoveryClients(LPCWSTR component, LPCWSTR sid, DWORD context, DWORD index,
    wchar_t product[39], MSIINSTALLCONTEXT* actual_context, LPWSTR output_sid, LPDWORD sid_length) {
  ++msi_queries;
  proper_machine_context = proper_machine_context && sid == nullptr && context == MSIINSTALLCONTEXT_MACHINE &&
      output_sid == nullptr && sid_length == nullptr &&
      std::wstring(component) == L"{7BFDFB64-AEB8-4957-8C31-F4B4C62EE911}";
  if (enumeration_error != ERROR_SUCCESS) return enumeration_error;
  // Match the real MSI cursor: a new index-zero call cannot interrupt a
  // sequence that has not reached ERROR_NO_MORE_ITEMS. Early return used to
  // make alternate startup state reads fail with ERROR_INVALID_PARAMETER.
  if (index != expected_enumeration_index) {
    ++enumeration_cursor_errors;
    enumeration_active = false;
    expected_enumeration_index = 0;
    return ERROR_INVALID_PARAMETER;
  }
  if (!overflowing_clients && index >= component_paths.size()) {
    enumeration_active = false;
    expected_enumeration_index = 0;
    ++completed_enumerations;
    return ERROR_NO_MORE_ITEMS;
  }
  enumeration_active = true;
  ++expected_enumeration_index;
  wcscpy_s(product, 39, ProductForIndex(index).c_str());
  *actual_context = returned_context;
  return ERROR_SUCCESS;
}
INSTALLSTATE WINAPI DiscoveryComponent(LPCWSTR product, LPCWSTR component, LPCWSTR sid,
    MSIINSTALLCONTEXT context, LPWSTR target, LPDWORD characters) {
  proper_machine_context = proper_machine_context && sid == nullptr && context == MSIINSTALLCONTEXT_MACHINE &&
      std::wstring(component) == L"{7BFDFB64-AEB8-4957-8C31-F4B4C62EE911}";
  ++component_queries;
  lookup_before_enumeration_complete |= enumeration_active;
  size_t index = component_paths.size();
  for (size_t candidate = 0; candidate < component_paths.size(); ++candidate) {
    if (std::wstring(product) == ProductForIndex(static_cast<DWORD>(candidate))) {
      index = candidate;
      break;
    }
  }
  if (index == component_paths.size()) return INSTALLSTATE_INVALIDARG;
  const auto& path = component_paths.at(index);
  if (*characters <= path.size()) { *characters = static_cast<DWORD>(path.size()); return INSTALLSTATE_MOREDATA; }
  std::memcpy(target, path.c_str(), (path.size() + 1) * sizeof(wchar_t));
  *characters = static_cast<DWORD>(path.size() + (malformed_length ? 1 : 0));
  return component_state;
}
void ResetDiscovery() {
  fixture_image = LR"(C:\Program Files\FuzeVPN\fuzevpn_windows.exe)";
  component_paths = {LR"(C:\Program Files\FuzeVPN\fuzevpn-service.exe)"};
  image_error = enumeration_error = ERROR_SUCCESS;
  fixture_marker_attributes = INVALID_FILE_ATTRIBUTES; fixture_marker_error = ERROR_FILE_NOT_FOUND;
  component_state = INSTALLSTATE_LOCAL; returned_context = MSIINSTALLCONTEXT_MACHINE;
  private_reads = msi_queries = component_queries = 0;
  proper_machine_context = true; malformed_length = overflowing_clients = false;
  enumeration_active = lookup_before_enumeration_complete = false;
  expected_enumeration_index = completed_enumerations = enumeration_cursor_errors = 0;
  SetLastError(ERROR_ACCESS_DENIED);
}
}

#define fuzevpn_distribution fuzevpn_distribution_discovery_test
#define GetModuleFileNameW DiscoveryImage
#define GetFileAttributesW DiscoveryMarker
#define MsiEnumClientsExW DiscoveryClients
#define MsiGetComponentPathExW DiscoveryComponent
#define RegOpenKeyExW(...) (++private_reads, ERROR_ACCESS_DENIED)
#define RegGetValueW(...) (++private_reads, ERROR_ACCESS_DENIED)
#define RegCloseKey(...) (++private_reads, ERROR_ACCESS_DENIED)
#include "../runner/distribution_mode.cpp"
#undef fuzevpn_distribution

bool TestCurrentModeDiscovery() {
  using namespace fuzevpn_distribution_discovery_test;
  const auto check = [](bool condition, const char* message) {
    if (!condition) std::cerr << "Distribution discovery: " << message << '\n';
    return condition;
  };
  ResetDiscovery();
  if (!check(CurrentMode() == Mode::installed && GetLastError() == ERROR_SUCCESS && private_reads == 0 &&
      proper_machine_context && component_queries == 1 && completed_enumerations == 1 &&
      !enumeration_active && !lookup_before_enumeration_complete && enumeration_cursor_errors == 0,
      "installed current copy ignores private-key access denied through actual CurrentMode")) return false;
  for (unsigned repeat = 0; repeat < 100; ++repeat) {
    if (!check(CurrentMode() == Mode::installed && GetLastError() == ERROR_SUCCESS &&
        !enumeration_active && !lookup_before_enumeration_complete && enumeration_cursor_errors == 0,
        "repeated installed startup reads must finish MSI enumeration without alternate error 87")) return false;
  }
  ResetDiscovery(); fixture_marker_attributes = FILE_ATTRIBUTE_NORMAL; enumeration_error = ERROR_ACCESS_DENIED;
  if (!check(CurrentMode() == Mode::portable && msi_queries == 0 && private_reads == 0,
      "explicit portable marker bypasses MSI and private metadata")) return false;
  ResetDiscovery(); fixture_image = L"D:\\Applications prot\u00e9g\u00e9es\\FuzeVPN\\fuzevpn_windows.exe";
  component_paths = {L"d:\\applications prot\u00e9g\u00e9es\\fuzevpn\\fuzevpn-service.exe"};
  if (!check(CurrentMode() == Mode::installed && proper_machine_context,
      "public machine metadata covers legacy custom Unicode installation")) return false;
  ResetDiscovery(); component_paths = {LR"(D:\Old\FuzeVPN\fuzevpn-service.exe)",
      LR"(C:\Program Files\FuzeVPN\fuzevpn-service.exe)"};
  if (!check(CurrentMode() == Mode::installed && component_queries == 2,
      "shared legacy/new MSI clients use matching per-machine directory")) return false;
  ResetDiscovery(); component_paths = {LR"(C:\Program Files\FuzeVPN\fuzevpn-service.exe)",
      LR"(D:\Other\FuzeVPN\fuzevpn-service.exe)"};
  if (!check(CurrentMode() == Mode::installed && component_queries == 1 && msi_queries == 3 &&
      completed_enumerations == 1 && !enumeration_active && !lookup_before_enumeration_complete,
      "even the first matching client cannot interrupt a multiple-client enumeration")) return false;
  ResetDiscovery(); fixture_image = LR"(C:\Users\Tester\Copy\fuzevpn_windows.exe)";
  if (!check(CurrentMode() == Mode::portable && proper_machine_context,
      "moved unmarked copy remains portable")) return false;
  for (unsigned repeat = 0; repeat < 20; ++repeat) {
    if (!check(CurrentMode() == Mode::portable && GetLastError() == ERROR_SUCCESS &&
        !enumeration_active && enumeration_cursor_errors == 0,
        "repeated copied portable reads preserve the completed MSI cursor")) return false;
  }
  ResetDiscovery(); component_paths.clear();
  if (!check(CurrentMode() == Mode::portable && GetLastError() == ERROR_SUCCESS,
      "confirmed absence of machine component permits portable copy")) return false;
  for (unsigned repeat = 0; repeat < 20; ++repeat) {
    if (!check(CurrentMode() == Mode::portable && GetLastError() == ERROR_SUCCESS &&
        !enumeration_active && enumeration_cursor_errors == 0 && component_queries == 0,
        "repeated absence checks complete their empty enumeration")) return false;
  }
  for (const UINT status : {ERROR_ACCESS_DENIED, ERROR_BAD_CONFIGURATION, ERROR_INVALID_PARAMETER}) {
    ResetDiscovery(); enumeration_error = status;
    if (!check(CurrentMode() == Mode::unavailable && GetLastError() == status && private_reads == 0,
        "public API errors remain explicit unknown rather than portable")) return false;
  }
  for (const auto* path : {LR"(C:\Apps\..\FuzeVPN\fuzevpn-service.exe)", L"relative\\fuzevpn-service.exe",
      LR"(\\server\share\fuzevpn-service.exe)", LR"(C:\Program Files\FuzeVPN\other.exe)"}) {
    ResetDiscovery(); component_paths = {path};
    if (!check(CurrentMode() == Mode::unavailable && GetLastError() == ERROR_BAD_CONFIGURATION,
        "malformed, remote and wrong component key paths stay unavailable")) return false;
  }
  ResetDiscovery(); returned_context = MSIINSTALLCONTEXT_USERMANAGED;
  if (!check(CurrentMode() == Mode::unavailable && GetLastError() == ERROR_BAD_CONFIGURATION,
      "unexpected per-user metadata cannot identify machine installation")) return false;
  returned_context = MSIINSTALLCONTEXT_MACHINE;
  if (!check(CurrentMode() == Mode::installed && GetLastError() == ERROR_SUCCESS &&
      completed_enumerations == 2 && enumeration_cursor_errors == 0,
      "invalid context cannot poison the next startup metadata read")) return false;
  ResetDiscovery(); component_state = INSTALLSTATE_ABSENT;
  if (!check(CurrentMode() == Mode::unavailable && GetLastError() == ERROR_BAD_CONFIGURATION,
      "nonlocal component state stays unknown")) return false;
  component_state = INSTALLSTATE_LOCAL;
  if (!check(CurrentMode() == Mode::installed && GetLastError() == ERROR_SUCCESS &&
      completed_enumerations == 2 && !lookup_before_enumeration_complete && enumeration_cursor_errors == 0,
      "failed component lookup leaves enumeration complete for the next startup read")) return false;
  ResetDiscovery(); malformed_length = true;
  if (!check(CurrentMode() == Mode::unavailable, "embedded terminator or bad length stays unknown")) return false;
  malformed_length = false;
  if (!check(CurrentMode() == Mode::installed && GetLastError() == ERROR_SUCCESS &&
      completed_enumerations == 2 && enumeration_cursor_errors == 0,
      "malformed component data cannot leave a partial enumeration behind")) return false;
  ResetDiscovery(); fixture_marker_error = ERROR_ACCESS_DENIED;
  if (!check(CurrentMode() == Mode::unavailable && GetLastError() == ERROR_ACCESS_DENIED && msi_queries == 0,
      "inaccessible marker preserves its native error")) return false;
  ResetDiscovery(); image_error = ERROR_ACCESS_DENIED;
  if (!check(CurrentMode() == Mode::unavailable && GetLastError() == ERROR_ACCESS_DENIED,
      "inaccessible fixture_image preserves its native error")) return false;
  ResetDiscovery(); component_paths = {LR"(D:\Other\FuzeVPN\fuzevpn-service.exe)"}; overflowing_clients = true;
  if (!check(CurrentMode() == Mode::unavailable && msi_queries == 256 && component_queries == 0,
      "malformed endless client enumeration is bounded")) return false;
  return true;
}
