// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <windows.h>
#include <msi.h>
#include <string_view>

namespace fuzevpn::installer {
inline constexpr wchar_t kProductUpgradeCode[] = L"{71B1A5A7-6393-4780-AF2B-C26952F66D24}";
inline constexpr wchar_t kDesktopComponentCode[] = L"{816C5662-8421-4DA8-8B3E-1B2D17C1E117}";

struct DesktopPreference {
  UINT error = ERROR_SUCCESS;
  // Null means an explicit caller preference must remain unchanged.
  const wchar_t* value = nullptr;
};

// Use public per-machine MSI metadata rather than the protected application
// registry key. Callbacks keep regression tests independent of live products.
template <typename EnumerateProduct, typename QueryComponent>
DesktopPreference ResolveDesktopPreference(std::wstring_view supplied,
    EnumerateProduct enumerate, QueryComponent query) {
  if (supplied != L"-1") return {};
  for (DWORD index = 0; index < 256; ++index) {
    wchar_t product[39]{};
    const UINT enumerated = enumerate(kProductUpgradeCode, 0, index, product);
    if (enumerated == ERROR_NO_MORE_ITEMS) return {ERROR_SUCCESS, L"0"};
    if (enumerated != ERROR_SUCCESS) return {enumerated, L"0"};
    INSTALLSTATE state = INSTALLSTATE_UNKNOWN;
    const UINT queried = query(product, nullptr, MSIINSTALLCONTEXT_MACHINE,
        kDesktopComponentCode, &state);
    if (queried == ERROR_UNKNOWN_COMPONENT || queried == ERROR_UNKNOWN_PRODUCT) continue;
    if (queried != ERROR_SUCCESS) return {queried, L"0"};
    if (state == INSTALLSTATE_LOCAL) return {ERROR_SUCCESS, L"1"};
  }
  return {ERROR_BAD_CONFIGURATION, L"0"};
}
}  // namespace fuzevpn::installer
