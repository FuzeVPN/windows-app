// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_MAINTENANCE_NETWORK_POLICY_H_
#define RUNNER_MAINTENANCE_NETWORK_POLICY_H_

#include <cwctype>
#include <string>
#include <string_view>

namespace fuzevpn_maintenance_policy {
inline std::wstring Fold(std::wstring_view value) {
  std::wstring result(value);
  for (auto& character : result) character = static_cast<wchar_t>(std::towlower(character));
  return result;
}
inline bool FuzeName(std::wstring_view value) {
  const std::wstring name = Fold(value);
  return name == L"fuzevpn" || name.starts_with(L"fuzevpn ");
}
inline bool VpnFilterName(std::wstring_view value) {
  const std::wstring name = Fold(value);
  // Core's block filters have no app-ID condition. An OpenVPN policy with a
  // missing permit filter is still blocking; do not infer ownership absence.
  return FuzeName(value) || name == L"openvpn" || name.starts_with(L"openvpn ");
}
inline bool FuzeExecutable(std::wstring_view value) {
  const std::wstring path = Fold(value);
  const auto separator = path.find_last_of(L"\\/");
  const std::wstring_view name(path.data() + (separator == std::wstring::npos ? 0 : separator + 1),
      path.size() - (separator == std::wstring::npos ? 0 : separator + 1));
  return name == L"fuzevpn-service.exe" || name == L"fuzevpn_windows.exe";
}
inline bool VpnAdapter(std::wstring_view alias, std::wstring_view description) {
  const std::wstring detail = Fold(description);
  // Exact alias keeps unrelated interfaces such as FuzeVPN-Lab out of scope.
  return Fold(alias) == L"fuzevpn" || detail.find(L"ovpn-dco") != std::wstring::npos ||
      detail.find(L"openvpn data channel offload") != std::wstring::npos ||
      detail.find(L"openvpn dco") != std::wstring::npos;
}
inline bool ActiveVpnAdapter(std::wstring_view alias, std::wstring_view description,
                             bool up, bool has_addresses, bool has_routes) {
  // DCO retains addresses/routes while disconnected. They cannot carry traffic
  // in that state and must not prevent repair of an old failed service.
  return up && (has_addresses || has_routes) && VpnAdapter(alias, description);
}
inline bool VpnNrptRule(std::wstring_view value) {
  const std::wstring name = Fold(value);
  // Pre-V1 OpenVPN rules have no Fuze ownership marker. They are deliberately
  // blocking rather than deleted or assumed harmless by an installer.
  return name.starts_with(L"fuzevpndnsroutingv1-") ||
      name.starts_with(L"openvpndnsrouting");
}
}  // namespace fuzevpn_maintenance_policy
#endif
