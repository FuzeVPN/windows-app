// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <array>
#include <string_view>
namespace fuzevpn::installer {
using Version = std::array<unsigned, 4>;
// Internal PE resource comparison. Public API/MSI versions are restricted to
// three components by the packaging tool; resources add a final zero.
inline bool ParseVersion(std::wstring_view text, Version* result) {
  if (!result || text.empty() || text.size() > 23) return false;
  Version parsed{};
  for (unsigned part = 0; part < 4; ++part) {
    const auto dot = text.find(L'.');
    const auto value = text.substr(0, dot);
    if (value.empty() || value.size() > 5) return false;
    for (const auto digit : value) {
      if (digit < L'0' || digit > L'9') return false;
      parsed[part] = parsed[part] * 10 + unsigned(digit - L'0');
    }
    if (parsed[part] > 65535) return false;
    if (dot == std::wstring_view::npos) {
      if (part < 2) return false;
      *result = parsed;
      return true;
    }
    text.remove_prefix(dot + 1);
  }
  return false;
}
inline bool UpgradeAllowed(const Version& installed, const Version& incoming) {
  return incoming >= installed;
}
} // namespace fuzevpn::installer
