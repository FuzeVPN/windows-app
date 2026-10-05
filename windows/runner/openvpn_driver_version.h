// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_DRIVER_VERSION_H_
#define RUNNER_OPENVPN_DRIVER_VERSION_H_
#include <cstdint>
#include <string_view>
namespace fuzevpn {
inline bool ParseOpenVpnDriverVersion(std::wstring_view text, std::uint64_t* version) {
  if (!version || text.empty() || text.size() > 23) return false;
  std::uint64_t result = 0;
  for (unsigned field = 0; field < 4; ++field) {
    const auto dot = text.find(L'.');
    if ((field == 3) != (dot == std::wstring_view::npos)) return false;
    const auto part = text.substr(0, dot);
    if (part.empty() || part.size() > 5) return false;
    unsigned number = 0;
    for (const auto c : part) {
      if (c < L'0' || c > L'9') return false;
      number = number * 10 + static_cast<unsigned>(c - L'0');
      if (number > 65535) return false;
    }
    result = (result << 16) | number;
    if (field != 3) text.remove_prefix(dot + 1);
  }
  *version = result;
  return true;
}
inline bool OpenVpnDriverVersionCompatible(std::uint64_t installed, std::uint64_t bundled) {
  // Newer versions are never downgraded. A changed major ABI must be reviewed.
  return bundled && installed >= bundled && (installed >> 48) == (bundled >> 48);
}
}
#endif
