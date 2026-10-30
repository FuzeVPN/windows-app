// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_ADDRESS_VALIDATION_H_
#define RUNNER_WIREGUARD_ADDRESS_VALIDATION_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>

namespace fuzevpn {
// DNS entries are numeric servers, never wg-quick DNS search suffixes. Reject
// embedded NULs before handing the string to the Windows address parser.
inline bool IsWireGuardDnsAddress(const std::string& value) {
  if (value.empty() || value.size() >= INET6_ADDRSTRLEN ||
      value.find('\0') != std::string::npos) {
    return false;
  }
  IN6_ADDR address{};
  return InetPtonA(AF_INET, value.c_str(), &address) == 1 ||
         InetPtonA(AF_INET6, value.c_str(), &address) == 1;
}

inline bool IsWireGuardUlaHostCidr(const std::string& value) {
  const auto slash = value.find('/');
  if (slash == std::string::npos || value.substr(slash) != "/128") {
    return false;
  }
  const auto host = value.substr(0, slash);
  if (host.empty() || host.size() >= INET6_ADDRSTRLEN ||
      host.find('\0') != std::string::npos) {
    return false;
  }
  IN6_ADDR address{};
  return InetPtonA(AF_INET6, host.c_str(), &address) == 1 &&
         (address.u.Byte[0] & 0xfe) == 0xfc;
}
}  // namespace fuzevpn

#endif  // RUNNER_WIREGUARD_ADDRESS_VALIDATION_H_
