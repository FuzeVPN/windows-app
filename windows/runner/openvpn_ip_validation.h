// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_IP_VALIDATION_H_
#define RUNNER_OPENVPN_IP_VALIDATION_H_
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
namespace fuzevpn {
inline bool IsStrictOpenVpnIPv4(const std::string& value) {
  if (value.empty() || value.size() > 15 || value.find('\0') != std::string::npos) return false;
  IN_ADDR address{};
  return InetPtonA(AF_INET, value.c_str(), &address) == 1;
}
}
#endif
