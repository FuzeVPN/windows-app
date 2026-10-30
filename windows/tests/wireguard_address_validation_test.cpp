// SPDX-License-Identifier: MPL-2.0
// Parsing only: no service manager, driver, filesystem or network mutations.
#include "wireguard_address_validation.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Check(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(EXIT_FAILURE);
  }
}
}  // namespace

int main() {
  using fuzevpn::IsWireGuardDnsAddress;
  using fuzevpn::IsWireGuardUlaHostCidr;
  for (const auto* address : {"1.1.1.1", "192.0.2.53", "2001:db8::53",
                            "FD00:ABCD:0:0:0:0:0:53", "::ffff:192.0.2.53"}) {
    Check(IsWireGuardDnsAddress(address), std::string("valid DNS rejected: ") + address);
  }
  for (const auto& address : std::vector<std::string>{
           "", "face", "deadbeef", "dns.example", "999.999.999.999",
           "1.1.1", "01.1.1.1", "1.1.1.1/32", "1.1.1.1:53",
           "[2001:db8::53]", "fd00::1:", "1:2:3", "fe80::1%2",
           " 1.1.1.1", "1.1.1.1 ", "1.1.1.1\nPostUp = bad",
           std::string("1.1.1.1\0suffix", 14), std::string("fd00::1\0", 8)}) {
    Check(!IsWireGuardDnsAddress(address), "invalid DNS accepted");
  }
  for (const auto* address : {"fc00::/128", "fd00::1/128", "FDFF:FFFF::1/128",
                            "fd00:abcd:0:0:0:0:0:1/128", "fd00::192.0.2.1/128"}) {
    Check(IsWireGuardUlaHostCidr(address), std::string("valid ULA rejected: ") + address);
  }
  for (const auto& address : std::vector<std::string>{
           "", "fd00::1:/128", "fd00:::1/128", "fd00::1::2/128",
           "fd00:1:2:3:4:5:6:7:8/128", "fd00::1", "fd00::1/64",
           "fd00::1/0128", "fd00::1/128/128", "fd00::1/128suffix",
           "fe80::1/128", "2001:db8::1/128", "::1/128", "192.0.2.1/128",
           "fd00::1%2/128", " fd00::1/128", "fd00::1/128 ",
           std::string("fd00::1\0/128", 12)}) {
    Check(!IsWireGuardUlaHostCidr(address), "invalid ULA accepted");
  }
  std::cout << "WireGuard address validation: 46 cases passed; no SCM or network calls\n";
  return EXIT_SUCCESS;
}
