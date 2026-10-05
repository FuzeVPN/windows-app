// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIAGNOSTICS_NETWORK_H_
#define RUNNER_DIAGNOSTICS_NETWORK_H_
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <array>
#include <span>
#include "diagnostics_state.h"

namespace fuzevpn_diagnostics {
struct NumericAddress {
  ADDRESS_FAMILY family = AF_UNSPEC;
  std::array<unsigned char, 16> bytes{};
  unsigned prefix = 0;
  bool operator==(const NumericAddress&) const = default;
};
std::optional<NumericAddress> ParseNumericAddress(const std::string& text, bool route = false);
CheckResult EvaluateAddresses(const NetworkExpectation& expected, ADDRESS_FAMILY family,
    std::span<const MIB_UNICASTIPADDRESS_ROW> rows, unsigned* configured_count);
CheckResult EvaluateRoutes(const NetworkExpectation& expected,
    std::span<const MIB_IPFORWARD_ROW2> rows);
CheckResult EvaluateDns(const std::vector<std::string>& expected,
                        const std::vector<NumericAddress>& actual);
// Reads exact owned adapter only. No sockets, netsh, service or registry writes.
NetworkObservation ReadNetworkObservation(const NetworkExpectation& expected);
}
#endif
