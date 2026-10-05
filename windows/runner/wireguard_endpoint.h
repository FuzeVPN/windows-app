// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_ENDPOINT_H_
#define RUNNER_WIREGUARD_ENDPOINT_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "api_bootstrap_dns.h"

namespace fuzevpn {
struct WireGuardEndpoint {
  std::string host;
  std::string port;
  bool numeric = false;
  bool ipv6 = false;
};

inline bool NumericEndpointHost(const std::string& host, bool* ipv6) {
  if (!ipv6 || host.empty() || host.find('\0') != std::string::npos) return false;
  IN6_ADDR address{};
  if (InetPtonA(AF_INET, host.c_str(), &address) == 1) {
    *ipv6 = false;
    return true;
  }
  if (InetPtonA(AF_INET6, host.c_str(), &address) == 1) {
    *ipv6 = true;
    return true;
  }
  return false;
}

inline bool ParseWireGuardEndpoint(const std::string& value, WireGuardEndpoint* endpoint) {
  if (!endpoint || value.empty() || value.size() > 261) return false;
  WireGuardEndpoint parsed;
  const bool bracketed = value.front() == '[';
  if (bracketed) {
    const auto close = value.find(']');
    if (close == std::string::npos || close + 1 >= value.size() || value[close + 1] != ':') return false;
    parsed.host = value.substr(1, close - 1);
    parsed.port = value.substr(close + 2);
  } else {
    const auto colon = value.find(':');
    if (colon == std::string::npos || value.find(':', colon + 1) != std::string::npos) return false;
    parsed.host = value.substr(0, colon);
    parsed.port = value.substr(colon + 1);
  }
  if (parsed.port.empty() || parsed.port.size() > 5) return false;
  unsigned port = 0;
  for (const auto c : parsed.port) {
    if (c < '0' || c > '9') return false;
    port = port * 10 + static_cast<unsigned>(c - '0');
  }
  if (!port || port > 65535) return false;
  parsed.numeric = NumericEndpointHost(parsed.host, &parsed.ipv6);
  if (bracketed && (!parsed.numeric || !parsed.ipv6)) return false;
  if (!parsed.numeric) {
    std::string host;
    if (!bootstrap::CanonicalHost(parsed.host, &host)) return false;
    if (std::all_of(host.begin(), host.end(), [](auto c) { return (c >= '0' && c <= '9') || c == '.'; }))
      return false;  // Do not reinterpret malformed numeric IPv4 as DNS.
    parsed.host = std::move(host);
  }
  *endpoint = std::move(parsed);
  return true;
}

inline std::uint64_t WireGuardWaitDeadline(std::uint64_t now, std::uint64_t maximum,
                                         std::uint64_t connection_deadline = 0) {
  const auto local = now + maximum;
  return connection_deadline ? std::min(local, connection_deadline) : local;
}

enum class WireGuardEndpointResult { ready, invalid, protection_failed, stop_failed, resolution_failed };

// This is the actual preparation sequence used by ConnectTunnel. There is no
// cleanup/unfilter callback: every failure keeps the prepared policy and owner.
template <typename Prepare, typename Stop, typename Resolve>
WireGuardEndpointResult PrepareWireGuardEndpoints(const std::string& original,
    Prepare prepare, Stop stop, Resolve resolve, std::vector<std::string>* numeric_endpoints) {
  if (!numeric_endpoints) return WireGuardEndpointResult::invalid;
  numeric_endpoints->clear();
  WireGuardEndpoint endpoint;
  if (!ParseWireGuardEndpoint(original, &endpoint)) return WireGuardEndpointResult::invalid;
  if (!prepare()) return WireGuardEndpointResult::protection_failed;
  if (!stop()) return WireGuardEndpointResult::stop_failed;
  if (endpoint.numeric) {
    numeric_endpoints->push_back(original);
    return WireGuardEndpointResult::ready;
  }
  std::vector<std::string> addresses;
  if (!resolve(endpoint.host, &addresses) || addresses.empty() || addresses.size() > bootstrap::kMaximumAddresses)
    return WireGuardEndpointResult::resolution_failed;
  for (const auto& address : addresses) {
    bool ipv6 = false;
    if (!NumericEndpointHost(address, &ipv6)) {
      numeric_endpoints->clear();
      return WireGuardEndpointResult::resolution_failed;
    }
    const auto candidate = (ipv6 ? "[" + address + "]" : address) + ":" + endpoint.port;
    if (std::find(numeric_endpoints->begin(), numeric_endpoints->end(), candidate) == numeric_endpoints->end())
      numeric_endpoints->push_back(candidate);
  }
  return WireGuardEndpointResult::ready;
}

// Compatibility for callers needing a single formatted address. Connections
// use the complete candidate set below and retain the hostname for reconnect.
template <typename Prepare, typename Stop, typename Resolve>
WireGuardEndpointResult PrepareWireGuardEndpoint(const std::string& original,
    Prepare prepare, Stop stop, Resolve resolve, std::string* numeric_endpoint) {
  if (!numeric_endpoint) return WireGuardEndpointResult::invalid;
  numeric_endpoint->clear();
  std::vector<std::string> endpoints;
  const auto status = PrepareWireGuardEndpoints(original, prepare, stop, resolve, &endpoints);
  if (status == WireGuardEndpointResult::ready) *numeric_endpoint = endpoints.front();
  return status;
}

enum class WireGuardAttemptResult { connected, retry, failed };

// All candidates share one deadline. A dead first address cannot consume the
// entire handshake budget and prevent a reachable later address being tried.
template <typename Now, typename Attempt>
bool TryWireGuardEndpoints(const std::vector<std::string>& endpoints,
                          std::uint64_t deadline, Now now, Attempt attempt) {
  for (size_t index = 0; index < endpoints.size(); ++index) {
    const auto started = now();
    if (started >= deadline) return false;
    const auto budget = (deadline - started) / (endpoints.size() - index);
    if (budget == 0) return false;
    const auto outcome = attempt(endpoints[index], started + budget);
    if (outcome == WireGuardAttemptResult::connected) return true;
    if (outcome == WireGuardAttemptResult::failed) return false;
  }
  return false;
}
}  // namespace fuzevpn
#endif
