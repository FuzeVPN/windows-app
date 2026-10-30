// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_ENDPOINT_H_
#define RUNNER_WIREGUARD_ENDPOINT_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "api_bootstrap_dns.h"
#include "wireguard_runtime_state.h"

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
// The attempt also receives its candidate index to choose its handshake window.
template <typename Now, typename Attempt>
bool TryWireGuardEndpoints(const std::vector<std::string>& endpoints,
                          std::uint64_t deadline, Now now, Attempt attempt) {
  for (size_t index = 0; index < endpoints.size(); ++index) {
    const auto started = now();
    if (started >= deadline) return false;
    const auto budget = (deadline - started) / (endpoints.size() - index);
    if (budget == 0) return false;
    const auto outcome = attempt(endpoints[index], started + budget, index);
    if (outcome == WireGuardAttemptResult::connected) return true;
    if (outcome == WireGuardAttemptResult::failed) return false;
  }
  return false;
}

// WireGuard retransmits an unanswered initiation every REKEY_TIMEOUT (5 s plus
// up to 333 ms of jitter). Earlier addresses of a multi-address hostname keep
// two initiations so failover stays fast. The last or only candidate has no
// alternative: four initiations tolerate lost or early ones, e.g. while a peer
// relocated by POST /v1/devices is still being applied on the exit node.
inline constexpr std::uint64_t kWireGuardFailoverHandshakeWaitMs = 8000;
inline constexpr std::uint64_t kWireGuardFinalHandshakeWaitMs = 20000;

inline std::uint64_t WireGuardHandshakeWindow(std::size_t candidate_index,
                                              std::size_t candidates) {
  return candidate_index + 1 >= candidates ? kWireGuardFinalHandshakeWaitMs
                                           : kWireGuardFailoverHandshakeWaitMs;
}

// The handshake wait used by ConnectTunnel. The tunnel service keeps running
// for the whole window; restarting it would reset the retransmission timer.
// Success is only an authenticated driver handshake reported by `read`.
template <typename Now, typename Solicit, typename ReadHandshake, typename Running,
          typename SleepFor>
bool WaitForWireGuardHandshake(std::uint64_t window_ms, std::uint64_t attempt_deadline,
                               Now now, Solicit solicit, ReadHandshake read,
                               Running running, SleepFor sleep) {
  const auto deadline = WireGuardWaitDeadline(now(), window_ms, attempt_deadline);
  std::uint64_t next_probe = 0;
  do {
    const auto current = now();
    if (current >= deadline) return false;
    if (current >= next_probe) {
      solicit();
      next_probe = current + 1000;
    }
    if (read()) return true;
    if (!running()) return false;
    const auto after_read = now();
    if (after_read >= deadline) return false;
    sleep(std::min<std::uint64_t>(100, deadline - after_read));
  } while (now() < deadline);
  return false;
}

// One driver reading during the handshake wait. Only a successful reading
// replaces the observed counters and is counted, so tx = rx = 0 with no
// counted reading means "no driver reading", not "nothing sent".
template <typename ReadStats>
bool ObserveWireGuardPeer(ReadStats read, WireGuardPeerStats* observed,
                          std::uint64_t* successful_reads) {
  WireGuardPeerStats stats;
  if (!read(&stats)) return false;
  *observed = stats;
  ++*successful_reads;
  return stats.handshake != 0;
}

// Times only the SCM start of the already written configuration, so a slow
// configuration generation or protected write is never blamed on SCM.
template <typename Now, typename Start>
bool TimeWireGuardServiceStart(Now now, Start start, std::uint64_t* elapsed_ms) {
  const auto began = now();
  const bool started = start();
  *elapsed_ms = now() - began;
  return started;
}

// Step in which a candidate attempt ended, reusing the native log's closed
// stage vocabulary: service start, adapter lookup, handshake wait, committed.
enum class WireGuardAttemptStage { starting, adapter_open, peer_ready, connected };

struct WireGuardAttemptSnapshot {
  std::size_t candidates = 0;
  std::size_t candidate_index = 0;
  WireGuardAttemptStage stage = WireGuardAttemptStage::starting;
  bool handshake = false;
  bool success = false;
  std::uint64_t elapsed_ms = 0;
  std::uint64_t budget_ms = 0;
  std::uint64_t service_start_ms = 0;
  std::uint64_t handshake_wait_ms = 0;
  std::uint64_t stop_ms = 0;
  std::uint64_t tx_bytes = 0;
  std::uint64_t rx_bytes = 0;
  // Successful PeerStats readings during the wait: with none, zero tx/rx
  // bytes mean the driver was never read, not that nothing was sent.
  std::uint64_t stats_reads = 0;
};

// Numeric and closed-set fields only: endpoints, addresses and keys never
// reach native_diagnostic.log.
inline std::string FormatWireGuardAttemptSnapshot(const WireGuardAttemptSnapshot& value) {
  constexpr const char* stages[] = {"starting", "adapter_open", "peer_ready", "connected"};
  const auto stage = static_cast<std::size_t>(value.stage);
  return "candidates=" + std::to_string(value.candidates) +
      " candidate_index=" + std::to_string(value.candidate_index) +
      " stage=" + stages[stage < 4 ? stage : 0] +
      " handshake=" + std::to_string(value.handshake ? 1 : 0) +
      " success=" + std::to_string(value.success ? 1 : 0) +
      " elapsed_ms=" + std::to_string(value.elapsed_ms) +
      " budget_ms=" + std::to_string(value.budget_ms) +
      " service_start_ms=" + std::to_string(value.service_start_ms) +
      " handshake_wait_ms=" + std::to_string(value.handshake_wait_ms) +
      " stop_ms=" + std::to_string(value.stop_ms) +
      " tx_bytes=" + std::to_string(value.tx_bytes) +
      " rx_bytes=" + std::to_string(value.rx_bytes) +
      " stats_reads=" + std::to_string(value.stats_reads);
}
}  // namespace fuzevpn
#endif
