// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIAGNOSTICS_STATE_H_
#define RUNNER_DIAGNOSTICS_STATE_H_

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace fuzevpn_diagnostics {
enum class CheckResult { unknown, skipped, passed, failed };
inline const char* ResultName(CheckResult value) {
  switch (value) {
    case CheckResult::skipped: return "skipped";
    case CheckResult::passed: return "passed";
    case CheckResult::failed: return "failed";
    default: return "unknown";
  }
}
inline constexpr std::uint64_t kMaximumDurationMs = 604800000;
inline constexpr std::uint64_t kMaximumBytes = 9007199254740991;
inline std::optional<std::uint64_t> BoundedAge(std::uint64_t now, std::uint64_t then) {
  if (!then || now < then || now - then > kMaximumDurationMs) return std::nullopt;
  return now - then;
}

// Internal only. Never serialize this structure: the OS configuration remains
// inside the authenticated privileged runtime, including pushed OpenVPN DNS.
struct NetworkExpectation {
  std::uint64_t luid = 0;
  std::uint32_t index = 0;
  std::vector<std::string> addresses, routes, dns;
  std::string nrpt_rule;
  std::uint64_t generation = 0;
};
struct NetworkObservation {
  CheckResult adapter = CheckResult::skipped;
  CheckResult ipv4 = CheckResult::skipped, ipv6 = CheckResult::skipped;
  CheckResult routing = CheckResult::skipped, dns = CheckResult::skipped;
  std::optional<unsigned> ipv4_count, ipv6_count;
};
struct DriverObservation {
  CheckResult available = CheckResult::unknown;
  std::string version;  // Numeric components only, populated from parsed uint64.
};
struct EngineObservation {
  std::uint64_t observation_tick = 0;  // Local selection only, never serialized.
  std::uint64_t generation = 0, configuration_generation = 0;  // Cache validation only.
  bool available = false;  // No evidence for this Windows account is not false.
  bool connected = false;
  bool attempt_failed = false;
  bool cleanup_eligible = false;
  const char* cleanup_state = "unknown";
  const char* phase = "unknown";
  std::optional<std::uint64_t> freshness_ms, connection_duration_ms;
  std::optional<std::uint64_t> bytes_sent, bytes_received, handshake_age_ms;
  std::optional<std::uint64_t> engine_connect_ms, configuration_ms, validation_ms;
  std::optional<unsigned> reconnect_count, dco_failures, postconditions_mask;
  bool dco = false;
  std::string first_error, last_error;
  NetworkObservation network;
};

// Capture is observational and best effort; allocation failure must never turn
// a successful VPN configuration into a failed connection.
class NetworkExpectationCapture {
 public:
  void Store(const std::vector<std::string>& addresses,
             const std::vector<std::string>& routes,
             const std::vector<std::string>& dns, std::uint32_t index,
             std::string nrpt_rule, std::uint64_t luid) noexcept {
    try {
      if (!index || !luid || addresses.size() > 16 || routes.size() > 256 || dns.size() > 16 ||
          nrpt_rule.size() > 128) { Invalidate(); return; }
      const auto bounded = [](const auto& values) {
        for (const auto& v : values) if (v.empty() || v.size() > 128) return false;
        return true;
      };
      if (!bounded(addresses) || !bounded(routes) || !bounded(dns)) { Invalidate(); return; }
      NetworkExpectation next{luid, index, addresses, routes, dns, std::move(nrpt_rule)};
      std::lock_guard<std::mutex> lock(mutex_);
      next.generation = ++generation_;
      value_ = std::move(next);
    } catch (...) { Invalidate(); }
  }
  NetworkExpectation Read() const { std::lock_guard<std::mutex> lock(mutex_); return value_; }
 private:
  void Invalidate() noexcept {
    try {
      std::lock_guard<std::mutex> lock(mutex_);
      value_ = {};
      value_.generation = ++generation_;
    } catch (...) {}
  }
  mutable std::mutex mutex_;
  NetworkExpectation value_;
  std::uint64_t generation_ = 0;
};
inline thread_local NetworkExpectationCapture* network_capture = nullptr;
class ScopedNetworkExpectationCapture {
 public:
  explicit ScopedNetworkExpectationCapture(NetworkExpectationCapture* value)
      : previous_(network_capture) { network_capture = value; }
  ~ScopedNetworkExpectationCapture() { network_capture = previous_; }
 private:
  NetworkExpectationCapture* previous_;
};
inline void CaptureNetworkExpectation(const std::vector<std::string>& addresses,
    const std::vector<std::string>& routes, const std::vector<std::string>& dns,
    std::uint32_t index, std::string nrpt_rule, std::uint64_t luid) noexcept {
  if (network_capture) network_capture->Store(addresses, routes, dns, index, std::move(nrpt_rule), luid);
}
}  // namespace fuzevpn_diagnostics
#endif
