// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NETWORK_PROTECTION_LIFECYCLE_H_
#define RUNNER_NETWORK_PROTECTION_LIFECYCLE_H_

#include "network_protection.h"

namespace fuzevpn {

enum class NetworkProtectionPhase { inactive, prepared, tunnel };

inline bool SameNetworkProtectionOptions(
    const NetworkProtectionOptions& left,
    const NetworkProtectionOptions& right) {
  return left.kill_switch == right.kill_switch &&
         left.dns_protection == right.dns_protection &&
         left.web_rtc_protection == right.web_rtc_protection;
}

struct NetworkProtectionFilterPlan {
  bool permit_engine;
  bool permit_ui;
  bool permit_system_dns;
  bool permit_tunnel;
  bool block_ipv4;
  bool block_dns;
  bool block_udp;
  bool block_ipv6;
};

inline NetworkProtectionFilterPlan BuildNetworkProtectionFilterPlan(
    bool prepared, const NetworkProtectionOptions& options) {
  return {
      true,
      prepared,
      false,
      !prepared,
      options.kill_switch,
      options.dns_protection && !options.kill_switch,
      options.web_rtc_protection && !options.kill_switch,
      true,
  };
}

// Owns the policy metadata independently from the WFP handle. Call Activate
// only after the candidate transaction commits; failed candidates therefore
// leave the previously active phase, owner and options unchanged.
class NetworkProtectionLifecycle {
 public:
  bool IsSamePrepared(NetworkProtectionOwner owner,
                      const NetworkProtectionOptions& options) const {
    return phase_ == NetworkProtectionPhase::prepared && owner_ == owner &&
           SameNetworkProtectionOptions(options_, options);
  }

  bool CanPromote(NetworkProtectionOwner owner,
                  const NetworkProtectionOptions& options) const {
    return !options.kill_switch ||
           (phase_ != NetworkProtectionPhase::inactive && owner_ == owner &&
            SameNetworkProtectionOptions(options_, options));
  }

  void ActivatePrepared(NetworkProtectionOwner owner,
                        const NetworkProtectionOptions& options) {
    owner_ = owner;
    options_ = options;
    phase_ = NetworkProtectionPhase::prepared;
  }

  void ActivateTunnel(NetworkProtectionOwner owner,
                      const NetworkProtectionOptions& options) {
    owner_ = owner;
    options_ = options;
    phase_ = NetworkProtectionPhase::tunnel;
  }

  bool IsActive(NetworkProtectionOwner owner) const {
    return phase_ != NetworkProtectionPhase::inactive && owner_ == owner;
  }

  bool IsTunnel(NetworkProtectionOwner owner) const {
    return phase_ == NetworkProtectionPhase::tunnel && owner_ == owner;
  }

  NetworkProtectionStatus Status(NetworkProtectionOwner owner) const {
    if (!IsActive(owner)) return {};
    return {true, options_.kill_switch,
            phase_ == NetworkProtectionPhase::tunnel
                ? NetworkProtectionStatus::Phase::tunnel
                : NetworkProtectionStatus::Phase::prepared};
  }

  void Clear() {
    options_ = NetworkProtectionOptions{};
    phase_ = NetworkProtectionPhase::inactive;
  }

 private:
  NetworkProtectionOwner owner_ = NetworkProtectionOwner::wire_guard;
  NetworkProtectionOptions options_;
  NetworkProtectionPhase phase_ = NetworkProtectionPhase::inactive;
};

}  // namespace fuzevpn

#endif  // RUNNER_NETWORK_PROTECTION_LIFECYCLE_H_
