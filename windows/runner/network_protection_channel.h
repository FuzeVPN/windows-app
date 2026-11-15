// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NETWORK_PROTECTION_CHANNEL_H_
#define RUNNER_NETWORK_PROTECTION_CHANNEL_H_

#include <flutter/encodable_value.h>
#include "network_protection.h"
#include "network_protection_failure.h"

inline flutter::EncodableValue NetworkProtectionFailureDetails() {
  const auto failure = fuzevpn_network_failure::Read();
  flutter::EncodableMap details;
  if (failure.stage && failure.status) {
    details[flutter::EncodableValue("stage")] = flutter::EncodableValue(failure.stage);
    details[flutter::EncodableValue("win32_error")] =
        flutter::EncodableValue(static_cast<int64_t>(failure.status));
  }
  return flutter::EncodableValue(details);
}

// The three keys every status reply carries, whoever computed the status.
inline flutter::EncodableMap NetworkProtectionStatusMap(
    const NetworkProtectionStatus& status) {
  const char* phase = status.phase == NetworkProtectionStatus::Phase::tunnel
                          ? "tunnel"
                          : status.phase == NetworkProtectionStatus::Phase::prepared
                                ? "prepared" : "inactive";
  return flutter::EncodableMap{
      {flutter::EncodableValue("active"), flutter::EncodableValue(status.active)},
      {flutter::EncodableValue("killSwitch"), flutter::EncodableValue(status.kill_switch)},
      {flutter::EncodableValue("phase"), flutter::EncodableValue(phase)},
  };
}

inline flutter::EncodableValue NetworkProtectionStatusValue(
    NetworkProtectionOwner owner) {
  return flutter::EncodableValue(
      NetworkProtectionStatusMap(GetNetworkProtectionStatus(owner)));
}

#endif
