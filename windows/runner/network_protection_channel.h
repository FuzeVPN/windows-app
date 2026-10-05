// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NETWORK_PROTECTION_CHANNEL_H_
#define RUNNER_NETWORK_PROTECTION_CHANNEL_H_

#include <flutter/encodable_value.h>
#include "network_protection.h"

inline flutter::EncodableValue NetworkProtectionStatusValue(
    NetworkProtectionOwner owner) {
  const auto status = GetNetworkProtectionStatus(owner);
  const char* phase = status.phase == NetworkProtectionStatus::Phase::tunnel
                          ? "tunnel"
                          : status.phase == NetworkProtectionStatus::Phase::prepared
                                ? "prepared" : "inactive";
  return flutter::EncodableValue(flutter::EncodableMap{
      {flutter::EncodableValue("active"), flutter::EncodableValue(status.active)},
      {flutter::EncodableValue("killSwitch"), flutter::EncodableValue(status.kill_switch)},
      {flutter::EncodableValue("phase"), flutter::EncodableValue(phase)},
  });
}

#endif
