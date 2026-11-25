// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_TRAFFIC_STATISTICS_H_
#define RUNNER_TRAFFIC_STATISTICS_H_

#include <cstdint>
#include <limits>

#include <flutter/encodable_value.h>

namespace fuzevpn {

// Bytes received from and sent to the VPN server by the current tunnel, as
// its engine counts them on the transport. Callers answer null instead when
// no verified tunnel can be read.
inline flutter::EncodableValue TrafficStatisticsValue(std::uint64_t received,
                                                      std::uint64_t sent) {
  constexpr auto kMaximum =
      static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  const auto bounded = [](std::uint64_t value) {
    return flutter::EncodableValue(
        static_cast<std::int64_t>(value < kMaximum ? value : kMaximum));
  };
  return flutter::EncodableValue(flutter::EncodableMap{
      {flutter::EncodableValue("received"), bounded(received)},
      {flutter::EncodableValue("sent"), bounded(sent)},
  });
}

}  // namespace fuzevpn

#endif  // RUNNER_TRAFFIC_STATISTICS_H_
