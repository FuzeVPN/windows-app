// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SPLIT_TUNNEL_ARGUMENTS_H_
#define RUNNER_SPLIT_TUNNEL_ARGUMENTS_H_

#include <flutter/encodable_value.h>

#include <string>
#include <vector>

#include "split_tunnel_policy.h"

namespace fuzevpn {

// Reads the optional split-tunnel arguments shared by both engines. Absent
// keys mean "off" (older UI). A present but malformed value rejects the
// whole request instead of silently widening or narrowing the tunnel.
inline bool DecodeSplitTunnelArguments(const flutter::EncodableMap& arguments,
                                       SplitTunnelPolicy* policy) {
  if (!policy) return false;
  std::string mode;
  std::vector<std::string> ranges;
  bool allow_lan = false;
  if (const auto it = arguments.find(flutter::EncodableValue("splitTunnelMode"));
      it != arguments.end()) {
    const auto* value = std::get_if<std::string>(&it->second);
    if (!value) return false;
    mode = *value;
  }
  if (const auto it = arguments.find(flutter::EncodableValue("splitTunnelRoutes"));
      it != arguments.end()) {
    const auto* list = std::get_if<flutter::EncodableList>(&it->second);
    if (!list || list->size() > kMaxSplitTunnelPrefixes) return false;
    for (const auto& item : *list) {
      const auto* value = std::get_if<std::string>(&item);
      if (!value) return false;
      ranges.push_back(*value);
    }
  }
  if (const auto it = arguments.find(flutter::EncodableValue("splitTunnelLan"));
      it != arguments.end()) {
    const auto* value = std::get_if<bool>(&it->second);
    if (!value) return false;
    allow_lan = *value;
  }
  return DecodeSplitTunnelPolicy(mode, ranges, allow_lan, policy);
}

}  // namespace fuzevpn

#endif  // RUNNER_SPLIT_TUNNEL_ARGUMENTS_H_
