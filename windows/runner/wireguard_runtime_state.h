// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_RUNTIME_STATE_H_
#define RUNNER_WIREGUARD_RUNTIME_STATE_H_

#include <cstdint>
#include <string>
#include <vector>

namespace fuzevpn {
inline std::vector<std::string> WireGuardRoutes(
    const std::vector<std::string>& allowed, bool kill_switch) {
  if (kill_switch) return allowed;
  std::vector<std::string> result;
  for (const auto& route : allowed) {
    if (route == "0.0.0.0/0") {
      result.emplace_back("0.0.0.0/1");
      result.emplace_back("128.0.0.0/1");
    } else if (route == "::/0") {
      result.emplace_back("::/1");
      result.emplace_back("8000::/1");
    } else result.push_back(route);
  }
  return result;
}

struct WireGuardPeerStats {
  std::uint64_t tx = 0, rx = 0, handshake = 0;
};

// A historical handshake is valid on an idle link. Only ongoing, unanswered
// outbound traffic with no new handshake is evidence of an unresponsive peer.
class WireGuardPeerHealth {
 public:
  bool Observe(const WireGuardPeerStats& current, std::uint64_t now_ms) {
    if (!current.handshake) return false;
    if (!initialized_ || current.handshake != previous_.handshake ||
        current.rx != previous_.rx || current.tx < previous_.tx) {
      pending_ = false;
      pending_since_ = 0;
    } else if (current.tx > previous_.tx && !pending_) {
      pending_ = true;
      pending_since_ = now_ms;
    }
    previous_ = current;
    initialized_ = true;
    return !pending_ || now_ms - pending_since_ < 240000;
  }
  void Reset() { *this = {}; }
 private:
  WireGuardPeerStats previous_{};
  std::uint64_t pending_since_ = 0;
  bool initialized_ = false, pending_ = false;
};

// Active observation identity is independent from permission/intention to
// reconnect. Cancelling reconnect must not hide a tunnel whose stop failed.
class WireGuardActivePeer {
 public:
  void Activate(const std::string& public_key, const WireGuardPeerStats& stats,
                 std::uint64_t now_ms) {
    public_key_ = public_key;
    health_.Reset();
    health_.Observe(stats, now_ms);
  }
  void StopResult(bool confirmed_stopped) {
    if (confirmed_stopped) {
      public_key_.clear();
      health_.Reset();
    }
  }
  const std::string& public_key() const { return public_key_; }
  bool Observe(const WireGuardPeerStats& stats, std::uint64_t now_ms) {
    return !public_key_.empty() && health_.Observe(stats, now_ms);
  }
 private:
  std::string public_key_;
  WireGuardPeerHealth health_;
};
}  // namespace fuzevpn
#endif
