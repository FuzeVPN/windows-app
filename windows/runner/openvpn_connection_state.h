// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_CONNECTION_STATE_H_
#define RUNNER_OPENVPN_CONNECTION_STATE_H_

#include <string_view>

namespace fuzevpn {
// Caller provides synchronization. CONNECTED is accepted only after the
// engine's actual adapter has received network protection.
struct OpenVpnConnectionState {
  bool connected = false;
  bool terminal = false;
  void Event(std::string_view name, bool error, bool fatal,
             bool protection_ready = true) {
    if (name == "CONNECTED") {
      connected = protection_ready && !error && !fatal;
      terminal = !connected;
    } else if (name == "RECONNECTING" || name == "DISCONNECTED" ||
               name == "PAUSE" || name == "RESUME" || error || fatal) {
      connected = false;
    }
    if (name == "DISCONNECTED" || error || fatal) terminal = true;
  }
  void Complete() {
    connected = false;
    terminal = true;
  }
};
}  // namespace fuzevpn
#endif
