// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_DIAGNOSTIC_STATE_H_
#define RUNNER_OPENVPN_DIAGNOSTIC_STATE_H_

#include <cstdint>
#include <initializer_list>
#include <mutex>
#include <string>
#include <string_view>

namespace fuzevpn {
// All retained strings point to fixed literals. Raw Core events, messages,
// endpoints, credentials and packet contents are never stored here.
enum class OpenVpnDcoDiagnostic { peer_ready, send_attempt, send_ok, send_failed, receive_ok };
struct OpenVpnDiagnosticSnapshot {
  bool peer_ready = false;
  std::uint32_t send_attempts = 0, send_ok = 0, send_failed = 0, received = 0;
  std::uint32_t reconnects = 0;
  unsigned stage = 0;
  const char* last_event = "none";
  const char* first_error = "none";
  const char* last_error = "none";
};

inline const char* SafeOpenVpnFailure(std::string_view value) {
  for (const char* known : {
      "none",
      "openvpn_connection_failed", "openvpn_transport_started", "openvpn_adapter_opened",
      "openvpn_adapter_failed", "openvpn_transport_failed", "openvpn_profile_crypto_failed",
      "openvpn_local_identity_mismatch", "openvpn_local_identity_failed", "openvpn_certificate_validation_failed",
      "openvpn_tls_handshake_failed", "openvpn_client_config_failed",
      "openvpn_dns_configuration_failed", "openvpn_network_configuration_failed",
      "openvpn_dco_profile_incompatible", "network_protection_failed",
      "openvpn_stop_timeout", "openvpn_cleanup_failed"}) {
    if (value == known) return known;
  }
  return "other";
}

class OpenVpnDiagnosticState {
 public:
  void Dco(OpenVpnDcoDiagnostic event) {
    std::lock_guard<std::mutex> lock(mutex_);
    switch (event) {
      case OpenVpnDcoDiagnostic::peer_ready: state_.peer_ready = true; Stage(2); break;
      case OpenVpnDcoDiagnostic::send_attempt: Increment(state_.send_attempts); break;
      case OpenVpnDcoDiagnostic::send_ok: Increment(state_.send_ok); break;
      case OpenVpnDcoDiagnostic::send_failed: Increment(state_.send_failed); break;
      case OpenVpnDcoDiagnostic::receive_ok: Increment(state_.received); break;
    }
  }
  void Event(std::string_view value) {
    const char* name = nullptr;
    for (const char* known : {"RESOLVE", "WAIT", "WAIT_PROXY", "CONNECTING", "GET_CONFIG",
        "ASSIGN_IP", "ADD_ROUTES", "CONNECTED", "RECONNECTING", "AUTH_PENDING",
        "DISCONNECTED", "PAUSE", "RESUME", "TRANSPORT_ERROR", "TUN_ERROR",
        "AUTH_FAILED", "CERT_VERIFY_FAIL", "TLS_ALERT_HANDSHAKE_FAILURE",
        "TUN_SETUP_FAILED", "CONNECTION_TIMEOUT", "CLIENT_SETUP"}) {
      if (value == known) { name = known; break; }
    }
    if (!name) return;
    std::lock_guard<std::mutex> lock(mutex_);
    state_.last_event = name;
    if (value == "CONNECTING") Stage(3);  // First received transport packet.
    else if (value == "GET_CONFIG" || value == "AUTH_PENDING") Stage(4);
    else if (value == "ASSIGN_IP") Stage(5);
    else if (value == "ADD_ROUTES") Stage(6);
    else if (value == "CONNECTED") Stage(7);
    else if (value == "RECONNECTING") Increment(state_.reconnects);
  }
  void Log(std::string_view value) {
    unsigned stage = 0;
    if (value.find("Open TAP device") != value.npos && value.find("SUCCEEDED") != value.npos) stage = 1;
    else if (value.starts_with("Connecting to ")) stage = 2;
    else if (value == "Session is ACTIVE" || value == "Session is ACTIVE\n") stage = 4;
    if (!stage) return;
    std::lock_guard<std::mutex> lock(mutex_);
    Stage(stage);
  }
  void Failure(std::string_view value) {
    const char* safe = SafeOpenVpnFailure(value);
    if (std::string_view(safe) == "other" || value == "openvpn_transport_started" ||
        value == "openvpn_adapter_opened") return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::string_view(state_.first_error) == "none") state_.first_error = safe;
    state_.last_error = safe;
  }
  OpenVpnDiagnosticSnapshot Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
  }
 private:
  static void Increment(std::uint32_t& value) { if (value < 1000000) ++value; }
  void Stage(unsigned value) { if (value > state_.stage) state_.stage = value; }
  mutable std::mutex mutex_;
  OpenVpnDiagnosticSnapshot state_;
};

inline thread_local OpenVpnDiagnosticState* openvpn_diagnostic_state = nullptr;
class ScopedOpenVpnDiagnosticState {
 public:
  explicit ScopedOpenVpnDiagnosticState(OpenVpnDiagnosticState* value)
      : previous_(openvpn_diagnostic_state) { openvpn_diagnostic_state = value; }
  ~ScopedOpenVpnDiagnosticState() { openvpn_diagnostic_state = previous_; }
 private:
  OpenVpnDiagnosticState* previous_;
};
inline void RecordOpenVpnDcoDiagnostic(OpenVpnDcoDiagnostic event) {
  if (openvpn_diagnostic_state) openvpn_diagnostic_state->Dco(event);
}
inline std::string FormatOpenVpnDiagnostic(const OpenVpnDiagnosticSnapshot& value,
                                         bool command_failed,
                                         std::string_view failure) {
  constexpr const char* stages[] = {"starting", "adapter_open", "peer_ready", "packet_received",
      "tls_active", "assign_ip", "add_routes", "connected"};
  return "peer_ready=" + std::to_string(value.peer_ready) +
      " send_attempts=" + std::to_string(value.send_attempts) +
      " send_ok=" + std::to_string(value.send_ok) +
      " send_failed=" + std::to_string(value.send_failed) +
      " received=" + std::to_string(value.received) +
      " reconnects=" + std::to_string(value.reconnects) +
      " stage=" + stages[value.stage < 8 ? value.stage : 0] +
      " last_event=" + value.last_event + " first_error=" + value.first_error +
      " last_error=" + value.last_error + " failure_before_stop=" + SafeOpenVpnFailure(failure) +
      " command_failed=" + std::to_string(command_failed);
}
}  // namespace fuzevpn
#endif
