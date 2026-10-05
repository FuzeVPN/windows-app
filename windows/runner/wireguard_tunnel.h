// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_TUNNEL_H_
#define RUNNER_WIREGUARD_TUNNEL_H_

#include <optional>
#include "diagnostics_state.h"

#include <flutter/method_call.h>
#include <flutter/method_result.h>
#include <flutter/encodable_value.h>

#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/flutter_engine.h>
#endif

// Returns an exit code only when this process was started by the embedded
// WireGuard tunnel service. Normal Flutter launches return std::nullopt.
std::optional<int> RunWireGuardServiceCommandIfRequested();

#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterWireGuardChannel(flutter::FlutterEngine* engine);
#endif

// Executes the small privileged WireGuard command surface inside the elevated
// broker process. It never receives an API token and never returns key data.
void HandleWireGuardPrivilegedCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    flutter::MethodResult<flutter::EncodableValue>* result);

// Query-only SCM access is intentionally kept in the unelevated UI process.
bool IsWireGuardTunnelConnected();
// Unlike isConnected, false includes transitional states; an SCM error remains
// unknown. Used only to release ownership after confirmed native teardown.
std::optional<bool> IsWireGuardTunnelStopped();
fuzevpn_diagnostics::EngineObservation WireGuardDiagnostics(const std::string& user, bool observe_owned_network = false);
bool WireGuardDiagnosticsCurrent(const std::string& user, const fuzevpn_diagnostics::EngineObservation& observation);

// Called when the UI exits so that a transient tunnel service and its
// restricted configuration file do not remain behind.
#ifndef FUZEVPN_SERVICE_PROCESS
void StopWireGuardTunnel();
#endif

// Removes the stopped per-session tunnel registration when its privileged
// owner exits. Normal Disconnect deliberately keeps it for fast reconnection.
void RemoveWireGuardTunnelService();

#endif  // RUNNER_WIREGUARD_TUNNEL_H_
