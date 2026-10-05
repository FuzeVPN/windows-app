// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_TUNNEL_H_
#define RUNNER_OPENVPN_TUNNEL_H_

#include <flutter/method_call.h>
#include <flutter/method_result.h>
#include <flutter/encodable_value.h>

#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/flutter_engine.h>
#endif

// The OpenVPN 3 Core implementation is intentionally isolated from the
// WireGuard service. It owns the P-256 key, CSR and encrypted profile store.
#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterOpenVpnChannel(flutter::FlutterEngine* engine);
#endif

// Executes the native-only tunnel and identity operations in the privileged
// broker/service. CSR generation may return the public CSR, but the private
// key remains in the user's DPAPI store and never enters Dart.
void HandleOpenVpnPrivilegedCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    flutter::MethodResult<flutter::EncodableValue>* result);

// Used only inside the elevated broker to publish a non-sensitive connection
// bit to the unelevated Flutter process.
bool IsOpenVpnTunnelConnected();
bool IsOpenVpnTunnelStopped();

// Best-effort cleanup used when the app exits.
#ifndef FUZEVPN_SERVICE_PROCESS
void StopOpenVpnTunnel();
#endif

#endif  // RUNNER_OPENVPN_TUNNEL_H_
