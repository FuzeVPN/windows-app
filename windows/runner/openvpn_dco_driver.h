// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_DCO_DRIVER_H_
#define RUNNER_OPENVPN_DCO_DRIVER_H_
#include "diagnostics_state.h"

// Stages the signed, bundled OpenVPN DCO driver in the Windows driver store.
// It never downloads or executes an external OpenVPN installer.
bool EnsureBundledOpenVpnDcoDriver();

// Read-only package presence check used by the unelevated UI. Installation is
// deferred until the privileged broker receives a real connect request.
bool BundledOpenVpnDcoDriverAvailable();
bool OpenVpnDcoDriverRestartRequired();
// Query-only SetupAPI/registry observation. Never invokes Ensure/Install.
fuzevpn_diagnostics::DriverObservation ObserveOpenVpnDcoDriver();

#endif  // RUNNER_OPENVPN_DCO_DRIVER_H_
