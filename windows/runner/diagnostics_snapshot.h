// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIAGNOSTICS_SNAPSHOT_H_
#define RUNNER_DIAGNOSTICS_SNAPSHOT_H_
#include <flutter/encodable_value.h>
#include "diagnostics_state.h"
#include "network_protection.h"
#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/flutter_engine.h>
void RegisterDiagnosticsChannel(flutter::FlutterEngine* engine);
#endif

namespace fuzevpn_diagnostics {
struct RuntimeObservation {
  std::optional<bool> present;
  bool owned = false, other_user = false;
  bool protection_known = false;
  NetworkProtectionStatus wireguard_protection, openvpn_protection;
  EngineObservation wireguard, openvpn;
  DriverObservation driver;
};
// Pure serialization surface, tested with fabricated observations. Neither
// strings from logs nor NetworkExpectation have a route into this function.
flutter::EncodableMap EncodeSnapshot(const RuntimeObservation& observation);
// Nonblocking cache access; all Windows observations run on one passive worker.
flutter::EncodableMap RequestRuntimeSnapshot(const std::string& user, bool owned, bool other_user);
void InvalidateRuntimeSnapshots();
void ShutdownRuntimeSnapshots();
}
#endif
