// SPDX-License-Identifier: MPL-2.0
#include "diagnostics_snapshot.h"
#include "diagnostics_async.h"
#include "privileged_broker.h"
#include "wireguard_tunnel.h"
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
#include "openvpn_core_module.h"
#include "openvpn_dco_driver.h"
#endif
#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#endif
#include <algorithm>
#include <string_view>

namespace fuzevpn_diagnostics {
using Map = flutter::EncodableMap;
using Value = flutter::EncodableValue;
namespace {
struct CollectedSnapshot {
  RuntimeObservation observation;
  NetworkProtectionObservation protection;
  std::uint64_t started = 0;
};
CollectedSnapshot Collect(const AsyncSnapshot<CollectedSnapshot>::Request& request) {
  CollectedSnapshot collected;
  collected.started = GetTickCount64();
  auto& observation = collected.observation;
  const auto& user = request.user;
  const bool owned = request.owned, other_user = request.other_user;
  observation.present = true;
  observation.owned = owned;
  observation.other_user = other_user;
  collected.protection = ObserveNetworkProtection();
  observation.protection_known = collected.protection.known;
  observation.wireguard_protection = collected.protection.wireguard;
  observation.openvpn_protection = collected.protection.openvpn;
  if (!other_user) {
    observation.wireguard = WireGuardDiagnostics(user, owned);
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    observation.openvpn = OpenVpnCoreDiagnostics(user, owned);
    // DCO driver availability is only relevant when OpenVPN is the selected
    // native evidence. Never label the WireGuard driver with a DCO version.
    if (observation.openvpn_protection.active || (!observation.wireguard_protection.active &&
        observation.openvpn.available && (!observation.wireguard.available ||
        observation.openvpn.observation_tick >= observation.wireguard.observation_tick)))
      observation.driver = ObserveOpenVpnDcoDriver();
#endif
    if (observation.wireguard.connected && !observation.openvpn_protection.active)
      observation.driver.available = CheckResult::passed;  // queried live driver peer
  }
  // Re-observe WFP outside engine lifecycle locks after potentially slow OS
  // queries. This is still a historical observation, never a traffic probe.
  const auto after = ObserveNetworkProtection();
  observation.protection_known = observation.protection_known && after.known &&
      after.generation == collected.protection.generation;
  return collected;
}
AsyncSnapshot<CollectedSnapshot>& Cache() {
  static AsyncSnapshot<CollectedSnapshot> cache(Collect);
  return cache;
}
Map Pending(bool owned, bool other_user) {
  RuntimeObservation pending;
  pending.present = true; pending.owned = owned; pending.other_user = other_user;
  auto result = EncodeSnapshot(pending);
  std::get<Map>(result.at(Value("runtime")))[Value("collection_pending")] = Value(true);
  return result;
}
}  // namespace
Map RequestRuntimeSnapshot(const std::string& user, bool owned, bool other_user) {
  auto collected = Cache().Poll(user, owned, other_user);
  if (!collected) return Pending(owned, other_user);
  const auto age = BoundedAge(GetTickCount64(), collected->started);
  auto& observation = collected->observation;
  // Only cheap in-memory generation checks run on the pipe thread. Mutations
  // invalidate the cache before touching the runtime, even for the same SID.
  bool current = age && *age <= 8000 && observation.present == true &&
      IsNetworkProtectionObservationCurrent(collected->protection) &&
      WireGuardDiagnosticsCurrent(user, observation.wireguard);
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
  current = current && OpenVpnCoreDiagnosticsCurrent(user, observation.openvpn);
#endif
  if (!current) {
    Cache().Invalidate();
    Cache().Poll(user, owned, other_user);
    return Pending(owned, other_user);
  }
  const auto add_age = [age](auto& engine) {
    if (engine.freshness_ms) {
      const auto value = *engine.freshness_ms + *age;
      engine.freshness_ms = value <= kMaximumDurationMs ? std::optional<std::uint64_t>(value) : std::nullopt;
    }
  };
  add_age(observation.wireguard); add_age(observation.openvpn);
  auto result = EncodeSnapshot(observation);
  // Every live check is tagged with a conservative age from collection start.
  for (auto& item : std::get<flutter::EncodableList>(result.at(Value("checks"))))
    std::get<Map>(item)[Value("age_ms")] = Value(static_cast<std::int64_t>(*age));
  return result;
}
void InvalidateRuntimeSnapshots() { Cache().Invalidate(); }
void ShutdownRuntimeSnapshots() { Cache().Stop(); }
}  // namespace fuzevpn_diagnostics

#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterDiagnosticsChannel(flutter::FlutterEngine* engine) {
  auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      engine->messenger(), "com.fuzevpn/windows_diagnostics", &flutter::StandardMethodCodec::GetInstance());
  channel->SetMethodCallHandler([](const auto& call, auto result) {
    if (call.method_name() != "collectSnapshot") { result->NotImplemented(); return; }
    const auto presence = PrivilegedRuntimePresence();
    if (!presence || !*presence) {
      fuzevpn_diagnostics::RuntimeObservation observation; observation.present = presence;
      result->Success(flutter::EncodableValue(fuzevpn_diagnostics::EncodeSnapshot(observation)));
      return;
    }
    ForwardPrivilegedCall("diagnostics", call, std::move(result), false);
  });
}
#endif
