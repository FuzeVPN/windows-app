// SPDX-License-Identifier: MPL-2.0
#include "diagnostics_snapshot.h"
#include <string_view>

namespace fuzevpn_diagnostics {
using Value = flutter::EncodableValue;
using Map = flutter::EncodableMap;
using List = flutter::EncodableList;
namespace {
void Check(List& checks, const char* id, CheckResult result) {
  checks.emplace_back(Map{{Value("id"), Value(id)}, {Value("result"), Value(ResultName(result))}});
}
void Number(Map& map, const char* key, std::optional<std::uint64_t> value,
            std::uint64_t limit = kMaximumDurationMs) {
  if (value && *value <= limit) map[Value(key)] = Value(static_cast<std::int64_t>(*value));
}
// The diagnostic state can contain progress sentinels. Only real public error
// categories are eligible for the closed API registry.
const char* ErrorCode(std::string_view code) {
  if (code.empty() || code == "none" || code == "openvpn_transport_started" || code == "openvpn_adapter_opened") return nullptr;
  for (const char* allowed : {"openvpn_connection_failed", "openvpn_adapter_failed",
      "openvpn_transport_failed", "openvpn_profile_crypto_failed", "openvpn_local_identity_mismatch",
      "openvpn_local_identity_failed", "openvpn_certificate_validation_failed", "openvpn_tls_handshake_failed",
      "openvpn_client_config_failed", "openvpn_dns_configuration_failed", "openvpn_network_configuration_failed",
      "openvpn_dco_profile_incompatible", "network_protection_failed", "openvpn_stop_timeout", "openvpn_cleanup_failed"})
    if (code == allowed) return allowed;
  return "unknown_error";
}
const char* Phase(std::string_view phase) {
  for (const char* value : {"unknown", "tunnel_start", "adapter_create", "handshake", "addresses_apply",
       "routes_apply", "completed", "cleanup"}) if (phase == value) return value;
  return "unknown";
}
const char* Cleanup(std::string_view state) {
  for (const char* value : {"not_requested", "pending", "completed", "failed"}) if (state == value) return value;
  return "unknown";
}
CheckResult ConfigurationResult(const NetworkObservation& value) {
  const CheckResult results[] = {value.adapter, value.ipv4, value.ipv6, value.routing, value.dns};
  for (const auto result : results) if (result == CheckResult::failed) return result;
  for (const auto result : results) if (result == CheckResult::unknown) return result;
  if (value.adapter == CheckResult::skipped) return CheckResult::skipped;
  if ((value.ipv4 == CheckResult::passed || value.ipv6 == CheckResult::passed) &&
      value.routing == CheckResult::passed && value.dns == CheckResult::passed) return CheckResult::passed;
  return CheckResult::unknown;
}
bool NumericVersion(const std::string& version) {
  if (version.empty() || version.size() > 23) return false;
  unsigned components = 1, digits = 0;
  for (const char c : version) {
    if (c == '.') { if (!digits || ++components > 4) return false; digits = 0; }
    else if (c < '0' || c > '9' || ++digits > 5) return false;
  }
  return digits != 0;
}
}

Map EncodeSnapshot(const RuntimeObservation& source) {
  Map snapshot, windows, runtime;
  List checks;
  runtime[Value("presence")] = Value(!source.present ? "unknown" : *source.present ? "present" : "absent");
  runtime[Value("cleanup_eligible")] = Value(false);
  runtime[Value("protocol")] = Value("unknown");
  if (source.present && !*source.present) {
    // A stopped/absent portable engine is normal. It proves no live observation
    // of its filters/adapter and is not a failing connectivity test.
    Check(checks, "service_availability", CheckResult::skipped);
    Check(checks, "tunnel_connection", CheckResult::skipped);
    Check(checks, "kill_switch", CheckResult::skipped);
  } else if (!source.present) {
    Check(checks, "service_availability", CheckResult::unknown);
    Check(checks, "tunnel_connection", CheckResult::unknown);
    Check(checks, "kill_switch", CheckResult::unknown);
  } else {
    snapshot[Value("owned_by_another_user")] = Value(source.other_user);
    runtime[Value("owned_by_another_user")] = Value(source.other_user);
    Check(checks, "service_availability", CheckResult::passed);  // authenticated runtime responded
    const auto* protection = source.openvpn_protection.active ? &source.openvpn_protection :
        source.wireguard_protection.active ? &source.wireguard_protection : nullptr;
    if (source.protection_known && protection) {
      // Requested UI preference is supplied by the controller, independently
      // from the verified installed policy reported here.
      snapshot[Value("kill_switch_verified")] = Value(protection->kill_switch);
      Check(checks, "kill_switch", protection->kill_switch ? CheckResult::passed : CheckResult::skipped);
    } else Check(checks, "kill_switch", source.protection_known ? CheckResult::skipped : CheckResult::unknown);
    if (!source.other_user) {
      const bool openvpn = source.openvpn_protection.active || (!source.wireguard_protection.active &&
          source.openvpn.available && (!source.wireguard.available || source.openvpn.observation_tick >= source.wireguard.observation_tick));
      const auto& engine = openvpn ? source.openvpn : source.wireguard;
      if (engine.available) {
        const bool cleanup_eligible = source.owned && (engine.cleanup_eligible ||
            (engine.attempt_failed && !engine.connected && source.protection_known && protection &&
             protection->phase == NetworkProtectionStatus::Phase::prepared));
        const bool cleanup_complete = std::string_view(Cleanup(engine.cleanup_state)) == "completed" &&
            source.protection_known && !source.wireguard_protection.active && !source.openvpn_protection.active;
        runtime[Value("protocol")] = Value(openvpn ? "openvpn" : "wireguard");
        runtime[Value("cleanup_eligible")] = Value(cleanup_eligible);
        snapshot[Value("phase")] = Value(Phase(engine.phase));
        const char* cleanup = Cleanup(engine.cleanup_state);
        if (std::string_view(cleanup) == "completed" && !cleanup_complete)
          cleanup = source.protection_known ? "pending" : "unknown";
        snapshot[Value("cleanup_state")] = Value(cleanup);
        Number(snapshot, "freshness_ms", engine.freshness_ms);
        Number(snapshot, "connection_duration_ms", engine.connection_duration_ms);
        Number(snapshot, "handshake_age_ms", engine.handshake_age_ms);
        Number(snapshot, "bytes_sent", engine.bytes_sent, kMaximumBytes);
        Number(snapshot, "bytes_received", engine.bytes_received, kMaximumBytes);
        Number(snapshot, "reconnect_count", engine.reconnect_count, 1000000);
        const bool protected_connection = source.protection_known && protection &&
            protection->phase == NetworkProtectionStatus::Phase::tunnel;
        Check(checks, "tunnel_connection", !source.protection_known ? CheckResult::unknown :
            engine.connected && protected_connection ? CheckResult::passed :
            !engine.connected && !source.owned && !protection ? CheckResult::skipped : CheckResult::failed);
        Check(checks, "cleanup", cleanup_complete ? CheckResult::passed : cleanup_eligible ? CheckResult::failed :
            std::string_view(cleanup) == "unknown" ? CheckResult::unknown : CheckResult::skipped);
        if (engine.handshake_age_ms) Check(checks, "handshake", CheckResult::passed);
        const auto& network = engine.network;
        Check(checks, "tunnel_configuration", ConfigurationResult(network));
        Check(checks, "ipv4", network.ipv4);
        Check(checks, "ipv6", network.ipv6);
        Check(checks, "routing", network.routing);
        Check(checks, "dns", network.dns);
        List families;
        if (network.ipv4_count && *network.ipv4_count) families.emplace_back("ipv4");
        if (network.ipv6_count && *network.ipv6_count) families.emplace_back("ipv6");
        if (!families.empty()) snapshot[Value("ip_families")] = Value(families);
        Number(windows, "configured_ipv4_count", network.ipv4_count, 1000);
        Number(windows, "configured_ipv6_count", network.ipv6_count, 1000);
        if (openvpn) {
          windows[Value("dco_enabled")] = Value(engine.dco);
          Number(windows, "engine_connect_ms", engine.engine_connect_ms);
          Number(windows, "configuration_ms", engine.configuration_ms);
          Number(windows, "validation_ms", engine.validation_ms);
          Number(windows, "dco_failures", engine.dco_failures, 1000000);
          Number(windows, "postconditions_mask", engine.postconditions_mask, 0xffffffffULL);
          if (const auto* code = ErrorCode(engine.first_error)) windows[Value("first_error")] = Value(code);
          if (const auto* code = ErrorCode(engine.last_error)) windows[Value("last_error")] = Value(code);
        }
      } else Check(checks, "tunnel_connection", CheckResult::unknown);
      Check(checks, "driver_availability", source.driver.available);
    } else {
      Check(checks, "tunnel_connection", CheckResult::skipped);
      Check(checks, "permissions", CheckResult::failed);
    }
  }
  Map result{{Value("runtime"), Value(runtime)}, {Value("snapshot"), Value(snapshot)},
             {Value("checks"), Value(checks)}, {Value("windows"), Value(windows)}};
  if (source.present && *source.present) {
    Map environment;
    if (!source.other_user && NumericVersion(source.driver.version)) environment[Value("driver_version")] = Value(source.driver.version);
    if (!environment.empty()) result[Value("environment")] = Value(environment);
  }
  return result;
}

}  // namespace fuzevpn_diagnostics
