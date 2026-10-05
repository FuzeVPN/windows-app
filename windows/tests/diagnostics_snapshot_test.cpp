// SPDX-License-Identifier: MPL-2.0
#include "diagnostics_network.h"
#include "diagnostics_snapshot.h"
#include "diagnostics_async.h"
#include "wireguard_runtime_state.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <atomic>
#include <chrono>
#include <future>

namespace {
using namespace fuzevpn_diagnostics;
using Value = flutter::EncodableValue;
using Map = flutter::EncodableMap;
using List = flutter::EncodableList;
void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void AsyncChecks() {
  struct Observation { std::string user; std::uint64_t generation = 0; bool owned = false; };
  std::promise<void> started, release;
  auto gate = release.get_future().share();
  std::atomic<unsigned> calls{0}, readers{0}, maximum{0};
  AsyncSnapshot<Observation> cache([&](const auto& request) {
    const auto active = ++readers;
    maximum.store((std::max)(maximum.load(), active));
    if (++calls == 1) { started.set_value(); gate.wait(); }
    --readers;
    return Observation{request.user, request.generation, request.owned};
  });
  const auto pending = cache.Poll("synthetic-account-a", true, false);
  const bool worker_started = started.get_future().wait_for(std::chrono::seconds(2)) == std::future_status::ready;
  // These operations must finish while the passive reader is blocked. This
  // simulates a slow IPHelper/WFP read without touching Windows or a tunnel.
  const auto start = std::chrono::steady_clock::now();
  const auto same_pending = cache.Poll("synthetic-account-a", true, false);
  cache.Invalidate();
  const auto other_pending = cache.Poll("synthetic-account-b", false, true);
  const auto duration = std::chrono::steady_clock::now() - start;
  release.set_value();
  Check(worker_started && !pending && !same_pending && !other_pending, "slow reader returns pending without exposing data");
  Check(duration < std::chrono::milliseconds(500), "passive worker does not hold IPC cache lock");
  auto await_result = [&](const std::string& user, bool owned, bool other) {
    std::optional<Observation> result;
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!result && std::chrono::steady_clock::now() < end) {
      result = cache.Poll(user, owned, other);
      if (!result) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    Check(result.has_value(), "asynchronous result eventually available");
    return *result;
  };
  const auto replacement = await_result("synthetic-account-b", false, true);
  Check(replacement.user == "synthetic-account-b" && replacement.generation == 1 && !replacement.owned,
        "mutation and account change discard old reader output");
  Check(!cache.Poll("synthetic-account-b", false, true), "result consumed only once");
  const auto foreign = await_result("synthetic-account-a", true, false);
  Check(foreign.user == "synthetic-account-a" && foreign.owned, "foreign cached result never crosses account boundary");
  cache.Invalidate();
  const auto next = await_result("synthetic-account-a", true, false);
  Check(next.generation == 2, "same owner mutation invalidates prior generation");
  Check(maximum == 1, "one passive reader maximum");
  cache.Stop();
  Check(!cache.Poll("synthetic-account-a", true, false), "stopped worker cannot restart");
}
const Map& Child(const Map& map, const char* key) { return std::get<Map>(map.at(Value(key))); }
bool Has(const Map& map, const char* key) { return map.contains(Value(key)); }
std::string Text(const Map& map, const char* key) { return std::get<std::string>(map.at(Value(key))); }
std::string CheckResultOf(const Map& map, const char* id) {
  for (const auto& value : std::get<List>(map.at(Value("checks")))) {
    const auto& item = std::get<Map>(value);
    if (Text(item, "id") == id) return Text(item, "result");
  }
  return {};
}
MIB_UNICASTIPADDRESS_ROW Address(const char* text, IP_DAD_STATE state,
                                ULONG index = 12, std::uint64_t luid = 800) {
  MIB_UNICASTIPADDRESS_ROW row{};
  row.InterfaceLuid.Value = luid; row.InterfaceIndex = index; row.DadState = state;
  row.Address.si_family = std::string_view(text).find(':') == std::string_view::npos ? AF_INET : AF_INET6;
  if (row.Address.si_family == AF_INET) InetPtonA(AF_INET, text, &row.Address.Ipv4.sin_addr);
  else InetPtonA(AF_INET6, text, &row.Address.Ipv6.sin6_addr);
  return row;
}
MIB_IPFORWARD_ROW2 Route(const char* text, unsigned prefix, ULONG index = 12,
                        std::uint64_t luid = 800) {
  MIB_IPFORWARD_ROW2 row{};
  row.InterfaceLuid.Value = luid; row.InterfaceIndex = index;
  row.DestinationPrefix.Prefix = Address(text, IpDadStatePreferred).Address;
  row.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix);
  return row;
}
void NetworkChecks() {
  NetworkExpectationCapture capture;
  capture.Store({"10.8.0.2"}, {"0.0.0.0/1"}, {"10.8.0.1"}, 12, {}, 800);
  const auto first = capture.Read();
  capture.Store({"10.8.0.2"}, {"0.0.0.0/1"}, {"10.8.0.1"}, 12, {}, 800);
  Check(first.generation != capture.Read().generation, "even identical reconnection invalidates prior observation");
  capture.Store({"10.8.0.2"}, {}, {}, 0, {}, 0);
  Check(capture.Read().luid == 0 && capture.Read().generation != first.generation,
        "invalid capture cannot reuse old adapter evidence");
  fuzevpn::WireGuardActivePeer live;
  live.Activate("synthetic", {0, 1, 100}, 1);
  auto diagnostic = live;
  Check(diagnostic.Observe({5, 1, 100}, 10), "passive copy observes outgoing traffic");
  Check(live.Observe({5, 1, 100}, 250011), "diagnostic copy did not start live failure timer");
  NetworkExpectation expected{800, 12, {"10.8.0.2/24", "fd00::2/128"},
      {"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}, {"10.8.0.1"}, {}};
  std::vector<MIB_UNICASTIPADDRESS_ROW> addresses{
      Address("10.8.0.2", IpDadStateTentative), Address("fd00:0:0:0:0:0:0:2", IpDadStatePreferred)};
  unsigned count = 0;
  Check(EvaluateAddresses(expected, AF_INET, addresses, &count) == CheckResult::passed && count == 1,
        "Tentative is configured without waiting or claiming data-plane availability");
  Check(EvaluateAddresses(expected, AF_INET6, addresses, &count) == CheckResult::passed,
        "IPv6 canonical spellings compare by bytes");
  auto bad = addresses;
  bad[0].InterfaceIndex = 13;
  Check(EvaluateAddresses(expected, AF_INET, bad, &count) == CheckResult::failed, "other interface rejected");
  bad = addresses; bad[0].InterfaceLuid.Value = 801;
  Check(EvaluateAddresses(expected, AF_INET, bad, &count) == CheckResult::failed, "recycled index rejected");
  for (auto state : {IpDadStateDuplicate, IpDadStateDeprecated, IpDadStateInvalid}) {
    bad = addresses; bad.push_back(Address("10.8.0.2", state));
    Check(EvaluateAddresses(expected, AF_INET, bad, &count) == CheckResult::failed, "conflicting address state rejected");
  }
  Check(EvaluateAddresses(expected, AF_INET, {}, &count) == CheckResult::failed, "missing address rejected");
  std::vector<MIB_IPFORWARD_ROW2> routes{Route("0.0.0.0", 1), Route("128.0.0.0", 1),
      Route("::", 1), Route("8000::", 1)};
  Check(EvaluateRoutes(expected, routes) == CheckResult::passed, "expected full split routes present");
  routes.back().InterfaceLuid.Value = 900;
  Check(EvaluateRoutes(expected, routes) == CheckResult::failed, "route on foreign adapter rejected");
  routes.back() = Route("8000::", 0);
  Check(EvaluateRoutes(expected, routes) == CheckResult::failed, "wrong route prefix rejected");
  Check(EvaluateRoutes(expected, {}) == CheckResult::failed, "empty routing table rejected");
  Check(EvaluateDns(expected.dns, {*ParseNumericAddress("10.8.0.1")}) == CheckResult::passed, "expected DNS present");
  Check(EvaluateDns(expected.dns, {*ParseNumericAddress("10.8.0.99")}) == CheckResult::failed, "wrong DNS rejected");
  Check(EvaluateDns({}, {}) == CheckResult::skipped, "unobserved DNS not passed");
  Check(!ParseNumericAddress(std::string("10.8.0.1\0x", 10)), "embedded NUL refused");
  Check(!ParseNumericAddress("10.8.0.0/33", true), "invalid IPv4 prefix refused");
  expected.luid = 0;
  Check(EvaluateAddresses(expected, AF_INET, addresses, &count) == CheckResult::failed, "no adapter identity never matches");
}
void EncodingChecks() {
  RuntimeObservation source;
  auto encoded = EncodeSnapshot(source);
  Check(Text(Child(encoded, "runtime"), "presence") == "unknown", "unknown runtime preserved");
  Check(CheckResultOf(encoded, "kill_switch") == "unknown", "unknown filters not false success");
  Check(!Has(Child(encoded, "snapshot"), "kill_switch_verified"), "unknown protection omitted");
  source.present = false;
  encoded = EncodeSnapshot(source);
  Check(CheckResultOf(encoded, "service_availability") == "skipped", "no runtime normal for portable");
  Check(!std::get<bool>(Child(encoded, "runtime").at(Value("cleanup_eligible"))), "absent runtime not repairable");
  source.present = true; source.owned = true; source.protection_known = true;
  source.openvpn_protection = {true, true, NetworkProtectionStatus::Phase::tunnel};
  source.openvpn.available = true; source.openvpn.connected = true;
  source.openvpn.observation_tick = 100; source.openvpn.dco = true;
  source.openvpn.phase = "completed"; source.openvpn.cleanup_state = "not_requested";
  source.openvpn.configuration_ms = 400; source.openvpn.validation_ms = 1;
  source.openvpn.first_error = "openvpn_dns_configuration_failed";
  source.openvpn.last_error = "sensitive server text";
  source.openvpn.network = {CheckResult::passed, CheckResult::passed, CheckResult::skipped,
      CheckResult::passed, CheckResult::passed, 1, 0};
  source.driver = {CheckResult::passed, "2.8.6.0"};
  encoded = EncodeSnapshot(source);
  Check(CheckResultOf(encoded, "tunnel_connection") == "passed", "owned protected connection observed");
  Check(Text(Child(encoded, "windows"), "first_error") == "openvpn_dns_configuration_failed", "allowed public code retained");
  Check(Text(Child(encoded, "windows"), "last_error") == "unknown_error", "raw error cannot escape encoder");
  Check(!Has(Child(encoded, "snapshot"), "traffic_blocked"), "filter presence never claims traffic result");
  Check(!Has(Child(encoded, "snapshot"), "bytes_sent"), "missing bytes not fabricated zero");
  source.openvpn.network.routing = CheckResult::failed;
  encoded = EncodeSnapshot(source);
  Check(CheckResultOf(encoded, "tunnel_configuration") == "failed", "adapter up alone is not complete configuration");
  source.openvpn.network.routing = CheckResult::passed;
  source.openvpn.bytes_sent = kMaximumBytes + 1;
  source.openvpn.engine_connect_ms = kMaximumDurationMs + 1;
  source.driver.version = "2.8.private-host";
  encoded = EncodeSnapshot(source);
  Check(!Has(Child(encoded, "snapshot"), "bytes_sent"), "oversized bytes omitted");
  Check(!Has(Child(encoded, "windows"), "engine_connect_ms"), "oversized duration omitted");
  Check(!Has(encoded, "environment"), "untrusted version text omitted");
  source.openvpn.cleanup_eligible = true; source.openvpn.cleanup_state = "failed";
  source.owned = false;
  encoded = EncodeSnapshot(source);
  Check(!std::get<bool>(Child(encoded, "runtime").at(Value("cleanup_eligible"))), "cleanup requires positive ownership");
  source.openvpn.cleanup_eligible = false;
  source.openvpn.connected = false;
  source.openvpn.cleanup_state = "completed";
  source.openvpn_protection = {};
  encoded = EncodeSnapshot(source);
  Check(CheckResultOf(encoded, "tunnel_connection") == "skipped", "intentional disconnect is not a connection failure");
  Check(CheckResultOf(encoded, "cleanup") == "passed", "stopped and unprotected cleanup is complete");
  source.openvpn_protection = {true, true, NetworkProtectionStatus::Phase::prepared};
  source.openvpn.attempt_failed = true;
  source.owned = true;
  encoded = EncodeSnapshot(source);
  Check(std::get<bool>(Child(encoded, "runtime").at(Value("cleanup_eligible"))), "failed attempt with retained owned guard can be explicitly disconnected");
  Check(CheckResultOf(encoded, "cleanup") == "failed", "prepared protection is not reported as complete cleanup");
  source.owned = true; source.other_user = true;
  encoded = EncodeSnapshot(source);
  Check(Child(encoded, "windows").empty(), "foreign user's connection evidence hidden");
  Check(!Has(Child(encoded, "snapshot"), "phase"), "foreign phase hidden");
  Check(!std::get<bool>(Child(encoded, "runtime").at(Value("cleanup_eligible"))), "foreign tunnel never repairable");
  source.other_user = false; source.protection_known = false;
  encoded = EncodeSnapshot(source);
  Check(CheckResultOf(encoded, "tunnel_connection") == "unknown", "stale filter handle cannot prove connected");
  Check(!Has(Child(encoded, "snapshot"), "kill_switch_verified"), "lost BFE omitted rather than false bit");
  Check(!BoundedAge(100, 101) && !BoundedAge(100, 0) && BoundedAge(100, 99) == 1, "freshness rejects unknown/future timestamps");
}
}
int main() {
  try { AsyncChecks(); NetworkChecks(); EncodingChecks(); std::cout << "diagnostics snapshot: passive synthetic checks passed\n"; return 0; }
  catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
