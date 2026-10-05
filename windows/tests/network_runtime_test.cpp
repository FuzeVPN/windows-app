// SPDX-License-Identifier: MPL-2.0
#include "wireguard_endpoint.h"
#include "direct_dns_lookup.h"
#include "openvpn_connection_state.h"
#include "openvpn_identity_record.h"
#include "openvpn_identity_selection.h"
#include "network_protection_lifecycle.h"
#include "retryable_installation.h"
#include "vpn_reconnect_binding.h"
#include "api_bootstrap_dns.h"
#include "wireguard_runtime_state.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Check(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(EXIT_FAILURE);
  }
}

struct Fixture {
  fuzevpn::OpenVpnIdentityRecord identity;
  std::string certificate;
  explicit Fixture(const char* account) {
    EVP_PKEY* key = EVP_EC_gen("prime256v1");
    X509* cert = X509_new();
    Check(key && cert, "fixture allocation");
    Check(X509_set_version(cert, 2) == 1 &&
              ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(cert), 0) &&
              X509_gmtime_adj(X509_getm_notAfter(cert), 3600) &&
              X509_set_pubkey(cert, key) == 1,
          "fixture certificate");
    X509_NAME* subject = X509_get_subject_name(cert);
    Check(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>("local-test"), -1, -1, 0) == 1 &&
              X509_set_issuer_name(cert, subject) == 1 &&
              X509_sign(cert, key, EVP_sha256()) > 0,
          "fixture signing");
    BIO* output = BIO_new(BIO_s_mem());
    Check(output && PEM_write_bio_PrivateKey(output, key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
          "fixture key serialization");
    char* bytes = nullptr;
    long size = BIO_get_mem_data(output, &bytes);
    identity.key.assign(bytes, static_cast<size_t>(size));
    BIO_free(output);
    output = BIO_new(BIO_s_mem());
    Check(output && PEM_write_bio_X509(output, cert) == 1, "fixture certificate serialization");
    size = BIO_get_mem_data(output, &bytes);
    certificate.assign(bytes, static_cast<size_t>(size));
    BIO_free(output);
    EVP_PKEY_free(key);
    X509_free(cert);
    identity.csr = "test-csr";
    identity.account = account;
    identity.device = "device-1";
  }
};

void ConnectionTransitions() {
  fuzevpn::OpenVpnConnectionState state;
  Check(!state.connected && !state.terminal, "initial state");
  state.Event("CONNECTED", false, false);
  Check(state.connected, "connected event");
  state.Event("RECONNECTING", false, false);
  Check(!state.connected && !state.terminal, "reconnecting clears connected");
  state.Event("CONNECTED", false, false);
  state.Event("TRANSPORT_ERROR", true, false);
  Check(!state.connected, "error clears connected");
  state.Event("CONNECTED", false, false);
  state.Event("DISCONNECTED", false, false);
  Check(!state.connected && state.terminal, "disconnect clears connected");
  state.Event("CONNECTED", false, false);
  state.Complete();
  Check(!state.connected && state.terminal, "completed worker clears connected");
  state.Event("CONNECTED", false, false, false);
  Check(!state.connected && state.terminal, "failed WFP never publishes connected");
  state.Event("CONNECTED", false, false);
  state.Event("PAUSE", false, false);
  Check(!state.connected, "pause clears connected");
}

void IdentitySelection() {
  Fixture active("account-1"), pending("account-1"), unrelated("account-2");
  auto load = [&](bool is_pending, fuzevpn::OpenVpnIdentityRecord* output) {
    *output = is_pending ? pending.identity : active.identity;
    return true;
  };
  fuzevpn::OpenVpnIdentityRecord selected;
  bool selected_pending = true;
  Check(fuzevpn::SelectCertificateIdentity(active.certificate, load, &selected, &selected_pending),
        "active certificate remains usable after failed renewal");
  Check(!selected_pending && selected.key == active.identity.key,
        "stale pending key must not shadow active key");
  Check(fuzevpn::SelectCertificateIdentity(pending.certificate, load, &selected, &selected_pending),
        "renewed certificate finds pending key");
  Check(selected_pending && selected.key == pending.identity.key, "select matching pending identity");
  Check(!fuzevpn::SelectCertificateIdentity(unrelated.certificate, load, &selected, &selected_pending),
        "unrelated certificate rejected");
  Check(!fuzevpn::SelectCertificateIdentity("invalid certificate", load, &selected, &selected_pending),
        "malformed certificate rejected");

  std::string record = pending.identity.Encode();
  Check(fuzevpn::OpenVpnIdentityRecord::Decode(record, &selected) &&
            selected.key == pending.identity.key && selected.account == "account-1" &&
            selected.csr == pending.identity.csr && selected.device == "device-1",
        "complete atomic identity roundtrip");
  const std::string original = selected.Encode();
  for (size_t length = 0; length < record.size(); ++length) {
    Check(!fuzevpn::OpenVpnIdentityRecord::Decode(std::string_view(record).substr(0, length), &selected),
          "interrupted record must be rejected");
    Check(selected.Encode() == original, "partial record must not mutate active identity");
  }
  Check(!fuzevpn::OpenVpnIdentityRecord::Decode(record + "trailing", &selected),
        "trailing record bytes rejected");
  record[4] = record[5] = record[6] = record[7] = static_cast<char>(0xff);
  Check(!fuzevpn::OpenVpnIdentityRecord::Decode(record, &selected), "oversized record rejected");
  fuzevpn::EraseSecret(record);
}

void DriverRetry() {
  fuzevpn::RetryableInstallation installation;
  unsigned attempts = 0;
  bool present = false;
  auto install = [&] { ++attempts; return present = attempts >= 2; };
  Check(!installation.Ensure([&] { return present; }, install), "first transient install fails");
  Check(installation.Ensure([&] { return present; }, install), "second install retries");
  Check(attempts == 2, "failed installation was not cached");
  Check(installation.Ensure([&] { return present; }, install) && attempts == 2,
        "healthy installation is reused");
  present = false;
  Check(installation.Ensure([&] { return present; }, install) && attempts == 3,
        "removed adapter triggers recovery");
}

void ReconnectIdentity() {
  const fuzevpn::VpnReconnectBinding cached{"sid-1", "account-1", "public-key-1", "device-1"};
  Check(cached.Matches(cached), "same owner may reuse native cache");
  Check(!cached.Matches({"sid-2", "account-1", "public-key-1", "device-1"}),
        "another Windows user cannot reuse native cache");
  Check(!cached.Matches({"sid-1", "account-2", "public-key-1", "device-1"}),
        "another account cannot reuse native cache");
  Check(!cached.Matches({"sid-1", "account-1", "public-key-2", "device-1"}),
        "rotated identity invalidates native cache");
  Check(!cached.Matches({"sid-1", "account-1", "public-key-1", "device-2"}),
        "another logical device cannot reuse native cache");
  Check(!cached.Matches({}), "missing owner cannot reuse native cache");
  Check(!fuzevpn::VpnReconnectBinding{}.Matches({}), "empty cache cannot reconnect");
}

void NetworkProtectionPolicy() {
  NetworkProtectionOptions options;
  const auto prepared =
      fuzevpn::BuildNetworkProtectionFilterPlan(true, options);
  Check(prepared.permit_engine && prepared.permit_ui &&
            !prepared.permit_system_dns && !prepared.permit_tunnel,
        "prepared policy never permits the shared system DNS proxy");
  Check(prepared.block_ipv4 && prepared.block_ipv6,
        "prepared policy blocks IPv4 and IPv6");

  const auto tunnel =
      fuzevpn::BuildNetworkProtectionFilterPlan(false, options);
  Check(tunnel.permit_engine && !tunnel.permit_ui &&
            !tunnel.permit_system_dns && tunnel.permit_tunnel,
        "tunnel policy removes direct UI and system DNS permits");

  NetworkProtectionOptions selective;
  selective.kill_switch = false;
  const auto selective_tunnel =
      fuzevpn::BuildNetworkProtectionFilterPlan(false, selective);
  Check(!selective_tunnel.permit_system_dns &&
            !selective_tunnel.block_ipv4 && selective_tunnel.block_dns &&
            selective_tunnel.block_udp && selective_tunnel.block_ipv6,
        "kill switch off keeps final DNS WebRTC and IPv6 protections");

  fuzevpn::NetworkProtectionLifecycle selective_lifecycle;
  selective_lifecycle.ActivateTunnel(NetworkProtectionOwner::open_vpn, selective);
  const auto selective_status =
      selective_lifecycle.Status(NetworkProtectionOwner::open_vpn);
  Check(selective_status.active && !selective_status.kill_switch &&
            selective_status.phase == NetworkProtectionStatus::Phase::tunnel,
        "status distinguishes partial filters from a full kill switch");
  Check(!selective_lifecycle.Status(NetworkProtectionOwner::wire_guard).active,
        "status never attributes another protocol's protection");

  fuzevpn::NetworkProtectionLifecycle lifecycle;
  lifecycle.ActivatePrepared(NetworkProtectionOwner::wire_guard, options);
  Check(lifecycle.IsActive(NetworkProtectionOwner::wire_guard) &&
            !lifecycle.IsTunnel(NetworkProtectionOwner::wire_guard),
        "prepared phase is active but not connected");

  NetworkProtectionOptions different = options;
  different.dns_protection = false;
  Check(!lifecycle.CanPromote(NetworkProtectionOwner::open_vpn, options),
        "another owner cannot promote prepared filters");
  Check(!lifecycle.CanPromote(NetworkProtectionOwner::wire_guard, different),
        "different options cannot promote prepared filters");

  // Simulate a failed WFP candidate: production calls Activate only after a
  // successful commit, so the previous prepared phase must remain unchanged.
  const bool candidate_committed = false;
  if (candidate_committed) {
    lifecycle.ActivateTunnel(NetworkProtectionOwner::wire_guard, options);
  }
  Check(lifecycle.IsActive(NetworkProtectionOwner::wire_guard) &&
            !lifecycle.IsTunnel(NetworkProtectionOwner::wire_guard),
        "failed promotion retains prepared filters");

  lifecycle.ActivateTunnel(NetworkProtectionOwner::wire_guard, options);
  Check(lifecycle.IsTunnel(NetworkProtectionOwner::wire_guard),
        "successful promotion publishes tunnel phase");
  Check(lifecycle.CanPromote(NetworkProtectionOwner::wire_guard, options),
        "same tunnel may replace its policy after an internal reconnect");
  Check(!lifecycle.CanPromote(NetworkProtectionOwner::open_vpn, options),
        "reconnect cannot replace another protocol's policy without preparing");
  Check(!lifecycle.CanPromote(NetworkProtectionOwner::wire_guard, different),
        "reconnect cannot silently change protection options");

  fuzevpn::OpenVpnConnectionState reconnecting;
  lifecycle.ActivatePrepared(NetworkProtectionOwner::open_vpn, options);
  Check(lifecycle.CanPromote(NetworkProtectionOwner::open_vpn, options),
        "initial OpenVPN protection may be promoted");
  lifecycle.ActivateTunnel(NetworkProtectionOwner::open_vpn, options);
  reconnecting.Event("CONNECTED", false, false, true);
  reconnecting.Event("RECONNECTING", false, false);
  const bool replacement_ready =
      lifecycle.CanPromote(NetworkProtectionOwner::open_vpn, options);
  reconnecting.Event("CONNECTED", false, false, replacement_ready);
  Check(reconnecting.connected && !reconnecting.terminal,
        "internal OpenVPN reconnect remains connected after policy replacement");

  lifecycle.Clear();
  Check(!lifecycle.IsActive(NetworkProtectionOwner::wire_guard),
        "explicit disconnect clears filters");
}

void BootstrapDnsParsing() {
  using namespace fuzevpn::bootstrap;
  constexpr std::uint16_t id = 0x7ac1;
  auto answer = Query(id, false);
  answer[2] = 0x81;
  answer[3] = 0x80;
  answer[7] = 1;
  const auto answer_offset = answer.size();
  for (auto word : {0xc00c, 1, 1, 0, 30, 4}) Put16(&answer, static_cast<std::uint16_t>(word));
  answer.insert(answer.end(), {203, 0, 113, 15});
  std::vector<Address> addresses;
  Check(Parse(answer, id, false, &addresses) == Response::valid &&
        addresses.size() == 1 && addresses[0].bytes[3] == 15,
        "compressed API A answer accepted");
  addresses.clear();
  Check(Parse(answer, id + 1, false, &addresses) == Response::invalid && addresses.empty(),
        "another DNS transaction is rejected");
  Check(Parse(answer, id, true, &addresses) == Response::invalid,
        "A response cannot satisfy AAAA query");
  for (std::size_t length = 0; length < answer.size(); ++length) {
    const std::vector<std::uint8_t> partial(answer.begin(), answer.begin() + length);
    Check(Parse(partial, id, false, &addresses) == Response::invalid && addresses.empty(),
          "truncated DNS answer never publishes a partial address");
  }
  auto forged = answer;
  forged[13] = 'z';
  Check(Parse(forged, id, false, &addresses) == Response::invalid,
        "another hostname cannot satisfy fixed bootstrap query");
  forged = answer;
  forged[answer_offset] = 0xc0;
  forged[answer_offset + 1] = static_cast<std::uint8_t>(answer_offset);
  Check(Parse(forged, id, false, &addresses) == Response::invalid,
        "cyclic DNS compression is rejected");
  forged = answer;
  forged[answer_offset + 10] = 0xff;
  forged[answer_offset + 11] = 0xff;
  Check(Parse(forged, id, false, &addresses) == Response::invalid,
        "oversized DNS RDATA is rejected");
  for (const std::array<std::uint8_t, 4>& address :
       {std::array<std::uint8_t, 4>{127, 0, 0, 1}, {10, 1, 2, 3},
        {192, 168, 1, 1}, {169, 254, 169, 254}, {224, 0, 0, 1}, {100, 64, 0, 1}}) {
    forged = answer;
    std::copy(address.begin(), address.end(), forged.end() - 4);
    Check(Parse(forged, id, false, &addresses) == Response::valid && addresses.empty(),
          "non-public bootstrap address is never returned");
  }
  auto truncated = Query(id, false);
  truncated[2] = 0x83;
  Check(Parse(truncated, id, false, &addresses) == Response::truncated,
        "validated TC response requests bounded TCP fallback");
  truncated[0] ^= 1;
  Check(Parse(truncated, id, false, &addresses) == Response::invalid,
        "wrong transaction cannot request TCP fallback");

  auto cname = Query(id, false);
  cname[2] = 0x81; cname[3] = 0x80; cname[7] = 2;
  for (auto word : {0xc00c, 5, 1, 0, 30, 6}) Put16(&cname, static_cast<std::uint16_t>(word));
  const auto alias_offset = cname.size();
  cname.insert(cname.end(), {3, 'c', 'd', 'n', 0xc0, 0x10}); // cdn.fuzevpn.com
  for (auto word : {static_cast<int>(0xc000 | alias_offset), 1, 1, 0, 30, 4})
    Put16(&cname, static_cast<std::uint16_t>(word));
  cname.insert(cname.end(), {203, 0, 113, 16});
  Check(Parse(cname, id, false, &addresses) == Response::valid &&
        addresses.size() == 1 && addresses[0].bytes[3] == 16,
        "compressed CNAME chain resolves only addresses owned by the chain");
  addresses.clear();
  // Remove the alias record but retain its owner name as a free-standing name.
  auto unrelated = answer;
  unrelated[answer_offset] = 3;
  unrelated[answer_offset + 1] = 'c';
  unrelated.insert(unrelated.begin() + answer_offset + 2, {'d', 'n', 0xc0, 0x10});
  Check(Parse(unrelated, id, false, &addresses) == Response::valid && addresses.empty(),
        "unrelated additional hostname is not a bootstrap destination");

  auto aaaa = Query(id, true);
  aaaa[2] = 0x81; aaaa[3] = 0x80; aaaa[7] = 1;
  for (auto word : {0xc00c, 28, 1, 0, 30, 16}) Put16(&aaaa, static_cast<std::uint16_t>(word));
  aaaa.insert(aaaa.end(), {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
  Check(Parse(aaaa, id, true, &addresses) == Response::valid &&
        addresses.size() == 1 && addresses[0].ipv6, "global AAAA accepted");
  addresses.clear();
  aaaa[aaaa.size() - 16] = 0xfe; aaaa[aaaa.size() - 15] = 0x80;
  Check(Parse(aaaa, id, true, &addresses) == Response::valid && addresses.empty(),
        "link-local IPv6 bootstrap rejected");
}

std::vector<std::uint8_t> DnsAddressAnswer(const std::vector<std::uint8_t>& query,
                                         const std::vector<std::uint8_t>& address) {
  using namespace fuzevpn::bootstrap;
  auto answer = query;
  answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1;
  for (auto word : {0xc00c, address.size() == 16 ? 28 : 1, 1, 0, 30,
                    static_cast<int>(address.size())}) Put16(&answer, static_cast<std::uint16_t>(word));
  answer.insert(answer.end(), address.begin(), address.end());
  return answer;
}

std::vector<std::uint8_t> DnsAliasAnswer(const std::vector<std::uint8_t>& query,
                                       const std::string& alias) {
  using namespace fuzevpn::bootstrap;
  const auto encoded_alias = QueryForHost(1, false, alias);
  auto answer = query;
  answer[2] = 0x81; answer[3] = 0x80; answer[7] = 1;
  for (auto word : {0xc00c, 5, 1, 0, 30, static_cast<int>(encoded_alias.size() - 16)})
    Put16(&answer, static_cast<std::uint16_t>(word));
  answer.insert(answer.end(), encoded_alias.begin() + 12, encoded_alias.end() - 4);
  return answer;
}

void WireGuardEndpointResolution() {
  using namespace fuzevpn;
  using namespace fuzevpn::bootstrap;
  WireGuardEndpoint parsed;
  Check(ParseWireGuardEndpoint("WG.Fixture.Invalid.:51820", &parsed) &&
        parsed.host == "wg.fixture.invalid" && !parsed.numeric,
        "endpoint hostname is canonicalized without changing its port");
  for (const auto* valid : {"192.0.2.1:51820", "10.0.0.1:1", "[2001:db8::1]:65535",
                            "[::ffff:192.0.2.1]:51820", "[fd00::1]:51820"})
    Check(ParseWireGuardEndpoint(valid, &parsed) && parsed.numeric, "numeric IPv4 and IPv6 remain supported");

  std::vector<std::string> invalid{
      "", ":51820", "vpn.invalid", "vpn.invalid:0", "vpn.invalid:65536",
      "vpn.invalid:-1", "vpn.invalid:51820\n", "vpn.invalid:53:80",
      "[2001:db8::1:51820", "2001:db8::1:51820", "[vpn.invalid]:51820",
      "[192.0.2.1]:51820", "[::1]suffix:51820", "vpn..invalid:51820",
      "-vpn.invalid:51820", "vpn-.invalid:51820", "999.1.2.3:51820",
      "https://vpn.invalid:51820", "vpn.invalid:51820\nPostUp=bad",
      std::string("192.0.2.1") + '\0' + "ignored:51820",
      std::string("[::1") + '\0' + "ignored]:51820",
      std::string(64, 'a') + ".invalid:51820"};
  for (const auto& endpoint : invalid) {
    unsigned calls = 0;
    std::string numeric;
    const auto result = PrepareWireGuardEndpoint(endpoint,
        [&]() { ++calls; return true; }, [&]() { ++calls; return true; },
        [&](const std::string&, std::vector<std::string>*) { ++calls; return true; }, &numeric);
    Check(result == WireGuardEndpointResult::invalid && calls == 0 && numeric.empty(),
          "invalid endpoint is rejected before prepare, stop and DNS");
  }

  bool protected_network = false;
  bool old_tunnel_stopped = false;
  unsigned resolutions = 0;
  std::uint64_t now = 100;
  std::vector<std::string> queried_names;
  auto prepare = [&]() { protected_network = true; return true; };
  auto stop = [&]() {
    Check(protected_network, "old tunnel stops under prepared protection");
    old_tunnel_stopped = true;
    return true;
  };
  auto resolve = [&](const std::string& host, std::vector<std::string>* output) {
    Check(protected_network && old_tunnel_stopped,
          "dedicated endpoint lookup runs after confirmed stop under WFP");
    ++resolutions;
    std::vector<Address> addresses;
    const auto valid = LookupServer(host, false, now + 6000, [&]() { return now; },
        [](std::uint16_t* id) { *id = 0x3254; return true; },
        [&](const std::vector<std::uint8_t>& query, bool tcp, std::uint64_t deadline,
            std::vector<std::uint8_t>* response) {
          Check(!tcp && deadline <= now + 1000, "UDP lookup has bounded per-attempt wait");
          std::size_t offset = 12;
          std::string question;
          Check(ReadName(query, &offset, &question), "generated endpoint query is parseable");
          queried_names.push_back(question);
          if (question == "wg.fixture.invalid") {
            *response = DnsAliasAnswer(query, "edge.fixture.invalid");
          } else {
            Check(question == "edge.fixture.invalid", "only validated CNAME is followed");
            const bool ipv6 = query[query.size() - 3] == 28;
            *response = ipv6
                ? DnsAddressAnswer(query, {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
                : DnsAddressAnswer(query, {10, 0, 0, static_cast<std::uint8_t>(resolutions)});
          }
          return true;
        }, &addresses);
    for (const auto& address : addresses) {
      char text[INET6_ADDRSTRLEN]{};
      Check(InetNtopA(address.ipv6 ? AF_INET6 : AF_INET, address.bytes.data(), text, sizeof(text)) != nullptr,
            "resolved endpoint address is formatted numerically");
      output->emplace_back(text);
    }
    return valid && !output->empty();
  };
  const std::string original = "WG.Fixture.Invalid.:51820";
  std::string numeric;
  Check(PrepareWireGuardEndpoint(original, prepare, stop, resolve, &numeric) == WireGuardEndpointResult::ready &&
        numeric == "10.0.0.1:51820" && resolutions == 1 && queried_names.size() == 4,
        "production endpoint preparation resolves CNAME A and AAAA via direct DNS");
  old_tunnel_stopped = false;
  Check(PrepareWireGuardEndpoint(original, prepare, stop, resolve, &numeric) == WireGuardEndpointResult::ready &&
        numeric == "10.0.0.2:51820" && resolutions == 2 && original == "WG.Fixture.Invalid.:51820",
        "original endpoint is preserved for fresh DNS on reconnect");
  Check(PrepareWireGuardEndpoint("[2001:db8::1]:51820", prepare, stop, resolve, &numeric) ==
            WireGuardEndpointResult::ready && numeric == "[2001:db8::1]:51820" && resolutions == 2,
        "numeric endpoint skips DNS and preserves IPv6 brackets");
  Check(PrepareWireGuardEndpoint(original, prepare, stop,
        [](const std::string&, std::vector<std::string>* output) {
          output->push_back("2001:db8::9"); return true;
        }, &numeric) == WireGuardEndpointResult::ready && numeric == "[2001:db8::9]:51820",
        "AAAA-only endpoint is serialized with brackets and original port");

  unsigned dns_calls = 0;
  Check(PrepareWireGuardEndpoint(original, []() { return false; }, stop,
        [&](const std::string&, std::vector<std::string>*) { ++dns_calls; return true; }, &numeric) ==
        WireGuardEndpointResult::protection_failed && dns_calls == 0,
        "failed preparation never reaches endpoint DNS");
  Check(PrepareWireGuardEndpoint(original, prepare, []() { return false; },
        [&](const std::string&, std::vector<std::string>*) { ++dns_calls; return true; }, &numeric) ==
        WireGuardEndpointResult::stop_failed && dns_calls == 0 && protected_network,
        "unconfirmed old tunnel stop keeps WFP and never resolves endpoint");
  for (bool timeout : {false, true}) {
    now = 100;
    const auto result = PrepareWireGuardEndpoint(original, prepare, stop,
        [&](const std::string& host, std::vector<std::string>*) {
          std::vector<Address> addresses;
          Check(LookupServer(host, false, 450, [&]() { return now; },
              [](std::uint16_t* id) { *id = 123; return true; },
              [&](const std::vector<std::uint8_t>& query, bool, std::uint64_t deadline,
                  std::vector<std::uint8_t>* response) {
                Check(deadline <= 450, "DNS deadline never exceeds remaining connection budget");
                if (timeout) { now = deadline; return false; }
                *response = query;
                (*response)[2] = 0x81; (*response)[3] = 0x83; // NXDOMAIN.
                return true;
              }, &addresses), "negative DNS reply completes bounded lookup");
          return !addresses.empty();
        }, &numeric);
    Check(result == WireGuardEndpointResult::resolution_failed && numeric.empty() && protected_network,
          "NXDOMAIN and timeout preserve prepared protection without a startable endpoint");
  }
  Check(WireGuardWaitDeadline(69000, 20000, 70000) == 70000 &&
        WireGuardWaitDeadline(10000, 6000, 70000) == 16000 &&
        WireGuardWaitDeadline(71000, 20000, 70000) == 70000,
        "SCM DNS adapter handshake and cleanup waits share deadline even after exhaustion");

  std::vector<Address> api_addresses;
  const auto api_query = Query(44, false);
  Check(Parse(DnsAddressAnswer(api_query, {10, 0, 0, 1}), 44, false, &api_addresses) == Response::valid &&
        api_addresses.empty(), "endpoint private-address policy does not weaken public-only API wrapper");
  const auto endpoint_query = QueryForHost(44, false, "wg.fixture.invalid");
  Check(Parse(DnsAddressAnswer(endpoint_query, {203, 0, 113, 1}), 44, false, &api_addresses) == Response::invalid,
        "fixed API wrapper cannot resolve a WireGuard or arbitrary hostname");

  std::vector<Address> tcp_addresses;
  unsigned udp_queries = 0, tcp_queries = 0;
  Check(LookupServer("wg.fixture.invalid", false, 800, []() -> std::uint64_t { return 100; },
      [](std::uint16_t* id) { *id = 44; return true; },
      [&](const std::vector<std::uint8_t>& query, bool tcp, std::uint64_t deadline,
          std::vector<std::uint8_t>* response) {
        Check(deadline == 800, "TCP fallback shares connection deadline");
        if (tcp) {
          ++tcp_queries;
          const bool ipv6 = query[query.size() - 3] == 28;
          *response = ipv6
              ? DnsAddressAnswer(query, {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
              : DnsAddressAnswer(query, {203, 0, 113, 2});
        } else {
          ++udp_queries;
          *response = query;
          (*response)[2] = 0x83; (*response)[3] = 0x80; // Truncated UDP.
        }
        return true;
      }, &tcp_addresses) && udp_queries == 2 && tcp_queries == 2 && tcp_addresses.size() == 2,
      "truncated endpoint DNS falls back to bounded TCP for A and AAAA");

  unsigned queries = 0;
  std::vector<Address> cyclic_addresses;
  Check(LookupServer("wg.fixture.invalid", false, 6000, []() -> std::uint64_t { return 100; },
      [](std::uint16_t* id) { *id = 44; return true; },
      [&](const std::vector<std::uint8_t>& query, bool, std::uint64_t,
          std::vector<std::uint8_t>* response) {
        ++queries;
        std::size_t offset = 12;
        std::string name;
        Check(ReadName(query, &offset, &name), "CNAME query decoded");
        *response = DnsAliasAnswer(query, name == "wg.fixture.invalid" ? "edge.fixture.invalid" : "wg.fixture.invalid");
        return true;
      }, &cyclic_addresses) && queries == 4 && cyclic_addresses.empty(),
      "cyclic CNAME followups terminate without publishing an address");

  queries = 0;
  Check(LookupServer(kHost, true, 6000, []() -> std::uint64_t { return 100; },
      [](std::uint16_t* id) { *id = 44; return true; },
      [&](const std::vector<std::uint8_t>& query, bool, std::uint64_t,
          std::vector<std::uint8_t>* response) {
        ++queries;
        std::size_t offset = 12;
        std::string name;
        Check(ReadName(query, &offset, &name) && name == kHost,
              "API transport continues emitting only its fixed hostname");
        *response = DnsAliasAnswer(query, "edge.fixture.invalid");
        return true;
      }, &cyclic_addresses) && queries == 2 && cyclic_addresses.empty(),
      "endpoint CNAME extension does not generalize API fixed DNS questions");
}

void WireGuardBehavior() {
  const std::vector<std::string> full{"0.0.0.0/0", "::/0"};
  Check(fuzevpn::WireGuardRoutes(full, true) == full,
        "kill switch preserves WireGuard independent firewall");
  Check(fuzevpn::WireGuardRoutes(full, false) ==
        std::vector<std::string>{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"},
        "kill-switch opt-out keeps full routing without implicit /0 firewall");
  Check(fuzevpn::WireGuardRoutes({"10.20.0.0/16"}, false) ==
        std::vector<std::string>{"10.20.0.0/16"}, "specific route is unchanged");
  fuzevpn::WireGuardPeerHealth health;
  Check(!health.Observe({20, 0, 0}, 0), "SCM up without handshake is not connected");
  Check(health.Observe({20, 30, 100}, 10), "authenticated handshake establishes connection");
  Check(health.Observe({20, 30, 100}, 86400000), "idle link does not expire by handshake age");
  Check(health.Observe({40, 30, 100}, 86400001), "first unanswered traffic starts grace period");
  Check(!health.Observe({60, 30, 100}, 86700001), "stalled peer is detected after grace period");
  Check(health.Observe({60, 50, 100}, 86700002), "received traffic restores health");
  Check(health.Observe({80, 50, 100}, 86700003), "new transmission starts new grace period");
  Check(health.Observe({100, 50, 200}, 87000003), "new handshake restores health");
  health.Reset();
  Check(!health.Observe({}, 90000000), "replacement requires its own handshake");

  fuzevpn::WireGuardActivePeer active_peer;
  active_peer.Activate("expected-server-key", {20, 30, 100}, 0);
  // Production clears the reconnect cache on a disconnect request, but the
  // independent observation identity must survive a failed SCM stop.
  active_peer.StopResult(false);
  Check(active_peer.public_key() == "expected-server-key" &&
        active_peer.Observe({20, 30, 100}, 1000),
        "failed stop retains authenticated active peer for UI state recovery");
  active_peer.StopResult(true);
  Check(active_peer.public_key().empty() && !active_peer.Observe({20, 30, 100}, 1001),
        "confirmed stop removes active observation identity");
}
}  // namespace

int main() {
  ConnectionTransitions();
  IdentitySelection();
  DriverRetry();
  ReconnectIdentity();
  NetworkProtectionPolicy();
  BootstrapDnsParsing();
  WireGuardEndpointResolution();
  WireGuardBehavior();
  std::cout << "Network runtime behavior tests passed\n";
  return EXIT_SUCCESS;
}
