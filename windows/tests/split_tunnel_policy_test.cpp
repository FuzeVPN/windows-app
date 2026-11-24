// SPDX-License-Identifier: MPL-2.0
// Pure policy arithmetic: no route, adapter, WFP or network mutation.
#include "split_tunnel_policy.h"
#include "wireguard_runtime_state.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Check(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(EXIT_FAILURE);
  }
}

using fuzevpn::IpPrefix;
using fuzevpn::SplitTunnelMode;
using fuzevpn::SplitTunnelPolicy;

IpPrefix P(const char* text) {
  IpPrefix prefix;
  Check(fuzevpn::ParseIpPrefix(text, &prefix), std::string("fixture rejected: ") + text);
  return prefix;
}

bool Contains(const std::vector<std::string>& values, const std::string& value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

// Every address of `whole` is in exactly one of `parts` ∪ `removed`.
void CheckPartition(const IpPrefix& whole, const std::vector<IpPrefix>& removed,
                    const std::vector<IpPrefix>& parts, const std::string& label) {
  for (std::size_t i = 0; i < parts.size(); ++i) {
    Check(fuzevpn::IpPrefixContains(whole, parts[i]), label + ": part escapes the whole");
    for (const auto& gone : removed)
      Check(!fuzevpn::IpPrefixesOverlap(parts[i], gone), label + ": removed range kept");
    for (std::size_t j = i + 1; j < parts.size(); ++j)
      Check(!fuzevpn::IpPrefixesOverlap(parts[i], parts[j]), label + ": overlapping parts");
  }
  // Address-space accounting at the whole's granularity: sizes must add up.
  const unsigned bits = fuzevpn::IpPrefixBits(whole.ipv6);
  const auto weight = [&](const IpPrefix& prefix) {
    const unsigned depth = prefix.length - whole.length;
    return depth >= 64 ? 0.0 : 1.0 / static_cast<double>(1ull << depth);
  };
  double covered = 0;
  for (const auto& part : parts) covered += weight(part);
  for (const auto& gone : fuzevpn::NormalizeIpPrefixes(removed))
    if (fuzevpn::IpPrefixContains(whole, gone)) covered += weight(gone);
  (void)bits;
  Check(covered > 0.999999 && covered < 1.000001, label + ": address space not preserved");
}

void Parsing() {
  for (const char* text : {"192.0.2.1", "10.0.0.0/8", "0.0.0.0/0", "2001:db8::/32",
                           "fe80::/10", "::/0", "2001:DB8:0:0:0:0:0:1", "1::", "::1",
                           "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8"}) {
    IpPrefix prefix;
    Check(fuzevpn::ParseIpPrefix(text, &prefix), std::string("valid prefix rejected: ") + text);
  }
  for (const std::string& text : std::vector<std::string>{
           "", "10.0.0.1/8", "10.0.0.0/33", "256.0.0.0/8", "01.0.0.0/8",
           "10.0.0.0/08", "10.0.0/8", "10.0.0.0.0/8", "10.0.0.0/",
           " 10.0.0.0/8", "10.0.0.0/8 ", "2001:db8::/129", "2001:db8::1/32",
           "2001:db8:::/32", "1::2::3", "::ffff:1.2.3.4", "fe80::1%2",
           "12345::/16", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:", ":1::",
           "host.example", "10.0.0.0/8\n", std::string("10.0.0.0\0/8", 11)}) {
    IpPrefix prefix;
    Check(!fuzevpn::ParseIpPrefix(text, &prefix), "invalid prefix accepted: " + text);
  }
  Check(fuzevpn::FormatIpPrefix(P("192.0.2.1")) == "192.0.2.1/32", "IPv4 host formatting");
  Check(fuzevpn::FormatIpPrefix(P("2001:DB8:0:0:0:0:0:1")) == "2001:db8::1/128", "IPv6 compression");
  Check(fuzevpn::FormatIpPrefix(P("1:0:1:1:1:1:1:1")) == "1:0:1:1:1:1:1:1/128", "single zero group kept");
  Check(fuzevpn::FormatIpPrefix(P("1:0:0:1:0:0:0:1")) == "1:0:0:1::1/128", "longest zero run compressed");
  Check(fuzevpn::FormatIpPrefix(P("::/0")) == "::/0", "all-zero IPv6");
  Check(fuzevpn::FormatIpv4Netmask(0) == "0.0.0.0" && fuzevpn::FormatIpv4Netmask(12) == "255.240.0.0" &&
        fuzevpn::FormatIpv4Netmask(32) == "255.255.255.255", "IPv4 netmasks");
}

void Policy() {
  for (const char* text : {"0.0.0.0/0", "0.0.0.0/1", "127.0.0.0/8", "127.0.0.1", "224.0.0.0/4",
                           "239.255.255.250", "255.255.255.255", "240.0.0.0/8", "::/0", "::1",
                           "::/128", "ff02::/16", "::ffff:0:0/96", "0.1.2.3"}) {
    Check(!fuzevpn::IsAllowedSplitTunnelPrefix(P(text)), std::string("forbidden range allowed: ") + text);
  }
  for (const char* text : {"10.0.0.0/8", "192.168.1.0/24", "8.8.8.8", "128.0.0.0/2", "2001:db8::/32", "fd00::/8"})
    Check(fuzevpn::IsAllowedSplitTunnelPrefix(P(text)), std::string("ordinary range refused: ") + text);

  SplitTunnelPolicy policy;
  Check(fuzevpn::DecodeSplitTunnelPolicy("exclude", {"10.0.0.0/8", "10.1.0.0/16", "10.0.0.0/8", "2001:db8::/32"},
                                         false, &policy) &&
        policy.mode == SplitTunnelMode::exclude && policy.prefixes.size() == 2 &&
        fuzevpn::FormatIpPrefix(policy.prefixes[0]) == "10.0.0.0/8" &&
        fuzevpn::FormatIpPrefix(policy.prefixes[1]) == "2001:db8::/32",
        "exclusion normalizes duplicates and covered ranges");
  Check(fuzevpn::DecodeSplitTunnelPolicy("exclude", {}, true, &policy) &&
        policy.mode == SplitTunnelMode::exclude && policy.allow_lan && policy.active(),
        "local network alone is an active exclusion policy");
  Check(fuzevpn::DecodeSplitTunnelPolicy("include", {}, true, &policy) && !policy.active() &&
        policy.mode == SplitTunnelMode::off && !policy.allow_lan,
        "empty inclusion normalizes to off and ignores the local network");
  Check(fuzevpn::DecodeSplitTunnelPolicy("include", {"203.0.113.0/24"}, true, &policy) &&
        policy.mode == SplitTunnelMode::include && !policy.allow_lan,
        "local-network option only applies to exclusion");
  Check(fuzevpn::DecodeSplitTunnelPolicy("", {}, false, &policy) && !policy.active(), "absent policy is off");
  Check(!fuzevpn::DecodeSplitTunnelPolicy("everything", {}, false, &policy), "unknown mode rejected");
  Check(!fuzevpn::DecodeSplitTunnelPolicy("exclude", {"0.0.0.0/0"}, false, &policy), "default route rejected");
  Check(!fuzevpn::DecodeSplitTunnelPolicy("exclude", {"10.0.0.1/8"}, false, &policy), "host bits rejected");
  Check(!fuzevpn::DecodeSplitTunnelPolicy("off", {"bad"}, false, &policy), "malformed range rejected even when off");
  std::vector<std::string> many(fuzevpn::kMaxSplitTunnelPrefixes + 1, "192.0.2.0/24");
  Check(!fuzevpn::DecodeSplitTunnelPolicy("exclude", many, false, &policy), "range count is bounded");
  SplitTunnelPolicy same;
  fuzevpn::DecodeSplitTunnelPolicy("exclude", {"2001:db8::/32", "10.0.0.0/8"}, false, &same);
  SplitTunnelPolicy reordered;
  fuzevpn::DecodeSplitTunnelPolicy("exclude", {"10.0.0.0/8", "2001:db8::/32"}, false, &reordered);
  Check(fuzevpn::SameSplitTunnelPolicy(same, reordered), "policy comparison ignores input order");
}

void Subtraction() {
  const IpPrefix half = P("0.0.0.0/1");
  const std::vector<IpPrefix> removed{P("10.0.0.0/8"), P("10.20.0.0/16"), P("100.64.0.1")};
  const auto parts = fuzevpn::SubtractIpPrefixes({half}, removed);
  CheckPartition(half, removed, parts, "IPv4 subtraction");
  Check(parts.size() <= 7 + 31, "subtraction stays minimal");
  const IpPrefix v6 = P("::/1");
  const std::vector<IpPrefix> removed6{P("2001:db8::/32")};
  CheckPartition(v6, removed6, fuzevpn::SubtractIpPrefixes({v6}, removed6), "IPv6 subtraction");
  Check(fuzevpn::SubtractIpPrefixes({P("10.0.0.0/8")}, {P("0.0.0.0/1")}).empty(), "covering removal empties");
  Check(fuzevpn::SubtractIpPrefixes({P("10.0.0.0/8")}, {P("2001:db8::/32")}).size() == 1,
        "families never interact");
}

void WireGuardRoutes() {
  const std::vector<std::string> full{"0.0.0.0/0", "::/0"};
  SplitTunnelPolicy off;
  Check(fuzevpn::WireGuardRoutes(full, true, off, {"10.64.0.1"}, "198.51.100.7") == full,
        "inactive policy keeps the kill-switch /0 routes");
  SplitTunnelPolicy exclude;
  fuzevpn::DecodeSplitTunnelPolicy("exclude", {"10.0.0.0/8", "203.0.113.0/24", "2001:db8::/32"}, false, &exclude);
  const auto routes = fuzevpn::WireGuardRoutes(full, true, exclude, {"10.64.0.1"}, "198.51.100.7");
  Check(!Contains(routes, "0.0.0.0/0") && !Contains(routes, "::/0"),
        "split routes never arm wireguard-windows' block-all");
  Check(Contains(routes, "10.64.0.1/32"), "VPN DNS stays in the tunnel inside an excluded range");
  std::vector<IpPrefix> parsed;
  for (const auto& route : routes) parsed.push_back(P(route.c_str()));
  for (const auto& route : parsed) {
    if (fuzevpn::SameIpPrefix(route, P("10.64.0.1"))) continue;
    for (const auto* excluded : {"10.0.0.0/8", "203.0.113.0/24", "2001:db8::/32"})
      Check(!fuzevpn::IpPrefixesOverlap(route, P(excluded)), "excluded range still routed into the tunnel");
  }
  std::vector<IpPrefix> ipv4;
  for (const auto& route : parsed)
    if (!route.ipv6 && !fuzevpn::SameIpPrefix(route, P("10.64.0.1"))) ipv4.push_back(route);
  CheckPartition(P("0.0.0.0/0"), {P("10.0.0.0/8"), P("203.0.113.0/24")}, ipv4, "WireGuard IPv4 tunnel coverage");

  SplitTunnelPolicy lan;
  fuzevpn::DecodeSplitTunnelPolicy("exclude", {}, true, &lan);
  Check(fuzevpn::WireGuardRoutes({"0.0.0.0/0"}, true, lan, {"10.64.0.1"}, "198.51.100.7") ==
            std::vector<std::string>({"0.0.0.0/1", "128.0.0.0/1", "10.64.0.1/32"}),
        "local network keeps the full tunnel without a /0");

  SplitTunnelPolicy include;
  fuzevpn::DecodeSplitTunnelPolicy("include", {"198.51.100.0/24", "2001:db8::/32"}, false, &include);
  const auto included = fuzevpn::WireGuardRoutes({"0.0.0.0/0"}, true, include, {"10.64.0.1"}, "198.51.100.7");
  Check(!Contains(included, "0.0.0.0/1") && !Contains(included, "198.51.100.0/24") &&
        Contains(included, "198.51.100.0/30") && Contains(included, "198.51.100.6/32") &&
        Contains(included, "10.64.0.1/32"),
        "inclusion routes only the listed ranges, minus the VPN endpoint, plus VPN DNS");
  for (const auto& route : included)
    Check(route.find(':') == std::string::npos, "IPv6 inclusion skipped without tunnel IPv6");
  const auto dual = fuzevpn::WireGuardRoutes(full, true, include, {"10.64.0.1"}, "198.51.100.7");
  Check(Contains(dual, "2001:db8::/32"), "IPv6 inclusion routed when the tunnel carries IPv6");
}

void OpenVpnDirectives() {
  const auto dns = fuzevpn::SplitTunnelHostPrefixes({"10.64.0.1"});
  const auto endpoint = fuzevpn::SplitTunnelHostPrefixes({"198.51.100.7"});
  SplitTunnelPolicy exclude;
  fuzevpn::DecodeSplitTunnelPolicy("exclude", {"203.0.113.0/24", "2001:db8::/32"}, true, &exclude);
  std::vector<std::string> routes;
  auto profile = fuzevpn::OpenVpnSplitTunnelDirectives(exclude, dns, endpoint, false, &routes);
  Check(profile.find("route 203.0.113.0 255.255.255.0 net_gateway\n") != std::string::npos,
        "IPv4 exclusion bypasses through the physical gateway");
  Check(profile.find("route-ipv6") == std::string::npos, "no IPv6 route without tunnel IPv6");
  Check(profile.find("route 10.64.0.1 255.255.255.255\n") != std::string::npos &&
        routes == std::vector<std::string>({"10.64.0.1/32"}), "VPN DNS host routed into the tunnel");
  Check(profile.find("redirect-gateway") == std::string::npos, "exclusion keeps the caller's redirect-gateway");
  routes.clear();
  profile = fuzevpn::OpenVpnSplitTunnelDirectives(exclude, dns, endpoint, true, &routes);
  Check(profile.find("route-ipv6 2001:db8::/32 net_gateway\n") != std::string::npos,
        "IPv6 exclusion bypasses when the tunnel carries IPv6");

  SplitTunnelPolicy include;
  fuzevpn::DecodeSplitTunnelPolicy("include", {"198.51.100.0/24", "2001:db8::/32"}, false, &include);
  routes.clear();
  profile = fuzevpn::OpenVpnSplitTunnelDirectives(include, dns, endpoint, true, &routes);
  Check(profile.find("pull-filter ignore \"redirect-gateway\"\n") == 0, "inclusion refuses a pushed default route");
  Check(profile.find("net_gateway") == std::string::npos, "inclusion never adds bypass routes");
  Check(Contains(routes, "198.51.100.0/30") && !Contains(routes, "198.51.100.0/24") &&
        Contains(routes, "2001:db8::/32") && Contains(routes, "10.64.0.1/32"),
        "inclusion routes listed ranges minus the endpoint, plus VPN DNS");
  SplitTunnelPolicy off;
  routes.clear();
  Check(fuzevpn::OpenVpnSplitTunnelDirectives(off, dns, endpoint, true, &routes).empty() && routes.empty(),
        "inactive policy adds nothing");
}
}  // namespace

int main() {
  Parsing();
  Policy();
  Subtraction();
  WireGuardRoutes();
  OpenVpnDirectives();
  std::cout << "Split-tunnel policy tests passed (no route, adapter or WFP changes)\n";
  return EXIT_SUCCESS;
}
