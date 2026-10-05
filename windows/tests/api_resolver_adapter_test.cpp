// SPDX-License-Identifier: MPL-2.0
// Exercise the production adapter selection with synthetic adapter/DNS lists.
// No real adapter query, DNS request, policy or service mutation is performed.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {
struct Fixture {
  IP_ADAPTER_ADDRESSES adapter{};
  std::vector<IP_ADAPTER_DNS_SERVER_ADDRESS> dns;
  std::vector<SOCKADDR_STORAGE> sockets;
};
std::vector<std::unique_ptr<Fixture>> fixtures;
std::uint64_t fixture_preferred_luid = 0;
ULONG adapter_error = NO_ERROR;
unsigned adapter_queries = 0;
Fixture& Add(NET_IFINDEX index, std::uint64_t luid,
    std::initializer_list<const char*> servers, bool up = true, bool loopback = false) {
  auto fixture = std::make_unique<Fixture>();
  auto& out = *fixture;
  out.adapter.Length = sizeof(out.adapter);
  out.adapter.IfIndex = out.adapter.Ipv6IfIndex = index;
  out.adapter.Luid.Value = luid;
  out.adapter.OperStatus = up ? IfOperStatusUp : IfOperStatusDown;
  out.adapter.IfType = loopback ? IF_TYPE_SOFTWARE_LOOPBACK : IF_TYPE_ETHERNET_CSMACD;
  out.dns.resize(servers.size()); out.sockets.resize(servers.size());
  size_t slot = 0;
  for (const char* server : servers) {
    auto& dns = out.dns[slot];
    auto& storage = out.sockets[slot];
    if (std::strchr(server, ':')) {
      auto* address = reinterpret_cast<SOCKADDR_IN6*>(&storage);
      address->sin6_family = AF_INET6;
      if (InetPtonA(AF_INET6, server, &address->sin6_addr) != 1) std::terminate();
      dns.Address.iSockaddrLength = sizeof(*address);
    } else {
      auto* address = reinterpret_cast<SOCKADDR_IN*>(&storage);
      address->sin_family = AF_INET;
      if (InetPtonA(AF_INET, server, &address->sin_addr) != 1) std::terminate();
      dns.Address.iSockaddrLength = sizeof(*address);
    }
    dns.Address.lpSockaddr = reinterpret_cast<SOCKADDR*>(&storage);
    dns.Next = slot + 1 < out.dns.size() ? &out.dns[slot + 1] : nullptr;
    ++slot;
  }
  out.adapter.FirstDnsServerAddress = out.dns.empty() ? nullptr : out.dns.data();
  if (!fixtures.empty()) fixtures.back()->adapter.Next = &out.adapter;
  fixtures.push_back(std::move(fixture));
  return out;
}
void Reset() { fixtures.clear(); fixture_preferred_luid = 0; adapter_error = NO_ERROR; adapter_queries = 0; }
ULONG WINAPI FixtureAdapters(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES target, PULONG size) {
  ++adapter_queries;
  if (adapter_error != NO_ERROR) return adapter_error;
  if (fixtures.empty()) return ERROR_NO_DATA;
  if (*size < sizeof(IP_ADAPTER_ADDRESSES)) {
    *size = sizeof(IP_ADAPTER_ADDRESSES); return ERROR_BUFFER_OVERFLOW;
  }
  std::memcpy(target, &fixtures.front()->adapter, sizeof(*target));
  return NO_ERROR;
}
}
std::uint64_t NetworkProtectionBootstrapTunnelLuid() { return fixture_preferred_luid; }
#define GetAdaptersAddresses FixtureAdapters
#include "../runner/api_bootstrap_resolver.cpp"
#undef GetAdaptersAddresses

namespace {
unsigned failures = 0;
void Check(bool ok, const char* message) {
  if (!ok) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}
void VirtualDefaults() {
  for (NET_IFINDEX index : {29U, 20U, 25U})
    Add(index, index, {"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"});
}
}
int main() {
  Reset(); VirtualDefaults(); Add(17, 17, {"192.168.1.1", "192.168.1.2"});
  auto servers = Servers();
  Check(servers.size() == 2 && servers[0].interface_index == 17 &&
      servers[1].interface_index == 17 && servers[0].address.ss_family == AF_INET,
      "nine automatic IPv6 placeholders ahead of Wi-Fi cannot consume its DNS quota");

  Reset(); VirtualDefaults(); Add(17, 17, {"192.168.1.1", "192.168.1.2"});
  Add(42, 4200, {"10.44.0.1"}); fixture_preferred_luid = 4200;
  servers = Servers();
  Check(servers.size() == 3 && servers[0].interface_index == 42 &&
      servers[1].interface_index == 17,
      "real private DNS of the preferred active tunnel keeps priority over physical DNS");

  Reset(); Add(17, 17, {"fd00::53", "fe80::53", "2606:4700:4700::1111"});
  servers = Servers();
  Check(servers.size() == 3 && reinterpret_cast<const SOCKADDR_IN6*>(
      &servers[1].address)->sin6_scope_id == 17,
      "configured private, link-local and global IPv6 DNS remain valid with link-local scope");

  Reset(); Add(17, 17, {"fec0:0:0:ffff::4", "fec0::1"});
  Check(Servers().size() == 2, "filter is limited to the three Windows automatic defaults");

  Reset(); VirtualDefaults(); Add(17, 17, {"10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4",
      "10.1.0.5", "10.1.0.6", "10.1.0.7", "10.1.0.8", "10.1.0.9", "10.1.0.10"});
  servers = Servers();
  Check(servers.size() == 8 && servers.front().interface_index == 17 &&
      servers.back().interface_index == 17,
      "eight-server bound still applies after automatic defaults are filtered");

  Reset(); Add(31, 31, {"10.0.0.1"}, false); Add(1, 1, {"127.0.0.1"}, true, true);
  Add(17, 17, {"192.168.1.1", "192.168.1.1"});
  servers = Servers();
  Check(servers.size() == 1 && servers[0].interface_index == 17,
      "down/loopback adapters remain excluded and duplicate DNS on one interface is collapsed");

  Reset(); Add(17, 17, {"192.168.1.1"}); Add(18, 18, {"192.168.1.1"});
  Check(Servers().size() == 2, "same configured DNS on different interfaces keeps distinct bindings");

  Reset(); Add(17, 17, {"::", "ff02::1", "0.0.0.0", "255.255.255.255", "224.0.0.1"});
  Check(Servers().empty(), "unspecified, broadcast and multicast DNS remain rejected");

  Reset(); adapter_error = ERROR_ACCESS_DENIED;
  Check(Servers().empty() && adapter_queries == 1,
      "unknown adapter query has no OS-resolver or public-DNS fallback");
  std::cout << (failures == 0 ? "PASS" : "FAIL") << ": API resolver adapter selection\n";
  return failures == 0 ? 0 : 1;
}
