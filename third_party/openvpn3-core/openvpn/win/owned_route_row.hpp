#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <limits>
#include <string>
namespace openvpn::Win {
inline bool BuildOwnedRouteRow(const std::string& destination, unsigned prefix,
    DWORD interface_index, const std::string& gateway, ULONG metric, MIB_IPFORWARD_ROW2* row) {
    if (!row || !interface_index || interface_index == MAXDWORD ||
        destination.find('\0') != std::string::npos || gateway.find('\0') != std::string::npos) return false;
    *row = {};
    const ADDRESS_FAMILY family = destination.find(':') == std::string::npos ? AF_INET : AF_INET6;
    const unsigned bits = family == AF_INET ? 32 : 128;
    if (prefix > bits) return false;
    row->DestinationPrefix.Prefix.si_family = family;
    row->NextHop.si_family = family;
    auto* address = family == AF_INET ? reinterpret_cast<BYTE*>(&row->DestinationPrefix.Prefix.Ipv4.sin_addr)
        : reinterpret_cast<BYTE*>(&row->DestinationPrefix.Prefix.Ipv6.sin6_addr);
    auto* next_hop = family == AF_INET ? reinterpret_cast<BYTE*>(&row->NextHop.Ipv4.sin_addr)
        : reinterpret_cast<BYTE*>(&row->NextHop.Ipv6.sin6_addr);
    if (InetPtonA(family, destination.c_str(), address) != 1 ||
        (!gateway.empty() && InetPtonA(family, gateway.c_str(), next_hop) != 1)) return false;
    // netsh accepts an address/prefix and normalizes the network. IP Helper
    // requires the canonical prefix explicitly (notably the IPv6 gateway /64).
    for (unsigned bit = prefix; bit < bits; ++bit) address[bit / 8] &= static_cast<BYTE>(~(0x80 >> (bit % 8)));
    row->DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix);
    row->InterfaceIndex = interface_index;
    row->Metric = metric;
    row->Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    row->ValidLifetime = row->PreferredLifetime = (std::numeric_limits<ULONG>::max)();
    // CreateIpForwardEntry2 changes only the active table: same store=active,
    // lifetime, non-published route, interface and next hop as our netsh calls.
    return true;
}
} // namespace openvpn::Win
