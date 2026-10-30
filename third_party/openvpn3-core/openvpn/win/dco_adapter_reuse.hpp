// SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <span>

namespace openvpn::Win {
enum class DcoAdapterReuse { eligible, configured_address, foreign_route };

inline bool AutomaticDcoAddress(const MIB_UNICASTIPADDRESS_ROW& row) {
    if (row.Address.si_family == AF_INET) {
        // Windows may assign APIPA to an otherwise unused adapter. An explicit
        // address, including a manually configured APIPA address, is not ours.
        const auto address = ntohl(row.Address.Ipv4.sin_addr.S_un.S_addr);
        return (address & 0xffff0000u) == 0xa9fe0000u && row.PrefixOrigin != IpPrefixOriginManual;
    }
    if (row.Address.si_family == AF_INET6) {
        const auto& bytes = row.Address.Ipv6.sin6_addr.u.Byte;
        return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 &&
            row.PrefixOrigin != IpPrefixOriginManual;
    }
    return false;
}

inline bool AutomaticDcoRoute(const MIB_IPFORWARD_ROW2& row) {
    if (row.Protocol != MIB_IPPROTO_LOCAL) return false;
    const auto& prefix = row.DestinationPrefix;
    if (prefix.Prefix.si_family == AF_INET) {
        const auto address = ntohl(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
        return (address == 0xe0000000u && prefix.PrefixLength == 4) ||
            (address == 0xffffffffu && prefix.PrefixLength == 32) ||
            ((address & 0xffff0000u) == 0xa9fe0000u && prefix.PrefixLength >= 16);
    }
    if (prefix.Prefix.si_family == AF_INET6) {
        const auto& bytes = prefix.Prefix.Ipv6.sin6_addr.u.Byte;
        return (bytes[0] == 0xff && prefix.PrefixLength >= 8) ||
            (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 && prefix.PrefixLength >= 64);
    }
    return false;
}

inline DcoAdapterReuse PlanDcoAdapterReuse(ULONG index,
    std::span<const MIB_UNICASTIPADDRESS_ROW> addresses,
    std::span<const MIB_IPFORWARD_ROW2> routes) {
    for (const auto& row : addresses)
        if (row.InterfaceIndex == index && !AutomaticDcoAddress(row))
            return DcoAdapterReuse::configured_address;
    for (const auto& row : routes)
        if (row.InterfaceIndex == index && !AutomaticDcoRoute(row))
            return DcoAdapterReuse::foreign_route;
    return DcoAdapterReuse::eligible;
}

// Query only. A generic DCO adapter with unknown/foreign configuration is
// skipped instead of deleting its routes or overwriting its static addresses.
inline bool DcoAdapterNetworkStateReusable(ULONG index) {
    if (!index || index == static_cast<ULONG>(-1)) return false;
    MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
    if (GetUnicastIpAddressTable(AF_UNSPEC, &addresses) != NO_ERROR) return false;
    MIB_IPFORWARD_TABLE2* routes = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &routes) != NO_ERROR) {
        FreeMibTable(addresses);
        return false;
    }
    const auto plan = PlanDcoAdapterReuse(index,
        std::span<const MIB_UNICASTIPADDRESS_ROW>(addresses->Table, addresses->NumEntries),
        std::span<const MIB_IPFORWARD_ROW2>(routes->Table, routes->NumEntries));
    FreeMibTable(routes);
    FreeMibTable(addresses);
    return plan == DcoAdapterReuse::eligible;
}
} // namespace openvpn::Win
