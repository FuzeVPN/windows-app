// SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace openvpn::Win {
inline SOCKADDR_INET ParseExpectedUnicastAddress(const std::string& text) {
    SOCKADDR_INET result{};
    result.si_family = text.find(':') == std::string::npos ? AF_INET : AF_INET6;
    void* bytes = result.si_family == AF_INET ? static_cast<void*>(&result.Ipv4.sin_addr)
        : static_cast<void*>(&result.Ipv6.sin6_addr);
    if (text.find('\0') != std::string::npos || InetPtonA(result.si_family, text.c_str(), bytes) != 1)
        throw std::invalid_argument("invalid expected tunnel address");
    return result;
}
inline bool SameUnicastAddress(const SOCKADDR_INET& left, const SOCKADDR_INET& right) {
    if (left.si_family != right.si_family) return false;
    if (left.si_family == AF_INET)
        return left.Ipv4.sin_addr.S_un.S_addr == right.Ipv4.sin_addr.S_un.S_addr;
    return left.si_family == AF_INET6 &&
        std::memcmp(&left.Ipv6.sin6_addr, &right.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
}
struct UnicastAddressConfiguration {
    unsigned expected = 0;
    unsigned matched = 0;
    unsigned assigned = 0;
    unsigned tentative = 0;
    unsigned duplicate = 0;
    bool configured() const { return assigned == expected && duplicate == 0; }
};
// IP Helper returns addresses in network byte order. Match their bytes on the
// exact interface instead of comparing strings from different formatters.
// Tentative confirms assignment while Windows continues DAD; this check does
// not assert that the address is already usable for IP traffic. OpenVPN can
// finish initializing its data channel without waiting synchronously for DAD.
inline UnicastAddressConfiguration EvaluateUnicastAddressConfiguration(
    std::span<const SOCKADDR_INET> expected, ULONG interface_index,
    std::span<const MIB_UNICASTIPADDRESS_ROW> observed) {
    UnicastAddressConfiguration result;
    result.expected = static_cast<unsigned>(expected.size());
    for (const auto& address : expected) {
        bool matched = false, assigned = false, tentative = false, duplicate = false, rejected = false;
        for (const auto& row : observed) {
            if (row.InterfaceIndex != interface_index || !SameUnicastAddress(address, row.Address)) continue;
            matched = true;
            assigned |= row.DadState == IpDadStatePreferred || row.DadState == IpDadStateTentative;
            tentative |= row.DadState == IpDadStateTentative;
            duplicate |= row.DadState == IpDadStateDuplicate;
            rejected |= row.DadState != IpDadStatePreferred && row.DadState != IpDadStateTentative;
        }
        result.matched += matched;
        result.assigned += assigned && !rejected;
        result.tentative += tentative;
        result.duplicate += duplicate;
    }
    return result;
}
} // namespace openvpn::Win
