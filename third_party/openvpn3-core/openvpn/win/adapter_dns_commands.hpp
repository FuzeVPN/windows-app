// SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace openvpn::Win {
struct AdapterDnsCommands {
    std::vector<std::string> create;
    std::vector<std::string> cleanup;
};

// Local dhcp-option values are merged with PUSH_REPLY values by Core. Windows
// rejects adding a DNS address twice, so assign indexes only to unique binary
// addresses. Preserve the first occurrence and the independent family order.
inline AdapterDnsCommands BuildAdapterDnsCommands(const std::vector<std::string>& addresses,
    const std::string& interface_name, bool block_ipv6, bool legacy_vista = false) {
    AdapterDnsCommands commands;
    std::set<std::array<unsigned char, 17>> seen;
    unsigned indices[2] = {0, 0};
    const std::string noun = legacy_vista ? "dnsserver" : "dnsservers";
    const std::string validate = legacy_vista ? "" : " validate=no";
    for (const auto& value : addresses) {
        if (value.find('\0') != std::string::npos)
            throw std::invalid_argument("invalid adapter DNS address");
        const bool ipv6 = value.find(':') != std::string::npos;
        const int family = ipv6 ? AF_INET6 : AF_INET;
        std::array<unsigned char, 17> identity{};
        identity[0] = ipv6 ? 6 : 4;
        IN_ADDR parsed4{};
        IN6_ADDR parsed6{};
        void* bytes = ipv6 ? static_cast<void*>(&parsed6) : static_cast<void*>(&parsed4);
        if (InetPtonA(family, value.c_str(), bytes) != 1)
            throw std::invalid_argument("invalid adapter DNS address");
        std::memcpy(identity.data() + 1, bytes, ipv6 ? sizeof(parsed6) : sizeof(parsed4));
        if ((ipv6 && block_ipv6) || !seen.insert(identity).second) continue;
        char text[INET6_ADDRSTRLEN]{};
        if (!InetNtopA(family, bytes, text, sizeof(text)))
            throw std::invalid_argument("cannot normalize adapter DNS address");
        const std::string address(text);
        const std::string prefix = "netsh interface " + std::string(ipv6 ? "ipv6" : "ip");
        const unsigned index = ++indices[ipv6 ? 1 : 0];
        if (index == 1) {
            commands.create.push_back(prefix + " set " + noun + " " + interface_name +
                " static " + address + " register=primary" + validate);
            commands.cleanup.push_back(prefix + " delete " + noun + " " + interface_name + " all" + validate);
        } else {
            commands.create.push_back(prefix + " add " + noun + " " + interface_name +
                " " + address + " " + std::to_string(index) + validate);
        }
    }
    return commands;
}
} // namespace openvpn::Win
