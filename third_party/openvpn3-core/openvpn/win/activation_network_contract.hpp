// SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <charconv>
#include <string>
#include <vector>
#include <openvpn/win/network_postcondition.hpp>

namespace openvpn::Win {
// These requirements come from the authenticated activation response, not
// PUSH_REPLY. A server cannot make a missing family disappear from validation.
struct ActivationNetworkContract {
    bool enabled = false;
    NetworkPostcondition expected;
    std::vector<unsigned> address_prefixes;
};

inline bool CanonicalActivationAddress(const std::string& value, bool ipv6,
                                      std::string* address, unsigned* prefix) {
    const auto slash = value.find('/');
    if (!address || !prefix || value.find('\0') != std::string::npos ||
        slash == std::string::npos || !slash || slash + 1 == value.size()) return false;
    const auto prefix_text = value.substr(slash + 1);
    unsigned parsed_prefix = 0;
    const auto parsed = std::from_chars(prefix_text.data(), prefix_text.data() + prefix_text.size(), parsed_prefix);
    if (parsed.ec != std::errc{} || parsed.ptr != prefix_text.data() + prefix_text.size() ||
        parsed_prefix > (ipv6 ? 128u : 32u)) return false;
    const auto text = value.substr(0, slash);
    IN_ADDR address4{};
    IN6_ADDR address6{};
    void* bytes = ipv6 ? static_cast<void*>(&address6) : static_cast<void*>(&address4);
    const int family = ipv6 ? AF_INET6 : AF_INET;
    char canonical[INET6_ADDRSTRLEN]{};
    if (InetPtonA(family, text.c_str(), bytes) != 1 ||
        !InetNtopA(family, bytes, canonical, sizeof(canonical))) return false;
    *address = canonical;
    *prefix = parsed_prefix;
    return true;
}

inline bool BuildActivationNetworkContract(const std::vector<std::string>& addresses,
                                          const std::vector<std::string>& dns,
                                          bool ipv6, ActivationNetworkContract* output) {
    if (!output || addresses.size() != (ipv6 ? 2u : 1u) || dns.empty()) return false;
    ActivationNetworkContract candidate;
    for (size_t index = 0; index < addresses.size(); ++index) {
        std::string address;
        unsigned prefix = 0;
        if (!CanonicalActivationAddress(addresses[index], index == 1, &address, &prefix)) return false;
        candidate.expected.addresses.push_back(std::move(address));
        candidate.address_prefixes.push_back(prefix);
    }
    candidate.expected.routes = {"0.0.0.0/1", "128.0.0.0/1"};
    if (ipv6) {
        candidate.expected.routes.emplace_back("::/1");
        candidate.expected.routes.emplace_back("8000::/1");
    }
    for (const auto& value : dns) {
        std::string address;
        unsigned prefix = 0;
        if (!CanonicalActivationAddress(value + "/32", false, &address, &prefix)) return false;
        candidate.expected.dns.push_back(std::move(address));
    }
    candidate.enabled = true;
    *output = std::move(candidate);
    return true;
}

inline unsigned ActivationNetworkContractFailures(const ActivationNetworkContract& contract,
                                                  const NetworkPostcondition& pushed,
                                                  const std::vector<unsigned>& prefixes) {
    if (!contract.enabled) return 2u | 4u | 8u;
    auto canonical = pushed;
    for (auto& address : canonical.addresses) {
        unsigned prefix = 0;
        const bool ipv6 = address.find(':') != std::string::npos;
        if (!CanonicalActivationAddress(address + (ipv6 ? "/128" : "/32"), ipv6, &address, &prefix)) return 2u;
    }
    for (auto& address : canonical.dns) {
        unsigned prefix = 0;
        const bool ipv6 = address.find(':') != std::string::npos;
        if (!CanonicalActivationAddress(address + (ipv6 ? "/128" : "/32"), ipv6, &address, &prefix)) return 8u;
    }
    unsigned failures = NetworkPostconditionFailures(contract.expected, canonical, true, true);
    // The API allocates hosts (/32 IPv4, /128 IPv6). OpenVPN's ifconfig
    // netmask and ifconfig-ipv6 prefix describe the interface subnets, not
    // different host allocations. Keep exact host/family checks and validate
    // both pushed interface prefixes independently of the allocation CIDRs.
    bool valid_prefixes = prefixes.size() == canonical.addresses.size() &&
        prefixes.size() == contract.address_prefixes.size();
    if (valid_prefixes) {
        for (size_t index = 0; index < prefixes.size(); ++index) {
            const auto bits = canonical.addresses[index].find(':') == std::string::npos ? 32u : 128u;
            valid_prefixes &= prefixes[index] > 0 && prefixes[index] <= bits;
        }
    }
    if (contract.expected.addresses != canonical.addresses || !valid_prefixes)
        failures |= 2u;
    return failures;
}
} // namespace openvpn::Win
