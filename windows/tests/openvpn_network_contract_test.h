// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <openvpn/win/activation_network_contract.hpp>
#include <openvpn/win/unicast_address_configuration.hpp>
#include <openvpn/win/dco_adapter_reuse.hpp>
#include <array>
#include <stdexcept>

inline void OpenVpnNetworkContractTests() {
    using namespace openvpn::Win;
    const auto check = [](bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    };
    ActivationNetworkContract dual;
    check(BuildActivationNetworkContract({"10.1.0.2/24", "FD42:0:0:0:0:0:0:2/128"},
        {"10.1.0.1"}, true, &dual), "valid activation produces an independent canonical contract");
    check(dual.enabled && dual.expected.addresses[1] == "fd42::2" &&
        dual.address_prefixes == std::vector<unsigned>{24, 128}, "contract retains exact address prefixes");
    check(!ActivationNetworkContractFailures(dual, dual.expected, {24, 128}), "complete dual stack satisfies activation");
    auto pushed = dual.expected;
    pushed.addresses[1] = "FD42:0000:0000:0000:0000:0000:0000:0002";
    check(!ActivationNetworkContractFailures(dual, pushed, {24, 128}), "equivalent IPv6 spelling satisfies activation");
    pushed = dual.expected;
    pushed.addresses.pop_back();
    pushed.routes.resize(2);
    check(ActivationNetworkContractFailures(dual, pushed, {24}) == 6,
        "IPv4-only PUSH cannot satisfy dual-stack activation even if Windows applied every pushed value");
    pushed = dual.expected;
    pushed.addresses[0] = "10.1.0.3";
    check(ActivationNetworkContractFailures(dual, pushed, {24, 128}) & 2,
        "a CCD address different from activation is rejected");
    pushed = dual.expected;
    check(!ActivationNetworkContractFailures(dual, pushed, {24, 64}),
        "an activated IPv6 /128 host can use the server's IPv6 /64 interface subnet");
    ActivationNetworkContract host_allocation;
    check(BuildActivationNetworkContract({"10.20.0.2/32", "fd42::2/128"},
        {"10.20.0.1"}, true, &host_allocation), "actual API contract allocates IPv4 /32 and IPv6 /128 hosts");
    check(!ActivationNetworkContractFailures(host_allocation, host_allocation.expected, {24, 64}),
        "actual server CCD pushes the same allocated hosts with IPv4 /24 and IPv6 /64 interface subnets");
    ActivationNetworkContract ipv4_host;
    check(BuildActivationNetworkContract({"10.20.0.2/32"}, {"10.20.0.1"}, false, &ipv4_host) &&
        !ActivationNetworkContractFailures(ipv4_host, ipv4_host.expected, {24}),
        "historical IPv4-only API host /32 works with a pushed /24 subnet");
    check(ActivationNetworkContractFailures(dual, pushed, {24, 129}) == 2 &&
        ActivationNetworkContractFailures(dual, pushed, {24, 0}) == 2 &&
        ActivationNetworkContractFailures(dual, pushed, {24}) == 2 &&
        ActivationNetworkContractFailures(dual, pushed, {33, 64}) == 2 &&
        ActivationNetworkContractFailures(dual, pushed, {0, 64}) == 2,
        "invalid or missing pushed interface prefixes fail closed");
    pushed.routes.pop_back();
    check(ActivationNetworkContractFailures(dual, pushed, {24, 128}) == 4,
        "one missing IPv6 half-default route is rejected");
    pushed = dual.expected;
    pushed.dns = {"192.0.2.53"};
    check(ActivationNetworkContractFailures(dual, pushed, {24, 128}) == 8,
        "server DNS cannot replace all required activation resolvers");
    check(ActivationNetworkContractFailures({}, dual.expected, {24, 128}) == 14,
        "an absent independent contract fails closed");
    ActivationNetworkContract single;
    check(BuildActivationNetworkContract({"10.1.0.2/24"}, {"10.1.0.1"}, false, &single),
        "historical IPv4-only activation remains supported");
    check(!ActivationNetworkContractFailures(single, single.expected, {24}), "complete IPv4 activation succeeds");
    check(ActivationNetworkContractFailures(single, dual.expected, {24, 128}) & 2,
        "unexpected IPv6 cannot silently expand an IPv4-only activation");
    for (const auto& invalid : {"10.1.0.2/33", "10.1.0.2/-1", "10.1.0.2/24x", "10.1.0.2/24/1",
             "10.1.0.2", "10.1.0.2/", "10.1.0.2\nremote x/24"}) {
        check(!BuildActivationNetworkContract({invalid}, {"10.1.0.1"}, false, &single),
            "malformed CIDR cannot enter a network contract");
    }
    check(!BuildActivationNetworkContract({"10.1.0.2/24"}, {"10.1.0.1"}, true, &single) &&
        !BuildActivationNetworkContract({"10.1.0.2/24", "fd42::2/128"}, {"10.1.0.1"}, false, &single) &&
        !BuildActivationNetworkContract({"10.1.0.2/24", "fd42::2/129"}, {"10.1.0.1"}, true, &single),
        "contract parsing requires the exact requested families and valid IPv6 prefix");

    MIB_UNICASTIPADDRESS_ROW assigned{};
    assigned.InterfaceIndex = 12;
    assigned.Address = ParseExpectedUnicastAddress("fd42::2");
    assigned.DadState = IpDadStatePreferred;
    const std::array expected{assigned.Address};
    const std::array prefixes{64u};
    assigned.OnLinkPrefixLength = 64;
    check(EvaluateUnicastAddressConfiguration(expected, 12, std::span(&assigned, 1), prefixes).configured(),
        "Windows must install the validated pushed IPv6 subnet, not the activation host prefix");
    assigned.OnLinkPrefixLength = 128;
    check(!EvaluateUnicastAddressConfiguration(expected, 12, std::span(&assigned, 1), prefixes).configured(),
        "the correct IPv6 host with a prefix different from the pushed configuration is rejected");
    assigned.Address = ParseExpectedUnicastAddress("10.20.0.2");
    assigned.OnLinkPrefixLength = 24;
    const std::array expected4{assigned.Address};
    const std::array prefixes4{24u};
    check(EvaluateUnicastAddressConfiguration(expected4, 12, std::span(&assigned, 1), prefixes4).configured(),
        "Windows IPv4 /24 satisfies the pushed interface configuration for an API /32 host");
    assigned.OnLinkPrefixLength = 16;
    check(!EvaluateUnicastAddressConfiguration(expected4, 12, std::span(&assigned, 1), prefixes4).configured(),
        "Windows IPv4 with a prefix different from the validated PUSH remains rejected");
}

inline void OpenVpnDcoAdapterReuseTests() {
    using namespace openvpn::Win;
    const auto check = [](bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    };
    check(PlanDcoAdapterReuse(12, {}, {}) == DcoAdapterReuse::eligible,
        "an empty DCO adapter is eligible without any route reset");
    MIB_UNICASTIPADDRESS_ROW address{};
    address.InterfaceIndex = 12;
    address.Address = ParseExpectedUnicastAddress("10.8.0.2");
    address.PrefixOrigin = IpPrefixOriginManual;
    check(PlanDcoAdapterReuse(12, std::span(&address, 1), {}) == DcoAdapterReuse::configured_address,
        "a generic DCO adapter with somebody else's static address is skipped");
    check(PlanDcoAdapterReuse(13, std::span(&address, 1), {}) == DcoAdapterReuse::eligible,
        "foreign configuration on another adapter never blocks a clean candidate");
    address.Address = ParseExpectedUnicastAddress("fe80::1");
    address.PrefixOrigin = IpPrefixOriginWellKnown;
    MIB_IPFORWARD_ROW2 route{};
    route.InterfaceIndex = 12;
    route.Protocol = MIB_IPPROTO_LOCAL;
    route.DestinationPrefix.Prefix = ParseExpectedUnicastAddress("ff00::");
    route.DestinationPrefix.PrefixLength = 8;
    check(PlanDcoAdapterReuse(12, std::span(&address, 1), std::span(&route, 1)) == DcoAdapterReuse::eligible,
        "Windows link-local and multicast state does not make an unused adapter foreign");
    route.Protocol = MIB_IPPROTO_NETMGMT;
    check(PlanDcoAdapterReuse(12, std::span(&address, 1), std::span(&route, 1)) == DcoAdapterReuse::foreign_route,
        "an explicitly managed route is preserved even if its prefix resembles an automatic route");
    route.DestinationPrefix.Prefix = ParseExpectedUnicastAddress("192.0.2.0");
    route.DestinationPrefix.PrefixLength = 24;
    check(PlanDcoAdapterReuse(12, {}, std::span(&route, 1)) == DcoAdapterReuse::foreign_route,
        "an idle adapter with a static route is rejected instead of resetting routes");
    route.Protocol = MIB_IPPROTO_LOCAL;
    check(PlanDcoAdapterReuse(12, {}, std::span(&route, 1)) == DcoAdapterReuse::foreign_route,
        "a stale on-link global route also requires explicit recovery instead of deletion");
    address.Address = ParseExpectedUnicastAddress("169.254.1.2");
    address.PrefixOrigin = IpPrefixOriginWellKnown;
    check(PlanDcoAdapterReuse(12, std::span(&address, 1), {}) == DcoAdapterReuse::eligible,
        "Windows APIPA on an unused adapter remains supported");
    address.PrefixOrigin = IpPrefixOriginManual;
    check(PlanDcoAdapterReuse(12, std::span(&address, 1), {}) == DcoAdapterReuse::configured_address,
        "a manually assigned APIPA address is foreign state");
}
