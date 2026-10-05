// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <openvpn/win/unicast_address_configuration.hpp>
#include <array>
#include <stdexcept>

inline void OpenVpnAddressConfigurationTests() {
    using namespace openvpn::Win;
    const auto check = [](bool condition, const char* message) {
        if (!condition) throw std::runtime_error(message);
    };
    const std::array expected{ParseExpectedUnicastAddress("10.1.0.2")};
    MIB_UNICASTIPADDRESS_ROW row{};
    row.InterfaceIndex = 12;
    row.Address = expected[0];
    row.DadState = IpDadStateTentative;
    // Configuration is present immediately, even while Windows is still
    // checking for duplicates. This is not a claim of data-plane availability.
    for (auto assigned : {IpDadStateTentative, IpDadStatePreferred}) {
        row.DadState = assigned;
        const auto state = EvaluateUnicastAddressConfiguration(expected, 12, std::span(&row, 1));
        check(state.expected == 1 && state.matched == 1 && state.assigned == 1 && state.configured(),
            "an exact Tentative or Preferred address confirms configuration without a DAD wait");
        check(state.tentative == (assigned == IpDadStateTentative ? 1u : 0u),
            "tentative diagnostic counts the exact address");
    }
    row.DadState = IpDadStateDuplicate;
    auto state = EvaluateUnicastAddressConfiguration(expected, 12, std::span(&row, 1));
    check(!state.configured() && state.duplicate == 1, "duplicate address cannot satisfy configuration");
    auto preferred_row = row;
    preferred_row.DadState = IpDadStatePreferred;
    const std::array conflicting_rows{preferred_row, row};
    state = EvaluateUnicastAddressConfiguration(expected, 12, conflicting_rows);
    check(!state.configured() && state.duplicate == 1 && state.assigned == 0,
        "a duplicate row overrides an identical Preferred row");
    for (auto invalid : {IpDadStateInvalid, IpDadStateDeprecated}) {
        row.DadState = invalid;
        check(!EvaluateUnicastAddressConfiguration(expected, 12, std::span(&row, 1)).configured(),
            "invalid or deprecated expected address cannot satisfy configuration");
    }
    state = EvaluateUnicastAddressConfiguration(expected, 12, {});
    check(!state.configured() && state.matched == 0, "an absent address cannot satisfy configuration");
    row.DadState = IpDadStatePreferred;
    row.InterfaceIndex = 13;
    state = EvaluateUnicastAddressConfiguration(expected, 12, std::span(&row, 1));
    check(!state.configured() && state.matched == 0, "same address on another interface cannot satisfy the tunnel");
    row.InterfaceIndex = 12;
    row.Address = ParseExpectedUnicastAddress("10.1.0.3");
    check(!EvaluateUnicastAddressConfiguration(expected, 12, std::span(&row, 1)).configured(),
        "a different address cannot satisfy assignment");
    const std::array expected6{ParseExpectedUnicastAddress("FD00:ABCD:0:0:0:0:0:2")};
    row.Address = ParseExpectedUnicastAddress("fd00:abcd::2");
    check(EvaluateUnicastAddressConfiguration(expected6, 12, std::span(&row, 1)).configured(),
        "IPv6 comparison uses bytes and ignores equivalent text spelling");
    const std::array both{expected[0], expected6[0]};
    const auto only6 = EvaluateUnicastAddressConfiguration(both, 12, std::span(&row, 1));
    check(!only6.configured() && only6.expected == 2 && only6.matched == 1,
        "dual stack requires both assigned addresses");
    const std::array dual_stack{preferred_row, row};
    check(EvaluateUnicastAddressConfiguration(both, 12, dual_stack).configured(),
        "dual stack succeeds when both exact addresses are assigned");
}
