#pragma once
#include <algorithm>
#include <string>
#include <vector>

namespace openvpn::Win {
struct NetworkPostcondition {
    std::vector<std::string> addresses;
    std::vector<std::string> routes;
    std::vector<std::string> dns;
};
inline unsigned NetworkPostconditionFailures(const NetworkPostcondition& expected,
                                     const NetworkPostcondition& actual,
                                     bool adapter_up, bool nrpt_present) {
    const auto contains_all = [](const auto& wanted, const auto& installed) {
        return std::all_of(wanted.begin(), wanted.end(), [&](const auto& value) {
            return std::find(installed.begin(), installed.end(), value) != installed.end();
        });
    };
    return (adapter_up ? 0u : 1u) |
           (contains_all(expected.addresses, actual.addresses) ? 0u : 2u) |
           (contains_all(expected.routes, actual.routes) ? 0u : 4u) |
           (contains_all(expected.dns, actual.dns) ? 0u : 8u) |
           (expected.dns.empty() || nrpt_present ? 0u : 16u);
}
inline bool NetworkPostconditionsMet(const NetworkPostcondition& expected,
                                     const NetworkPostcondition& actual,
                                     bool adapter_up, bool nrpt_present) {
    return NetworkPostconditionFailures(expected, actual, adapter_up, nrpt_present) == 0;
}
} // namespace openvpn::Win
