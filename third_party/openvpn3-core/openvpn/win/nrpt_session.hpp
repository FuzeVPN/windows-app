#pragma once

#include <windows.h>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace openvpn::Win {
inline constexpr wchar_t kFuzeNrptPrefix[] = L"FuzeVPNDNSRoutingV1-";
struct NrptSession { DWORD pid = 0; std::uint64_t created = 0; };
inline std::uint64_t ProcessCreationValue(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
    return (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}
inline std::wstring NrptSessionRule(DWORD pid, std::uint64_t created,
                                    std::optional<std::uint32_t> exclude = {}) {
    auto rule = std::wstring(kFuzeNrptPrefix) + std::to_wstring(pid) + L"-" + std::to_wstring(created);
    if (exclude) rule += L"-X" + std::to_wstring(*exclude);
    return rule;
}
inline bool NrptNumber(std::wstring_view value, std::uint64_t limit, std::uint64_t* output) {
    if (value.empty() || (value.size() > 1 && value.front() == L'0')) return false;
    std::uint64_t number = 0;
    for (const wchar_t c : value) {
        if (c < L'0' || c > L'9' || number > (limit - (c - L'0')) / 10) return false;
        number = number * 10 + (c - L'0');
    }
    *output = number;
    return true;
}
inline bool ParseNrptSessionRule(std::wstring_view rule, NrptSession* session) {
    if (!session || !rule.starts_with(kFuzeNrptPrefix)) return false;
    rule.remove_prefix(std::size(kFuzeNrptPrefix) - 1);
    const auto dash = rule.find(L'-');
    if (dash == std::wstring_view::npos) return false;
    std::uint64_t pid = 0, created = 0, exclude = 0;
    if (!NrptNumber(rule.substr(0, dash), MAXDWORD, &pid) || !pid) return false;
    rule.remove_prefix(dash + 1);
    const auto suffix = rule.find(L'-');
    if (!NrptNumber(rule.substr(0, suffix), std::numeric_limits<std::uint64_t>::max(), &created) || !created)
        return false;
    if (suffix != std::wstring_view::npos &&
        (!rule.substr(suffix).starts_with(L"-X") ||
         !NrptNumber(rule.substr(suffix + 2), MAXDWORD, &exclude))) return false;
    *session = {static_cast<DWORD>(pid), created};
    return true;
}
enum class NrptProcessState { matching_live, orphaned, unavailable };
template<typename Probe, typename Remove>
bool RecoverNrptSessions(const std::vector<std::wstring>& names, Probe probe, Remove remove) {
    bool success = true;
    for (const auto& name : names) {
        NrptSession session;
        if (!ParseNrptSessionRule(name, &session)) continue;
        const auto state = probe(session);
        if (state == NrptProcessState::unavailable) success = false;
        else if (state == NrptProcessState::orphaned && !remove(name)) success = false;
    }
    return success;
}
} // namespace openvpn::Win
