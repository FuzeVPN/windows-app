#pragma once

#include <windows.h>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <string_view>
#include <utility>
#include <vector>

namespace openvpn::Win {
// Only these fixed categories and numeric result codes may leave the worker.
// Never retain a command line, route, DNS address, profile, or exception text.
enum class DiagnosticAction : unsigned {
    none, command_other, command_route_add, command_route_delete,
    command_address_set, command_address_delete, command_interface,
    command_dns_set, command_dns_add, command_dns_delete, command_dns_flush,
    route_lookup, route_create, route_remove, setup_actions,
    postcondition_adapter, postcondition_address, postcondition_route,
    postcondition_dns, postcondition_read_adapter, postcondition_read_routes,
    postcondition_read_nrpt, dns_manager_open, dns_service_open, dns_notify,
    dns_gpo_notify
};
inline const char* CommandFailureActionName(DiagnosticAction action) {
#define FUZEVPN_ACTION_NAME(value) case DiagnosticAction::value: return #value
    switch (action) {
        FUZEVPN_ACTION_NAME(none); FUZEVPN_ACTION_NAME(command_other);
        FUZEVPN_ACTION_NAME(command_route_add); FUZEVPN_ACTION_NAME(command_route_delete);
        FUZEVPN_ACTION_NAME(command_address_set); FUZEVPN_ACTION_NAME(command_address_delete);
        FUZEVPN_ACTION_NAME(command_interface); FUZEVPN_ACTION_NAME(command_dns_set);
        FUZEVPN_ACTION_NAME(command_dns_add); FUZEVPN_ACTION_NAME(command_dns_delete);
        FUZEVPN_ACTION_NAME(command_dns_flush); FUZEVPN_ACTION_NAME(route_lookup);
        FUZEVPN_ACTION_NAME(route_create); FUZEVPN_ACTION_NAME(route_remove);
        FUZEVPN_ACTION_NAME(setup_actions); FUZEVPN_ACTION_NAME(postcondition_adapter);
        FUZEVPN_ACTION_NAME(postcondition_address); FUZEVPN_ACTION_NAME(postcondition_route);
        FUZEVPN_ACTION_NAME(postcondition_dns); FUZEVPN_ACTION_NAME(postcondition_read_adapter);
        FUZEVPN_ACTION_NAME(postcondition_read_routes); FUZEVPN_ACTION_NAME(postcondition_read_nrpt);
        FUZEVPN_ACTION_NAME(dns_manager_open); FUZEVPN_ACTION_NAME(dns_service_open);
        FUZEVPN_ACTION_NAME(dns_notify); FUZEVPN_ACTION_NAME(dns_gpo_notify);
    }
#undef FUZEVPN_ACTION_NAME
    return "unknown";
}
inline DiagnosticAction ClassifyNetworkCommand(std::string_view command) {
    if (command == "ipconfig /flushdns") return DiagnosticAction::command_dns_flush;
    if (command.starts_with("netsh interface ip ")) command.remove_prefix(19);
    else if (command.starts_with("netsh interface ipv6 ")) command.remove_prefix(21);
    else return DiagnosticAction::command_other;
    if (command.starts_with("add route ")) return DiagnosticAction::command_route_add;
    if (command.starts_with("delete route ")) return DiagnosticAction::command_route_delete;
    if (command.starts_with("set address ")) return DiagnosticAction::command_address_set;
    if (command.starts_with("delete address ")) return DiagnosticAction::command_address_delete;
    if (command.starts_with("set interface ")) return DiagnosticAction::command_interface;
    if (command.starts_with("set dnsserver")) return DiagnosticAction::command_dns_set;
    if (command.starts_with("add dnsserver")) return DiagnosticAction::command_dns_add;
    if (command.starts_with("delete dnsserver")) return DiagnosticAction::command_dns_delete;
    return DiagnosticAction::command_other;
}
// One context is installed on the VPN worker. Cancellation is requested by the
// owning thread; cleanup receives its own bounded budget instead of inheriting
// an already expired connection deadline.
inline constexpr unsigned kMaximumCleanupFailureCount = 1000000;
inline constexpr std::uint64_t kCleanupBudgetMs = 15000;
struct CommandControl {
    std::atomic<bool> cancelled{false};
    std::atomic<bool> command_failed{false};
    std::atomic<DiagnosticAction> first_failed_action{DiagnosticAction::none};
    std::atomic<DWORD> first_failed_code{ERROR_SUCCESS};
    std::atomic<unsigned> postcondition_failures{0};
    std::atomic<unsigned> address_expected{0};
    std::atomic<unsigned> address_matched{0};
    std::atomic<unsigned> address_tentative{0};
    std::atomic<unsigned> address_duplicate{0};
    std::atomic<std::uint64_t> setup_commands_ms{0};
    std::atomic<std::uint64_t> setup_validation_ms{0};
    std::atomic<DiagnosticAction> last_cleanup_action{DiagnosticAction::none};
    std::atomic<DWORD> last_cleanup_code{ERROR_SUCCESS};
    std::atomic<unsigned> cleanup_failure_count{0};
    std::uint64_t connection_deadline = 0;
    // Populated only on the worker, then retried after that worker is joined.
    std::vector<std::function<bool()>> cleanup_actions;
};
inline thread_local CommandControl* command_control = nullptr;
inline thread_local std::uint64_t cleanup_deadline = 0;

inline void RecordCommandFailure(DiagnosticAction action, DWORD code = ERROR_GEN_FAILURE) {
    // Cleanup has separate failure reporting and must not replace the cause of
    // an unsuccessful connection. The worker writes first; Stop retries only
    // after joining it. Diagnostics retain fixed categories and numeric codes.
    if (!command_control) return;
    if (cleanup_deadline) {
        command_control->last_cleanup_code.store(code);
        command_control->last_cleanup_action.store(action);
        auto count = command_control->cleanup_failure_count.load();
        while (count < kMaximumCleanupFailureCount &&
            !command_control->cleanup_failure_count.compare_exchange_weak(count, count + 1)) {}
        return;
    }
    if (command_control->first_failed_action.load() != DiagnosticAction::none) return;
    command_control->first_failed_code.store(code);
    command_control->first_failed_action.store(action);
}

inline void RecordNetworkCommandFailure(DiagnosticAction action, DWORD code,
                                       bool record_failure = true) {
    // A caller that reconciles an already-present route records its own final
    // outcome. Neither that handled error nor cleanup may poison setup state.
    if (!record_failure || !command_control) return;
    if (!cleanup_deadline) command_control->command_failed.store(true);
    RecordCommandFailure(action, code);
}

class ScopedCommandControl {
public:
    explicit ScopedCommandControl(CommandControl* value) : previous_(command_control) { command_control = value; }
    ~ScopedCommandControl() { command_control = previous_; }
private:
    CommandControl* previous_;
};
class ScopedCommandCleanup {
public:
    ScopedCommandCleanup() : previous_(cleanup_deadline) {
        if (!cleanup_deadline) cleanup_deadline = GetTickCount64() + kCleanupBudgetMs;
    }
    ~ScopedCommandCleanup() { cleanup_deadline = previous_; }
private:
    std::uint64_t previous_;
};
inline std::uint64_t CommandDeadline(std::uint64_t now, std::uint64_t timeout) {
    auto deadline = now + timeout;
    if (cleanup_deadline) return std::min(deadline, cleanup_deadline);
    if (command_control && command_control->connection_deadline)
        deadline = std::min(deadline, command_control->connection_deadline);
    return deadline;
}
inline bool CommandCancelled() {
    return !cleanup_deadline && command_control && command_control->cancelled.load();
}
inline bool RetryCommandCleanup(CommandControl* control) {
    if (!control) return true;
    ScopedCommandControl scope(control);
    ScopedCommandCleanup cleanup;
    auto pending = std::move(control->cleanup_actions);
    control->cleanup_actions.clear();
    for (auto& action : pending) {
        bool removed = false;
        try { removed = action(); } catch (...) {}
        if (!removed) control->cleanup_actions.push_back(std::move(action));
    }
    return control->cleanup_actions.empty();
}
} // namespace openvpn::Win
