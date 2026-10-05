#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <openvpn/common/action.hpp>
#include <openvpn/win/command_context.hpp>
#include <openvpn/win/call.hpp>
#include <openvpn/win/owned_route_state.hpp>
#include <openvpn/win/owned_route_row.hpp>

namespace openvpn::Win {
struct OwnedRoute {
    MIB_IPFORWARD_ROW2 row{};
    OwnedRouteState ownership;
    std::string creation_command;
};
class OwnedRouteAction final : public Action {
public:
    OwnedRouteAction(std::shared_ptr<OwnedRoute> route, bool create) : route_(std::move(route)), create_(create) {}
    void execute(std::ostream& output) override {
        if (CommandCancelled()) throw std::runtime_error("route action cancelled");
        DWORD status = ERROR_SUCCESS;
        if (create_ && !route_->creation_command.empty()) {
            const auto before = Lookup();
            if (before == ERROR_SUCCESS) return; // Borrow the exact existing tuple.
            if (before != ERROR_NOT_FOUND && before != ERROR_FILE_NOT_FOUND) {
                RecordCommandFailure(DiagnosticAction::route_lookup, before);
                throw std::runtime_error("cannot inspect Windows route before creation");
            }
            try { call(route_->creation_command, false); }
            catch (const win_call_exit& failure) {
                // Another creator can win the race after the initial lookup.
                // Our failed add confers no right to remove that tuple.
                if (Lookup() == ERROR_SUCCESS) return;
                RecordCommandFailure(DiagnosticAction::command_route_add, failure.code());
                throw;
            } catch (...) {
                RecordCommandFailure(DiagnosticAction::command_route_add);
                route_->ownership.MarkUncertain();
                route_->ownership.ReconcileUncertain(Lookup());
                throw;
            }
            route_->ownership.MarkCreated();
            status = Lookup();
        } else if (create_) {
            status = route_->ownership.CreateRoute([&] { return CreateIpForwardEntry2(&route_->row); });
        } else {
            if (route_->ownership.uncertain()) status = route_->ownership.ReconcileUncertain(Lookup());
            if (status == ERROR_SUCCESS)
                status = route_->ownership.RemoveRoute([&] { return DeleteIpForwardEntry2(&route_->row); });
        }
        output << to_string() << '\n';
        if (status != ERROR_SUCCESS) {
            RecordCommandFailure(create_ ? DiagnosticAction::route_create : DiagnosticAction::route_remove, status);
            throw std::runtime_error("Windows route action failed: " + std::to_string(status));
        }
    }
    std::string to_string() const override { return create_ ? "Create owned VPN route" : "Remove owned VPN route"; }
private:
    DWORD Lookup() const { auto row = route_->row; return GetIpForwardEntry2(&row); }
    std::shared_ptr<OwnedRoute> route_;
    bool create_;
};
inline void AddOwnedRoutePair(ActionList& create, ActionList& cleanup,
    const std::string& destination, unsigned prefix, DWORD interface_index,
    const std::string& gateway, ULONG metric, const std::string& creation_command = {}) {
    auto route = std::make_shared<OwnedRoute>();
    if (!BuildOwnedRouteRow(destination, prefix, interface_index, gateway, metric, &route->row))
        throw std::runtime_error("invalid Windows route tuple");
    route->creation_command = creation_command;
    create.add(new OwnedRouteAction(route, true));
    cleanup.add(new OwnedRouteAction(std::move(route), false));
}
} // namespace openvpn::Win
