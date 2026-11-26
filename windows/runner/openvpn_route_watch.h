// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_ROUTE_WATCH_H_
#define RUNNER_OPENVPN_ROUTE_WATCH_H_

namespace fuzevpn {

// Windows deletes the routes of an interface that goes down, including those
// an OpenVPN runtime owns outside the tunnel: the route to its server and the
// split-tunnel exclusions. Nothing re-creates them until the core notices its
// dead session through keepalive, minutes later. Once a default route is back
// on a physical interface, the core reconnects instead, which re-creates them.
enum class OpenVpnRouteChange { ignore, owned_route_lost, network_restored };

inline OpenVpnRouteChange ClassifyOpenVpnRouteChange(bool deleted, bool added,
                                                     bool tunnel_interface,
                                                     bool default_route,
                                                     bool owned_route) {
  if (tunnel_interface) return OpenVpnRouteChange::ignore;
  if (deleted && owned_route) return OpenVpnRouteChange::owned_route_lost;
  if (added && default_route) return OpenVpnRouteChange::network_restored;
  return OpenVpnRouteChange::ignore;
}

}  // namespace fuzevpn

#endif  // RUNNER_OPENVPN_ROUTE_WATCH_H_
