// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_VPN_RECONNECT_BINDING_H_
#define RUNNER_VPN_RECONNECT_BINDING_H_

#include <string>

namespace fuzevpn {
struct VpnReconnectBinding {
  std::string user;
  std::string account;
  std::string credential;
  std::string device;

  bool Matches(const VpnReconnectBinding& current) const {
    return !user.empty() && !account.empty() && !credential.empty() &&
        user == current.user && account == current.account &&
        credential == current.credential && device == current.device;
  }
};
}  // namespace fuzevpn
#endif
