// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_MAINTENANCE_NETWORK_STATE_H_
#define RUNNER_MAINTENANCE_NETWORK_STATE_H_

#include <windows.h>
#include <string>

namespace fuzevpn_maintenance {
// Read-only fallback for a service that was already stopped with a historical
// startup/crash error. Called while the maintenance gate and runtime lock hold.
// An inaccessible resource or any surviving VPN state is blocking.
bool ConfirmStoppedNetworkState(const std::wstring& installation_directory,
                                DWORD* error);
}  // namespace fuzevpn_maintenance
#endif
