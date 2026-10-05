// SPDX-License-Identifier: MPL-2.0
#include <windows.h>

#include "privileged_broker.h"
#include "wireguard_tunnel.h"
#include "runtime_architecture.h"

// Dedicated native entry point for every privileged VPN runtime. This binary
// deliberately contains no Flutter engine, window, tray or UI plugin.
int APIENTRY wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ wchar_t*,
                      _In_ int) {
  if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return ERROR_BAD_EXE_FORMAT;
  if (const auto service_exit = RunWireGuardServiceCommandIfRequested();
      service_exit.has_value()) {
    return *service_exit;
  }
  if (const auto broker_exit = RunPrivilegedBrokerIfRequested();
      broker_exit.has_value()) {
    return *broker_exit;
  }
  return EXIT_FAILURE;
}
