// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_MAINTENANCE_SERVICE_CONFIG_H_
#define RUNNER_MAINTENANCE_SERVICE_CONFIG_H_

#include <windows.h>
#include <winsvc.h>

namespace fuzevpn_maintenance {
// Maintenance restores operational settings only. MSI owns the localized
// display name and description, including during repair and rollback.
template <typename Configure>
bool ConfigureServiceRuntime(SC_HANDLE service, Configure configure) {
  SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};
  SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
  SC_ACTION actions[]{{SC_ACTION_RESTART, 1000}, {SC_ACTION_RESTART, 5000},
                      {SC_ACTION_RESTART, 30000}};
  SERVICE_FAILURE_ACTIONSW recovery{86400, nullptr, nullptr, 3, actions};
  SERVICE_FAILURE_ACTIONS_FLAG failures{TRUE};
  return configure(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid) &&
      configure(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed) &&
      configure(service, SERVICE_CONFIG_FAILURE_ACTIONS, &recovery) &&
      configure(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failures);
}
}  // namespace fuzevpn_maintenance
#endif
