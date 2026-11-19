// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_MAINTENANCE_SERVICE_CONFIG_H_
#define RUNNER_MAINTENANCE_SERVICE_CONFIG_H_

#include <windows.h>
#include <sddl.h>
#include <winsvc.h>

namespace fuzevpn_maintenance {
// Same service ACL as installer/Package.wxs. Users may query and start (RP)
// the service: the UI starts it before its delayed automatic start without an
// elevation prompt. The service itself refuses to run during maintenance,
// from an unprotected installation or while another runtime holds its lock.
constexpr wchar_t kServiceSecurity[] =
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCSWRPLORC;;;BU)";

// MSI is not relied upon to rewrite the ACL of a service it keeps across an
// upgrade. `apply` is SetServiceObjectSecurity in production.
template <typename Apply>
bool ApplyServiceSecurity(SC_HANDLE service, Apply apply) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          kServiceSecurity, SDDL_REVISION_1, &descriptor, nullptr)) return false;
  const bool applied = apply(service, DACL_SECURITY_INFORMATION, descriptor) != FALSE;
  const DWORD apply_error = GetLastError();
  LocalFree(descriptor);
  SetLastError(apply_error);
  return applied;
}

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
