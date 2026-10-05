// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_MAINTENANCE_STATE_H_
#define RUNNER_MAINTENANCE_STATE_H_

#include <windows.h>
#include <string>

namespace fuzevpn_maintenance {
// Read errors are blocking. The gate is machine-wide and only writable by
// administrators/SYSTEM; a failed installer cannot accidentally reopen VPNs.
bool IsBlocked();
bool BeginInstallerMaintenance(const std::wstring& transaction,
                               const std::wstring& installation_directory,
                               DWORD* error);
// Same-thread diagnostic only; fixed literals contain no transaction/path data.
const wchar_t* LastInstallerMaintenanceStage();
bool EndInstallerMaintenance(const std::wstring& transaction,
                             bool restart_service, DWORD* error,
                             bool* restart_attempted = nullptr);
constexpr wchar_t kServiceName[] = L"FuzeVPNService";
}  // namespace fuzevpn_maintenance
#endif
