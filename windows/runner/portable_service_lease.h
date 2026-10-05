// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_SERVICE_LEASE_H_
#define RUNNER_PORTABLE_SERVICE_LEASE_H_
#include <windows.h>
#include <winsvc.h>
#include <string>
#include "broker_security.h"
#include "installation_security.h"
#include "update_security.h"
#include "service_handoff_mutex.h"

namespace fuzevpn_handoff {
using ValidateService = bool (*)(SC_HANDLE, const fuzevpn_update::PinnedFile&,
    fuzevpn_update::PinnedFile*, fuzevpn_installation::ProtectedInstallation*,
    std::wstring*, DWORD*);
bool ValidateInstalledService(SC_HANDLE service, const fuzevpn_update::PinnedFile& helper,
    fuzevpn_update::PinnedFile* installed, fuzevpn_installation::ProtectedInstallation* tree,
    std::wstring* command, DWORD* error);

// The elevated, authenticated portable bootstrap retains this lease until its
// engine exits. A separate machine mutex prevents two helpers adopting the
// same service stop. Destruction restores only a service this helper yielded.
class InstalledServiceLease final {
 public:
  explicit InstalledServiceLease(ValidateService validate = ValidateInstalledService) : validate_(validate) {}
  ~InstalledServiceLease();
  InstalledServiceLease(const InstalledServiceLease&) = delete;
  InstalledServiceLease& operator=(const InstalledServiceLease&) = delete;
  bool Acquire(const fuzevpn_update::PinnedFile& helper, HANDLE parent, DWORD* error);
  bool TrackEngine(HANDLE engine, DWORD* error);
  bool Restore(DWORD* error);
 private:
  bool Query(SERVICE_STATUS_PROCESS* state, DWORD* error);
  bool SameConfiguration(DWORD* error);
  ValidateService validate_;
  Reservation reservation_;
  fuzevpn_update::PinnedFile installed_;
  fuzevpn_installation::ProtectedInstallation tree_;
  std::wstring command_;
  SC_HANDLE manager_ = nullptr;
  SC_HANDLE service_ = nullptr;
  HANDLE old_process_ = nullptr;
  HANDLE engine_ = nullptr;
  ULONGLONG deadline_ = 0;
  bool requested_ = false;
};
}  // namespace fuzevpn_handoff
#endif
