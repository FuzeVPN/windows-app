// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_BROKER_DEVELOPMENT_POLICY_H_
#define RUNNER_BROKER_DEVELOPMENT_POLICY_H_

#include <windows.h>

namespace fuzevpn_broker {
#if defined(FUZEVPN_ALLOW_PORTABLE_DEV) && FUZEVPN_ALLOW_PORTABLE_DEV
inline constexpr bool kAllowPortableDevelopment = true;
#else
inline constexpr bool kAllowPortableDevelopment = false;
#endif

// This opt-in only removes the protected-installation prerequisite for local
// unsigned test builds. It does not make a signed, invalidly signed or mixed
// pair eligible for the development broker, and never changes IPC identity.
template <bool AllowPortable = kAllowPortableDevelopment>
constexpr bool CanSkipProtectedInstallation(LONG ui_trust, LONG service_trust) {
  return AllowPortable && ui_trust == TRUST_E_NOSIGNATURE &&
      service_trust == TRUST_E_NOSIGNATURE;
}
}  // namespace fuzevpn_broker
#endif
