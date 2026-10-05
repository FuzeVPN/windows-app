// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PRIVILEGED_RUNTIME_H_
#define RUNNER_PRIVILEGED_RUNTIME_H_

enum class PrivilegedRuntimeKind {
  user_interface,
  elevated_broker,
  vpn_service,
};

void SetPrivilegedRuntimeKind(PrivilegedRuntimeKind kind);
bool CanManageNetworkProtection();
bool IsVpnServiceRuntime();

#endif  // RUNNER_PRIVILEGED_RUNTIME_H_
