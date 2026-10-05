// SPDX-License-Identifier: MPL-2.0
#include "privileged_runtime.h"

#include <atomic>

namespace {
std::atomic<PrivilegedRuntimeKind> runtime_kind{
    PrivilegedRuntimeKind::user_interface};
}

void SetPrivilegedRuntimeKind(PrivilegedRuntimeKind kind) {
  runtime_kind.store(kind, std::memory_order_release);
}

bool CanManageNetworkProtection() {
  const auto kind = runtime_kind.load(std::memory_order_acquire);
  return kind == PrivilegedRuntimeKind::vpn_service ||
         kind == PrivilegedRuntimeKind::elevated_broker;
}

bool IsVpnServiceRuntime() {
  return runtime_kind.load(std::memory_order_acquire) ==
         PrivilegedRuntimeKind::vpn_service;
}
