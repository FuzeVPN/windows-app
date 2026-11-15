// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RUNTIME_ABSENT_CHANNEL_H_
#define RUNNER_RUNTIME_ABSENT_CHANNEL_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <flutter/encodable_value.h>
#include <flutter/method_result.h>

#include "network_protection.h"
#include "network_protection_channel.h"
#include "privileged_broker.h"
#include "protected_store.h"
#include "runtime_absent_policy.h"

// UI-process glue between the VPN method channels and the pure policy in
// runtime_absent_policy.h. The local answers apply only once
// PrivilegedRuntimePresence() has confirmed that no privileged runtime
// process exists.
namespace fuzevpn_runtime_absent {

inline std::optional<Method> MethodNamed(const std::string& name) {
  if (name == "isConnected") return Method::is_connected;
  if (name == "isNetworkProtectionActive") return Method::is_network_protection_active;
  if (name == "networkProtectionStatus") return Method::network_protection_status;
  if (name == "reconnect") return Method::reconnect;
  if (name == "disconnect") return Method::disconnect;
  if (name == "suspendForMigration") return Method::suspend_for_migration;
  return std::nullopt;
}

// Same keys as a runtime's reply ("active", "killSwitch", "phase",
// "ownedByAnotherUser") plus "runtimeAbsent": true, which only this local
// answer ever carries: the policy is enforced by BFE, no process holds it.
inline flutter::EncodableValue StatusValue(const Decision& decision) {
  auto status = NetworkProtectionStatusMap(decision.status);
  status[flutter::EncodableValue("ownedByAnotherUser")] =
      flutter::EncodableValue(decision.owned_by_another_user);
  status[flutter::EncodableValue("runtimeAbsent")] = flutter::EncodableValue(true);
  return flutter::EncodableValue(std::move(status));
}

// One bounded, read-only BFE query. On `unknown` the thread's last error is
// the Windows status of the step that failed.
inline Evidence ReadEvidence() {
  Evidence evidence;
  std::string owner_account;
  evidence.persisted = ReadPersistedNetworkProtection(
      &evidence.owner, &evidence.kill_switch, &owner_account);
  if (evidence.persisted != PersistedNetworkProtection::present) return evidence;
  // Same rule as the runtime: an account that cannot be established is
  // neither the owner nor a stranger. The identifiers are compared only.
  const std::string current_account = ProtectedStoreUserId();
  if (current_account.empty()) {
    const DWORD account_error = GetLastError();
    evidence = Evidence{};
    SetLastError(account_error != ERROR_SUCCESS ? account_error : ERROR_NO_SUCH_USER);
    return evidence;
  }
  evidence.same_user = current_account == owner_account;
  return evidence;
}

// Completes `result` with the answer for a UI that has no privileged runtime.
// Returns false, leaving `result` untouched, only for an explicit Disconnect
// that must be forwarded with start_if_missing = true: starting (and, in
// portable or development mode, elevating) a runtime is the only way to
// release a persisted policy. No other method ever returns false.
inline bool AnswerWithoutRuntime(
    NetworkProtectionOwner channel, const std::string& method_name,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>* result) {
  const auto method = MethodNamed(method_name);
  Evidence evidence;
  DWORD read_error = ERROR_NOT_SUPPORTED;
  if (method.has_value() && NeedsPersistedProtection(*method)) {
    evidence = ReadEvidence();
    read_error = GetLastError();
  }
  const Decision decision =
      method.has_value() ? Decide(*method, channel, evidence) : Decision{};
  switch (decision.reply) {
    case Reply::boolean:
      (*result)->Success(flutter::EncodableValue(decision.value));
      return true;
    case Reply::status:
      (*result)->Success(StatusValue(decision));
      return true;
    case Reply::success:
      (*result)->Success();
      return true;
    case Reply::owned_by_another_user:
      (*result)->Error("runtime_owned_by_another_user",
                       "Windows could not authorize control of the VPN runtime.");
      return true;
    case Reply::start_runtime:
      // Enforced here as well as in the policy: a status read, a reconnect or
      // a migration suspend can never start or elevate a runtime.
      if (method == Method::disconnect) return false;
      break;
    case Reply::status_unavailable:
      break;
  }
  SetLastError(read_error);
  CompleteRuntimeStatusFailure(std::move(*result));
  return true;
}

// Whole routing of a channel method that only reads the runtime or stops it.
// A runtime that exists is asked passively: such a call never starts or
// elevates one. A confirmed absence is answered here, except an explicit
// Disconnect against a persisted or unreadable policy, which starts the
// runtime exactly as a connect does. An unknown presence is a status failure,
// never a guess.
inline void RouteStatusOrStop(
    const std::string& scope, NetworkProtectionOwner channel,
    const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  bool detection_failed = false;
  const auto presence = PrivilegedRuntimePresence(&detection_failed);
  if (!presence.has_value()) {
    CompleteRuntimeStatusFailure(std::move(result), detection_failed);
    return;
  }
  if (*presence) {
    ForwardPrivilegedCall(scope, call, std::move(result), false);
    return;
  }
  if (AnswerWithoutRuntime(channel, call.method_name(), &result)) return;
  ForwardPrivilegedCall(scope, call, std::move(result), true);
}

}  // namespace fuzevpn_runtime_absent

#endif  // RUNNER_RUNTIME_ABSENT_CHANNEL_H_
