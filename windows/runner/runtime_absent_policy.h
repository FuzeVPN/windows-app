// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RUNTIME_ABSENT_POLICY_H_
#define RUNNER_RUNTIME_ABSENT_POLICY_H_

#include "network_protection.h"

// What the unprivileged UI answers on its VPN channels while NO privileged
// runtime process exists (PrivilegedRuntimePresence() == false): after a
// reboot before the delayed-start service runs, after a portable relaunch, or
// with a stopped service. No runtime means no OpenVPN engine and nothing that
// can be asked, but a kill switch a previous runtime persisted in BFE may
// still block the network. Pure decisions only: no Windows or Flutter call.
namespace fuzevpn_runtime_absent {

enum class Method {
  is_connected,
  is_network_protection_active,
  network_protection_status,
  reconnect,
  disconnect,
  suspend_for_migration,
};

// The durable intent as the UI could read it. `owner`, `kill_switch` and
// `same_user` are meaningful only for `present`.
struct Evidence {
  PersistedNetworkProtection persisted = PersistedNetworkProtection::unknown;
  NetworkProtectionOwner owner = NetworkProtectionOwner::wire_guard;
  bool kill_switch = false;
  // The Windows account that armed the policy is the one asking now. Only
  // that account may release it.
  bool same_user = false;
};

enum class Reply {
  boolean,                // Success(value)
  status,                 // Success(status map carrying "runtimeAbsent": true)
  success,                // Success(): nothing exists that could be stopped
  status_unavailable,     // runtime_status_unavailable: never guess a state
  owned_by_another_user,  // runtime_owned_by_another_user: not ours to release
  start_runtime,          // forward with start_if_missing = true
};

struct Decision {
  Reply reply = Reply::status_unavailable;
  bool value = false;                    // Reply::boolean
  NetworkProtectionStatus status;        // Reply::status
  bool owned_by_another_user = false;    // Reply::status
};

// Only these answers depend on BFE. The others must not cost a WFP session.
constexpr bool NeedsPersistedProtection(Method method) {
  return method == Method::is_network_protection_active ||
         method == Method::network_protection_status ||
         method == Method::disconnect;
}

constexpr Decision Decide(Method method, NetworkProtectionOwner channel,
                          const Evidence& evidence) {
  Decision decision;
  switch (method) {
    case Method::is_connected:
    case Method::reconnect:
      // No runtime process: no tunnel of ours and no reconnect cache. A status
      // read or an automatic reconnect never starts (or elevates) a runtime.
      decision.reply = Reply::boolean;
      return decision;
    case Method::suspend_for_migration:
      // Stops a tunnel and keeps the policy: with no runtime, already true.
      decision.reply = Reply::success;
      return decision;
    case Method::is_network_protection_active:
    case Method::network_protection_status: {
      if (evidence.persisted == PersistedNetworkProtection::unknown) return decision;
      const bool present = evidence.persisted == PersistedNetworkProtection::present;
      // A restarted runtime restores exactly this: the prepared baseline of
      // the protocol that armed it, without any tunnel or UI exception.
      const bool owned = present && evidence.owner == channel;
      if (method == Method::is_network_protection_active) {
        decision.reply = Reply::boolean;
        decision.value = owned;
        return decision;
      }
      decision.reply = Reply::status;
      if (owned) {
        decision.status.active = true;
        decision.status.kill_switch = evidence.kill_switch;
        decision.status.phase = NetworkProtectionStatus::Phase::prepared;
      }
      decision.owned_by_another_user = present && !evidence.same_user;
      return decision;
    }
    case Method::disconnect:
      // The only path that may start a runtime here, exactly as a connect
      // does: an explicit stop. `unknown` is forwarded too, so the runtime
      // settles what the UI could not read; a failed read never becomes a
      // successful Disconnect that released nothing.
      if (evidence.persisted == PersistedNetworkProtection::absent) {
        decision.reply = Reply::success;
      } else if (evidence.persisted == PersistedNetworkProtection::present &&
                 !evidence.same_user) {
        // The restored runtime would refuse this account. Do not raise an
        // elevation prompt for a release that cannot be granted.
        decision.reply = Reply::owned_by_another_user;
      } else {
        decision.reply = Reply::start_runtime;
      }
      return decision;
  }
  return decision;
}

}  // namespace fuzevpn_runtime_absent

#endif  // RUNNER_RUNTIME_ABSENT_POLICY_H_
