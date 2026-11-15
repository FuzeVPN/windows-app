// SPDX-License-Identifier: MPL-2.0
// What the unprivileged UI answers on its VPN channels while no privileged
// runtime process exists. The pure policy is enumerated exhaustively, then the
// channel glue and routing are driven with in-memory doubles for the runtime
// presence, the persisted-intent read, the Windows account, the forward to the
// runtime and the Flutter reply. No WFP session, service, pipe, elevation or
// network access is involved.
#include "runtime_absent_channel.h"

#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace fixture {
int failures = 0;
void Check(bool condition, const char* message) {
  if (!condition) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}

// What BFE would answer to the unprivileged read.
PersistedNetworkProtection persisted = PersistedNetworkProtection::absent;
NetworkProtectionOwner persisted_owner = NetworkProtectionOwner::wire_guard;
bool persisted_kill_switch = false;
std::string persisted_account;
DWORD persisted_error = ERROR_ACCESS_DENIED;
// The Windows account of the UI process; empty means it cannot be established.
std::string current_account;
unsigned persisted_reads = 0, account_reads = 0, local_status_reads = 0;
unsigned status_failures = 0;
DWORD status_failure_error = ERROR_SUCCESS;
bool status_failure_was_detection = false;
// Whether a privileged runtime process exists; nullopt: Windows cannot tell.
std::optional<bool> runtime_present = false;
bool runtime_detection_failed = false;
unsigned presence_queries = 0;
// Calls handed to the privileged runtime instead of being answered here.
struct Forward {
  std::string scope, method;
  bool start_if_missing;
};
std::vector<Forward> forwards;
std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> forwarded_result;

constexpr char kAccount[] = "S-1-5-21-123-456-789-1001";
constexpr char kOtherAccount[] = "S-1-5-21-123-456-789-1002";

void Arm(PersistedNetworkProtection state, NetworkProtectionOwner owner = NetworkProtectionOwner::wire_guard,
         bool kill_switch = false, const char* account = kAccount) {
  persisted = state;
  persisted_owner = owner;
  persisted_kill_switch = kill_switch;
  persisted_account = account;
  current_account = kAccount;
  persisted_error = ERROR_ACCESS_DENIED;
  persisted_reads = account_reads = local_status_reads = status_failures = presence_queries = 0;
  status_failure_error = ERROR_SUCCESS;
  status_failure_was_detection = false;
  runtime_present = false;
  runtime_detection_failed = false;
  forwards.clear();
  forwarded_result.reset();
}

class RecordingResult final : public flutter::MethodResult<flutter::EncodableValue> {
 public:
  struct Reply {
    unsigned replies = 0;
    bool success = false, has_value = false, not_implemented = false;
    flutter::EncodableValue value;
    std::string error;
    flutter::EncodableValue details;
  };
  explicit RecordingResult(Reply* reply) : reply_(reply) {}

 protected:
  void SuccessInternal(const flutter::EncodableValue* value) override {
    ++reply_->replies;
    reply_->success = true;
    reply_->has_value = value != nullptr && !value->IsNull();
    if (value != nullptr) reply_->value = *value;
  }
  void ErrorInternal(const std::string& code, const std::string&,
                     const flutter::EncodableValue* details) override {
    ++reply_->replies;
    reply_->error = code;
    if (details != nullptr) reply_->details = *details;
  }
  void NotImplementedInternal() override {
    ++reply_->replies;
    reply_->not_implemented = true;
  }

 private:
  Reply* reply_;
};

struct Answer {
  bool answered = false;        // false: forward with start_if_missing = true
  bool result_kept = false;     // the caller still holds the result to forward
  RecordingResult::Reply reply;
};
Answer Ask(NetworkProtectionOwner channel, const char* method) {
  Answer answer;
  std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result =
      std::make_unique<RecordingResult>(&answer.reply);
  answer.answered = fuzevpn_runtime_absent::AnswerWithoutRuntime(channel, method, &result);
  answer.result_kept = result != nullptr;
  return answer;
}

// One call through the whole routing of a status-or-stop channel method.
struct Routed {
  RecordingResult::Reply reply;
  std::vector<Forward> forwards;
};
Routed Route(const char* scope, NetworkProtectionOwner channel, const char* method) {
  Routed routed;
  forwards.clear();
  const flutter::MethodCall<flutter::EncodableValue> call(method, nullptr);
  fuzevpn_runtime_absent::RouteStatusOrStop(scope, channel, call,
                                            std::make_unique<RecordingResult>(&routed.reply));
  routed.forwards = forwards;
  // A forwarded call is completed later by the runtime, never by the router.
  forwarded_result.reset();
  return routed;
}
bool ForwardedOnce(const Routed& routed, const char* scope, const char* method, bool start_if_missing) {
  return routed.reply.replies == 0 && routed.forwards.size() == 1 &&
         routed.forwards[0].scope == scope && routed.forwards[0].method == method &&
         routed.forwards[0].start_if_missing == start_if_missing;
}
Answer Local(const Routed& routed) {
  Answer answer;
  answer.answered = routed.forwards.empty();
  answer.reply = routed.reply;
  return answer;
}

const bool* Bool(const flutter::EncodableValue& value) { return std::get_if<bool>(&value); }
bool IsBool(const Answer& answer, bool expected) {
  const bool* value = Bool(answer.reply.value);
  return answer.answered && answer.reply.replies == 1 && answer.reply.success &&
         value != nullptr && *value == expected;
}
bool IsBareSuccess(const Answer& answer) {
  return answer.answered && answer.reply.replies == 1 && answer.reply.success &&
         !answer.reply.has_value;
}
bool IsError(const Answer& answer, const char* code) {
  return answer.answered && answer.reply.replies == 1 && !answer.reply.success &&
         answer.reply.error == code;
}
bool IsForwardedWithStart(const Answer& answer) {
  return !answer.answered && answer.result_kept && answer.reply.replies == 0;
}
// The exact method-channel contract of the local status map.
bool IsStatus(const Answer& answer, bool active, bool kill_switch, const char* phase,
              bool owned_by_another_user) {
  if (!answer.answered || answer.reply.replies != 1 || !answer.reply.success)
    return false;
  const auto* map = std::get_if<flutter::EncodableMap>(&answer.reply.value);
  if (map == nullptr || map->size() != 5) return false;
  std::set<std::string> keys;
  for (const auto& [key, value] : *map) {
    (void)value;
    const auto* name = std::get_if<std::string>(&key);
    if (name == nullptr) return false;
    keys.insert(*name);
  }
  if (keys != std::set<std::string>{"active", "killSwitch", "phase", "ownedByAnotherUser", "runtimeAbsent"})
    return false;
  // References into the recorded map, which outlives every pointer below.
  const auto field = [&](const char* name) -> const flutter::EncodableValue& {
    return map->at(flutter::EncodableValue(name));
  };
  const bool* active_value = Bool(field("active"));
  const bool* kill_switch_value = Bool(field("killSwitch"));
  const bool* owned_value = Bool(field("ownedByAnotherUser"));
  const bool* absent_value = Bool(field("runtimeAbsent"));
  const auto* phase_value = std::get_if<std::string>(&field("phase"));
  return active_value && kill_switch_value && owned_value && absent_value && phase_value &&
         *active_value == active && *kill_switch_value == kill_switch && *phase_value == phase &&
         *owned_value == owned_by_another_user && *absent_value;
}
}  // namespace fixture

// In-memory doubles for the three things the glue asks Windows.
PersistedNetworkProtection ReadPersistedNetworkProtection(
    NetworkProtectionOwner* owner, bool* kill_switch, std::string* user) {
  ++fixture::persisted_reads;
  if (fixture::persisted == PersistedNetworkProtection::unknown) SetLastError(fixture::persisted_error);
  if (fixture::persisted != PersistedNetworkProtection::present) return fixture::persisted;
  *owner = fixture::persisted_owner;
  *kill_switch = fixture::persisted_kill_switch;
  if (user) *user = fixture::persisted_account;
  return fixture::persisted;
}
std::string ProtectedStoreUserId() {
  ++fixture::account_reads;
  if (fixture::current_account.empty()) SetLastError(ERROR_NO_TOKEN);
  return fixture::current_account;
}
// The process-local status of a UI that may not manage WFP is always
// "inactive": answering from it is exactly the defect being fixed.
NetworkProtectionStatus GetNetworkProtectionStatus(NetworkProtectionOwner) {
  ++fixture::local_status_reads;
  return {};
}
void CompleteRuntimeStatusFailure(
    flutter::MethodResult<flutter::EncodableValue>* result, bool detection_failed) {
  fixture::status_failure_error = GetLastError();
  ++fixture::status_failures;
  fixture::status_failure_was_detection = detection_failed;
  result->Error(detection_failed ? "runtime_detection_failed" : "runtime_status_unavailable",
                "Windows could not read the VPN runtime status.");
}
void CompleteRuntimeStatusFailure(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result, bool detection_failed) {
  CompleteRuntimeStatusFailure(result.get(), detection_failed);
}
std::optional<bool> PrivilegedRuntimePresence(bool* detection_failed) {
  ++fixture::presence_queries;
  if (detection_failed != nullptr) *detection_failed = fixture::runtime_detection_failed;
  if (!fixture::runtime_present.has_value()) SetLastError(ERROR_NOT_READY);
  return fixture::runtime_present;
}
void ForwardPrivilegedCall(
    const std::string& scope, const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result, bool start_if_missing) {
  fixture::forwards.push_back({scope, call.method_name(), start_if_missing});
  fixture::forwarded_result = std::move(result);
}

namespace {
using fixture::Arm;
using fixture::Ask;
using fixture::Check;
using fuzevpn_runtime_absent::Decide;
using fuzevpn_runtime_absent::Decision;
using fuzevpn_runtime_absent::Evidence;
using fuzevpn_runtime_absent::Method;
using fuzevpn_runtime_absent::NeedsPersistedProtection;
using fuzevpn_runtime_absent::Reply;
using Persisted = PersistedNetworkProtection;
using Owner = NetworkProtectionOwner;
using Phase = NetworkProtectionStatus::Phase;

constexpr Method kMethods[] = {Method::is_connected, Method::is_network_protection_active,
                               Method::network_protection_status, Method::reconnect,
                               Method::disconnect, Method::suspend_for_migration};
constexpr Owner kOwners[] = {Owner::wire_guard, Owner::open_vpn};
constexpr Persisted kStates[] = {Persisted::absent, Persisted::present, Persisted::unknown};

// The policy stays a constant expression: no Windows call can hide in it. Its
// value is checked at run time below, with every other decision.
constexpr Decision kConstantDecision = Decide(Method::is_connected, Owner::open_vpn, Evidence{});

bool SameDecision(const Decision& left, const Decision& right) {
  return left.reply == right.reply && left.value == right.value &&
         left.status.active == right.status.active &&
         left.status.kill_switch == right.status.kill_switch &&
         left.status.phase == right.status.phase &&
         left.owned_by_another_user == right.owned_by_another_user;
}

void CheckPolicy() {
  unsigned cases = 0, starts = 0;
  for (const Method method : kMethods) {
    const bool reads = method == Method::is_network_protection_active ||
                       method == Method::network_protection_status || method == Method::disconnect;
    Check(NeedsPersistedProtection(method) == reads,
          "only protection status and Disconnect may cost a BFE query");
    for (const Owner channel : kOwners) {
      for (const Persisted state : kStates) {
        // Fields of an absent or unreadable intent carry no meaning: every
        // combination of them must give the answer of the plain state.
        const Decision plain = Decide(method, channel, Evidence{state});
        for (const Owner owner : kOwners) {
          for (const bool kill_switch : {false, true}) {
            for (const bool same_user : {false, true}) {
              ++cases;
              const Evidence evidence{state, owner, kill_switch, same_user};
              const Decision decision = Decide(method, channel, evidence);
              const bool present = state == Persisted::present;
              const bool owned = present && owner == channel;
              if (!present) {
                Check(SameDecision(decision, plain),
                      "owner, kill switch and account of an absent or unreadable intent are ignored");
              }
              if (decision.reply == Reply::start_runtime) {
                ++starts;
                Check(method == Method::disconnect,
                      "only an explicit Disconnect may start a runtime");
              }
              Check(decision.reply == Reply::status || (!decision.status.active &&
                    !decision.status.kill_switch && decision.status.phase == Phase::inactive &&
                    !decision.owned_by_another_user),
                    "a non-status reply carries no status payload");
              Check(decision.reply == Reply::boolean || !decision.value,
                    "a non-boolean reply carries no boolean payload");
              switch (method) {
                case Method::is_connected:
                  Check(decision.reply == Reply::boolean && !decision.value,
                        "no runtime process: no tunnel is connected, whatever BFE holds");
                  break;
                case Method::reconnect:
                  Check(decision.reply == Reply::boolean && !decision.value,
                        "no runtime process: nothing to reconnect and nothing is started");
                  break;
                case Method::suspend_for_migration:
                  Check(decision.reply == Reply::success,
                        "a migration suspend keeps the policy and never starts a runtime");
                  break;
                case Method::is_network_protection_active:
                  if (state == Persisted::unknown) {
                    Check(decision.reply == Reply::status_unavailable,
                          "an unreadable intent is never reported as protected or unprotected");
                  } else {
                    Check(decision.reply == Reply::boolean && decision.value == owned,
                          "protection is active exactly for the protocol that armed the persisted policy");
                  }
                  break;
                case Method::network_protection_status:
                  if (state == Persisted::unknown) {
                    Check(decision.reply == Reply::status_unavailable,
                          "an unreadable intent has no status map");
                    break;
                  }
                  Check(decision.reply == Reply::status, "a readable state has a status map");
                  Check(decision.status.active == owned,
                        "status is active exactly for the protocol that armed the persisted policy");
                  Check(decision.status.phase == (owned ? Phase::prepared : Phase::inactive),
                        "a persisted policy is the prepared baseline, never a live tunnel");
                  Check(decision.status.kill_switch == (owned && kill_switch),
                        "the kill-switch flag is the persisted one and only for the owner protocol");
                  Check(decision.owned_by_another_user == (present && !same_user),
                        "both protocols report a policy armed by another Windows account");
                  break;
                case Method::disconnect:
                  if (state == Persisted::absent) {
                    Check(decision.reply == Reply::success,
                          "with no persisted policy a Disconnect stays a local success");
                  } else if (present && !same_user) {
                    Check(decision.reply == Reply::owned_by_another_user,
                          "another account's policy is refused without starting or elevating a runtime");
                  } else {
                    Check(decision.reply == Reply::start_runtime,
                          "a present or unreadable policy forwards Disconnect to a started runtime");
                  }
                  break;
              }
            }
          }
        }
      }
    }
  }
  // 6 methods x 2 channels x 3 states x 2 owners x 2 flags x 2 accounts.
  Check(cases == 288, "the whole decision space was enumerated");
  // Disconnect only: unknown (2 channels x 8) and present for the same
  // account (2 channels x 2 owners x 2 flags).
  Check(starts == 24, "the runtime is started for exactly the expected Disconnect cases");

  Check(SameDecision(kConstantDecision, Decide(Method::is_connected, Owner::open_vpn, Evidence{})),
        "the compile-time decision is the run-time decision");

  // The answers the Dart side relies on, spelled out once without any loop.
  const Evidence openvpn_kill_switch{Persisted::present, Owner::open_vpn, true, true};
  const Decision blocked = Decide(Method::network_protection_status, Owner::open_vpn, openvpn_kill_switch);
  Check(blocked.reply == Reply::status && blocked.status.active && blocked.status.kill_switch &&
        blocked.status.phase == Phase::prepared && !blocked.owned_by_another_user,
        "a persisted OpenVPN kill switch reads active, kill switch on, prepared");
  Check(Decide(Method::disconnect, Owner::open_vpn, openvpn_kill_switch).reply == Reply::start_runtime,
        "its owner's Disconnect starts the runtime");
  Check(Decide(Method::disconnect, Owner::open_vpn, Evidence{Persisted::absent}).reply == Reply::success,
        "Disconnect with nothing persisted is a local success");
  Check(Decide(Method::disconnect, Owner::wire_guard, Evidence{Persisted::unknown}).reply ==
            Reply::start_runtime, "Disconnect with an unreadable policy starts the runtime");
  Check(Decide(Method::network_protection_status, Owner::wire_guard, Evidence{Persisted::unknown}).reply ==
            Reply::status_unavailable, "a status read with an unreadable policy is unavailable");
  Check(Decide(Method::is_network_protection_active, Owner::open_vpn, Evidence{Persisted::unknown}).reply ==
            Reply::status_unavailable, "an activity read with an unreadable policy is unavailable");

  // At most one protocol owns the persisted policy.
  for (const Owner owner : kOwners) {
    const Evidence evidence{Persisted::present, owner, true, true};
    const bool wireguard = Decide(Method::is_network_protection_active, Owner::wire_guard, evidence).value;
    const bool openvpn = Decide(Method::is_network_protection_active, Owner::open_vpn, evidence).value;
    Check(wireguard != openvpn && wireguard == (owner == Owner::wire_guard),
          "exactly the owner protocol reports the persisted policy");
  }
  // A Disconnect addressed to the other protocol still starts the runtime:
  // it settles the real state, and the owner's Disconnect then releases it.
  Check(Decide(Method::disconnect, Owner::open_vpn,
               Evidence{Persisted::present, Owner::wire_guard, true, true}).reply == Reply::start_runtime,
        "Disconnect is forwarded for a present policy whichever protocol armed it");
}

void CheckMethodNames() {
  using fuzevpn_runtime_absent::MethodNamed;
  Check(MethodNamed("isConnected") == Method::is_connected &&
        MethodNamed("isNetworkProtectionActive") == Method::is_network_protection_active &&
        MethodNamed("networkProtectionStatus") == Method::network_protection_status &&
        MethodNamed("reconnect") == Method::reconnect &&
        MethodNamed("disconnect") == Method::disconnect &&
        MethodNamed("suspendForMigration") == Method::suspend_for_migration,
        "channel method names map to their decisions");
  for (const char* other : {"connect", "importAndConnect", "prepareConnection", "Disconnect",
                            "disconnect ", "", "resetIdentity", "deleteProfile"}) {
    Check(!MethodNamed(other).has_value(), "no other method has a runtime-absent answer");
  }
}

void CheckStatusReads() {
  // RC7: the kill switch a previous runtime persisted is reported, with its
  // flag, for the protocol that armed it, and marked as held by no process.
  Arm(Persisted::present, Owner::open_vpn, true);
  Check(fixture::IsStatus(Ask(Owner::open_vpn, "networkProtectionStatus"), true, true, "prepared", false),
        "OpenVPN status reports its persisted kill switch as active/prepared with runtimeAbsent");
  Check(fixture::persisted_reads == 1 && fixture::local_status_reads == 0,
        "the status comes from one BFE read, never from the UI's own empty policy");
  Check(fixture::IsStatus(Ask(Owner::wire_guard, "networkProtectionStatus"), false, false, "inactive", false),
        "the other protocol reports inactive, still marked runtimeAbsent");
  Check(fixture::IsBool(Ask(Owner::open_vpn, "isNetworkProtectionActive"), true) &&
        fixture::IsBool(Ask(Owner::wire_guard, "isNetworkProtectionActive"), false),
        "isNetworkProtectionActive is true only for the owner protocol");

  Arm(Persisted::present, Owner::wire_guard, false);
  Check(fixture::IsStatus(Ask(Owner::wire_guard, "networkProtectionStatus"), true, false, "prepared", false),
        "a selective WireGuard policy is active/prepared with the kill switch reported off");
  Check(fixture::IsStatus(Ask(Owner::open_vpn, "networkProtectionStatus"), false, false, "inactive", false),
        "OpenVPN reports inactive for a WireGuard policy");

  Arm(Persisted::absent);
  for (const Owner channel : kOwners) {
    Check(fixture::IsStatus(Ask(channel, "networkProtectionStatus"), false, false, "inactive", false),
          "a confirmed absence is inactive and marked runtimeAbsent");
    Check(fixture::IsBool(Ask(channel, "isNetworkProtectionActive"), false),
          "a confirmed absence is not protected");
  }
  Check(fixture::account_reads == 0, "the account is not queried when nothing is persisted");

  // Unknown: the existing runtime_status_unavailable error with the Windows
  // status of the failed read, never a guessed map or boolean.
  for (const DWORD failed : {DWORD(ERROR_ACCESS_DENIED), DWORD(FWP_E_TIMEOUT), DWORD(ERROR_INVALID_DATA)}) {
    for (const Owner channel : kOwners) {
      for (const char* method : {"networkProtectionStatus", "isNetworkProtectionActive"}) {
        Arm(Persisted::unknown, Owner::open_vpn, true);
        fixture::persisted_error = failed;
        Check(fixture::IsError(Ask(channel, method), "runtime_status_unavailable") &&
              fixture::status_failures == 1 && fixture::status_failure_error == failed &&
              !fixture::status_failure_was_detection,
              "an unreadable policy fails the status read with the read's Windows status");
      }
    }
  }

  // The policy belongs to another Windows account: reported, never hidden.
  Arm(Persisted::present, Owner::open_vpn, true, fixture::kOtherAccount);
  Check(fixture::IsStatus(Ask(Owner::open_vpn, "networkProtectionStatus"), true, true, "prepared", true) &&
        fixture::IsStatus(Ask(Owner::wire_guard, "networkProtectionStatus"), false, false, "inactive", true),
        "both protocols flag a policy armed by another Windows account");

  // The UI's own account cannot be established: neither owner nor stranger.
  Arm(Persisted::present, Owner::open_vpn, true);
  fixture::current_account.clear();
  Check(fixture::IsError(Ask(Owner::open_vpn, "networkProtectionStatus"), "runtime_status_unavailable") &&
        fixture::status_failure_error == ERROR_NO_TOKEN,
        "an unknown UI account makes the policy unknown instead of claiming ownership");

  // isConnected, reconnect and suspendForMigration never touch BFE.
  for (const Persisted state : kStates) {
    for (const Owner channel : kOwners) {
      Arm(state, Owner::open_vpn, true);
      Check(fixture::IsBool(Ask(channel, "isConnected"), false),
            "isConnected stays false while no runtime exists");
      Check(fixture::IsBool(Ask(channel, "reconnect"), false),
            "reconnect stays a local false and starts nothing");
      Check(fixture::IsBareSuccess(Ask(channel, "suspendForMigration")),
            "suspendForMigration stays a local success");
      Check(fixture::persisted_reads == 0 && fixture::account_reads == 0 && fixture::status_failures == 0,
            "answers that do not depend on BFE open no WFP session");
    }
  }
}

void CheckDisconnect() {
  for (const Owner channel : kOwners) {
    Arm(Persisted::absent);
    Check(fixture::IsBareSuccess(Ask(channel, "disconnect")) && fixture::persisted_reads == 1,
          "with no persisted policy Disconnect is a local success after one read");

    for (const Owner owner : kOwners) {
      for (const bool kill_switch : {false, true}) {
        Arm(Persisted::present, owner, kill_switch);
        Check(fixture::IsForwardedWithStart(Ask(channel, "disconnect")) && fixture::status_failures == 0,
              "a persisted policy forwards Disconnect to a started runtime with the result untouched");
        Arm(Persisted::present, owner, kill_switch, fixture::kOtherAccount);
        Check(fixture::IsError(Ask(channel, "disconnect"), "runtime_owned_by_another_user"),
              "another account's policy is refused locally, without an elevation prompt");
      }
    }

    Arm(Persisted::unknown);
    Check(fixture::IsForwardedWithStart(Ask(channel, "disconnect")) && fixture::status_failures == 0,
          "an unreadable policy forwards Disconnect: a failed read is never a successful Disconnect");

    Arm(Persisted::present, Owner::open_vpn, true);
    fixture::current_account.clear();
    Check(fixture::IsForwardedWithStart(Ask(channel, "disconnect")),
          "with an unknown UI account the runtime decides who may disconnect");
  }
}

void CheckGlueInvariants() {
  // Whatever BFE or the account query returns, nothing but an explicit
  // Disconnect can leave the call unanswered (i.e. start a runtime), and an
  // answered call is completed exactly once.
  const char* const methods[] = {"isConnected", "isNetworkProtectionActive", "networkProtectionStatus",
                                 "reconnect", "disconnect", "suspendForMigration", "connect",
                                 "importAndConnect", "prepareConnection", "deleteProfile", ""};
  for (const char* method : methods) {
    for (const Owner channel : kOwners) {
      for (const Persisted state : kStates) {
        for (const Owner owner : kOwners) {
          for (const char* account : {fixture::kAccount, fixture::kOtherAccount, ""}) {
            Arm(state, owner, true);
            fixture::current_account = account;
            const auto answer = Ask(channel, method);
            Check(answer.answered || std::string(method) == "disconnect",
                  "only Disconnect is ever forwarded to a started runtime");
            Check(answer.answered ? answer.reply.replies == 1
                                  : (answer.result_kept && answer.reply.replies == 0),
                  "a call is either completed exactly once or handed back untouched");
            Check(!answer.reply.not_implemented, "the local answer is never NotImplemented");
          }
        }
      }
    }
  }
  // A method without a runtime-absent answer fails closed, without a read.
  Arm(Persisted::absent);
  Check(fixture::IsError(Ask(Owner::open_vpn, "importAndConnect"), "runtime_status_unavailable") &&
        fixture::persisted_reads == 0 && fixture::status_failure_error == ERROR_NOT_SUPPORTED,
        "an unexpected method is an unavailable status, never a guessed success or a started runtime");
}
// The complete routing the OpenVPN channel uses for its six status-or-stop
// methods and the WireGuard channel for its two protection reads.
void CheckRouting() {
  using fixture::ForwardedOnce;
  using fixture::Local;
  using fixture::Route;
  struct Channel {
    const char* scope;
    Owner owner;
  };
  const Channel channels[] = {{"openvpn", Owner::open_vpn}, {"wireguard", Owner::wire_guard}};
  const char* const methods[] = {"isConnected", "isNetworkProtectionActive", "networkProtectionStatus",
                                 "reconnect", "disconnect", "suspendForMigration"};
  for (const Channel& channel : channels) {
    for (const char* method : methods) {
      for (const Persisted state : kStates) {
        // A runtime exists: it is asked, passively, and nothing is read here,
        // even when a policy is persisted.
        Arm(state, channel.owner, true);
        fixture::runtime_present = true;
        Check(ForwardedOnce(Route(channel.scope, channel.owner, method), channel.scope, method, false) &&
              fixture::persisted_reads == 0 && fixture::presence_queries == 1,
              "with a runtime every status-or-stop call is forwarded without starting anything");

        // Windows cannot tell whether a runtime exists: a failure, not a guess.
        for (const bool detection : {false, true}) {
          Arm(state, channel.owner, true);
          fixture::runtime_present = std::nullopt;
          fixture::runtime_detection_failed = detection;
          const auto unknown = Route(channel.scope, channel.owner, method);
          Check(unknown.forwards.empty() && unknown.reply.replies == 1 &&
                unknown.reply.error == (detection ? "runtime_detection_failed" : "runtime_status_unavailable") &&
                fixture::status_failure_was_detection == detection &&
                fixture::status_failure_error == ERROR_NOT_READY && fixture::persisted_reads == 0,
                "an unknown runtime presence is reported as such and nothing is read or forwarded");
        }

        // No runtime: answered here, or forwarded with a start for Disconnect.
        Arm(state, channel.owner, true);
        const auto routed = Route(channel.scope, channel.owner, method);
        const bool stop = std::string(method) == "disconnect";
        const bool starts = stop && state != Persisted::absent;
        if (starts) {
          Check(ForwardedOnce(routed, channel.scope, "disconnect", true),
                "Disconnect against a persisted or unreadable policy is forwarded with start_if_missing");
        } else {
          Check(routed.forwards.empty() && routed.reply.replies == 1,
                "every other call without a runtime is answered locally, exactly once");
        }
      }
    }

    // The local answers reach the caller unchanged through the router.
    Arm(Persisted::present, channel.owner, true);
    Check(fixture::IsStatus(Local(Route(channel.scope, channel.owner, "networkProtectionStatus")),
                            true, true, "prepared", false),
          "the routed status is the persisted policy marked runtimeAbsent");
    Check(fixture::IsBool(Local(Route(channel.scope, channel.owner, "isNetworkProtectionActive")), true) &&
          fixture::IsBool(Local(Route(channel.scope, channel.owner, "isConnected")), false) &&
          fixture::IsBool(Local(Route(channel.scope, channel.owner, "reconnect")), false) &&
          fixture::IsBareSuccess(Local(Route(channel.scope, channel.owner, "suspendForMigration"))),
          "the routed local answers keep their values");
    Arm(Persisted::present, channel.owner, true, fixture::kOtherAccount);
    Check(fixture::IsError(Local(Route(channel.scope, channel.owner, "disconnect")),
                           "runtime_owned_by_another_user"),
          "another account's Disconnect is refused through the router without a forward");
    Arm(Persisted::absent);
    Check(fixture::IsBareSuccess(Local(Route(channel.scope, channel.owner, "disconnect"))),
          "Disconnect with nothing persisted is a routed local success");
    Arm(Persisted::unknown);
    Check(fixture::IsError(Local(Route(channel.scope, channel.owner, "networkProtectionStatus")),
                           "runtime_status_unavailable") && !fixture::status_failure_was_detection,
          "an unreadable policy is a routed status failure");
  }
}
}  // namespace

int main() {
  CheckPolicy();
  CheckMethodNames();
  CheckStatusReads();
  CheckDisconnect();
  CheckGlueInvariants();
  CheckRouting();
  if (fixture::failures != 0) return EXIT_FAILURE;
  std::cout << "Runtime-absent channel checks passed (no WFP, service or elevation)\n";
  return EXIT_SUCCESS;
}
