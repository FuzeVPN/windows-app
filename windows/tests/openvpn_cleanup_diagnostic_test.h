// SPDX-License-Identifier: MPL-2.0
#ifndef TESTS_OPENVPN_CLEANUP_DIAGNOSTIC_TEST_H_
#define TESTS_OPENVPN_CLEANUP_DIAGNOSTIC_TEST_H_

#include <openvpn/win/command_context.hpp>
#include <stdexcept>

// Exercise the same recording branch used by Win::call. No process, network,
// service or registry operation is performed by these tests.
inline void OpenVpnCleanupDiagnosticTests() {
  using namespace openvpn::Win;
  const auto check = [](bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
  };
  CommandControl control;
  ScopedCommandControl scope(&control);
  check(control.address_expected.load() == 0 && control.address_matched.load() == 0 &&
      control.address_tentative.load() == 0 && control.address_duplicate.load() == 0,
      "address diagnostic counters start empty");

  RecordNetworkCommandFailure(DiagnosticAction::command_route_add, 1, false);
  check(!control.command_failed.load() &&
      control.first_failed_action.load() == DiagnosticAction::none &&
      control.cleanup_failure_count.load() == 0,
      "a reconciled route command does not become a setup or cleanup failure");

  {
    ScopedCommandCleanup cleanup;
    const auto deadline = cleanup_deadline;
    RecordNetworkCommandFailure(DiagnosticAction::command_dns_delete, ERROR_TIMEOUT);
    check(!control.command_failed.load() &&
        control.first_failed_action.load() == DiagnosticAction::none &&
        control.first_failed_code.load() == ERROR_SUCCESS,
        "failed cleanup does not poison connection evidence");
    check(control.last_cleanup_action.load() == DiagnosticAction::command_dns_delete &&
        control.last_cleanup_code.load() == ERROR_TIMEOUT &&
        control.cleanup_failure_count.load() == 1,
        "cleanup exposes the fixed operation and numeric failure");
    {
      ScopedCommandCleanup nested;
      check(cleanup_deadline == deadline,
          "nested cleanup retains the shared bounded deadline");
      RecordCommandFailure(DiagnosticAction::route_remove, ERROR_ACCESS_DENIED);
    }
    check(control.last_cleanup_action.load() == DiagnosticAction::route_remove &&
        control.last_cleanup_code.load() == ERROR_ACCESS_DENIED &&
        control.cleanup_failure_count.load() == 2,
        "typed cleanup failures update the latest cause and count");
    RecordNetworkCommandFailure(DiagnosticAction::command_other, 1, false);
    check(control.cleanup_failure_count.load() == 2 &&
        control.last_cleanup_action.load() == DiagnosticAction::route_remove,
        "suppressed command errors do not pollute cleanup diagnostics");
    control.cleanup_failure_count.store(kMaximumCleanupFailureCount - 1);
    RecordCommandFailure(DiagnosticAction::dns_notify, ERROR_ACCESS_DENIED);
    RecordCommandFailure(DiagnosticAction::command_dns_flush, ERROR_TIMEOUT);
    check(control.cleanup_failure_count.load() == kMaximumCleanupFailureCount &&
        control.last_cleanup_action.load() == DiagnosticAction::command_dns_flush,
        "retry diagnostics saturate without losing the latest failure");
  }

  RecordNetworkCommandFailure(DiagnosticAction::command_dns_add, 1);
  RecordNetworkCommandFailure(DiagnosticAction::command_address_set, ERROR_INVALID_PARAMETER);
  check(control.command_failed.load() &&
      control.first_failed_action.load() == DiagnosticAction::command_dns_add &&
      control.first_failed_code.load() == 1,
      "setup still retains its first command failure");
  {
    ScopedCommandCleanup cleanup;
    RecordCommandFailure(DiagnosticAction::route_remove, ERROR_NOT_FOUND);
  }
  check(control.first_failed_action.load() == DiagnosticAction::command_dns_add &&
      control.first_failed_code.load() == 1,
      "later cleanup preserves the original setup cause");
}

#endif
