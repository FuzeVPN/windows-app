// SPDX-License-Identifier: MPL-2.0
#ifndef TESTS_OPENVPN_FAILURE_CLASSIFICATION_TEST_H_
#define TESTS_OPENVPN_FAILURE_CLASSIFICATION_TEST_H_

#include "openvpn_attempt_failure.h"
#include <stdexcept>
#include <string_view>

inline void OpenVpnFailureClassificationTests() {
  using openvpn::Win::DiagnosticAction;
  const auto matches = [](const char* actual, const char* expected) {
    return actual && std::string_view(actual) == expected;
  };
  const auto check = [](bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
  };
  check(matches(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_transport_started",
      DiagnosticAction::command_dns_add, true, 0), "openvpn_dns_configuration_failed"),
      "DNS setup failure remains visible after retry overwrites transport progress");
  check(matches(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_adapter_opened",
      DiagnosticAction::route_create, true, 0), "openvpn_network_configuration_failed"),
      "route setup failure is distinct from failure to create a DCO peer");
  for (unsigned bit : {8U, 16U}) {
    check(matches(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_transport_started",
        DiagnosticAction::none, false, bit), "openvpn_dns_configuration_failed"),
        "failed DNS or NRPT postcondition is reported as local DNS configuration");
  }
  check(matches(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_transport_started",
      DiagnosticAction::none, true, 0), "openvpn_network_configuration_failed"),
      "failed command with no more specific action remains a local network error");
  check(matches(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_transport_started",
      DiagnosticAction::none, false, 4), "openvpn_network_configuration_failed"),
      "missing expected route is reported as local network configuration");
  check(matches(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_transport_started",
      DiagnosticAction::none, false, 0), "openvpn_no_server_response"),
      "transport timeout without local failure retains its existing classification");
  check(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_certificate_validation_failed",
      DiagnosticAction::none, false, 0) == nullptr,
      "specific certificate error survives when no local configuration error was observed");
  check(fuzevpn::ClassifyOpenVpnAttemptFailure("openvpn_tls_handshake_failed",
      DiagnosticAction::none, false, 0) == nullptr,
      "specific TLS error is not changed into a generic timeout");
}
#endif
