// SPDX-License-Identifier: MPL-2.0
#ifndef TESTS_OPENVPN_FAILURE_CLASSIFICATION_TEST_H_
#define TESTS_OPENVPN_FAILURE_CLASSIFICATION_TEST_H_

#include "openvpn_attempt_failure.h"
#include "openvpn_diagnostic_state.h"
#include <openvpn/error/error.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

inline void OpenVpnCoreEventClassificationTests() {
  const auto check = [](bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
  };
  const auto classify = [&](std::string_view name, std::string_view detail,
                            std::string_view expected, const char* message) {
    const std::string_view actual = fuzevpn::ClassifyOpenVpnCoreEvent(name, detail);
    check(actual == expected, message);
    // Every produced code reaches the diagnostic vocabulary unchanged, except
    // the Dart-only rejection code, which support reports know as
    // certificate_invalid.
    const std::string_view diagnostic = fuzevpn::SafeOpenVpnFailure(actual);
    check(diagnostic == (actual == "openvpn_client_certificate_rejected"
        ? std::string_view("certificate_invalid") : actual), message);
  };
  // OpenSSLException text that Core attaches to a received alert: the alert's
  // description is appended in brackets. A locally detected failure has none.
  const std::string read = "OpenSSLContext::SSL::read_cleartext: BIO_read failed, cap=2048 status=-1: ";
  classify("TLS_ALERT_CERTIFICATE_EXPIRED", "", "openvpn_certificate_expired",
      "server alert certificate_expired names an expired certificate in our chain");
  for (const char* rejected : {"TLS_ALERT_BAD_CERTIFICATE", "TLS_ALERT_CERTIFICATE_REQUIRED",
      "TLS_ALERT_CERTIFICATE_REVOKED", "TLS_ALERT_UNKNOWN_CA", "TLS_ALERT_UNSUPPORTED_CERTIFICATE"}) {
    classify(rejected, "", "openvpn_client_certificate_rejected",
        "server certificate alerts report a rejected client certificate");
  }
  classify("TLS_ALERT_MISC", read +
      "error:0A000416:SSL routines::sslv3 alert certificate unknown[certificate unknown]",
      "openvpn_client_certificate_rejected", "received certificate_unknown is a client certificate rejection");
  classify("TLS_ALERT_MISC", read + "error:0A000419:SSL routines::tlsv1 alert access denied[access denied]",
      "openvpn_client_certificate_rejected", "received access_denied is a client certificate rejection");
  classify("TLS_ALERT_MISC", read + "error:0A000433:SSL routines::tlsv1 alert decrypt error[decrypt error]",
      "openvpn_tls_handshake_failed", "ambiguous received alert stays a generic TLS failure");
  classify("TLS_ALERT_MISC", read + "error:0A000438:SSL routines::tlsv1 alert internal error[internal error]",
      "openvpn_tls_handshake_failed", "server internal_error is not attributed to the certificate");
  classify("TLS_ALERT_MISC", "", "openvpn_tls_handshake_failed",
      "alert without a recognised description stays a generic TLS failure");
  classify("TLS_ALERT_HANDSHAKE_FAILURE", "", "openvpn_tls_handshake_failed",
      "handshake_failure has non-certificate causes and stays generic");
  classify("TLS_ALERT_PROTOCOL_VERSION", "", "openvpn_tls_handshake_failed",
      "protocol version alert stays a TLS failure");
  classify("TLS_VERSION_MIN", "", "openvpn_tls_handshake_failed", "local TLS version floor stays a TLS failure");
  classify("TLS_SIGALG_DISALLOWED_OR_UNSUPPORTED", "", "openvpn_tls_handshake_failed",
      "signature algorithm mismatch stays a TLS failure");
  classify("AUTH_FAILED", "", "openvpn_tls_handshake_failed",
      "server AUTH_FAILED control message is not attributed to the certificate");
  // The server certificate is verified locally: OpenSSL reports
  // certificate_verify_failed and sends the alert itself.
  classify("CERT_VERIFY_FAIL", "", "openvpn_certificate_validation_failed",
      "local server certificate verification failure keeps its code");
  classify("CERT_VERIFY_FAIL", read + "error:0A000086:SSL routines::certificate verify failed",
      "openvpn_certificate_validation_failed", "OpenSSL local verify failure keeps its code");
  classify("CERT_VERIFY_FAIL", read + "error:0A000086:SSL routines::certificate verify failed"
      " [certificate has expired] [certificate expired]",
      "openvpn_certificate_validation_failed", "an expired SERVER certificate is never reported as ours");
  // Terminal status names come from Error::name and must classify identically.
  using openvpn::Error::Type;
  for (const auto& [code, expected] : {
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_CERTIFICATE_EXPIRED, "openvpn_certificate_expired"},
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_CERTIFICATE_REQUIRED, "openvpn_client_certificate_rejected"},
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_CERTIFICATE_REVOKED, "openvpn_client_certificate_rejected"},
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_BAD_CERTIFICATE, "openvpn_client_certificate_rejected"},
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_UNKNOWN_CA, "openvpn_client_certificate_rejected"},
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_UNSUPPORTED_CERTIFICATE, "openvpn_client_certificate_rejected"},
      std::pair<Type, std::string_view>{openvpn::Error::CERT_VERIFY_FAIL, "openvpn_certificate_validation_failed"},
      std::pair<Type, std::string_view>{openvpn::Error::TLS_ALERT_HANDSHAKE_FAILURE, "openvpn_tls_handshake_failed"}}) {
    classify(openvpn::Error::name(code), "", expected, "Core status names match event names");
  }
  // Existing detail and name classifications are unchanged.
  classify("CLIENT_SETUP", "dco_compatibility: option", "openvpn_dco_profile_incompatible",
      "DCO incompatibility detail retained");
  classify("CLIENT_SETUP", "cannot acquire TAP handle", "openvpn_adapter_failed", "adapter detail retained");
  classify("CLIENT_SETUP", "tls-crypt-v2 key", "openvpn_profile_crypto_failed", "tls-crypt detail retained");
  classify("CLIENT_SETUP", "private key does not match", "openvpn_local_identity_mismatch",
      "local key mismatch detail retained");
  classify("TUN_SETUP_FAILED", "", "openvpn_adapter_failed", "tunnel setup failure retained");
  classify("ERR_INVALID_CONFIG", "", "openvpn_client_config_failed", "configuration failure retained");
  classify("ERR_INVALID_OPTION_CRYPTO", "", "openvpn_profile_crypto_failed", "crypto option failure retained");
  classify("TRANSPORT_ERROR", "", "openvpn_transport_failed", "transport failure retained");
  classify("", "client_connect_unhandled_exception", "openvpn_connection_failed",
      "unnamed Core status stays generic");

  // The attempt snapshot written to native_diagnostic.log reaches support
  // reports, whose closed vocabulary has no openvpn_client_certificate_rejected.
  fuzevpn::OpenVpnDiagnosticState state;
  state.Failure("openvpn_certificate_expired");
  state.Failure("openvpn_client_certificate_rejected");
  const auto snapshot = state.Snapshot();
  const auto expired = fuzevpn::FormatOpenVpnDiagnostic(snapshot, false, "openvpn_certificate_expired");
  const auto rejected = fuzevpn::FormatOpenVpnDiagnostic(snapshot, false, "openvpn_client_certificate_rejected");
  check(std::string_view(snapshot.first_error) == "openvpn_certificate_expired" &&
      std::string_view(snapshot.last_error) == "certificate_invalid" &&
      expired.find(" failure_before_stop=openvpn_certificate_expired ") != std::string::npos &&
      rejected.find(" last_error=certificate_invalid failure_before_stop=certificate_invalid ") != std::string::npos &&
      rejected.find("openvpn_client_certificate_rejected") == std::string::npos,
      "client certificate verdicts are retained in their support spelling");
  check(std::string_view(fuzevpn::SafeOpenVpnFailure("certificate_invalid")) == "certificate_invalid" &&
      fuzevpn::OpenVpnDiagnosticCode("openvpn_certificate_expired") == "openvpn_certificate_expired" &&
      fuzevpn::OpenVpnDiagnosticCode("openvpn_tls_handshake_failed") == "openvpn_tls_handshake_failed",
      "only the Dart-only rejection code is renamed for diagnostics");
}

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
  for (const char* verdict : {"openvpn_certificate_expired", "openvpn_client_certificate_rejected"}) {
    check(fuzevpn::ClassifyOpenVpnAttemptFailure(verdict, DiagnosticAction::none, false, 0) == nullptr,
        "server verdict on the client certificate reaches the caller after cleanup");
  }
  OpenVpnCoreEventClassificationTests();
}
#endif
