// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_ATTEMPT_FAILURE_H_
#define RUNNER_OPENVPN_ATTEMPT_FAILURE_H_

#include <string_view>
#include <openvpn/win/command_context.hpp>

namespace fuzevpn {
// Map a Core event name (or terminal status name) to a public failure code.
// The detail text is only searched, never retained.
inline const char* ClassifyOpenVpnCoreEvent(std::string_view name,
                                            std::string_view detail = {}) {
  const auto contains = [](std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
  };
  if (contains(detail, "dco_compatibility"))
    return "openvpn_dco_profile_incompatible";
  if (contains(detail, "cannot acquire TAP handle") ||
      contains(detail, "DeviceIoControl(") ||
      contains(detail, "no device handle"))
    return "openvpn_adapter_failed";
  if (contains(detail, "tls-crypt") || contains(detail, "static key"))
    return "openvpn_profile_crypto_failed";
  if (contains(detail, "private key") || contains(detail, "PEM"))
    return "openvpn_local_identity_mismatch";
  // With OpenSSL, Core emits TLS_ALERT_* only for an alert the server sent
  // (reason SSL_AD_REASON_OFFSET + description), i.e. its verdict while
  // verifying OUR chain. A local failure to verify the server certificate is
  // CERT_VERIFY_FAIL, even though OpenSSL then sends its own alert.
  // certificate_expired names an expired certificate or CRL in that
  // verification, usually our leaf, but also a lapsed CRL or issuing CA.
  if (name == "TLS_ALERT_CERTIFICATE_EXPIRED")
    return "openvpn_certificate_expired";
  // Other alerts arrive as TLS_ALERT_MISC; Core appends the received alert's
  // OpenSSL description in brackets. handshake_failure, decrypt_error and
  // internal_error are also sent for non-certificate causes, so they remain
  // generic TLS failures.
  if (name == "TLS_ALERT_BAD_CERTIFICATE" ||
      name == "TLS_ALERT_CERTIFICATE_REQUIRED" ||
      name == "TLS_ALERT_CERTIFICATE_REVOKED" ||
      name == "TLS_ALERT_UNKNOWN_CA" ||
      name == "TLS_ALERT_UNSUPPORTED_CERTIFICATE" ||
      (name == "TLS_ALERT_MISC" &&
       (contains(detail, "[certificate unknown]") ||
        contains(detail, "[access denied]"))))
    return "openvpn_client_certificate_rejected";
  if (contains(name, "CERT") || contains(name, "VERIFY"))
    return "openvpn_certificate_validation_failed";
  if (contains(name, "AUTH") || contains(name, "TLS"))
    return "openvpn_tls_handshake_failed";
  if (contains(name, "TUN") || contains(name, "DCO"))
    return "openvpn_adapter_failed";
  if (name == "ERR_INVALID_CONFIG" ||
      name == "ERR_INVALID_OPTION_VAL" ||
      name == "UNUSED_OPTIONS_ERROR")
    return "openvpn_client_config_failed";
  if (name == "ERR_INVALID_OPTION_CRYPTO")
    return "openvpn_profile_crypto_failed";
  if (name == "TRANSPORT_ERROR" || name == "UDP_CONNECT_ERROR")
    return "openvpn_transport_failed";
  return "openvpn_connection_failed";
}

// Classify the immutable pre-cleanup evidence, so a retry's transport progress
// cannot hide the original local setup failure. nullptr preserves an existing
// specific Core error. Failed cleanup is handled by the caller before this.
inline const char* ClassifyOpenVpnAttemptFailure(
    std::string_view progress, openvpn::Win::DiagnosticAction first_action,
    bool command_failed, unsigned postcondition_failures) {
  using openvpn::Win::DiagnosticAction;
  switch (first_action) {
    case DiagnosticAction::command_dns_set:
    case DiagnosticAction::command_dns_add:
    case DiagnosticAction::command_dns_delete:
    case DiagnosticAction::command_dns_flush:
    case DiagnosticAction::postcondition_dns:
    case DiagnosticAction::postcondition_read_nrpt:
    case DiagnosticAction::dns_manager_open:
    case DiagnosticAction::dns_service_open:
    case DiagnosticAction::dns_notify:
    case DiagnosticAction::dns_gpo_notify:
      return "openvpn_dns_configuration_failed";
    default: break;
  }
  if (first_action != DiagnosticAction::none)
    return "openvpn_network_configuration_failed";
  if ((postcondition_failures & (8U | 16U)) != 0)
    return "openvpn_dns_configuration_failed";
  if (command_failed || postcondition_failures != 0)
    return "openvpn_network_configuration_failed";
  if (progress == "openvpn_transport_started") return "openvpn_no_server_response";
  if (progress == "openvpn_adapter_opened") return "openvpn_dco_peer_failed";
  if (progress == "openvpn_connection_failed") return "openvpn_core_stalled";
  return nullptr;
}
}  // namespace fuzevpn
#endif
