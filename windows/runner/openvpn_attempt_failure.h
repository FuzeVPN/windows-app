// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_ATTEMPT_FAILURE_H_
#define RUNNER_OPENVPN_ATTEMPT_FAILURE_H_

#include <string_view>
#include <openvpn/win/command_context.hpp>

namespace fuzevpn {
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
