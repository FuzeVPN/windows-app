// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_CORE_MODULE_H_
#define RUNNER_OPENVPN_CORE_MODULE_H_

#include <string>
#include <vector>

#include "network_protection.h"
#include "diagnostics_state.h"

struct OpenVpnActivationInput {
  std::string certificate_pem;
  std::string ca_certificate_pem;
  std::string tls_crypt_v2_client_key;
  std::string endpoint;
  std::string address;
  std::vector<std::string> addresses;
  std::vector<std::string> allowed_ips;
  std::string server_name;
  std::vector<std::string> dns;
  std::vector<std::string> ciphers;
  bool remote_cert_tls_server = false;
  bool ipv6_enabled = false;
  NetworkProtectionOptions protection;
};

// This module has no Flutter dependency. It owns the OpenVPN 3 Core client,
// the DPAPI-protected P-256 identity and all sensitive profile material.
bool OpenVpnCoreGetCsr(const std::string& account_id, const std::string& device_id,
                       bool renew, std::string* csr);
bool OpenVpnCoreAvailable();
bool OpenVpnCoreConnect(const OpenVpnActivationInput& activation);
// false with cache_available=false means there is no matching local session.
bool OpenVpnCoreReconnect(bool* cache_available);
// Returns only a bounded category. It never contains profile material, keys,
// certificates, endpoints, or server-provided error text.
std::string OpenVpnCoreFailureCode();
bool OpenVpnCoreConnected();
bool OpenVpnCoreStopped();
fuzevpn_diagnostics::EngineObservation OpenVpnCoreDiagnostics(const std::string& user, bool observe_owned_network = false);
bool OpenVpnCoreDiagnosticsCurrent(const std::string& user, const fuzevpn_diagnostics::EngineObservation& observation);
bool OpenVpnCoreSuspendForMigration();
bool OpenVpnCoreDisconnect();
bool OpenVpnCoreDeleteIdentity();
// Startup recovery is limited to FuzeVPN NRPT sessions whose exact originating
// process generation is no longer alive. Never removes generic OpenVPN rules.
bool OpenVpnCoreRecoverNetworkState();

#endif  // RUNNER_OPENVPN_CORE_MODULE_H_
