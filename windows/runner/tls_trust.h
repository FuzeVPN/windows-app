// SPDX-License-Identifier: MPL-2.0
#ifndef FUZEVPN_TLS_TRUST_H_
#define FUZEVPN_TLS_TRUST_H_

#include <windows.h>
#include <wincrypt.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace fuzevpn_tls {

inline constexpr size_t kMaximumCertificateBytes = 64 * 1024;
inline constexpr DWORD kUrlRetrievalTimeoutMs = 5000;

struct TlsTrustVerification {
  bool trusted = false;
  std::vector<uint8_t> anchor_der;
  uint32_t trust_status = 0;
  uint32_t windows_error = 0;
};

// Explicit injection for isolated, memory-store tests. The application channel
// uses only the defaults: the current user's Windows chain engine and clock.
struct TlsTrustOptions {
  HCERTCHAINENGINE chain_engine = nullptr;
  HCERTSTORE additional_store = nullptr;
  const FILETIME* verification_time = nullptr;
};

// This may retrieve missing issuers/roots using standard Windows policy. Call
// it on a worker thread. Only an OS-verified root of a complete SSL server chain
// can be returned, and only for the application's fixed API hostname.
TlsTrustVerification VerifyApiCertificate(
    const std::vector<uint8_t>& certificate_der, const std::string& hostname,
    const TlsTrustOptions& options = {});

}  // namespace fuzevpn_tls

#endif  // FUZEVPN_TLS_TRUST_H_
