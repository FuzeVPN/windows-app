// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_IDENTITY_SELECTION_H_
#define RUNNER_OPENVPN_IDENTITY_SELECTION_H_

#include "openvpn_identity_record.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace fuzevpn {
template <typename Loader>
bool SelectCertificateIdentity(const std::string& certificate, Loader load,
                               OpenVpnIdentityRecord* identity, bool* pending) {
  if (!identity || !pending || certificate.size() > 65536) return false;
  BIO* input = BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size()));
  X509* cert = input ? PEM_read_bio_X509(input, nullptr, nullptr, nullptr) : nullptr;
  bool matched = false;
  for (const bool candidate_pending : {false, true}) {
    OpenVpnIdentityRecord candidate;
    if (!cert || !load(candidate_pending, &candidate)) continue;
    BIO* key_input = BIO_new_mem_buf(candidate.key.data(), static_cast<int>(candidate.key.size()));
    EVP_PKEY* key = key_input ? PEM_read_bio_PrivateKey(key_input, nullptr, nullptr, nullptr) : nullptr;
    matched = key && X509_check_private_key(cert, key) == 1;
    if (!matched) ERR_clear_error();
    if (key) EVP_PKEY_free(key);
    if (key_input) BIO_free(key_input);
    if (matched) {
      *identity = candidate;
      *pending = candidate_pending;
      break;
    }
  }
  if (cert) X509_free(cert);
  if (input) BIO_free(input);
  return matched;
}
}  // namespace fuzevpn
#endif
