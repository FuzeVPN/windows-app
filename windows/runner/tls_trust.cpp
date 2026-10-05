// SPDX-License-Identifier: MPL-2.0
#include "tls_trust.h"

#include <algorithm>
#include <memory>

namespace fuzevpn_tls {
namespace {

constexpr char kApiHostname[] = "api.fuzevpn.com";
constexpr wchar_t kApiHostnameWide[] = L"api.fuzevpn.com";
constexpr DWORD kMaximumChainElements = 16;

struct CertificateDeleter {
  void operator()(const CERT_CONTEXT* certificate) const {
    if (certificate != nullptr) CertFreeCertificateContext(certificate);
  }
};

struct ChainDeleter {
  void operator()(const CERT_CHAIN_CONTEXT* chain) const {
    if (chain != nullptr) CertFreeCertificateChain(chain);
  }
};

using Certificate = std::unique_ptr<const CERT_CONTEXT, CertificateDeleter>;
using Chain = std::unique_ptr<const CERT_CHAIN_CONTEXT, ChainDeleter>;

bool CompleteDerEnvelope(const std::vector<uint8_t>& bytes) {
  if (bytes.size() < 2 || bytes[0] != 0x30) return false;
  size_t length = bytes[1];
  size_t header = 2;
  if ((length & 0x80) != 0) {
    const size_t octets = length & 0x7f;
    if (octets == 0 || octets > 4 || bytes.size() < header + octets ||
        bytes[header] == 0) {
      return false;
    }
    length = 0;
    for (size_t index = 0; index < octets; ++index) {
      length = (length << 8) | bytes[header++];
    }
    if (length < 128) return false;
  }
  return length == bytes.size() - header;
}

bool IsRootCertificate(PCCERT_CONTEXT certificate) {
  if (certificate == nullptr || certificate->pCertInfo == nullptr ||
      !CertCompareCertificateName(X509_ASN_ENCODING,
                                  &certificate->pCertInfo->Subject,
                                  &certificate->pCertInfo->Issuer)) {
    return false;
  }
  // Name equality alone is insufficient: require the anchor's own signature.
  if (!CryptVerifyCertificateSignatureEx(
          0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
          const_cast<CERT_CONTEXT*>(certificate),
          CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
          const_cast<CERT_CONTEXT*>(certificate), 0, nullptr)) {
    return false;
  }
  const auto* constraints = CertFindExtension(
      szOID_BASIC_CONSTRAINTS2, certificate->pCertInfo->cExtension,
      certificate->pCertInfo->rgExtension);
  if (constraints == nullptr) return true;  // Legacy Windows roots may be v1.
  CERT_BASIC_CONSTRAINTS2_INFO* decoded = nullptr;
  DWORD decoded_size = 0;
  if (!CryptDecodeObjectEx(
          X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
          constraints->Value.pbData, constraints->Value.cbData,
          CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &decoded_size)) {
    return false;
  }
  const bool is_ca = decoded != nullptr && decoded->fCA != FALSE;
  LocalFree(decoded);
  return is_ca;
}

}  // namespace

TlsTrustVerification VerifyApiCertificate(
    const std::vector<uint8_t>& certificate_der, const std::string& hostname,
    const TlsTrustOptions& options) {
  TlsTrustVerification verification;
  if (hostname != kApiHostname || certificate_der.empty() ||
      certificate_der.size() > kMaximumCertificateBytes ||
      !CompleteDerEnvelope(certificate_der)) {
    verification.windows_error = ERROR_INVALID_PARAMETER;
    return verification;
  }

  Certificate certificate(CertCreateCertificateContext(
      X509_ASN_ENCODING, certificate_der.data(),
      static_cast<DWORD>(certificate_der.size())));
  if (!certificate) {
    verification.windows_error = GetLastError();
    return verification;
  }

  LPSTR server_auth = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
  CERT_CHAIN_PARA chain_parameters = {};
  chain_parameters.cbSize = sizeof(chain_parameters);
  chain_parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
  chain_parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
  chain_parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &server_auth;
  chain_parameters.dwUrlRetrievalTimeout = kUrlRetrievalTimeoutMs;

  FILETIME verification_time = {};
  FILETIME* requested_time = nullptr;
  if (options.verification_time != nullptr) {
    verification_time = *options.verification_time;
    requested_time = &verification_time;
  }

  PCCERT_CHAIN_CONTEXT raw_chain = nullptr;
  // Zero flags retain normal Windows AIA/automatic-root retrieval. No cache-
  // only, disabled-root-update, or certificate-error ignore flag is used.
  if (!CertGetCertificateChain(
          options.chain_engine, certificate.get(), requested_time,
          options.additional_store, &chain_parameters, 0, nullptr,
          &raw_chain)) {
    verification.windows_error = GetLastError();
    return verification;
  }
  Chain chain(raw_chain);
  if (!chain) {
    verification.windows_error = ERROR_INVALID_DATA;
    return verification;
  }
  verification.trust_status = chain->TrustStatus.dwErrorStatus;

  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_parameters = {};
  ssl_parameters.cbSize = sizeof(ssl_parameters);
  ssl_parameters.dwAuthType = AUTHTYPE_SERVER;
  ssl_parameters.fdwChecks = 0;
  ssl_parameters.pwszServerName = const_cast<LPWSTR>(kApiHostnameWide);
  CERT_CHAIN_POLICY_PARA policy_parameters = {};
  policy_parameters.cbSize = sizeof(policy_parameters);
  policy_parameters.dwFlags = 0;
  policy_parameters.pvExtraPolicyPara = &ssl_parameters;
  CERT_CHAIN_POLICY_STATUS policy_status = {};
  policy_status.cbSize = sizeof(policy_status);
  if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.get(),
                                        &policy_parameters, &policy_status)) {
    verification.windows_error = GetLastError();
    return verification;
  }
  if (policy_status.dwError != 0 || verification.trust_status != 0) {
    verification.windows_error = policy_status.dwError;
    return verification;
  }

  if (chain->cChain == 0 || chain->rgpChain == nullptr ||
      chain->rgpChain[0] == nullptr) {
    verification.windows_error = ERROR_INVALID_DATA;
    return verification;
  }
  const auto* simple_chain = chain->rgpChain[0];
  if (simple_chain->cElement < 2 ||
      simple_chain->cElement > kMaximumChainElements ||
      simple_chain->rgpElement == nullptr ||
      simple_chain->rgpElement[simple_chain->cElement - 1] == nullptr) {
    verification.windows_error = ERROR_INVALID_DATA;
    return verification;
  }
  const auto* root =
      simple_chain->rgpElement[simple_chain->cElement - 1]->pCertContext;
  if (root == nullptr || root->pbCertEncoded == nullptr ||
      root->cbCertEncoded == 0 ||
      root->cbCertEncoded > kMaximumCertificateBytes ||
      (root->cbCertEncoded == certificate_der.size() &&
       std::equal(certificate_der.begin(), certificate_der.end(),
                  root->pbCertEncoded)) ||
      !IsRootCertificate(root)) {
    verification.windows_error = ERROR_INVALID_DATA;
    return verification;
  }
  verification.anchor_der.assign(root->pbCertEncoded,
                                 root->pbCertEncoded + root->cbCertEncoded);
  verification.trusted = true;
  return verification;
}

}  // namespace fuzevpn_tls
