// SPDX-License-Identifier: MPL-2.0
// Verify the production TLS trust helper against synthetic, exclusive memory
// stores. These tests never modify a Windows system certificate store.
#include "../runner/tls_trust.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

std::vector<uint8_t> ReadCertificate(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  Require(static_cast<bool>(file), "cannot read public TLS fixture");
  const std::string pem((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
  Require(!pem.empty() && pem.size() <= fuzevpn_tls::kMaximumCertificateBytes,
          "invalid TLS fixture size");
  DWORD length = 0;
  const DWORD pem_length = static_cast<DWORD>(pem.size());
  Require(CryptStringToBinaryA(pem.data(), pem_length,
                              CRYPT_STRING_BASE64HEADER, nullptr, &length,
                              nullptr, nullptr) != FALSE,
          "cannot size TLS fixture DER");
  std::vector<uint8_t> der(length);
  Require(CryptStringToBinaryA(pem.data(), pem_length,
                              CRYPT_STRING_BASE64HEADER, der.data(), &length,
                              nullptr, nullptr) != FALSE,
          "cannot decode TLS fixture DER");
  der.resize(length);
  return der;
}

class MemoryStore {
 public:
  MemoryStore()
      : handle_(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                              CERT_STORE_CREATE_NEW_FLAG, nullptr)) {
    Require(handle_ != nullptr, "cannot create isolated certificate store");
  }
  ~MemoryStore() { CertCloseStore(handle_, 0); }
  MemoryStore(const MemoryStore&) = delete;
  MemoryStore& operator=(const MemoryStore&) = delete;

  HCERTSTORE get() const { return handle_; }
  void Add(const std::vector<uint8_t>& certificate) {
    Require(CertAddEncodedCertificateToStore(
                handle_, X509_ASN_ENCODING, certificate.data(),
                static_cast<DWORD>(certificate.size()), CERT_STORE_ADD_ALWAYS,
                nullptr) != FALSE,
            "cannot add synthetic certificate to memory store");
  }

 private:
  HCERTSTORE handle_;
};

class MemoryEngine {
 public:
  MemoryEngine(HCERTSTORE roots, HCERTSTORE other,
               bool allow_intermediate_anchor = false) {
    CERT_CHAIN_ENGINE_CONFIG configuration = {};
    configuration.cbSize = sizeof(configuration);
    configuration.hExclusiveRoot = roots;
    // Windows forbids combining exclusive roots with any restricted store.
    // Keep the synthetic issuers as an additional store instead; only roots
    // in the exclusive memory store can still establish trust.
    configuration.cAdditionalStore = 1;
    configuration.rghAdditionalStore = &other;
    configuration.dwFlags =
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA;
    configuration.dwUrlRetrievalTimeout = 1;
    if (allow_intermediate_anchor) {
      configuration.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
    }
    if (CertCreateCertificateChainEngine(&configuration, &handle_) == FALSE) {
      const auto error = GetLastError();
      throw std::runtime_error(
          "cannot create exclusive memory chain engine (Windows " +
          std::to_string(error) + ", config size " +
          std::to_string(configuration.cbSize) + ", flags " +
          std::to_string(configuration.dwFlags) + ")");
    }
  }
  ~MemoryEngine() { CertFreeCertificateChainEngine(handle_); }
  MemoryEngine(const MemoryEngine&) = delete;
  MemoryEngine& operator=(const MemoryEngine&) = delete;
  HCERTCHAINENGINE get() const { return handle_; }

 private:
  HCERTCHAINENGINE handle_ = nullptr;
};

FILETIME VerificationTime() {
  SYSTEMTIME time = {};
  time.wYear = 2026;
  time.wMonth = 10;
  time.wDay = 5;
  time.wHour = 12;
  FILETIME result = {};
  Require(SystemTimeToFileTime(&time, &result) != FALSE,
          "cannot create fixed verification time");
  return result;
}

void RequireRejected(const fuzevpn_tls::TlsTrustVerification& result,
                     const char* message) {
  Require(!result.trusted && result.anchor_der.empty(), message);
  Require(result.windows_error != 0 || result.trust_status != 0,
          "rejected TLS verification must retain its numeric cause");
}

}  // namespace

int main(int argc, char** argv) {
  try {
    Require(argc == 2, "explicit TLS fixture directory required");
    const std::filesystem::path fixtures = argv[1];
    const auto root = ReadCertificate(fixtures / "root.pem");
    const auto intermediate = ReadCertificate(fixtures / "intermediate.pem");
    const auto expired_intermediate =
        ReadCertificate(fixtures / "expired-intermediate.pem");
    const auto valid = ReadCertificate(fixtures / "valid.pem");
    const auto expired = ReadCertificate(fixtures / "expired.pem");
    const auto client_only = ReadCertificate(fixtures / "client-only.pem");
    const auto wrong_host = ReadCertificate(fixtures / "wrong-host.pem");
    const auto self_signed_leaf =
        ReadCertificate(fixtures / "self-signed-leaf.pem");
    const auto time = VerificationTime();

    MemoryStore roots;
    roots.Add(root);
    MemoryStore issuers;
    issuers.Add(intermediate);
    issuers.Add(root);
    MemoryEngine engine(roots.get(), issuers.get());
    fuzevpn_tls::TlsTrustOptions options;
    options.chain_engine = engine.get();
    options.additional_store = issuers.get();
    options.verification_time = &time;

    const auto accepted = fuzevpn_tls::VerifyApiCertificate(
        valid, "api.fuzevpn.com", options);
    Require(accepted.trusted && !accepted.certificate_is_ca &&
                accepted.trust_status == 0 &&
                accepted.windows_error == 0,
            "valid synthetic SSL server chain must be accepted");
    Require(accepted.anchor_der == root && accepted.anchor_der != valid &&
                accepted.anchor_der != intermediate,
            "only the exclusive trusted root may be returned as an anchor");

    // Dart's bad-certificate callback can supply an issuer, not the peer leaf.
    // A CA has no API DNS name; its chain must be verified without treating it
    // as a server leaf. The subsequent Dart TLS handshake still checks the leaf.
    const auto accepted_issuer = fuzevpn_tls::VerifyApiCertificate(
        intermediate, "api.fuzevpn.com", options);
    Require(accepted_issuer.trusted && accepted_issuer.certificate_is_ca &&
                accepted_issuer.trust_status == 0 &&
                accepted_issuer.windows_error == 0 &&
                accepted_issuer.anchor_der == root,
            "trusted intermediate input must recover only its root anchor");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        root, "api.fuzevpn.com", options),
                    "the input certificate can never be its own recovered root");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        expired_intermediate, "api.fuzevpn.com", options),
                    "expired intermediate must not recover an anchor");
    auto tampered_intermediate = intermediate;
    tampered_intermediate.back() ^= 1;
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        tampered_intermediate, "api.fuzevpn.com", options),
                    "tampered intermediate signature must be rejected");

    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        wrong_host, "api.fuzevpn.com", options),
                    "SSL hostname mismatch must be rejected under trusted root");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        valid, "other.fuzevpn.test", options),
                    "non-API origin must be rejected");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        valid, std::string("api.fuzevpn.com") + '\0' + "evil",
                        options),
                    "hostname NUL suffix must be rejected");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        expired, "api.fuzevpn.com", options),
                    "expired SSL server certificate must be rejected");
    const auto client_only_result = fuzevpn_tls::VerifyApiCertificate(
        client_only, "api.fuzevpn.com", options);
    RequireRejected(client_only_result,
                    "client-authentication-only certificate must be rejected");
    Require(!client_only_result.certificate_is_ca,
            "client-authentication leaf must not be classified as a CA");

    auto bad_signature = valid;
    bad_signature.back() ^= 1;
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        bad_signature, "api.fuzevpn.com", options),
                    "tampered certificate signature must be rejected");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        {}, "api.fuzevpn.com", options),
                    "empty certificate must be rejected");
    const auto malformed = fuzevpn_tls::VerifyApiCertificate(
        {0x30, 0x02, 0x01}, "api.fuzevpn.com", options);
    RequireRejected(malformed,
                    "malformed DER must be rejected");
    Require(!malformed.certificate_is_ca,
            "malformed certificate cannot be classified as a CA");
    auto truncated = valid;
    truncated.pop_back();
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        truncated, "api.fuzevpn.com", options),
                    "truncated DER must be rejected");
    auto trailing_bytes = valid;
    trailing_bytes.push_back(0);
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        trailing_bytes, "api.fuzevpn.com", options),
                    "trailing certificate data must be rejected");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        std::vector<uint8_t>(
                            fuzevpn_tls::kMaximumCertificateBytes + 1, 0),
                        "api.fuzevpn.com", options),
                    "oversized certificate must be rejected");

    MemoryStore empty_roots;
    MemoryEngine untrusted_engine(empty_roots.get(), issuers.get());
    auto untrusted_options = options;
    untrusted_options.chain_engine = untrusted_engine.get();
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        valid, "api.fuzevpn.com", untrusted_options),
                    "available issuer chain without trusted root must fail");
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        intermediate, "api.fuzevpn.com", untrusted_options),
                    "untrusted intermediate must not recover an anchor");

    MemoryStore peer_roots;
    peer_roots.Add(self_signed_leaf);
    MemoryStore empty_issuers;
    MemoryEngine peer_engine(peer_roots.get(), empty_issuers.get());
    auto peer_options = options;
    peer_options.chain_engine = peer_engine.get();
    peer_options.additional_store = empty_issuers.get();
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        self_signed_leaf, "api.fuzevpn.com", peer_options),
                    "trusted self-signed leaf must never become a root anchor");

    MemoryStore intermediate_roots;
    intermediate_roots.Add(intermediate);
    MemoryEngine intermediate_engine(intermediate_roots.get(),
                                     empty_issuers.get(), true);
    auto intermediate_options = options;
    intermediate_options.chain_engine = intermediate_engine.get();
    intermediate_options.additional_store = empty_issuers.get();
    RequireRejected(fuzevpn_tls::VerifyApiCertificate(
                        valid, "api.fuzevpn.com", intermediate_options),
                    "trusted non-self-signed intermediate cannot be exported");

    std::cout << "TLS trust regression tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
}
