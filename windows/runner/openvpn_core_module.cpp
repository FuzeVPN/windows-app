// SPDX-License-Identifier: MPL-2.0
#include "openvpn_core_module.h"
#include "openvpn_dco_driver.h"
#include "protected_store.h"
#include "openvpn_identity_record.h"
#include "openvpn_identity_selection.h"
#include "openvpn_connection_state.h"
#include "openvpn_diagnostic_state.h"
#include "vpn_reconnect_binding.h"

#include <chrono>
#include <cstdio>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define FUZEVPN_OPENVPN_DCO_DIAGNOSTIC(event) \
  ::fuzevpn::RecordOpenVpnDcoDiagnostic(::fuzevpn::OpenVpnDcoDiagnostic::event)
#define FUZEVPN_OPENVPN_CONFIGURATION_DIAGNOSTIC(expected, index, rule) \
  do { try { NET_LUID diagnostic_luid{}; \
    if (ConvertInterfaceIndexToLuid(index, &diagnostic_luid) == NO_ERROR) \
      ::fuzevpn_diagnostics::CaptureNetworkExpectation(expected.addresses, expected.routes, \
          expected.dns, index, rule, diagnostic_luid.Value); \
  } catch (...) {} } while (false)
#include <client/ovpncli.cpp>
#undef FUZEVPN_OPENVPN_DCO_DIAGNOSTIC
#undef FUZEVPN_OPENVPN_CONFIGURATION_DIAGNOSTIC
#include <openvpn/win/command_context.hpp>
#include <openvpn/win/nrpt_session.hpp>
#include "openvpn_ip_validation.h"
#include "openvpn_attempt_failure.h"
#include "diagnostics_network.h"

// ovpncli.cpp establishes the required Windows header order for OpenVPN Core.

namespace {
constexpr char kPrivateKey[] = "openvpn_private_key_pem";
constexpr char kCsr[] = "openvpn_csr_pem";
constexpr char kAccount[] = "openvpn_account_id";
constexpr char kDevice[] = "openvpn_device_id";
constexpr char kPendingPrivateKey[] = "openvpn_pending_private_key_pem";
constexpr char kPendingCsr[] = "openvpn_pending_csr_pem";
constexpr char kPendingAccount[] = "openvpn_pending_account_id";
constexpr char kPendingDevice[] = "openvpn_pending_device_id";
constexpr char kIdentityRecord[] = "openvpn_identity_v1";
constexpr char kPendingIdentityRecord[] = "openvpn_pending_identity_v1";
using Identity = fuzevpn::OpenVpnIdentityRecord;

struct ReconnectCache {
  OpenVpnActivationInput activation;
  fuzevpn::VpnReconnectBinding binding;
  ~ReconnectCache() {
    fuzevpn::EraseSecret(activation.certificate_pem);
    fuzevpn::EraseSecret(activation.ca_certificate_pem);
    fuzevpn::EraseSecret(activation.tls_crypt_v2_client_key);
    fuzevpn::EraseSecret(binding.credential);
  }
};
std::optional<ReconnectCache> reconnect_cache;

std::mutex core_mutex;
std::mutex failure_mutex;
std::string failure_code = "openvpn_connection_failed";
fuzevpn_diagnostics::EngineObservation retained_diagnostic;
std::string diagnostic_user;
std::uint64_t diagnostic_tick = 0;
bool diagnostic_cleanup_failed = false;
std::uint64_t diagnostic_generation = 0;

void SetFailure(const char* code) {
  std::lock_guard<std::mutex> lock(failure_mutex);
  failure_code = code;
  if (fuzevpn::openvpn_diagnostic_state)
    fuzevpn::openvpn_diagnostic_state->Failure(code);
}

void WriteConnectionDiagnostic(const fuzevpn::OpenVpnDiagnosticSnapshot& snapshot,
                               const openvpn::Win::CommandControl& commands,
                               const std::string& failure,
                               std::uint64_t engine_connect_ms,
                               bool success) {
  // Called only by the broker request thread, which has the selected user's
  // protected-store context. No worker-thread filesystem I/O or new driver IOCTL.
  try {
    retained_diagnostic.available = true;
    retained_diagnostic.attempt_failed = !success;
    retained_diagnostic.dco = true;
    retained_diagnostic.engine_connect_ms = engine_connect_ms;
    retained_diagnostic.configuration_ms = commands.setup_commands_ms.load();
    retained_diagnostic.validation_ms = commands.setup_validation_ms.load();
    retained_diagnostic.reconnect_count = snapshot.reconnects;
    retained_diagnostic.dco_failures = snapshot.send_failed;
    retained_diagnostic.postconditions_mask = commands.postcondition_failures.load();
    retained_diagnostic.first_error = snapshot.first_error;
    retained_diagnostic.last_error = snapshot.last_error;
    if (std::string_view(failure) != "none") retained_diagnostic.last_error = fuzevpn::SafeOpenVpnFailure(failure);
    constexpr const char* phases[] = {"tunnel_start", "adapter_create", "handshake", "handshake",
        "handshake", "addresses_apply", "routes_apply", "completed"};
    retained_diagnostic.phase = phases[snapshot.stage < 8 ? snapshot.stage : 0];
    diagnostic_tick = GetTickCount64();
    SYSTEMTIME now{};
    GetSystemTime(&now);
    char timestamp[32]{};
    std::snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
    const auto action = commands.first_failed_action.load();
    const auto result = commands.first_failed_code.load();
    WriteUserDiagnostic("native_diagnostic.log", std::string(timestamp) +
        " area=openvpn event=connection_attempt_snapshot " +
        fuzevpn::FormatOpenVpnDiagnostic(snapshot, commands.command_failed.load(), failure) +
        " success=" + std::to_string(success) +
        " engine_connect_ms=" + std::to_string(engine_connect_ms) +
        " setup_commands_ms=" + std::to_string(commands.setup_commands_ms.load()) +
        " setup_validation_ms=" + std::to_string(commands.setup_validation_ms.load()) +
        " first_failed_action=" + openvpn::Win::CommandFailureActionName(action) +
        " first_failed_code=" + std::to_string(result) +
        " postcondition_failures=" + std::to_string(commands.postcondition_failures.load()) +
        " address_expected=" + std::to_string(commands.address_expected.load()) +
        " address_matched=" + std::to_string(commands.address_matched.load()) +
        " address_tentative=" + std::to_string(commands.address_tentative.load()) +
        " address_duplicate=" + std::to_string(commands.address_duplicate.load()) +
        "\r\n", true);
  } catch (...) {
    // Diagnostics cannot alter a connection or its cleanup result.
  }
}

void WriteCleanupDiagnostic(const openvpn::Win::CommandControl& commands,
                            std::uint64_t elapsed_ms, bool complete) {
  // Stop has joined the worker before reading cleanup_actions. Emit bounded,
  // non-sensitive evidence even when the orphaned broker retries cleanup.
  try {
    static std::uint64_t last_report = 0;
    const auto tick = GetTickCount64();
    if (!complete && last_report && tick - last_report < 5000) return;
    last_report = tick;
    SYSTEMTIME now{};
    GetSystemTime(&now);
    char timestamp[32]{};
    std::snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
    WriteUserDiagnostic("native_diagnostic.log", std::string(timestamp) +
        " area=openvpn event=cleanup_snapshot complete=" + std::to_string(complete) +
        " last_action=" + openvpn::Win::CommandFailureActionName(commands.last_cleanup_action.load()) +
        " last_code=" + std::to_string(commands.last_cleanup_code.load()) +
        " failure_count=" + std::to_string(commands.cleanup_failure_count.load()) +
        " pending_groups=" + std::to_string(commands.cleanup_actions.size()) +
        " elapsed_ms=" + std::to_string(elapsed_ms) +
        " budget_ms=" + std::to_string(openvpn::Win::kCleanupBudgetMs) + "\r\n", true);
  } catch (...) {
    // Recording a cleanup failure must not change whether cleanup succeeded.
  }
}

std::string FailureForEvent(const std::string& name,
                            const std::string& detail = {}) {
  if (detail.find("dco_compatibility") != std::string::npos)
    return "openvpn_dco_profile_incompatible";
  if (detail.find("cannot acquire TAP handle") != std::string::npos ||
      detail.find("DeviceIoControl(") != std::string::npos ||
      detail.find("no device handle") != std::string::npos)
    return "openvpn_adapter_failed";
  if (detail.find("tls-crypt") != std::string::npos ||
      detail.find("static key") != std::string::npos)
    return "openvpn_profile_crypto_failed";
  if (detail.find("private key") != std::string::npos ||
      detail.find("PEM") != std::string::npos)
    return "openvpn_local_identity_mismatch";
  if (name.find("CERT") != std::string::npos || name.find("VERIFY") != std::string::npos)
    return "openvpn_certificate_validation_failed";
  if (name.find("AUTH") != std::string::npos || name.find("TLS") != std::string::npos)
    return "openvpn_tls_handshake_failed";
  if (name.find("TUN") != std::string::npos || name.find("DCO") != std::string::npos)
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

void Erase(std::string* value) {
  if (value && !value->empty()) { SecureZeroMemory(value->data(), value->size()); value->clear(); }
}

bool Identifier(const std::string& value) {
  if (value.empty() || value.size() > 128) return false;
  for (const char c : value) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  return true;
}

bool DeleteIdentity(bool pending) {
  bool success = true;
  for (const char* key : {pending ? kPendingIdentityRecord : kIdentityRecord,
                         pending ? kPendingPrivateKey : kPrivateKey,
                         pending ? kPendingCsr : kCsr,
                         pending ? kPendingAccount : kAccount,
                         pending ? kPendingDevice : kDevice}) {
    success = DeleteProtectedValue(key) && success;
  }
  return success;
}

bool IsPem(const std::string& value, size_t max_size = 65536) {
  return value.size() >= 32 && value.size() <= max_size && value.starts_with("-----BEGIN ") &&
      value.find('\0') == std::string::npos;
}

bool SaveIdentity(bool pending, const Identity& identity) {
  std::string encoded = identity.Encode();
  const bool saved = WriteProtectedValue(
      pending ? kPendingIdentityRecord : kIdentityRecord, encoded);
  Erase(&encoded);
  if (saved) {
    // Retire the pre-record representation only after the atomic replacement
    // succeeds. It must not later resurrect an older key/account combination.
    for (const char* key : {pending ? kPendingPrivateKey : kPrivateKey,
                           pending ? kPendingCsr : kCsr,
                           pending ? kPendingAccount : kAccount,
                           pending ? kPendingDevice : kDevice}) {
      DeleteProtectedValue(key);
    }
  }
  return saved;
}

bool ReadIdentity(bool pending, Identity* identity, bool* missing = nullptr) {
  if (missing) *missing = false;
  std::string encoded;
  const auto record_status = ReadProtectedValueStatus(
      pending ? kPendingIdentityRecord : kIdentityRecord, &encoded);
  if (record_status == ProtectedValueReadStatus::found) {
    const bool valid = Identity::Decode(encoded, identity) &&
        IsPem(identity->key) && IsPem(identity->csr) &&
        Identifier(identity->account) && Identifier(identity->device);
    Erase(&encoded);
    return valid;
  }
  if (record_status != ProtectedValueReadStatus::not_found) return false;
  Identity legacy;
  const auto key_status = ReadProtectedValueStatus(pending ? kPendingPrivateKey : kPrivateKey, &legacy.key);
  const auto csr_status = ReadProtectedValueStatus(pending ? kPendingCsr : kCsr, &legacy.csr);
  const auto account_status = ReadProtectedValueStatus(pending ? kPendingAccount : kAccount, &legacy.account);
  const auto device_status = ReadProtectedValueStatus(pending ? kPendingDevice : kDevice, &legacy.device);
  if (key_status == ProtectedValueReadStatus::not_found && csr_status == key_status &&
      account_status == key_status && device_status == key_status) {
    if (missing) *missing = true;
    return false;
  }
  if (key_status != ProtectedValueReadStatus::found || csr_status != key_status ||
      account_status != key_status || device_status != key_status ||
      !IsPem(legacy.key) || !IsPem(legacy.csr) ||
      !Identifier(legacy.account) || !Identifier(legacy.device)) return false;
  if (!SaveIdentity(pending, legacy)) return false;
  *identity = legacy;
  return true;
}

bool NormalizeLineEndings(const std::string& value, size_t max_size,
                          std::string* normalized) {
  if (!normalized || value.empty() || value.size() > max_size ||
      value.find('\0') != std::string::npos) {
    return false;
  }
  normalized->clear();
  normalized->reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '\r') {
      if (i + 1 >= value.size() || value[i + 1] != '\n') return false;
      normalized->push_back('\n');
      ++i;
    } else {
      normalized->push_back(value[i]);
    }
  }
  return true;
}

bool ValidBase64Payload(const std::string& payload) {
  if (payload.empty() || payload.size() % 4 != 0) return false;
  size_t padding = 0;
  while (padding < 2 && payload[payload.size() - padding - 1] == '=') {
    ++padding;
  }
  for (size_t i = 0; i < payload.size() - padding; ++i) {
    const char c = payload[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '+' || c == '/')) {
      return false;
    }
  }
  for (size_t i = payload.size() - padding; i < payload.size(); ++i) {
    if (payload[i] != '=') return false;
  }
  return true;
}

bool ParseArmoredBlocks(const std::string& value, const std::string& label,
                        size_t max_size, bool allow_multiple,
                        std::vector<std::string>* blocks) {
  if (!blocks) return false;
  blocks->clear();

  std::string normalized;
  if (!NormalizeLineEndings(value, max_size, &normalized)) return false;

  std::vector<std::string> lines;
  size_t start = 0;
  while (true) {
    const size_t newline = normalized.find('\n', start);
    if (newline == std::string::npos) {
      lines.push_back(normalized.substr(start));
      break;
    }
    lines.push_back(normalized.substr(start, newline - start));
    start = newline + 1;
    if (start == normalized.size()) {
      lines.emplace_back();
      break;
    }
  }

  const std::string begin = "-----BEGIN " + label + "-----";
  const std::string end = "-----END " + label + "-----";
  size_t index = 0;
  while (index < lines.size() && !lines[index].empty()) {
    if (lines[index++] != begin) return false;

    std::string payload;
    std::string canonical = begin + "\n";
    size_t payload_lines = 0;
    while (index < lines.size() && lines[index] != end) {
      const std::string& line = lines[index++];
      if (line.empty() || line.size() > 64) return false;
      for (const char c : line) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) {
          return false;
        }
      }
      payload += line;
      canonical += line + "\n";
      ++payload_lines;
    }
    if (payload_lines == 0 || index >= lines.size() ||
        lines[index++] != end || !ValidBase64Payload(payload)) {
      return false;
    }

    canonical += end + "\n";
    blocks->push_back(std::move(canonical));
    while (index < lines.size() && lines[index].empty()) ++index;
    if (!allow_multiple && index < lines.size()) return false;
  }

  return !blocks->empty() && (allow_multiple || blocks->size() == 1);
}

bool CanonicalizeCertificates(const std::string& value, bool allow_multiple,
                              std::string* canonical) {
  if (!canonical) return false;
  canonical->clear();
  std::vector<std::string> blocks;
  if (!ParseArmoredBlocks(value, "CERTIFICATE", 64 * 1024,
                          allow_multiple, &blocks)) {
    return false;
  }

  for (const auto& block : blocks) {
    BIO* input = BIO_new_mem_buf(block.data(), static_cast<int>(block.size()));
    X509* certificate = input ? PEM_read_bio_X509(input, nullptr, nullptr, nullptr) : nullptr;
    BIO* output = certificate ? BIO_new(BIO_s_mem()) : nullptr;
    const bool written = output && PEM_write_bio_X509(output, certificate) == 1;
    char* data = nullptr;
    const long size = written ? BIO_get_mem_data(output, &data) : 0;
    if (!written || size <= 0 || !data) {
      if (output) BIO_free(output);
      if (certificate) X509_free(certificate);
      if (input) BIO_free(input);
      Erase(canonical);
      return false;
    }
    canonical->append(data, static_cast<size_t>(size));
    BIO_free(output);
    X509_free(certificate);
    BIO_free(input);
  }
  return !canonical->empty();
}

bool NormalizeTlsCryptV2Key(const std::string& value,
                            std::string* normalized) {
  if (!normalized) return false;
  std::vector<std::string> blocks;
  if (!ParseArmoredBlocks(value, "OpenVPN tls-crypt-v2 client key", 8 * 1024,
                          false, &blocks)) {
    return false;
  }
  *normalized = std::move(blocks.front());
  return true;
}

bool CanonicalizePrivateKey(std::string* key) {
  if (!key) return false;
  std::vector<std::string> blocks;
  if (!ParseArmoredBlocks(*key, "PRIVATE KEY", 64 * 1024, false, &blocks)) {
    return false;
  }
  BIO* input = BIO_new_mem_buf(blocks.front().data(),
                               static_cast<int>(blocks.front().size()));
  EVP_PKEY* private_key = input
      ? PEM_read_bio_PrivateKey(input, nullptr, nullptr, nullptr)
      : nullptr;
  BIO* output = private_key ? BIO_new(BIO_s_mem()) : nullptr;
  const bool written = output && PEM_write_bio_PrivateKey(
      output, private_key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
  char* data = nullptr;
  const long size = written ? BIO_get_mem_data(output, &data) : 0;
  if (!written || size <= 0 || !data) {
    if (output) BIO_free(output);
    if (private_key) EVP_PKEY_free(private_key);
    if (input) BIO_free(input);
    return false;
  }
  Erase(key);
  key->assign(data, static_cast<size_t>(size));
  BIO_free(output);
  EVP_PKEY_free(private_key);
  BIO_free(input);
  return true;
}

bool CreateIdentity(const std::string& account, const std::string& device, bool pending, std::string* csr) {
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr); EVP_PKEY* key = nullptr;
  X509_REQ* request = nullptr; BIO* key_bio = nullptr; BIO* csr_bio = nullptr;
  std::string private_pem, csr_pem; bool success = false;
  do {
    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) != 1 ||
        EVP_PKEY_keygen(context, &key) != 1 || !(key_bio = BIO_new(BIO_s_mem())) ||
        PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr) != 1 ||
        !(request = X509_REQ_new()) || X509_REQ_set_version(request, 0L) != 1 ||
        X509_REQ_set_pubkey(request, key) != 1) break;
    X509_NAME* subject = X509_REQ_get_subject_name(request);
    if (!subject || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("FuzeVPN Windows"), -1, -1, 0) != 1 ||
        X509_REQ_sign(request, key, EVP_sha256()) <= 0 || !(csr_bio = BIO_new(BIO_s_mem())) ||
        PEM_write_bio_X509_REQ(csr_bio, request) != 1) break;
    char* data = nullptr; const long private_size = BIO_get_mem_data(key_bio, &data);
    if (private_size <= 0 || !data) break; private_pem.assign(data, static_cast<size_t>(private_size));
    data = nullptr; const long csr_size = BIO_get_mem_data(csr_bio, &data);
    if (csr_size <= 0 || !data) break; csr_pem.assign(data, static_cast<size_t>(csr_size));
    Identity identity;
    identity.key = private_pem;
    identity.csr = csr_pem;
    identity.account = account;
    identity.device = device;
    if (!SaveIdentity(pending, identity)) break;
    *csr = csr_pem; success = true;
  } while (false);
  Erase(&private_pem); Erase(&csr_pem); if (csr_bio) BIO_free(csr_bio); if (key_bio) BIO_free(key_bio);
  if (request) X509_REQ_free(request); if (key) EVP_PKEY_free(key); if (context) EVP_PKEY_CTX_free(context);
  return success;
}

bool GetCsr(const std::string& account, const std::string& device, bool renew, std::string* csr) {
  Identity identity;
  bool missing = false;
  const bool loaded = ReadIdentity(renew, &identity, &missing);
  if (!loaded && !missing) return false;
  if (loaded && identity.account == account &&
      identity.device == device) {
    *csr = identity.csr;
    return true;
  }
  reconnect_cache.reset();
  return CreateIdentity(account, device, renew, csr);
}

class EngineInterfaceReceiver {
 public:
  virtual void SetEngineInterface(std::uint32_t index) = 0;
  virtual ~EngineInterfaceReceiver() = default;
};

// Preserve Core's event queue, intercepting only the typed local adapter index
// before it is reduced to a text event. No address/alias lookup is involved.
class AdapterEvents final : public openvpn::ClientAPI::MyClientEvents {
 public:
  explicit AdapterEvents(openvpn::ClientAPI::OpenVPNClient* parent)
      : MyClientEvents(parent), receiver_(dynamic_cast<EngineInterfaceReceiver*>(parent)) {}
  void add_event(openvpn::ClientEvent::Base::Ptr event) override {
    if (receiver_ && event->id() == openvpn::ClientEvent::CONNECTED) {
      const auto* connected = event->connected_cast();
      if (connected) receiver_->SetEngineInterface(connected->vpn_interface_index);
    }
    MyClientEvents::add_event(std::move(event));
  }
 private:
  EngineInterfaceReceiver* receiver_;
};

class Client final : public openvpn::ClientAPI::OpenVPNClient,
                     public EngineInterfaceReceiver {
 public:
  explicit Client(const NetworkProtectionOptions& protection) : protection_(protection) {}
  void SetEngineInterface(std::uint32_t index) override {
    NET_LUID luid{};
    interface_luid_ = index != 0 && index != 0xffffffffU &&
        ConvertInterfaceIndexToLuid(index, &luid) == NO_ERROR ? luid.Value : 0;
  }
  bool pause_on_connection_timeout() override { return false; }
  bool socket_protect(openvpn_io::detail::socket_type, std::string, bool) override {
    // On ovpn-dco-win this callback is reached after the adapter is open and
    // immediately before the peer/remote endpoint is installed in the driver.
    SetFailure("openvpn_transport_started");
    return true;
  }
  void event(const openvpn::ClientAPI::Event& event) override {
    diagnostics.Event(event.name);
    bool protection_ready = true;
    if (event.name == "CONNECTED") {
      protection_ready = interface_luid_ != 0 &&
          PromoteNetworkProtection(NetworkProtectionOwner::open_vpn,
                                   interface_luid_, protection_);
      if (!protection_ready) {
        SetFailure("network_protection_failed");
        stop();
      }
      commands->connection_deadline = 0;
    } else if (event.name == "RECONNECTING") {
      commands->connection_deadline = GetTickCount64() + 25000;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    connection_.Event(event.name, event.error, event.fatal, protection_ready);
    if (event.error || event.fatal) {
      SetFailure(FailureForEvent(event.name, event.info).c_str());
    }
    condition_.notify_all();
  }
  void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent&) override {}
  void log(const openvpn::ClientAPI::LogInfo& log) override {
    diagnostics.Log(log.text);
    // Keep only a fixed progress category. The raw OpenVPN line is never
    // retained or exposed because it may contain endpoint/profile details.
    if (log.text.find("Contacting ") != std::string::npos ||
        log.text.find("UDP link remote") != std::string::npos) {
      SetFailure("openvpn_transport_started");
    } else if (log.text.find("Open TAP device") != std::string::npos &&
               log.text.find("SUCCEEDED") != std::string::npos) {
      SetFailure("openvpn_adapter_opened");
    } else if (log.text.find("Open TAP device") != std::string::npos &&
               log.text.find("FAILED") != std::string::npos) {
      SetFailure("openvpn_adapter_failed");
    }
  }
  void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest& r) override { r.error = true; }
  void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest& r) override { r.error = true; }
  void Complete(const openvpn::ClientAPI::Status& status) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connection_.terminal) {
      if (status.error)
        SetFailure(FailureForEvent(status.status, status.message).c_str());
    }
    connection_.Complete();
    worker_complete_ = true;
    condition_.notify_all();
  }
  bool Wait() { std::unique_lock<std::mutex> lock(mutex_); return condition_.wait_for(lock, std::chrono::seconds(25), [this] { return connection_.connected || connection_.terminal; }) && connection_.connected; }
  bool connected() const { std::lock_guard<std::mutex> lock(mutex_); return connection_.connected; }
  void RequestStop() { commands->cancelled.store(true); stop(); }
  bool WaitForCompletion(std::chrono::seconds maximum) {
    std::unique_lock<std::mutex> lock(mutex_);
    return condition_.wait_for(lock, maximum, [this] { return worker_complete_; });
  }
  std::shared_ptr<openvpn::Win::CommandControl> commands = std::make_shared<openvpn::Win::CommandControl>();
  fuzevpn::OpenVpnDiagnosticState diagnostics;
  fuzevpn_diagnostics::NetworkExpectationCapture network_configuration;
  std::uint64_t diagnostic_connected_at = 0;
 protected:
  void connect_attach() override {
    state->attach<openvpn::ClientAPI::MySessionStats, AdapterEvents>(
        this, nullptr, get_async_stop());
  }
 private:
  mutable std::mutex mutex_;
  std::condition_variable condition_;
  fuzevpn::OpenVpnConnectionState connection_;
  NetworkProtectionOptions protection_;
  std::uint64_t interface_luid_ = 0;
  bool worker_complete_ = false;
};

std::unique_ptr<Client> client;
std::thread thread;
std::shared_ptr<openvpn::Win::CommandControl> pending_cleanup;

bool Stop() {
  ++diagnostic_generation;
  const auto commands = client ? client->commands : pending_cleanup;
  if (client) client->RequestStop();
  if (thread.joinable()) {
    // A native/driver call can ignore cooperative cancellation. Preserve the
    // worker and Client until completion; never detach a user of Client memory.
    if (!client || !client->WaitForCompletion(std::chrono::seconds(20))) {
      diagnostic_cleanup_failed = true;
      SetFailure("openvpn_stop_timeout");
      return false;
    }
    thread.join();
  }
  // Destruction and retries share one cleanup budget. A later Stop call gets a
  // fresh bounded attempt while failed actions continue to retain protection.
  const auto cleanup_started = GetTickCount64();
  openvpn::Win::ScopedCommandControl command_scope(commands.get());
  openvpn::Win::ScopedCommandCleanup cleanup_scope;
  client.reset();
  pending_cleanup = commands;
  if (!openvpn::Win::RetryCommandCleanup(pending_cleanup.get())) {
    diagnostic_cleanup_failed = true;
    WriteCleanupDiagnostic(*pending_cleanup, GetTickCount64() - cleanup_started, false);
    SetFailure("openvpn_cleanup_failed");
    return false;
  }
  if (pending_cleanup && pending_cleanup->cleanup_failure_count.load())
    WriteCleanupDiagnostic(*pending_cleanup, GetTickCount64() - cleanup_started, true);
  pending_cleanup.reset();
  diagnostic_cleanup_failed = false;
  if (retained_diagnostic.available) retained_diagnostic.cleanup_state = "completed";
  return true;
}

bool PendingToActive(const Identity& identity) {
  if (!SaveIdentity(false, identity)) return false;
  // The committed active record is already complete if cleanup is interrupted.
  return DeleteIdentity(true);
}

bool ReadMatchingIdentity(const std::string& certificate, Identity* identity,
                          bool* pending) {
  return fuzevpn::SelectCertificateIdentity(certificate,
      [](bool candidate_pending, Identity* candidate) {
        return ReadIdentity(candidate_pending, candidate) &&
            CanonicalizePrivateKey(&candidate->key);
      }, identity, pending);
}
bool IPv4(const std::string& value) {
  return fuzevpn::IsStrictOpenVpnIPv4(value);
}
bool IPv4Cidr(const std::string& value, std::string* address, std::string* netmask) {
  const size_t slash = value.find('/');
  if (slash == std::string::npos || slash == 0 || slash == value.size() - 1 ||
      value.find('/', slash + 1) != std::string::npos) return false;
  const std::string ip = value.substr(0, slash); const std::string prefix_text = value.substr(slash + 1);
  if (!IPv4(ip) || prefix_text.size() > 2) return false;
  unsigned prefix = 0;
  for (const char c : prefix_text) { if (c < '0' || c > '9') return false; prefix = prefix * 10 + static_cast<unsigned>(c - '0'); }
  if (prefix > 32) return false;
  IN_ADDR mask{}; mask.S_un.S_addr = htonl(prefix == 0 ? 0U : 0xFFFFFFFFU << (32 - prefix));
  char text[INET_ADDRSTRLEN]{};
  if (!InetNtopA(AF_INET, &mask, text, static_cast<DWORD>(sizeof(text)))) return false;
  *address = ip; *netmask = text; return true;
}
bool UlaIPv6HostCidr(const std::string& value) {
  if (value.find('\0') != std::string::npos) return false;
  const size_t slash = value.find('/');
  if (slash == std::string::npos || value.substr(slash + 1) != "128") return false;
  const std::string ip = value.substr(0, slash);
  IN6_ADDR address{};
  return InetPtonA(AF_INET6, ip.c_str(), &address) == 1 &&
      (address.u.Byte[0] & 0xfe) == 0xfc;
}
bool Name(const std::string& value) { if (value.empty() || value.size() > 253) return false; for (char c : value) if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='-'||c=='_')) return false; return true; }
bool Cipher(const std::string& value) { if (value.empty() || value.size() > 64) return false; for (const char c : value) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false; return true; }
}  // namespace

bool OpenVpnCoreGetCsr(const std::string& account_id, const std::string& device_id, bool renew, std::string* csr) {
  std::lock_guard<std::mutex> lock(core_mutex); return csr && Identifier(account_id) && Identifier(device_id) && GetCsr(account_id, device_id, renew, csr);
}
bool OpenVpnCoreAvailable() {
  // Availability is a read-only UI query. Driver staging is intentionally
  // deferred to OpenVpnCoreConnect, which runs only in the elevated broker.
  return BundledOpenVpnDcoDriverAvailable();
}
static bool ConnectLocked(const OpenVpnActivationInput& a) {
  ++diagnostic_generation;
  SetFailure("openvpn_connection_failed");
  std::string vpn_address, vpn_netmask;
  if (!IPv4(a.endpoint) || !IPv4Cidr(a.address, &vpn_address, &vpn_netmask) ||
      !Name(a.server_name) || !a.remote_cert_tls_server || a.ciphers.empty() ||
      a.ciphers.size() > 16 ||
      a.dns.empty() || a.dns.size() > 8 || a.addresses.empty() ||
      a.addresses.front() != a.address) {
    SetFailure("openvpn_profile_rejected");
    return false;
  }
  if (a.ipv6_enabled) {
    if (a.addresses.size() != 2 || !UlaIPv6HostCidr(a.addresses[1]) ||
        a.allowed_ips.size() != 2 || a.allowed_ips[0] != "0.0.0.0/0" ||
        a.allowed_ips[1] != "::/0") {
      SetFailure("openvpn_profile_rejected");
      return false;
    }
  } else if (a.addresses.size() != 1 || a.allowed_ips.size() > 1 ||
             (!a.allowed_ips.empty() && a.allowed_ips[0] != "0.0.0.0/0")) {
    SetFailure("openvpn_profile_rejected");
    return false;
  }
  for (const auto& cipher : a.ciphers) if (!Cipher(cipher)) { SetFailure("openvpn_profile_rejected"); return false; }
  for (const auto& dns : a.dns) if (!IPv4(dns)) { SetFailure("openvpn_profile_rejected"); return false; }
  std::string certificate, ca_certificates, tls_crypt_v2;
  const auto erase_remote_material = [&]() {
    Erase(&certificate);
    Erase(&ca_certificates);
    Erase(&tls_crypt_v2);
  };
  if (!CanonicalizeCertificates(a.certificate_pem, false, &certificate) ||
      !CanonicalizeCertificates(a.ca_certificate_pem, true, &ca_certificates) ||
      !NormalizeTlsCryptV2Key(a.tls_crypt_v2_client_key, &tls_crypt_v2)) {
    erase_remote_material();
    SetFailure("openvpn_profile_rejected");
    return false;
  }
  Identity identity;
  bool pending_identity = false;
  const std::string user = ProtectedStoreUserId();
  std::string current_account;
  if (user.empty() || !ReadMatchingIdentity(certificate, &identity, &pending_identity) ||
      !ReadProtectedValue("wireguard_account_id", &current_account) ||
      current_account != identity.account) {
    erase_remote_material();
    SetFailure("openvpn_local_identity_failed");
    return false;
  }
  // Flutter normally arms this policy before its first control-plane request.
  // Repeat the operation inside the privileged engine so reconnects and older
  // callers cannot reach driver setup, tunnel teardown, or transport startup
  // without a matching prepared policy. Later failures deliberately retain it
  // until an explicit disconnect.
  if (!PrepareNetworkProtection(NetworkProtectionOwner::open_vpn,
                                a.protection)) {
    erase_remote_material();
    SetFailure("network_protection_failed");
    return false;
  }
  if (!EnsureBundledOpenVpnDcoDriver()) {
    erase_remote_material();
    SetFailure(OpenVpnDcoDriverRestartRequired() ? "openvpn_driver_restart_required" : "openvpn_adapter_failed");
    return false;
  }
  // The inline <tls-crypt-v2> block below is the complete client directive.
  // A bare `tls-crypt-v2` line has no key argument and can make OpenVPN Core
  // reject this generated profile before it opens its UDP socket.
  // OpenVPN 3 treats topology/ifconfig as push-only directives. The server's
  // agent-managed CCD owns the static address, so duplicating them here makes
  // ClientOptions stop with UNUSED_OPTIONS_ERROR before UDP is opened.
  std::string profile = "client\ndev tun\nproto udp4\nremote " + a.endpoint + " 1194\nnobind\nremote-cert-tls server\nverify-x509-name " + a.server_name + " name\nallow-compression no\nauth-nocache\n";
  profile += "redirect-gateway def1";
  if (a.ipv6_enabled) profile += " ipv6";
  if (a.protection.kill_switch) profile += " block-local";
  profile += "\n";
  if (a.protection.dns_protection)
    profile += "block-outside-dns\n";
  if (!a.ipv6_enabled)
    profile += "block-ipv6\npull-filter ignore \"route-ipv6\"\npull-filter ignore \"ifconfig-ipv6\"\n";
  for (const auto& dns : a.dns) profile += "dhcp-option DNS " + dns + "\n";
  profile += "data-ciphers ";
  for (size_t i=0;i<a.ciphers.size();++i) { if (i) profile += ':'; profile += a.ciphers[i]; }
  profile += "\n<ca>\n" + ca_certificates + "</ca>\n<cert>\n" + certificate +
      "</cert>\n<key>\n" + identity.key + "</key>\n<tls-crypt-v2>\n" + tls_crypt_v2 +
      "</tls-crypt-v2>\n";
  erase_remote_material();
  if (!Stop()) { Erase(&profile); return false; }
  diagnostic_user = user;
  retained_diagnostic = {};
  diagnostic_tick = 0;
  client = std::make_unique<Client>(a.protection); openvpn::ClientAPI::Config config; config.content = std::move(profile); config.protoVersionOverride = 4; config.compressionMode = "no"; config.dco = true;
  const auto eval = client->eval_config(config); if (eval.error || !eval.autologin) { Erase(&config.content); client.reset(); SetFailure("openvpn_profile_rejected"); return false; }
  Client* const connecting_client = client.get();
  connecting_client->commands->connection_deadline = GetTickCount64() + 25000;
  // Engine timing includes transport, tunnel setup and WFP promotion, but not
  // API enrollment, bundled-driver validation or the previous tunnel's stop.
  const auto engine_started = GetTickCount64();
  thread = std::thread([connecting_client, config = std::move(config)]() mutable {
    fuzevpn::ScopedOpenVpnDiagnosticState diagnostic_scope(&connecting_client->diagnostics);
    fuzevpn_diagnostics::ScopedNetworkExpectationCapture network_scope(&connecting_client->network_configuration);
    openvpn::Win::ScopedCommandControl command_scope(connecting_client->commands.get());
    openvpn::ClientAPI::Status status;
    try { status = connecting_client->connect(); }
    catch (...) { status.error = true; status.status = "OPENVPN_WORKER_FAILED"; }
    connecting_client->Complete(status);
    Erase(&config.content);
  });
  const bool engine_connected = client->Wait();
  const auto engine_connect_ms = GetTickCount64() - engine_started;
  if (!engine_connected) {
    const std::string progress = OpenVpnCoreFailureCode();
    const auto first_action = client->commands->first_failed_action.load();
    const bool command_failed = client->commands->command_failed.load();
    const unsigned postcondition_failures = client->commands->postcondition_failures.load();
    WriteConnectionDiagnostic(client->diagnostics.Snapshot(),
        *client->commands, progress, engine_connect_ms, false);
    if (!Stop()) return false;
    const char* classified = fuzevpn::ClassifyOpenVpnAttemptFailure(
        progress, first_action, command_failed, postcondition_failures);
    SetFailure(classified ? classified : progress.c_str());
    return false;
  }
  if (pending_identity && !PendingToActive(identity)) {
    WriteConnectionDiagnostic(client->diagnostics.Snapshot(),
        *client->commands, "openvpn_local_identity_failed", engine_connect_ms, false);
    if (!Stop()) return false;
    SetFailure("openvpn_local_identity_failed");
    return false;
  }
  reconnect_cache.reset();
  reconnect_cache.emplace();
  reconnect_cache->activation = a;
  reconnect_cache->binding = {user, identity.account, identity.csr, identity.device};
  WriteConnectionDiagnostic(client->diagnostics.Snapshot(),
      *client->commands, "none", engine_connect_ms, true);
  client->diagnostic_connected_at = GetTickCount64();
  retained_diagnostic.cleanup_state = "not_requested";
  return true;
}
bool OpenVpnCoreConnect(const OpenVpnActivationInput& activation) {
  std::lock_guard<std::mutex> lock(core_mutex);
  return ConnectLocked(activation);
}
bool OpenVpnCoreReconnect(bool* cache_available) {
  std::lock_guard<std::mutex> lock(core_mutex);
  *cache_available = false;
  Identity identity;
  const std::string user = ProtectedStoreUserId();
  std::string current_account;
  if (!reconnect_cache ||
      !ReadIdentity(false, &identity) ||
      !ReadProtectedValue("wireguard_account_id", &current_account) ||
      current_account != identity.account ||
      !reconnect_cache->binding.Matches({user, current_account, identity.csr, identity.device})) {
    reconnect_cache.reset();
    return false;
  }
  *cache_available = true;
  // Copy before ConnectLocked replaces the cache after successful connection.
  ReconnectCache candidate = *reconnect_cache;
  return ConnectLocked(candidate.activation);
}
std::string OpenVpnCoreFailureCode() { std::lock_guard<std::mutex> lock(failure_mutex); return failure_code; }
bool OpenVpnCoreConnected() {
  std::lock_guard<std::mutex> lock(core_mutex);
  return client && client->connected() &&
      IsTunnelNetworkProtectionActive(NetworkProtectionOwner::open_vpn);
}
bool OpenVpnCoreStopped() {
  std::lock_guard<std::mutex> lock(core_mutex);
  return !client && !thread.joinable() && !pending_cleanup;
}
fuzevpn_diagnostics::EngineObservation OpenVpnCoreDiagnostics(const std::string& user, bool observe_owned_network) {
  using namespace fuzevpn_diagnostics;
  std::unique_lock<std::mutex> lock(core_mutex, std::try_to_lock);
  if (!lock.owns_lock() || user.empty() || diagnostic_user != user) return {};
  const auto generation = diagnostic_generation;
  const Client* const observed_client = client.get();
  NetworkExpectation expected;
  auto out = retained_diagnostic;
  out.generation = generation;
  out.observation_tick = diagnostic_tick;
  out.available = client != nullptr || pending_cleanup != nullptr || retained_diagnostic.available;
  out.connected = client && client->connected();
  out.cleanup_eligible = diagnostic_cleanup_failed && (client || thread.joinable() || pending_cleanup);
  if (out.cleanup_eligible) out.cleanup_state = "failed";
  out.freshness_ms = BoundedAge(GetTickCount64(), diagnostic_tick);
  if (client) {
    const auto fresh = client->diagnostics.Snapshot();
    out.reconnect_count = fresh.reconnects;
    out.dco_failures = fresh.send_failed;
    out.first_error = fresh.first_error;
    out.last_error = fresh.last_error;
    out.dco = true;
    if (out.connected) {
      out.phase = "completed";
      out.connection_duration_ms = BoundedAge(GetTickCount64(), client->diagnostic_connected_at);
      if (observe_owned_network) expected = client->network_configuration.Read();
      out.configuration_generation = expected.generation;
      out.freshness_ms = 0;
    }
  }
  // No IP Helper/registry work while holding the engine lifecycle mutex.
  // A subsequent disconnect, replacement or pushed configuration invalidates
  // this observation instead of delaying teardown or mixing generations.
  lock.unlock();
  if (observe_owned_network && out.connected) out.network = ReadNetworkObservation(expected);
  if (!lock.try_lock() || diagnostic_generation != generation || client.get() != observed_client ||
      (client && (client->connected() != out.connected ||
        (observe_owned_network && out.connected &&
         client->network_configuration.Read().generation != expected.generation)))) return {};
  return out;
}
bool OpenVpnCoreDiagnosticsCurrent(const std::string& user, const fuzevpn_diagnostics::EngineObservation& out) {
  if (!out.available) return true;
  std::unique_lock<std::mutex> lock(core_mutex, std::try_to_lock);
  return lock.owns_lock() && diagnostic_user == user && diagnostic_generation == out.generation &&
      bool(client && client->connected()) == out.connected &&
      (!out.configuration_generation || (client &&
       client->network_configuration.Read().generation == out.configuration_generation));
}
bool OpenVpnCoreSuspendForMigration() { std::lock_guard<std::mutex> lock(core_mutex); reconnect_cache.reset(); return Stop(); }
bool OpenVpnCoreDisconnect() { std::lock_guard<std::mutex> lock(core_mutex); reconnect_cache.reset(); if (!Stop()) return false; DisableNetworkProtection(NetworkProtectionOwner::open_vpn); return true; }
bool OpenVpnCoreDeleteIdentity() { std::lock_guard<std::mutex> lock(core_mutex); reconnect_cache.reset(); if (!Stop()) return false; const bool active = DeleteIdentity(false); const bool pending = DeleteIdentity(true); return active && pending; }

bool OpenVpnCoreRecoverNetworkState() {
  std::lock_guard<std::mutex> lock(core_mutex);
  if (client || thread.joinable() || pending_cleanup) return false;
  bool success = true, changed = false;
  for (const wchar_t* path : {openvpn::Win::Reg::gpol_nrpt_subkey,
                              openvpn::Win::Reg::local_nrpt_subkey}) {
    HKEY key = nullptr;
    const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0,
                                         KEY_READ | KEY_WRITE | DELETE, &key);
    if (opened == ERROR_FILE_NOT_FOUND) continue;
    if (opened != ERROR_SUCCESS) { success = false; continue; }
    struct KeyCleanup { HKEY key; ~KeyCleanup() { RegCloseKey(key); } } key_cleanup{key};
    std::vector<std::wstring> names;
    for (DWORD index = 0;; ++index) {
      wchar_t name[256]{}; DWORD length = static_cast<DWORD>(std::size(name));
      const auto status = RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
      if (status == ERROR_NO_MORE_ITEMS) break;
      if (status != ERROR_SUCCESS) { success = false; break; }
      names.emplace_back(name, length);
    }
    success = openvpn::Win::RecoverNrptSessions(names,
      [](const openvpn::Win::NrptSession& session) {
        using State = openvpn::Win::NrptProcessState;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, session.pid);
        if (!process) return GetLastError() == ERROR_INVALID_PARAMETER ? State::orphaned : State::unavailable;
        const auto created = openvpn::Win::ProcessCreationValue(process);
        const auto exited = WaitForSingleObject(process, 0);
        CloseHandle(process);
        if (!created || exited == WAIT_FAILED) return State::unavailable;
        return exited == WAIT_OBJECT_0 || created != session.created ? State::orphaned : State::matching_live;
      }, [&](const std::wstring& name) {
        const auto status = RegDeleteTreeW(key, name.c_str());
        if (status == ERROR_SUCCESS) changed = true;
        return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
      }) && success;
  }
  if (changed) {
    try { std::ostringstream ignored; openvpn::TunWin::DNS::ActionApply().execute(ignored); }
    catch (...) { success = false; }
  }
  return success;
}
