// SPDX-License-Identifier: MPL-2.0
#include "openvpn_tunnel.h"

#include "network_protection.h"
#include "network_protection_channel.h"
#include "privileged_broker.h"

#include <windows.h>

#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
#include "openvpn_core_module.h"
#endif

#include <memory>
#include <mutex>

#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#endif

namespace {
std::mutex channel_mutex;

const flutter::EncodableMap* Args(const flutter::MethodCall<flutter::EncodableValue>& call) {
  return std::get_if<flutter::EncodableMap>(call.arguments());
}
const std::string* Text(const flutter::EncodableMap& args, const char* name) {
  const auto it = args.find(flutter::EncodableValue(name));
  return it == args.end() ? nullptr : std::get_if<std::string>(&it->second);
}
bool Flag(const flutter::EncodableMap& args, const char* name) {
  const auto it = args.find(flutter::EncodableValue(name));
  const auto* value = it == args.end() ? nullptr : std::get_if<bool>(&it->second);
  return value && *value;
}
bool FlagOrDefault(const flutter::EncodableMap& args, const char* name,
                   bool default_value) {
  const auto it = args.find(flutter::EncodableValue(name));
  if (it == args.end()) return default_value;
  const auto* value = std::get_if<bool>(&it->second);
  return value == nullptr ? default_value : *value;
}
bool ProtectionOptions(const flutter::EncodableValue& argument,
                       NetworkProtectionOptions* protection) {
  const auto* args = std::get_if<flutter::EncodableMap>(&argument);
  if (!args || !protection) return false;
  protection->kill_switch = FlagOrDefault(*args, "killSwitch", true);
  protection->dns_protection =
      FlagOrDefault(*args, "dnsProtection", true);
  protection->web_rtc_protection =
      FlagOrDefault(*args, "webRtcProtection", true);
  return true;
}
bool StringList(const flutter::EncodableMap& args, const char* name,
                std::vector<std::string>* values, bool required) {
  const auto it = args.find(flutter::EncodableValue(name));
  if (it == args.end()) return !required;
  const auto* list = std::get_if<flutter::EncodableList>(&it->second);
  if (!list) return false;
  values->clear();
  values->reserve(list->size());
  for (const auto& item : *list) {
    const auto* value = std::get_if<std::string>(&item);
    if (!value) return false;
    values->push_back(*value);
  }
  return true;
}
void Fail(std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result, const char* code) {
  result->Error(code, "OpenVPN operation failed.");
}
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
bool Activation(const flutter::EncodableMap& args, OpenVpnActivationInput* input) {
  const auto* certificate = Text(args, "certificatePem"); const auto* ca = Text(args, "caCertificatePem");
  const auto* tls_crypt = Text(args, "tlsCryptV2ClientKey"); const auto* endpoint = Text(args, "endpoint");
  const auto* server_name = Text(args, "serverName");
  const auto* address = Text(args, "address");
  const auto list = args.find(flutter::EncodableValue("ciphers"));
  const auto* ciphers = list == args.end() ? nullptr : std::get_if<flutter::EncodableList>(&list->second);
  const auto dns_list = args.find(flutter::EncodableValue("dns"));
  const auto* dns = dns_list == args.end() ? nullptr : std::get_if<flutter::EncodableList>(&dns_list->second);
  if (!certificate || !ca || !tls_crypt || !endpoint || !address || !server_name || !ciphers || !dns) return false;
  input->certificate_pem = *certificate; input->ca_certificate_pem = *ca; input->tls_crypt_v2_client_key = *tls_crypt;
  input->endpoint = *endpoint; input->address = *address; input->server_name = *server_name; input->remote_cert_tls_server = Flag(args, "remoteCertTlsServer");
  if (!StringList(args, "addresses", &input->addresses, false) ||
      !StringList(args, "allowedIps", &input->allowed_ips, false)) return false;
  if (input->addresses.empty()) input->addresses.push_back(*address);
  input->ipv6_enabled = FlagOrDefault(args, "ipv6Enabled", false);
  // Keep the native boundary fail-closed when an older or malformed UI call
  // omits a protection flag. The remote certificate requirement above remains
  // strict and intentionally does not use this defaulting behavior.
  input->protection.kill_switch = FlagOrDefault(args, "killSwitch", true);
  input->protection.dns_protection =
      FlagOrDefault(args, "dnsProtection", true);
  input->protection.web_rtc_protection =
      FlagOrDefault(args, "webRtcProtection", true);
  for (const auto& item : *ciphers) { const auto* cipher = std::get_if<std::string>(&item); if (!cipher) return false; input->ciphers.push_back(*cipher); }
  for (const auto& item : *dns) { const auto* value = std::get_if<std::string>(&item); if (!value) return false; input->dns.push_back(*value); }
  return true;
}
void WipeActivation(OpenVpnActivationInput* input) {
  if (!input) return;
  auto wipe = [](std::string* value) { if (!value->empty()) SecureZeroMemory(value->data(), value->size()); value->clear(); };
  wipe(&input->certificate_pem); wipe(&input->ca_certificate_pem); wipe(&input->tls_crypt_v2_client_key);
  wipe(&input->endpoint); wipe(&input->address); wipe(&input->server_name);
  for (auto& address : input->addresses) wipe(&address); input->addresses.clear();
  for (auto& route : input->allowed_ips) wipe(&route); input->allowed_ips.clear();
  for (auto& cipher : input->ciphers) wipe(&cipher); input->ciphers.clear();
  for (auto& dns : input->dns) wipe(&dns); input->dns.clear();
}
#endif
}  // namespace

bool IsOpenVpnTunnelConnected() {
  std::lock_guard<std::mutex> lock(channel_mutex);
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
  return OpenVpnCoreConnected();
#else
  return false;
#endif
}

bool IsOpenVpnTunnelStopped() {
  std::lock_guard<std::mutex> lock(channel_mutex);
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
  return OpenVpnCoreStopped();
#else
  return true;
#endif
}

void HandleOpenVpnPrivilegedCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    flutter::MethodResult<flutter::EncodableValue>* result) {
  std::lock_guard<std::mutex> lock(channel_mutex);
  if (call.method_name() == "prepareConnection") {
    NetworkProtectionOptions protection;
    const auto* arguments = call.arguments();
    if (!arguments || !ProtectionOptions(*arguments, &protection)) {
      result->Error("invalid_configuration", "OpenVPN operation failed.");
      return;
    }
    if (!PrepareNetworkProtection(NetworkProtectionOwner::open_vpn,
                                  protection)) {
      result->Error("network_protection_failed",
                    "OpenVPN operation failed.");
      return;
    }
    result->Success();
    return;
  }
  if (call.method_name() == "isConnected") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    result->Success(flutter::EncodableValue(OpenVpnCoreConnected()));
#else
    result->Success(flutter::EncodableValue(false));
#endif
    return;
  }
  if (call.method_name() == "isNetworkProtectionActive") {
    result->Success(flutter::EncodableValue(IsNetworkProtectionActive(
        NetworkProtectionOwner::open_vpn)));
    return;
  }
  if (call.method_name() == "networkProtectionStatus") {
    result->Success(NetworkProtectionStatusValue(NetworkProtectionOwner::open_vpn));
    return;
  }
  if (call.method_name() == "reconnect") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    bool cache_available = false;
    const bool connected = OpenVpnCoreReconnect(&cache_available);
    if (cache_available && !connected) {
      result->Error(OpenVpnCoreFailureCode(), "OpenVPN operation failed.");
    } else {
      result->Success(flutter::EncodableValue(connected));
    }
#else
    result->Success(flutter::EncodableValue(false));
#endif
    return;
  }
  if (call.method_name() == "disconnect") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    if (!OpenVpnCoreDisconnect()) {
      result->Error(OpenVpnCoreFailureCode(), "OpenVPN could not confirm tunnel shutdown.");
      return;
    }
#endif
    result->Success();
    return;
  }
  if (call.method_name() == "suspendForMigration") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    if (!OpenVpnCoreSuspendForMigration()) {
      result->Error(OpenVpnCoreFailureCode(), "OpenVPN could not confirm tunnel shutdown.");
      return;
    }
#endif
    result->Success();
    return;
  }
  if (call.method_name() == "deleteProfile") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    if (!OpenVpnCoreDeleteIdentity()) {
      result->Error("storage_error", "OpenVPN operation failed.");
      return;
    }
#endif
    result->Success();
    return;
  }
  if (call.method_name() == "getOrCreateCsr" ||
      call.method_name() == "renewCsr") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    const auto* args = Args(call);
    const auto* account = args ? Text(*args, "accountId") : nullptr;
    const auto* device = args ? Text(*args, "deviceId") : nullptr;
    std::string csr;
    if (!account || !device ||
        !OpenVpnCoreGetCsr(*account, *device,
                           call.method_name() == "renewCsr", &csr)) {
      result->Error("openvpn_signer_unavailable",
                    "OpenVPN operation failed.");
      return;
    }
    result->Success(flutter::EncodableValue(csr));
    if (!csr.empty()) SecureZeroMemory(csr.data(), csr.size());
    return;
#else
    result->Error("openvpn_signer_unavailable",
                  "OpenVPN operation failed.");
    return;
#endif
  }
  if (call.method_name() == "importAndConnect") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
    const auto* args = Args(call);
    OpenVpnActivationInput input;
    const bool connected =
        args && Activation(*args, &input) && OpenVpnCoreConnect(input);
    WipeActivation(&input);
    if (!connected) {
      const std::string code = OpenVpnCoreFailureCode();
      result->Error(code, "OpenVPN operation failed.");
      return;
    }
    result->Success();
    return;
#else
    result->Error("openvpn_signer_unavailable",
                  "OpenVPN operation failed.");
    return;
#endif
  }
  result->NotImplemented();
}

#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterOpenVpnChannel(flutter::FlutterEngine* engine) {
  auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      engine->messenger(), "com.fuzevpn/windows_openvpn", &flutter::StandardMethodCodec::GetInstance());
  channel->SetMethodCallHandler([](const auto& call, auto result) {
    if (call.method_name() == "isConnected" ||
        call.method_name() == "isNetworkProtectionActive" ||
        call.method_name() == "networkProtectionStatus" ||
        call.method_name() == "reconnect" ||
        call.method_name() == "disconnect" ||
        call.method_name() == "suspendForMigration") {
      bool detection_failed = false;
      const auto presence = PrivilegedRuntimePresence(&detection_failed);
      if (!presence) {
        CompleteRuntimeStatusFailure(std::move(result), detection_failed);
        return;
      }
      if (!*presence) {
        if (call.method_name() == "disconnect" ||
            call.method_name() == "suspendForMigration") result->Success();
        else if (call.method_name() == "networkProtectionStatus")
          result->Success(NetworkProtectionStatusValue(NetworkProtectionOwner::open_vpn));
        else result->Success(flutter::EncodableValue(false));
        return;
      }
      ForwardPrivilegedCall("openvpn", call, std::move(result), false);
      return;
    }
    if (call.method_name() == "isAvailable") {
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
      std::lock_guard<std::mutex> lock(channel_mutex);
      result->Success(flutter::EncodableValue(OpenVpnCoreAvailable()));
#else
      result->Success(flutter::EncodableValue(false));
#endif
      return;
    }
    if (call.method_name() == "deleteProfile") {
      if (IsPrivilegedBrokerRunning()) {
        ForwardPrivilegedCall("openvpn", call, std::move(result), false);
        return;
      }
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
      std::lock_guard<std::mutex> lock(channel_mutex);
      if (!OpenVpnCoreDeleteIdentity()) { Fail(std::move(result), "storage_error"); return; }
#endif
      result->Success(); return;
    }
    if (call.method_name() == "getOrCreateCsr" || call.method_name() == "renewCsr") {
      // CSR generation and access to its DPAPI-protected private key are
      // deliberately user-scoped operations. They must not switch to the
      // elevated broker merely because an earlier tunnel used it; doing so
      // made the second connection differ from the first one.
#ifdef FUZEVPN_ENABLE_OPENVPN3_CORE
      std::lock_guard<std::mutex> lock(channel_mutex);
      const auto* args = Args(call); const auto* account = args ? Text(*args, "accountId") : nullptr; const auto* device = args ? Text(*args, "deviceId") : nullptr; std::string csr;
      if (!account || !device || !OpenVpnCoreGetCsr(*account, *device, call.method_name() == "renewCsr", &csr)) { Fail(std::move(result), "openvpn_signer_unavailable"); return; }
      result->Success(flutter::EncodableValue(csr)); SecureZeroMemory(csr.data(), csr.size()); return;
#else
      Fail(std::move(result), "openvpn_signer_unavailable"); return;
#endif
    }
    if (call.method_name() == "prepareConnection" ||
        call.method_name() == "importAndConnect") {
      ForwardPrivilegedCall("openvpn", call, std::move(result), true);
      return;
    }
    result->NotImplemented();
  });
}

void StopOpenVpnTunnel() {
  class CleanupResult final
      : public flutter::MethodResult<flutter::EncodableValue> {
   protected:
    void SuccessInternal(const flutter::EncodableValue*) override {}
    void ErrorInternal(const std::string&, const std::string&,
                       const flutter::EncodableValue*) override {}
    void NotImplementedInternal() override {}
  };
  if (!IsPrivilegedBrokerRunning()) {
    return;
  }
  flutter::MethodCall<flutter::EncodableValue> call("disconnect", nullptr);
  ForwardPrivilegedCall("openvpn", call,
                        std::make_unique<CleanupResult>(), false);
}
#endif
