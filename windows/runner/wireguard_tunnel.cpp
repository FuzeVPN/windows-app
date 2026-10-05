// SPDX-License-Identifier: MPL-2.0
#include "wireguard_tunnel.h"

#include "network_protection.h"
#include "network_protection_channel.h"
#include "api_bootstrap_resolver.h"
#include "api_bootstrap_dns.h"
#include "privileged_broker.h"
#include "secure_store_channel.h"
#include "vpn_reconnect_binding.h"
#include "wireguard_runtime_state.h"
#include "wireguard_endpoint.h"
#include "diagnostics_network.h"
#include "installation_security.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <winsvc.h>
#include "wireguard_driver_status.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#endif

namespace {

constexpr wchar_t kServiceName[] = L"WireGuardTunnel$FuzeVPN";
constexpr wchar_t kServiceDisplayName[] = L"FuzeVPN — tunnel sécurisé";
constexpr wchar_t kConfigFileName[] = L"FuzeVPN.conf";
constexpr wchar_t kRuntimeDllName[] = L"tunnel.dll";
constexpr wchar_t kServiceSwitch[] = L"--fuzevpn-wireguard-service";
constexpr char kPrivateKeyStoreKey[] = "wireguard_private_key";
constexpr char kPublicKeyStoreKey[] = "wireguard_public_key";
constexpr char kAccountBindingStoreKey[] = "wireguard_account_id";

std::mutex tunnel_mutex;

enum class TunnelFailure {
  kNone,
  kRuntimeUnavailable,
  kInvalidConfiguration,
  kKeyUnavailable,
  kStorageFailure,
  kPermissionDenied,
  kServiceFailure,
  kNetworkProtectionFailure,
  kHandshakeFailure,
  kEndpointResolutionFailure,
};

bool DisconnectTunnel(TunnelFailure* failure);
bool ResetIdentity(TunnelFailure* failure, bool release_network_protection);

struct TunnelConfiguration {
  std::string address;
  std::vector<std::string> addresses;
  std::vector<std::string> dns;
  std::string server_public_key;
  std::string endpoint;
  std::vector<std::string> allowed_ips;
  NetworkProtectionOptions protection;
};

struct ReconnectCache {
  TunnelConfiguration configuration;
  fuzevpn::VpnReconnectBinding binding;
};
std::optional<ReconnectCache> reconnect_cache;
fuzevpn::WireGuardActivePeer active_peer;
std::optional<fuzevpn_diagnostics::NetworkExpectation> diagnostic_network;
std::string diagnostic_user;
std::uint64_t diagnostic_connected_at = 0;
std::uint64_t diagnostic_observed_at = 0;
bool diagnostic_stop_failed = false;
bool diagnostic_attempt_failed = false;
std::uint64_t diagnostic_generation = 0;

void RecordDiagnosticFailure() noexcept {
  try {
    diagnostic_user = ProtectedStoreUserId();
    diagnostic_attempt_failed = true;
    diagnostic_observed_at = GetTickCount64();
  } catch (...) {}
}

class ScopedServiceHandle {
 public:
  explicit ScopedServiceHandle(SC_HANDLE handle = nullptr) : handle_(handle) {}
  ~ScopedServiceHandle() {
    if (handle_ != nullptr) {
      CloseServiceHandle(handle_);
    }
  }
  ScopedServiceHandle(const ScopedServiceHandle&) = delete;
  ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;
  ScopedServiceHandle(ScopedServiceHandle&& other) noexcept
      : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  ScopedServiceHandle& operator=(ScopedServiceHandle&& other) noexcept {
    if (this != &other) {
      reset();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  SC_HANDLE get() const { return handle_; }
  explicit operator bool() const { return handle_ != nullptr; }
  void reset() {
    if (handle_ != nullptr) {
      CloseServiceHandle(handle_);
      handle_ = nullptr;
    }
  }

 private:
  SC_HANDLE handle_;
};

class TunnelRuntime {
 public:
  using TunnelServiceFunction = BOOL(__cdecl*)(LPCWSTR);
  using GenerateKeypairFunction = void(__cdecl*)(BYTE*, BYTE*);

  TunnelRuntime() = default;
  ~TunnelRuntime() {
    if (module_ != nullptr) {
      FreeLibrary(module_);
    }
  }
  TunnelRuntime(const TunnelRuntime&) = delete;
  TunnelRuntime& operator=(const TunnelRuntime&) = delete;

  bool Load() {
    const auto directory = ExecutableDirectory();
    if (!directory.has_value()) {
      return false;
    }

    // tunnel.dll subsequently loads wireguard.dll. Keep the application
    // directory in the safe DLL search path for the lifetime of this process.
    SetDllDirectoryW(directory->c_str());
    const auto path = *directory / kRuntimeDllName;
    module_ = LoadLibraryExW(
        path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
            LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module_ == nullptr) {
      return false;
    }

    tunnel_service_ = reinterpret_cast<TunnelServiceFunction>(
        GetProcAddress(module_, "WireGuardTunnelService"));
    generate_keypair_ = reinterpret_cast<GenerateKeypairFunction>(
        GetProcAddress(module_, "WireGuardGenerateKeypair"));
    if (tunnel_service_ == nullptr || generate_keypair_ == nullptr) {
      FreeLibrary(module_);
      module_ = nullptr;
      tunnel_service_ = nullptr;
      generate_keypair_ = nullptr;
      return false;
    }
    return true;
  }

  TunnelServiceFunction tunnel_service() const { return tunnel_service_; }
  GenerateKeypairFunction generate_keypair() const { return generate_keypair_; }

  static bool AdapterLuid(std::uint64_t* result, std::uint64_t connection_deadline = 0) {
    const auto deadline = fuzevpn::WireGuardWaitDeadline(GetTickCount64(), 5000, connection_deadline);
    const auto directory = ExecutableDirectory();
    if (!directory) return false;
    HMODULE driver = LoadLibraryExW((*directory / L"wireguard.dll").c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!driver) return false;
    using OpenAdapter = void*(WINAPI*)(LPCWSTR);
    using GetAdapterLuid = void(WINAPI*)(void*, NET_LUID*);
    using CloseAdapter = void(WINAPI*)(void*);
    const auto open = reinterpret_cast<OpenAdapter>(GetProcAddress(driver, "WireGuardOpenAdapter"));
    const auto luid = reinterpret_cast<GetAdapterLuid>(GetProcAddress(driver, "WireGuardGetAdapterLUID"));
    const auto close = reinterpret_cast<CloseAdapter>(GetProcAddress(driver, "WireGuardCloseAdapter"));
    NET_LUID adapter_luid{};
    if (open && luid && close) {
      // The driver verifies that this is a WireGuard adapter. A physical
      // interface with the same address or alias cannot satisfy this lookup.
      for (unsigned attempt = 0; attempt < 50 && GetTickCount64() < deadline; ++attempt) {
        void* adapter = open(L"FuzeVPN");
        if (adapter) {
          luid(adapter, &adapter_luid);
          close(adapter);
          break;
        }
        const auto now = GetTickCount64();
        if (now >= deadline) break;
        Sleep(static_cast<DWORD>(std::min<std::uint64_t>(100, deadline - now)));
      }
    }
    FreeLibrary(driver);
    *result = adapter_luid.Value;
    return *result != 0;
  }

  static bool PeerStats(const std::string& expected_key,
                        fuzevpn::WireGuardPeerStats* result) {
    std::array<BYTE, 32> public_key{};
    DWORD key_size = static_cast<DWORD>(public_key.size());
    if (!CryptStringToBinaryA(expected_key.data(), static_cast<DWORD>(expected_key.size()),
        CRYPT_STRING_BASE64, public_key.data(), &key_size, nullptr, nullptr) ||
        key_size != public_key.size()) return false;
    const auto directory = ExecutableDirectory();
    if (!directory) return false;
    HMODULE driver = LoadLibraryExW((*directory / L"wireguard.dll").c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!driver) return false;
    using OpenAdapter = void*(WINAPI*)(LPCWSTR);
    using CloseAdapter = void(WINAPI*)(void*);
    using GetState = BOOL(WINAPI*)(void*, int*);
    using GetConfiguration = BOOL(WINAPI*)(void*, fuzevpn::wireguard_abi::Interface*, DWORD*);
    const auto open = reinterpret_cast<OpenAdapter>(GetProcAddress(driver, "WireGuardOpenAdapter"));
    const auto close = reinterpret_cast<CloseAdapter>(GetProcAddress(driver, "WireGuardCloseAdapter"));
    const auto state = reinterpret_cast<GetState>(GetProcAddress(driver, "WireGuardGetAdapterState"));
    const auto configuration = reinterpret_cast<GetConfiguration>(
        GetProcAddress(driver, "WireGuardGetConfiguration"));
    bool valid = false;
    if (open && close && state && configuration) {
      if (void* adapter = open(L"FuzeVPN")) {
        int adapter_state = 0;
        // Driver configuration contains secret key material. Allocate one
        // bounded buffer and wipe its entire allocation on every result path.
        std::vector<BYTE> buffer(64 * 1024);
        DWORD size = static_cast<DWORD>(buffer.size());
        auto* iface = reinterpret_cast<fuzevpn::wireguard_abi::Interface*>(buffer.data());
        const bool state_known = state(adapter, &adapter_state) != FALSE;
        if (state_known && adapter_state == 0) {
          *result = {};
          valid = true;
        } else if (state_known && adapter_state == 1 &&
            configuration(adapter, iface, &size) && size <= buffer.size() &&
            size >= sizeof(*iface) + sizeof(fuzevpn::wireguard_abi::Peer) &&
            iface->peers_count == 1) {
          const auto* peer = reinterpret_cast<const fuzevpn::wireguard_abi::Peer*>(
              buffer.data() + sizeof(*iface));
          if (std::memcmp(peer->public_key, public_key.data(), public_key.size()) == 0) {
            *result = {peer->tx_bytes, peer->rx_bytes, peer->last_handshake};
            valid = true;
          }
        }
        SecureZeroMemory(buffer.data(), buffer.size());
        close(adapter);
      }
    }
    FreeLibrary(driver);
    return valid;
  }

 private:
  static std::optional<std::filesystem::path> ExecutableDirectory() {
    std::wstring path(MAX_PATH, L'\0');
    DWORD length = 0;
    while (true) {
      length = GetModuleFileNameW(nullptr, path.data(),
                                  static_cast<DWORD>(path.size()));
      if (length == 0) {
        return std::nullopt;
      }
      if (length < path.size() - 1) {
        path.resize(length);
        return std::filesystem::path(path).parent_path();
      }
      path.resize(path.size() * 2);
    }
  }

  HMODULE module_ = nullptr;
  TunnelServiceFunction tunnel_service_ = nullptr;
  GenerateKeypairFunction generate_keypair_ = nullptr;
};

void SecureErase(std::string* value) {
  if (value != nullptr && !value->empty()) {
    SecureZeroMemory(value->data(), value->size());
    value->clear();
  }
}

bool IsWireGuardKey(const std::string& value) {
  if (value.size() != 44 || value.back() != '=') return false;
  for (size_t index = 0; index + 1 < value.size(); ++index) {
    const char character = value[index];
    if (!((character >= 'A' && character <= 'Z') ||
          (character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') ||
          character == '+' || character == '/')) return false;
  }
  DWORD size = 0;
  if (!CryptStringToBinaryA(value.data(), static_cast<DWORD>(value.size()),
                            CRYPT_STRING_BASE64, nullptr, &size, nullptr,
                            nullptr)) {
    return false;
  }
  return size == 32;
}

// The account identifier is not secret, but validating it ensures that the
// native key store is never bound to an arbitrary MethodChannel payload.
bool IsAccountID(const std::string& value) {
  if (value.empty() || value.size() > 128) {
    return false;
  }
  for (const char character : value) {
    const bool allowed =
        (character >= 'a' && character <= 'z') ||
        (character >= 'A' && character <= 'Z') ||
        (character >= '0' && character <= '9') || character == '-' ||
        character == '_';
    if (!allowed) {
      return false;
    }
  }
  return true;
}

bool DeleteStoredIdentity(TunnelFailure* failure) {
  if (!DeleteProtectedValue(kPrivateKeyStoreKey) ||
      !DeleteProtectedValue(kPublicKeyStoreKey) ||
      !DeleteProtectedValue(kAccountBindingStoreKey)) {
    *failure = TunnelFailure::kStorageFailure;
    return false;
  }
  return true;
}

std::string EncodeKey(const std::array<BYTE, 32>& key) {
  DWORD length = 0;
  if (!CryptBinaryToStringA(key.data(), static_cast<DWORD>(key.size()),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            nullptr, &length)) {
    return {};
  }
  std::string encoded(length, '\0');
  if (!CryptBinaryToStringA(key.data(), static_cast<DWORD>(key.size()),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            encoded.data(), &length)) {
    SecureErase(&encoded);
    return {};
  }
  if (!encoded.empty() && encoded.back() == '\0') {
    encoded.pop_back();
  }
  return encoded;
}

bool ReadStoredPublicKeyForAccount(const std::string& account_id,
                                   std::string* public_key,
                                   bool* storage_error = nullptr) {
  if (storage_error != nullptr) *storage_error = false;
  std::string private_key;
  std::string stored_public_key;
  std::string stored_account_id;
  const auto private_status = ReadProtectedValueStatus(kPrivateKeyStoreKey, &private_key);
  const auto public_status = ReadProtectedValueStatus(kPublicKeyStoreKey, &stored_public_key);
  const auto account_status = ReadProtectedValueStatus(kAccountBindingStoreKey, &stored_account_id);
  const bool private_exists = private_status == ProtectedValueReadStatus::found;
  const bool public_exists = public_status == ProtectedValueReadStatus::found;
  const bool account_exists = account_status == ProtectedValueReadStatus::found;
  if (storage_error != nullptr) {
    for (const auto status : {private_status, public_status, account_status}) {
      if (status != ProtectedValueReadStatus::found &&
          status != ProtectedValueReadStatus::not_found) *storage_error = true;
    }
    *storage_error |= (private_exists && !IsWireGuardKey(private_key)) ||
        (public_exists && !IsWireGuardKey(stored_public_key)) ||
        (account_exists && !IsAccountID(stored_account_id));
  }
  const bool valid =
      private_exists && public_exists && IsWireGuardKey(private_key) &&
      IsWireGuardKey(stored_public_key) && account_exists &&
      IsAccountID(stored_account_id) && stored_account_id == account_id;
  if (valid) {
    *public_key = stored_public_key;
  }
  SecureErase(&private_key);
  SecureErase(&stored_public_key);
  SecureErase(&stored_account_id);
  return valid;
}

bool CreateIdentityForAccount(const std::string& account_id,
                              std::string* public_key,
                              TunnelFailure* failure) {
  TunnelRuntime runtime;
  if (!runtime.Load()) {
    *failure = TunnelFailure::kRuntimeUnavailable;
    return false;
  }

  std::array<BYTE, 32> public_bytes{};
  std::array<BYTE, 32> private_bytes{};
  runtime.generate_keypair()(public_bytes.data(), private_bytes.data());
  std::string generated_public_key = EncodeKey(public_bytes);
  std::string generated_private_key = EncodeKey(private_bytes);
  SecureZeroMemory(public_bytes.data(), public_bytes.size());
  SecureZeroMemory(private_bytes.data(), private_bytes.size());
  if (!IsWireGuardKey(generated_public_key) ||
      !IsWireGuardKey(generated_private_key) ||
      !WriteProtectedValue(kPrivateKeyStoreKey, generated_private_key) ||
      !WriteProtectedValue(kPublicKeyStoreKey, generated_public_key) ||
      !WriteProtectedValue(kAccountBindingStoreKey, account_id)) {
    TunnelFailure cleanup_failure = TunnelFailure::kNone;
    DeleteStoredIdentity(&cleanup_failure);
    SecureErase(&generated_private_key);
    SecureErase(&generated_public_key);
    *failure = TunnelFailure::kStorageFailure;
    return false;
  }

  *public_key = generated_public_key;
  SecureErase(&generated_private_key);
  SecureErase(&generated_public_key);
  return true;
}

bool GetOrCreatePublicKey(const std::string& account_id,
                           std::string* public_key,
                           TunnelFailure* failure,
                           bool release_network_protection) {
  if (!IsAccountID(account_id)) {
    *failure = TunnelFailure::kKeyUnavailable;
    return false;
  }
  bool storage_error = false;
  if (ReadStoredPublicKeyForAccount(account_id, public_key, &storage_error)) {
    return true;
  }
  if (storage_error) {
    *failure = TunnelFailure::kStorageFailure;
    return false;
  }

  // This is either a migrated installation with no account binding or a
  // different VPN account. Stop any active tunnel before permanently removing
  // its native-only identity so a key can never be reused across accounts.
  if (!ResetIdentity(failure, release_network_protection)) {
    return false;
  }
  return CreateIdentityForAccount(account_id, public_key, failure);
}

// Creates or validates an account-bound key pair without returning even the
// public key to Dart. This is used as soon as a user signs in.
bool PrepareIdentityForAccount(const std::string& account_id,
                               TunnelFailure* failure) {
  std::string ignored_public_key;
  const bool success =
      GetOrCreatePublicKey(account_id, &ignored_public_key, failure, true);
  SecureErase(&ignored_public_key);
  return success;
}

bool IsAllowedAddressCharacter(char value, bool allow_slash) {
  if ((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
      (value >= 'A' && value <= 'F') || value == '.' || value == ':') {
    return true;
  }
  return allow_slash && value == '/';
}

bool IsAddressValue(const std::string& value, bool allow_slash) {
  if (value.empty() || value.size() > 96) {
    return false;
  }
  for (const char character : value) {
    if (!IsAllowedAddressCharacter(character, allow_slash)) {
      return false;
    }
  }
  return true;
}

bool IsIPv4Cidr(const std::string& value) {
  const size_t slash = value.find('/');
  if (slash == std::string::npos || slash == 0 ||
      value.find('/', slash + 1) != std::string::npos) {
    return false;
  }
  const std::string raw_address = value.substr(0, slash);
  const std::string raw_prefix = value.substr(slash + 1);
  if (raw_prefix.empty()) return false;
  for (const char character : raw_prefix) {
    if (character < '0' || character > '9') return false;
  }
  char* end = nullptr;
  const long prefix = std::strtol(raw_prefix.c_str(), &end, 10);
  if (end == raw_prefix.c_str() || *end != '\0' || prefix < 0 || prefix > 32) {
    return false;
  }
  size_t start = 0;
  for (int group = 0; group < 4; ++group) {
    const size_t dot = raw_address.find('.', start);
    const bool final_group = group == 3;
    if ((final_group && dot != std::string::npos) ||
        (!final_group && dot == std::string::npos)) {
      return false;
    }
    const size_t finish = final_group ? raw_address.size() : dot;
    const std::string part = raw_address.substr(start, finish - start);
    if (part.empty() || part.size() > 3 ||
        (part.size() > 1 && part.front() == '0')) {
      return false;
    }
    for (const char character : part) {
      if (character < '0' || character > '9') return false;
    }
    char* part_end = nullptr;
    const long octet = std::strtol(part.c_str(), &part_end, 10);
    if (part_end == part.c_str() || *part_end != '\0' || octet < 0 ||
        octet > 255) {
      return false;
    }
    start = finish + 1;
  }
  return true;
}

bool IsUlaIPv6HostCidr(const std::string& value) {
  const size_t slash = value.find('/');
  if (slash == std::string::npos || value.substr(slash + 1) != "128") {
    return false;
  }
  const std::string raw_address = value.substr(0, slash);
  if (raw_address.empty() || raw_address.find('.') != std::string::npos) {
    return false;
  }
  const size_t compression = raw_address.find("::");
  if (compression == std::string::npos && raw_address.back() == ':') {
    return false;
  }
  if (compression != std::string::npos &&
      raw_address.find("::", compression + 2) != std::string::npos) {
    return false;
  }
  auto count_groups = [](std::string_view part, size_t* count,
                         unsigned long* first_group) {
    if (part.empty()) return true;
    size_t start = 0;
    while (start < part.size()) {
      const size_t colon = part.find(':', start);
      const size_t finish = colon == std::string_view::npos ? part.size() : colon;
      const std::string group(part.substr(start, finish - start));
      if (group.empty() || group.size() > 4) return false;
      for (const char character : group) {
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f') ||
              (character >= 'A' && character <= 'F'))) {
          return false;
        }
      }
      char* end = nullptr;
      const unsigned long parsed = std::strtoul(group.c_str(), &end, 16);
      if (end == group.c_str() || *end != '\0' || parsed > 0xffff) return false;
      if (*count == 0 && first_group != nullptr) *first_group = parsed;
      ++*count;
      if (colon == std::string_view::npos) break;
      start = colon + 1;
    }
    return true;
  };
  size_t groups = 0;
  unsigned long first_group = 0;
  if (compression == std::string::npos) {
    if (!count_groups(raw_address, &groups, &first_group) || groups != 8) {
      return false;
    }
  } else {
    if (!count_groups(std::string_view(raw_address).substr(0, compression),
                      &groups, &first_group) ||
        !count_groups(std::string_view(raw_address).substr(compression + 2),
                      &groups, nullptr) ||
        groups >= 8) {
      return false;
    }
  }
  return groups > 0 && first_group >= 0xfc00 && first_group <= 0xfdff;
}

bool IsEndpointValue(const std::string& value) {
  fuzevpn::WireGuardEndpoint endpoint;
  return fuzevpn::ParseWireGuardEndpoint(value, &endpoint);
}

bool IsValidConfiguration(const TunnelConfiguration& configuration,
                          const std::string& private_key) {
  if (!IsWireGuardKey(private_key) ||
      !IsWireGuardKey(configuration.server_public_key) ||
      !IsIPv4Cidr(configuration.address) ||
      !IsEndpointValue(configuration.endpoint) || configuration.dns.empty() ||
      configuration.dns.size() > 8 || configuration.allowed_ips.empty() ||
      configuration.allowed_ips.size() > 16 ||
      configuration.addresses.empty() || configuration.addresses.size() > 2 ||
      configuration.addresses.front() != configuration.address) {
    return false;
  }
  for (const auto& dns : configuration.dns) {
    if (!IsAddressValue(dns, false)) {
      return false;
    }
  }
  for (const auto& allowed_ip : configuration.allowed_ips) {
    if (!IsAddressValue(allowed_ip, true)) {
      return false;
    }
  }
  if (configuration.addresses.size() == 2) {
    if (!IsUlaIPv6HostCidr(configuration.addresses[1]) ||
        configuration.allowed_ips.size() != 2 ||
        configuration.allowed_ips[0] != "0.0.0.0/0" ||
        configuration.allowed_ips[1] != "::/0") {
      return false;
    }
  } else if (configuration.allowed_ips.size() == 2 &&
             configuration.allowed_ips[1] == "::/0") {
    return false;
  }
  return true;
}

std::string ToWgQuickConfiguration(const TunnelConfiguration& configuration,
                                   const std::string& private_key) {
  std::string result;
  result.reserve(512);
  result += "[Interface]\nPrivateKey = ";
  result += private_key;
  result += "\nAddress = ";
  for (size_t index = 0; index < configuration.addresses.size(); ++index) {
    if (index != 0) {
      result += ", ";
    }
    result += configuration.addresses[index];
  }
  result += "\nDNS = ";
  for (size_t index = 0; index < configuration.dns.size(); ++index) {
    if (index != 0) {
      result += ", ";
    }
    result += configuration.dns[index];
  }
  result += "\n\n[Peer]\nPublicKey = ";
  result += configuration.server_public_key;
  result += "\nEndpoint = ";
  result += configuration.endpoint;
  result += "\nAllowedIPs = ";
  // /0 activates WireGuard's independent firewall. Retain that second safety
  // net for kill-switch sessions; equivalent /1 routes honor an explicit opt-out.
  const auto routes = fuzevpn::WireGuardRoutes(configuration.allowed_ips,
                                              configuration.protection.kill_switch);
  for (size_t index = 0; index < routes.size(); ++index) {
    if (index != 0) {
      result += ", ";
    }
    result += routes[index];
  }
  result += "\nPersistentKeepalive = 25\n";
  return result;
}

std::optional<std::filesystem::path> TunnelConfigPath() {
  fuzevpn_installation::ProtectedRuntimeDirectory directory;
  if (!directory.Open(false)) return std::nullopt;
  return directory.path() / kConfigFileName;
}

bool WriteRestrictedConfiguration(const std::string& configuration) {
  fuzevpn_installation::ProtectedRuntimeDirectory directory;
  if (!directory.Open(true)) return false;
  const auto config_path = directory.path() / kConfigFileName;
  auto temporary = config_path;
  temporary += L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
               std::to_wstring(GetTickCount64());
  struct TemporaryCleanup {
    const std::filesystem::path& path;
    ~TemporaryCleanup() { std::error_code ignored; std::filesystem::remove(path, ignored); }
  } temporary_cleanup{temporary};
  HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  const bool complete = configuration.size() <= MAXDWORD &&
      WriteFile(file, configuration.data(), static_cast<DWORD>(configuration.size()),
                &written, nullptr) && written == configuration.size() && FlushFileBuffers(file);
  CloseHandle(file);
  if (!complete) return false;
  if (!MoveFileExW(temporary.c_str(), config_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    return false;
  }
  return true;
}

void RemoveRestrictedConfiguration() {
  fuzevpn_installation::ProtectedRuntimeDirectory directory;
  if (!directory.Open(false)) return;
  const auto path = directory.path() / kConfigFileName;
  std::error_code error;
  std::filesystem::remove(path, error);
}

TunnelFailure FailureForLastError(DWORD error) {
  return error == ERROR_ACCESS_DENIED ? TunnelFailure::kPermissionDenied
                                      : TunnelFailure::kServiceFailure;
}

bool WaitForServiceState(SC_HANDLE service, DWORD expected_state,
                         DWORD timeout_ms, std::uint64_t connection_deadline = 0) {
  const auto deadline = fuzevpn::WireGuardWaitDeadline(GetTickCount64(), timeout_ms, connection_deadline);
  SERVICE_STATUS status{};
  do {
    if (!QueryServiceStatus(service, &status)) {
      return false;
    }
    if (status.dwCurrentState == expected_state) {
      return true;
    }
    if (expected_state == SERVICE_RUNNING &&
        status.dwCurrentState == SERVICE_STOPPED) {
      return false;
    }
    const auto now = GetTickCount64();
    if (now >= deadline) return false;
    Sleep(static_cast<DWORD>(std::min<std::uint64_t>(100, deadline - now)));
  } while (GetTickCount64() < deadline);
  return false;
}

bool WaitForServiceDeletion(SC_HANDLE manager, DWORD timeout_ms,
                            std::uint64_t connection_deadline = 0) {
  const auto deadline = fuzevpn::WireGuardWaitDeadline(GetTickCount64(), timeout_ms, connection_deadline);
  do {
    SC_HANDLE service =
        OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
      const DWORD error = GetLastError();
      if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
        return true;
      }
      if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
        return false;
      }
    } else {
      CloseServiceHandle(service);
    }
    const auto now = GetTickCount64();
    if (now >= deadline) return false;
    Sleep(static_cast<DWORD>(std::min<std::uint64_t>(50, deadline - now)));
  } while (GetTickCount64() < deadline);
  return false;
}

bool StopServiceForReuse(TunnelFailure* failure, std::uint64_t connection_deadline = 0) {
  ScopedServiceHandle manager(
      OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  ScopedServiceHandle service(OpenServiceW(
      manager.get(), kServiceName, SERVICE_QUERY_STATUS | SERVICE_STOP));
  if (!service) {
    const DWORD error = GetLastError();
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      return true;
    }
    // Accept and finish cleaning a service left marked for deletion by an
    // older build. New builds keep the service registered for this session.
    if (error == ERROR_SERVICE_MARKED_FOR_DELETE &&
        WaitForServiceDeletion(manager.get(), 5000, connection_deadline)) {
      return true;
    }
    *failure = FailureForLastError(error);
    return false;
  }

  SERVICE_STATUS status{};
  if (!QueryServiceStatus(service.get(), &status)) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  if (status.dwCurrentState == SERVICE_STOPPED) {
    return true;
  }
  if (status.dwCurrentState != SERVICE_STOP_PENDING) {
    if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status) &&
        GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
      *failure = FailureForLastError(GetLastError());
      return false;
    }
  }
  if (!WaitForServiceState(service.get(), SERVICE_STOPPED, 20000, connection_deadline)) {
    *failure = TunnelFailure::kServiceFailure;
    return false;
  }
  return true;
}

bool StopAndDeleteService(TunnelFailure* failure) {
  ScopedServiceHandle manager(
      OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  ScopedServiceHandle service(OpenServiceW(
      manager.get(), kServiceName,
      SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE));
  if (!service) {
    const DWORD error = GetLastError();
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      return true;
    }
    if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
      if (WaitForServiceDeletion(manager.get(), 5000)) {
        return true;
      }
    }
    *failure = FailureForLastError(error);
    return false;
  }

  SERVICE_STATUS status{};
  if (QueryServiceStatus(service.get(), &status) &&
      status.dwCurrentState != SERVICE_STOPPED) {
    ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
    if (!WaitForServiceState(service.get(), SERVICE_STOPPED, 20000)) {
      *failure = TunnelFailure::kServiceFailure;
      return false;
    }
  }
  bool deletion_requested = DeleteService(service.get()) != FALSE;
  if (!deletion_requested) {
    const DWORD error = GetLastError();
    if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
      *failure = FailureForLastError(error);
      return false;
    }
    deletion_requested = true;
  }
  // SCM keeps a deleted service record alive until every handle is closed.
  // Do not report completion until that record has actually disappeared: a
  // following Connect must be able to reuse the service name immediately.
  service.reset();
  if (!deletion_requested ||
      !WaitForServiceDeletion(manager.get(), 5000)) {
    *failure = TunnelFailure::kServiceFailure;
    return false;
  }
  return true;
}

bool StartServiceForConfig(const std::filesystem::path& config_path,
                           TunnelFailure* failure, std::uint64_t connection_deadline = 0) {
  if (connection_deadline && GetTickCount64() >= connection_deadline) {
    *failure = TunnelFailure::kServiceFailure;
    return false;
  }
  std::wstring executable(MAX_PATH, L'\0');
  const DWORD size = GetModuleFileNameW(
      nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  if (size == 0 || size >= executable.size() - 1) {
    *failure = TunnelFailure::kServiceFailure;
    return false;
  }
  executable.resize(size);
  const std::wstring command = L"\"" + executable + L"\" " +
                               kServiceSwitch + L" \"" +
                               config_path.wstring() + L"\"";
  const wchar_t dependencies[] = L"Nsi\0TcpIp\0\0";

  ScopedServiceHandle manager(OpenSCManagerW(
      nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
  if (!manager) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  ScopedServiceHandle service(OpenServiceW(
      manager.get(), kServiceName,
      SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG));
  if (!service) {
    const DWORD open_error = GetLastError();
    if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
      *failure = FailureForLastError(open_error);
      return false;
    }
    service = ScopedServiceHandle(CreateServiceW(
        manager.get(), kServiceName, kServiceDisplayName, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        command.c_str(), nullptr, nullptr, dependencies, nullptr, nullptr));
    if (!service) {
      *failure = FailureForLastError(GetLastError());
      return false;
    }
  } else if (!ChangeServiceConfigW(
                 service.get(), SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                 SERVICE_NO_CHANGE, command.c_str(), nullptr, nullptr,
                 dependencies, nullptr, nullptr, kServiceDisplayName)) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }

  SERVICE_SID_INFO sid_info{};
  sid_info.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
  if (!ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_SERVICE_SID_INFO,
                             &sid_info)) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  SERVICE_STATUS status{};
  if (!QueryServiceStatus(service.get(), &status)) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  if (status.dwCurrentState != SERVICE_RUNNING &&
      (!StartServiceW(service.get(), 0, nullptr) &&
       GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)) {
    *failure = FailureForLastError(GetLastError());
    return false;
  }
  if (!WaitForServiceState(service.get(), SERVICE_RUNNING, 20000, connection_deadline)) {
    *failure = TunnelFailure::kServiceFailure;
    return false;
  }
  return true;
}

std::optional<DWORD> QueryServiceState() {
  ScopedServiceHandle manager(
      OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
  if (!manager) {
    return std::nullopt;
  }
  ScopedServiceHandle service(
      OpenServiceW(manager.get(), kServiceName, SERVICE_QUERY_STATUS));
  if (!service) {
    return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST
        ? std::optional<DWORD>(SERVICE_STOPPED) : std::nullopt;
  }
  SERVICE_STATUS status{};
  if (!QueryServiceStatus(service.get(), &status)) return std::nullopt;
  return status.dwCurrentState;
}

std::optional<bool> QueryServiceRunning() {
  const auto state = QueryServiceState();
  return state ? std::optional<bool>(*state == SERVICE_RUNNING) : std::nullopt;
}

bool IsServiceRunning() { return QueryServiceRunning().value_or(false); }

void SolicitHandshake(const TunnelConfiguration& configuration, std::uint64_t luid_value) {
  WSADATA winsock{};
  if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return;
  NET_LUID luid{};
  luid.Value = luid_value;
  NET_IFINDEX index = 0;
  if (ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR || !index) {
    WSACleanup();
    return;
  }
  // This fixed DNS question merely creates tunneled traffic. No DNS answer is
  // trusted here: success is exclusively the authenticated driver handshake.
  const auto query = fuzevpn::bootstrap::Query(0x4655, false);
  for (const auto& dns : configuration.dns) {
    SOCKADDR_STORAGE destination{};
    auto* ipv4 = reinterpret_cast<SOCKADDR_IN*>(&destination);
    auto* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(&destination);
    int length = 0;
    if (InetPtonA(AF_INET, dns.c_str(), &ipv4->sin_addr) == 1) {
      ipv4->sin_family = AF_INET;
      ipv4->sin_port = htons(53);
      length = sizeof(*ipv4);
    } else if (InetPtonA(AF_INET6, dns.c_str(), &ipv6->sin6_addr) == 1) {
      ipv6->sin6_family = AF_INET6;
      ipv6->sin6_port = htons(53);
      length = sizeof(*ipv6);
    } else continue;
    const auto family = destination.ss_family;
    const SOCKET socket = WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                                     WSA_FLAG_NO_HANDLE_INHERIT);
    if (socket == INVALID_SOCKET) continue;
    const DWORD interface_index = family == AF_INET ? htonl(index) : index;
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) == 0 &&
        setsockopt(socket, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                   family == AF_INET ? IP_UNICAST_IF : IPV6_UNICAST_IF,
                   reinterpret_cast<const char*>(&interface_index), sizeof(interface_index)) == 0) {
      sendto(socket, reinterpret_cast<const char*>(query.data()),
             static_cast<int>(query.size()), 0,
             reinterpret_cast<const SOCKADDR*>(&destination), length);
    }
    closesocket(socket);
  }
  WSACleanup();
}

bool WaitForAuthenticatedPeer(const TunnelConfiguration& configuration,
                              std::uint64_t interface_luid,
                              fuzevpn::WireGuardPeerStats* authenticated_stats,
                              std::uint64_t connection_deadline = 0) {
  // DNS, SCM, adapter, handshake and cleanup all share the connection deadline.
  const auto deadline = fuzevpn::WireGuardWaitDeadline(GetTickCount64(), 8000, connection_deadline);
  ULONGLONG next_probe = 0;
  do {
    const auto now = GetTickCount64();
    if (now >= deadline) return false;
    if (now >= next_probe) {
      SolicitHandshake(configuration, interface_luid);
      next_probe = now + 1000;
    }
    fuzevpn::WireGuardPeerStats stats;
    if (TunnelRuntime::PeerStats(configuration.server_public_key, &stats) && stats.handshake) {
      *authenticated_stats = stats;
      return true;
    }
    if (!IsServiceRunning()) return false;
    const auto after_read = GetTickCount64();
    if (after_read >= deadline) return false;
    Sleep(static_cast<DWORD>(std::min<std::uint64_t>(100, deadline - after_read)));
  } while (GetTickCount64() < deadline);
  return false;
}

std::optional<bool> ConnectedPeerState() {
  const auto running = QueryServiceRunning();
  if (!running) return std::nullopt;
  if (!*running || active_peer.public_key().empty() || !IsTunnelNetworkProtectionActive(
          NetworkProtectionOwner::wire_guard)) return false;
  fuzevpn::WireGuardPeerStats stats;
  if (!TunnelRuntime::PeerStats(active_peer.public_key(), &stats))
    return std::nullopt;
  return active_peer.Observe(stats, GetTickCount64());
}

bool ConnectTunnel(const TunnelConfiguration& configuration,
                    TunnelFailure* failure) {
  // Leave 5 s of margin under the 75 s broker response deadline. Synchronous
  // Windows/driver calls cannot be forcibly interrupted, but all our waits,
  // including failure cleanup, consume this one monotonic budget.
  const auto connection_deadline = GetTickCount64() + 70000;
  const std::string user = ProtectedStoreUserId();
  std::string account;
  std::string public_key;
  if (user.empty() || !ReadProtectedValue(kAccountBindingStoreKey, &account) ||
      !IsAccountID(account) || !ReadStoredPublicKeyForAccount(account, &public_key)) {
    *failure = TunnelFailure::kKeyUnavailable;
    return false;
  }
  std::string private_key;
  if (!ReadProtectedValue(kPrivateKeyStoreKey, &private_key) ||
      !IsWireGuardKey(private_key)) {
    SecureErase(&private_key);
    *failure = TunnelFailure::kKeyUnavailable;
    return false;
  }
  if (!IsValidConfiguration(configuration, private_key)) {
    SecureErase(&private_key);
    *failure = TunnelFailure::kInvalidConfiguration;
    return false;
  }

  // Arm a service-owned fail-closed policy before touching the existing
  // tunnel service or its configuration. Flutter normally prepares this phase
  // before reporting `connecting`, but keeping this defensive call here also
  // protects reconnects and older callers. Every later failure deliberately
  // retains the prefilter until an explicit Disconnect.
  TunnelFailure stop_failure = TunnelFailure::kNone;
  std::vector<std::string> numeric_endpoints;
  const auto endpoint_result = fuzevpn::PrepareWireGuardEndpoints(configuration.endpoint,
      [&]() { return PrepareNetworkProtection(NetworkProtectionOwner::wire_guard, configuration.protection); },
      [&]() {
        // Resolve after stopping the old /0 tunnel's independent firewall.
        if (!StopServiceForReuse(&stop_failure, connection_deadline)) return false;
        active_peer.StopResult(true);
        RemoveRestrictedConfiguration();
        return true;
      },
      [&](const std::string& host, std::vector<std::string>* addresses) {
        return ResolveWireGuardEndpointAddresses(host, connection_deadline, addresses);
      }, &numeric_endpoints);
  if (endpoint_result != fuzevpn::WireGuardEndpointResult::ready) {
    SecureErase(&private_key);
    switch (endpoint_result) {
      case fuzevpn::WireGuardEndpointResult::invalid:
        *failure = TunnelFailure::kInvalidConfiguration; break;
      case fuzevpn::WireGuardEndpointResult::protection_failed:
        *failure = TunnelFailure::kNetworkProtectionFailure; break;
      case fuzevpn::WireGuardEndpointResult::stop_failed:
        *failure = stop_failure; break;
      default:
        *failure = TunnelFailure::kEndpointResolutionFailure; break;
    }
    return false;
  }
  // Only ephemeral copies become numeric. Retry under the same prepared policy
  // and retain the original hostname for the next reconnection's DNS lookup.
  const bool connected = fuzevpn::TryWireGuardEndpoints(numeric_endpoints,
      connection_deadline, []() { return GetTickCount64(); },
      [&](const std::string& endpoint, std::uint64_t attempt_deadline) {
        using Outcome = fuzevpn::WireGuardAttemptResult;
        TunnelConfiguration resolved = configuration;
        resolved.endpoint = endpoint;
        std::string config_text = ToWgQuickConfiguration(resolved, private_key);
        const bool written = WriteRestrictedConfiguration(config_text);
        SecureErase(&config_text);
        if (!written) {
          *failure = TunnelFailure::kStorageFailure;
          return Outcome::failed;
        }
        const auto path = TunnelConfigPath();
        if (!path || !StartServiceForConfig(*path, failure, attempt_deadline)) {
          TunnelFailure cleanup = TunnelFailure::kNone;
          StopServiceForReuse(&cleanup, connection_deadline);
          RemoveRestrictedConfiguration();
          return Outcome::failed;
        }
        std::uint64_t interface_luid = 0;
        fuzevpn::WireGuardPeerStats stats;
        if (!TunnelRuntime::AdapterLuid(&interface_luid, attempt_deadline) ||
            !WaitForAuthenticatedPeer(configuration, interface_luid, &stats, attempt_deadline)) {
          TunnelFailure cleanup = TunnelFailure::kNone;
          const bool stopped = StopServiceForReuse(&cleanup, connection_deadline);
          RemoveRestrictedConfiguration();
          *failure = stopped ? TunnelFailure::kHandshakeFailure : cleanup;
          return stopped ? Outcome::retry : Outcome::failed;
        }
        if (!PromoteNetworkProtection(NetworkProtectionOwner::wire_guard,
                                      interface_luid, configuration.protection)) {
          TunnelFailure cleanup = TunnelFailure::kNone;
          StopServiceForReuse(&cleanup, connection_deadline);
          RemoveRestrictedConfiguration();
          *failure = TunnelFailure::kNetworkProtectionFailure;
          return Outcome::failed;
        }
        active_peer.Activate(configuration.server_public_key, stats, GetTickCount64());
        // Keep only the native expectations needed for a later passive check.
        // Diagnostic allocations never alter whether the tunnel connected.
        try {
          NET_LUID luid{}; luid.Value = interface_luid;
          NET_IFINDEX index = 0;
          if (ConvertInterfaceLuidToIndex(&luid, &index) == NO_ERROR) {
            diagnostic_network = fuzevpn_diagnostics::NetworkExpectation{
                interface_luid, index, configuration.addresses,
                fuzevpn::WireGuardRoutes(configuration.allowed_ips, configuration.protection.kill_switch),
                configuration.dns, {}};
          } else diagnostic_network.reset();
          diagnostic_user = user;
          diagnostic_connected_at = GetTickCount64();
          diagnostic_observed_at = diagnostic_connected_at;
          diagnostic_stop_failed = false;
          diagnostic_attempt_failed = false;
        } catch (...) { diagnostic_network.reset(); }
        reconnect_cache = ReconnectCache{configuration, {user, account, public_key, {}}};
        return Outcome::connected;
      });
  SecureErase(&private_key);
  if (!connected && *failure == TunnelFailure::kNone)
    *failure = TunnelFailure::kHandshakeFailure;
  return connected;
}

bool DisconnectTunnel(TunnelFailure* failure) {
  reconnect_cache.reset();
  // Stopping the service fully tears down the WireGuard adapter. Keep only the
  // inert registration so the next Connect can call StartService immediately
  // instead of deleting and recreating an SCM object.
  const bool stopped = StopServiceForReuse(failure);
  diagnostic_stop_failed = !stopped;
  active_peer.StopResult(stopped);
  if (stopped) {
    DisableNetworkProtection(NetworkProtectionOwner::wire_guard);
    RemoveRestrictedConfiguration();
    diagnostic_network.reset();
  }
  return stopped;
}

bool SuspendTunnelForMigration(TunnelFailure* failure) {
  reconnect_cache.reset();
  const bool stopped = StopServiceForReuse(failure);
  diagnostic_stop_failed = !stopped;
  active_peer.StopResult(stopped);
  if (!stopped) return false;
  // A migration is not an explicit request to release the fail-closed policy.
  // The next preparation/promotion replaces it only after a candidate commits.
  RemoveRestrictedConfiguration();
  return true;
}

// Revocation of the current device must also remove its local identity. This
// code executes entirely in the native runner: the private key is never read
// into Dart or returned through the MethodChannel.
bool ResetIdentity(TunnelFailure* failure,
                   bool release_network_protection = true) {
  reconnect_cache.reset();
  const bool stopped = StopServiceForReuse(failure);
  active_peer.StopResult(stopped);
  if (!stopped) {
    return false;
  }
  if (release_network_protection) {
    DisableNetworkProtection(NetworkProtectionOwner::wire_guard);
  }
  RemoveRestrictedConfiguration();
  return DeleteStoredIdentity(failure);
}

// Replacing an identity is one privileged operation. Keeping the stop, erase
// and creation under the same native mutex prevents the UI from observing a
// half-reset identity or trying to load the WireGuard runtime itself.
bool RecreateIdentityForAccount(const std::string& account_id,
                                TunnelFailure* failure) {
  if (!IsAccountID(account_id)) {
    *failure = TunnelFailure::kKeyUnavailable;
    return false;
  }
  // This path is used while a connection attempt already owns a prepared WFP
  // policy. Replacing the local key must not release that policy between the
  // revocation response and the retrying control-plane request.
  if (!ResetIdentity(failure, false)) {
    return false;
  }
  std::string ignored_public_key;
  const bool success =
      CreateIdentityForAccount(account_id, &ignored_public_key, failure);
  SecureErase(&ignored_public_key);
  return success;
}

const std::string* StringArgument(const flutter::EncodableMap& arguments,
                                  const char* name) {
  const auto it = arguments.find(flutter::EncodableValue(name));
  return it == arguments.end() ? nullptr
                               : std::get_if<std::string>(&it->second);
}

bool StringListArgument(const flutter::EncodableMap& arguments,
                        const char* name, std::vector<std::string>* values) {
  const auto it = arguments.find(flutter::EncodableValue(name));
  if (it == arguments.end()) {
    return false;
  }
  const auto* list = std::get_if<flutter::EncodableList>(&it->second);
  if (list == nullptr) {
    return false;
  }
  values->clear();
  values->reserve(list->size());
  for (const auto& item : *list) {
    const auto* value = std::get_if<std::string>(&item);
    if (value == nullptr) {
      return false;
    }
    values->push_back(*value);
  }
  return true;
}

bool BoolArgument(const flutter::EncodableMap& arguments, const char* name,
                  bool default_value) {
  const auto it = arguments.find(flutter::EncodableValue(name));
  if (it == arguments.end()) {
    return default_value;
  }
  const auto* value = std::get_if<bool>(&it->second);
  return value == nullptr ? default_value : *value;
}

bool DecodeConfiguration(const flutter::EncodableValue& argument,
                          TunnelConfiguration* configuration) {
  const auto* arguments = std::get_if<flutter::EncodableMap>(&argument);
  if (arguments == nullptr) {
    return false;
  }
  const auto* address = StringArgument(*arguments, "address");
  const auto* server_public_key =
      StringArgument(*arguments, "serverPublicKey");
  const auto* endpoint = StringArgument(*arguments, "endpoint");
  if (address == nullptr || server_public_key == nullptr || endpoint == nullptr ||
      !StringListArgument(*arguments, "dns", &configuration->dns) ||
      !StringListArgument(*arguments, "allowedIps", &configuration->allowed_ips)) {
    return false;
  }
  configuration->address = *address;
  const auto addresses_it =
      arguments->find(flutter::EncodableValue("addresses"));
  if (addresses_it == arguments->end()) {
    configuration->addresses = {*address};
  } else if (!StringListArgument(*arguments, "addresses",
                                 &configuration->addresses)) {
    return false;
  }
  configuration->server_public_key = *server_public_key;
  configuration->endpoint = *endpoint;
  configuration->protection.kill_switch =
      BoolArgument(*arguments, "killSwitch", true);
  configuration->protection.dns_protection =
      BoolArgument(*arguments, "dnsProtection", true);
  configuration->protection.web_rtc_protection =
      BoolArgument(*arguments, "webRtcProtection", true);
  return true;
}

bool DecodeProtectionOptions(const flutter::EncodableValue& argument,
                             NetworkProtectionOptions* protection) {
  const auto* arguments = std::get_if<flutter::EncodableMap>(&argument);
  if (arguments == nullptr) {
    return false;
  }
  protection->kill_switch = BoolArgument(*arguments, "killSwitch", true);
  protection->dns_protection =
      BoolArgument(*arguments, "dnsProtection", true);
  protection->web_rtc_protection =
      BoolArgument(*arguments, "webRtcProtection", true);
  return true;
}

std::pair<const char*, const char*> PublicFailure(TunnelFailure failure) {
  switch (failure) {
    case TunnelFailure::kRuntimeUnavailable:
      return {"runtime_unavailable",
              "L’installation de FuzeVPN est incomplète. Réinstallez l’application."};
    case TunnelFailure::kKeyUnavailable:
      return {"key_unavailable",
              "L’identité sécurisée de cet appareil ne peut pas être utilisée."};
    case TunnelFailure::kStorageFailure:
      return {"storage_failure",
              "FuzeVPN ne peut pas préparer la configuration sécurisée."};
    case TunnelFailure::kPermissionDenied:
      return {"permission_denied",
              "Windows doit autoriser FuzeVPN à configurer le tunnel VPN."};
    case TunnelFailure::kInvalidConfiguration:
      return {"invalid_configuration",
              "La configuration reçue du service VPN est invalide."};
    case TunnelFailure::kServiceFailure:
      return {"tunnel_failure",
              "Le tunnel VPN n’a pas pu être démarré."};
    case TunnelFailure::kNetworkProtectionFailure:
      return {"network_protection_failed",
              "Windows n’a pas pu activer la protection contre les fuites réseau."};
    case TunnelFailure::kHandshakeFailure:
      return {"tunnel_handshake_timeout",
              "Le serveur VPN n’a pas confirmé la connexion sécurisée."};
    case TunnelFailure::kEndpointResolutionFailure:
      return {"endpoint_resolution_failed",
              "Le nom du serveur WireGuard n’a pas pu être résolu. Réessayez lorsque le réseau est disponible."};
    case TunnelFailure::kNone:
      return {"tunnel_failure", "Le tunnel VPN n’a pas pu être démarré."};
  }
  return {"tunnel_failure", "Le tunnel VPN n’a pas pu être démarré."};
}

}  // namespace

bool IsWireGuardTunnelConnected() {
  std::lock_guard<std::mutex> lock(tunnel_mutex);
  return ConnectedPeerState().value_or(false);
}

std::optional<bool> IsWireGuardTunnelStopped() {
  std::lock_guard<std::mutex> lock(tunnel_mutex);
  const auto state = QueryServiceState();
  return state ? std::optional<bool>(*state == SERVICE_STOPPED) : std::nullopt;
}

fuzevpn_diagnostics::EngineObservation WireGuardDiagnostics(const std::string& user, bool observe_owned_network) {
  using namespace fuzevpn_diagnostics;
  std::unique_lock<std::mutex> lock(tunnel_mutex, std::try_to_lock);
  if (!lock.owns_lock() || user.empty() || diagnostic_user != user) return {};
  const auto generation = diagnostic_generation;
  auto peer = active_peer;  // Diagnostic Observe must not advance the live health tracker.
  const auto expected = diagnostic_network;
  const auto connected_at = diagnostic_connected_at;
  const bool stop_failed = diagnostic_stop_failed;
  EngineObservation out;
  out.generation = generation;
  out.observation_tick = diagnostic_observed_at;
  out.attempt_failed = diagnostic_attempt_failed;
  lock.unlock();
  const auto service = QueryServiceState();
  if (!service) return out;
  out.available = true;
  out.freshness_ms = 0;
  out.cleanup_state = stop_failed ? "failed" : *service == SERVICE_STOPPED ? "completed" : "not_requested";
  out.cleanup_eligible = stop_failed;
  if (*service != SERVICE_RUNNING || peer.public_key().empty()) {
    if (!lock.try_lock() || diagnostic_generation != generation) return {};
    return out;
  }
  fuzevpn::WireGuardPeerStats stats;
  if (!TunnelRuntime::PeerStats(peer.public_key(), &stats)) {
    out.available = false;
    return out;
  }
  out.connected = peer.Observe(stats, GetTickCount64());
  if (stats.tx <= kMaximumBytes) out.bytes_sent = stats.tx;
  if (stats.rx <= kMaximumBytes) out.bytes_received = stats.rx;
  if (stats.handshake) {
    FILETIME time{}; GetSystemTimeAsFileTime(&time);
    const auto now = (std::uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    if (now >= stats.handshake && (now - stats.handshake) / 10000 <= kMaximumDurationMs)
      out.handshake_age_ms = (now - stats.handshake) / 10000;
  }
  if (out.connected) {
    out.phase = "completed";
    out.connection_duration_ms = BoundedAge(GetTickCount64(), connected_at);
    if (observe_owned_network && expected) out.network = ReadNetworkObservation(*expected);
  }
  const auto service_after = QueryServiceState();
  if (!service_after || *service_after != *service || !lock.try_lock() || diagnostic_generation != generation) return {};
  return out;
}
bool WireGuardDiagnosticsCurrent(const std::string& user, const fuzevpn_diagnostics::EngineObservation& out) {
  if (!out.available) return true;
  std::unique_lock<std::mutex> lock(tunnel_mutex, std::try_to_lock);
  return lock.owns_lock() && diagnostic_user == user && diagnostic_generation == out.generation;
}

void HandleWireGuardPrivilegedCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    flutter::MethodResult<flutter::EncodableValue>* result) {
  std::lock_guard<std::mutex> lock(tunnel_mutex);
  if (call.method_name() != "isConnected" && call.method_name() != "isNetworkProtectionActive" &&
      call.method_name() != "networkProtectionStatus" && call.method_name() != "resolveApiAddresses")
    ++diagnostic_generation;
  if (call.method_name() == "resolveApiAddresses") {
    std::vector<std::string> addresses;
    if (!ResolveApiBootstrapAddresses(&addresses)) {
      result->Error("api_bootstrap_unavailable", "API bootstrap resolution failed.");
      return;
    }
    flutter::EncodableList values;
    for (const auto& address : addresses) values.emplace_back(address);
    result->Success(flutter::EncodableValue(values));
    return;
  }
  if (call.method_name() == "prepareConnection") {
    NetworkProtectionOptions protection;
    const auto* arguments = call.arguments();
    if (arguments == nullptr ||
        !DecodeProtectionOptions(*arguments, &protection)) {
      const auto [code, message] =
          PublicFailure(TunnelFailure::kInvalidConfiguration);
      result->Error(code, message);
      return;
    }
    if (PrepareNetworkProtection(NetworkProtectionOwner::wire_guard,
                                 protection)) {
      result->Success();
    } else {
      const auto [code, message] =
          PublicFailure(TunnelFailure::kNetworkProtectionFailure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "getOrCreatePublicKey" ||
      call.method_name() == "prepareIdentityForAccount" ||
      call.method_name() == "recreateIdentityForAccount") {
    const auto* arguments = call.arguments() == nullptr
                                ? nullptr
                                : std::get_if<flutter::EncodableMap>(
                                      call.arguments());
    const auto* account_id = arguments == nullptr
                                 ? nullptr
                                 : StringArgument(*arguments, "accountId");
    if (account_id == nullptr || !IsAccountID(*account_id)) {
      const auto [code, message] =
          PublicFailure(TunnelFailure::kKeyUnavailable);
      result->Error(code, message);
      return;
    }
    TunnelFailure failure = TunnelFailure::kNone;
    if (call.method_name() == "recreateIdentityForAccount") {
      if (RecreateIdentityForAccount(*account_id, &failure)) {
        result->Success();
      } else {
        const auto [code, message] = PublicFailure(failure);
        result->Error(code, message);
      }
      return;
    }
    if (call.method_name() == "prepareIdentityForAccount") {
      if (PrepareIdentityForAccount(*account_id, &failure)) {
        result->Success();
      } else {
        const auto [code, message] = PublicFailure(failure);
        result->Error(code, message);
      }
      return;
    }
    std::string public_key;
    // Flutter arms WFP before requesting the connection identity. If the
    // stored identity is missing or damaged, rebuild it without reopening the
    // physical network between this request and device enrollment.
    if (GetOrCreatePublicKey(*account_id, &public_key, &failure, false)) {
      result->Success(flutter::EncodableValue(public_key));
      SecureErase(&public_key);
    } else {
      const auto [code, message] = PublicFailure(failure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "connect") {
    TunnelConfiguration configuration;
    const auto* arguments = call.arguments();
    if (arguments == nullptr ||
        !DecodeConfiguration(*arguments, &configuration)) {
      const auto [code, message] =
          PublicFailure(TunnelFailure::kInvalidConfiguration);
      result->Error(code, message);
      return;
    }
    TunnelFailure failure = TunnelFailure::kNone;
    if (ConnectTunnel(configuration, &failure)) {
      result->Success();
    } else {
      RecordDiagnosticFailure();
      const auto [code, message] = PublicFailure(failure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "reconnect") {
    const std::string user = ProtectedStoreUserId();
    std::string current_public_key;
    std::string current_account;
    if (!reconnect_cache ||
        !ReadProtectedValue(kAccountBindingStoreKey, &current_account) ||
        !ReadStoredPublicKeyForAccount(current_account, &current_public_key) ||
        !reconnect_cache->binding.Matches({user, current_account, current_public_key, {}})) {
      reconnect_cache.reset();
      result->Success(flutter::EncodableValue(false));
      return;
    }
    const TunnelConfiguration configuration = reconnect_cache->configuration;
    TunnelFailure failure = TunnelFailure::kNone;
    if (ConnectTunnel(configuration, &failure)) {
      result->Success(flutter::EncodableValue(true));
    } else {
      RecordDiagnosticFailure();
      const auto [code, message] = PublicFailure(failure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "disconnect") {
    TunnelFailure failure = TunnelFailure::kNone;
    if (DisconnectTunnel(&failure)) {
      result->Success();
    } else {
      const auto [code, message] = PublicFailure(failure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "suspendForMigration") {
    TunnelFailure failure = TunnelFailure::kNone;
    if (SuspendTunnelForMigration(&failure)) result->Success();
    else {
      const auto [code, message] = PublicFailure(failure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "resetIdentity") {
    TunnelFailure failure = TunnelFailure::kNone;
    if (ResetIdentity(&failure)) {
      result->Success();
    } else {
      const auto [code, message] = PublicFailure(failure);
      result->Error(code, message);
    }
    return;
  }
  if (call.method_name() == "isConnected") {
    const auto connected = ConnectedPeerState();
    if (!connected) {
      CompleteRuntimeStatusFailure(std::move(result));
    } else {
      result->Success(flutter::EncodableValue(*connected));
    }
    return;
  }
  if (call.method_name() == "isNetworkProtectionActive") {
    result->Success(flutter::EncodableValue(IsNetworkProtectionActive(
        NetworkProtectionOwner::wire_guard)));
    return;
  }
  if (call.method_name() == "networkProtectionStatus") {
    result->Success(NetworkProtectionStatusValue(NetworkProtectionOwner::wire_guard));
    return;
  }
  result->NotImplemented();
}

std::optional<int> RunWireGuardServiceCommandIfRequested() {
  int argument_count = 0;
  LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
  if (arguments == nullptr) {
    return std::nullopt;
  }
  const bool is_service = argument_count == 3 &&
                          wcscmp(arguments[1], kServiceSwitch) == 0;
  std::wstring config_path = is_service ? arguments[2] : L"";
  LocalFree(arguments);
  if (!is_service) {
    return std::nullopt;
  }

  TunnelRuntime runtime;
  if (!runtime.Load()) {
    return EXIT_FAILURE;
  }
  return runtime.tunnel_service()(config_path.c_str()) ? EXIT_SUCCESS
                                                        : EXIT_FAILURE;
}

#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterWireGuardChannel(flutter::FlutterEngine* engine) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          engine->messenger(), "com.fuzevpn/windows_wireguard",
          &flutter::StandardMethodCodec::GetInstance());
  channel->SetMethodCallHandler([](const auto& call, auto result) {
    if (call.method_name() == "resolveApiAddresses") {
      bool detection_failed = false;
      const auto presence = PrivilegedRuntimePresence(&detection_failed);
      if (!presence) {
        CompleteRuntimeStatusFailure(std::move(result), detection_failed);
        return;
      }
      if (!*presence) {
        // No service-owned WFP exists. Ordinary UI DNS is allowed before VPN
        // use, without prompting for elevation merely to sign in.
        result->Success(flutter::EncodableValue(flutter::EncodableList{}));
        return;
      }
      ForwardPrivilegedCall("wireguard", call, std::move(result), false);
      return;
    }
    if (call.method_name() == "getOrCreatePublicKey") {
      const auto* argument = call.arguments();
      const auto* arguments = argument == nullptr
                                  ? nullptr
                                  : std::get_if<flutter::EncodableMap>(argument);
      const auto* account_id = arguments == nullptr
                                   ? nullptr
                                   : StringArgument(*arguments, "accountId");
      if (account_id == nullptr || !IsAccountID(*account_id)) {
        const auto [code, message] = PublicFailure(TunnelFailure::kKeyUnavailable);
        result->Error(code, message);
        return;
      }
      {
        // Reading an existing identity remains local, user-scoped DPAPI work.
        // Missing or damaged material must be rebuilt by the privileged
        // runtime because the safe replacement also stops any old tunnel.
        std::lock_guard<std::mutex> lock(tunnel_mutex);
        std::string public_key;
        if (ReadStoredPublicKeyForAccount(*account_id, &public_key)) {
          result->Success(flutter::EncodableValue(public_key));
          SecureErase(&public_key);
          return;
        }
        SecureErase(&public_key);
      }
      ForwardPrivilegedCall("wireguard", call, std::move(result), true);
      return;
    }
    if (call.method_name() == "prepareIdentityForAccount") {
      if (IsServiceRunning() || IsPrivilegedBrokerRunning()) {
        ForwardPrivilegedCall("wireguard", call, std::move(result), true);
        return;
      }
      std::lock_guard<std::mutex> lock(tunnel_mutex);
      const auto* argument = call.arguments();
      const auto* arguments = argument == nullptr
                                  ? nullptr
                                  : std::get_if<flutter::EncodableMap>(argument);
      const auto* account_id = arguments == nullptr
                                   ? nullptr
                                   : StringArgument(*arguments, "accountId");
      if (account_id == nullptr || !IsAccountID(*account_id)) {
        const auto [code, message] = PublicFailure(TunnelFailure::kKeyUnavailable);
        result->Error(code, message);
        return;
      }
      TunnelFailure failure = TunnelFailure::kNone;
      if (PrepareIdentityForAccount(*account_id, &failure)) {
        result->Success();
      } else {
        const auto [code, message] = PublicFailure(failure);
        result->Error(code, message);
      }
      return;
    }
    if (call.method_name() == "prepareConnection") {
      ForwardPrivilegedCall("wireguard", call, std::move(result), true);
      return;
    }
    if (call.method_name() == "connect") {
      ForwardPrivilegedCall("wireguard", call, std::move(result), true);
      return;
    }
    if (call.method_name() == "reconnect") {
      if (!IsPrivilegedBrokerRunning()) {
        result->Success(flutter::EncodableValue(false));
        return;
      }
      ForwardPrivilegedCall("wireguard", call, std::move(result), false);
      return;
    }
    if (call.method_name() == "disconnect" ||
        call.method_name() == "suspendForMigration") {
      bool detection_failed = false;
      const auto presence = PrivilegedRuntimePresence(&detection_failed);
      if (!presence) {
        CompleteRuntimeStatusFailure(std::move(result), detection_failed);
        return;
      }
      const auto tunnel = QueryServiceRunning();
      if (!tunnel) {
        CompleteRuntimeStatusFailure(std::move(result));
        return;
      }
      if (!*tunnel && !*presence) {
        result->Success();
        return;
      }
      ForwardPrivilegedCall("wireguard", call, std::move(result), true);
      return;
    }
    if (call.method_name() == "resetIdentity") {
      if (IsServiceRunning() || IsPrivilegedBrokerRunning()) {
        ForwardPrivilegedCall("wireguard", call, std::move(result), true);
        return;
      }
      std::lock_guard<std::mutex> lock(tunnel_mutex);
      TunnelFailure failure = TunnelFailure::kNone;
      if (!ResetIdentity(&failure)) {
        const auto [code, message] = PublicFailure(failure);
        result->Error(code, message);
        return;
      }
      result->Success();
      return;
    }
    if (call.method_name() == "recreateIdentityForAccount") {
      ForwardPrivilegedCall("wireguard", call, std::move(result), true);
      return;
    }
    if (call.method_name() == "isConnected") {
      bool detection_failed = false;
      const auto presence = PrivilegedRuntimePresence(&detection_failed);
      if (!presence) {
        CompleteRuntimeStatusFailure(std::move(result), detection_failed);
        return;
      }
      if (!*presence) {
        const auto tunnel = QueryServiceRunning();
        if (!tunnel || *tunnel) {
          CompleteRuntimeStatusFailure(std::move(result));
          return;
        }
        result->Success(flutter::EncodableValue(false));
        return;
      }
      ForwardPrivilegedCall("wireguard", call, std::move(result), false);
      return;
    }
    if (call.method_name() == "isNetworkProtectionActive" ||
        call.method_name() == "networkProtectionStatus") {
      bool detection_failed = false;
      const auto presence = PrivilegedRuntimePresence(&detection_failed);
      if (!presence) {
        CompleteRuntimeStatusFailure(std::move(result), detection_failed);
        return;
      }
      if (!*presence) {
        if (call.method_name() == "networkProtectionStatus")
          result->Success(NetworkProtectionStatusValue(NetworkProtectionOwner::wire_guard));
        else result->Success(flutter::EncodableValue(false));
        return;
      }
      ForwardPrivilegedCall("wireguard", call, std::move(result), false);
      return;
    }
    result->NotImplemented();
  });
}

void StopWireGuardTunnel() {
  class CleanupResult final
      : public flutter::MethodResult<flutter::EncodableValue> {
   protected:
    void SuccessInternal(const flutter::EncodableValue*) override {}
    void ErrorInternal(const std::string&, const std::string&,
                       const flutter::EncodableValue*) override {}
    void NotImplementedInternal() override {}
  };
  if (!IsServiceRunning() && !IsPrivilegedBrokerRunning()) {
    return;
  }
  flutter::MethodCall<flutter::EncodableValue> call("disconnect", nullptr);
  ForwardPrivilegedCall("wireguard", call,
                        std::make_unique<CleanupResult>(), true);
}
#endif

void RemoveWireGuardTunnelService() {
  std::lock_guard<std::mutex> lock(tunnel_mutex);
  reconnect_cache.reset();
  TunnelFailure failure = TunnelFailure::kNone;
  active_peer.StopResult(StopAndDeleteService(&failure));
  RemoveRestrictedConfiguration();
}
