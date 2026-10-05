// SPDX-License-Identifier: MPL-2.0
#include "secure_store_channel.h"
#include "privileged_runtime.h"

#include <windows.h>
#include <shlobj.h>
#include <sddl.h>
#include <wincrypt.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <atomic>

#include <flutter/encodable_value.h>
#ifndef FUZEVPN_SERVICE_PROCESS
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#endif

namespace {
constexpr wchar_t kStoreName[] = L"FuzeVPN";
thread_local HANDLE protected_store_user_token = nullptr;
constexpr DWORD kMaximumStoreBytes = 1024 * 1024;
std::atomic<unsigned long> temporary_sequence{0};

class ScopedStoreImpersonation final {
 public:
  ScopedStoreImpersonation() {
    if (protected_store_user_token != nullptr) {
      active_ = ImpersonateLoggedOnUser(protected_store_user_token) != FALSE;
    }
  }
  ~ScopedStoreImpersonation() {
    if (active_) {
      RevertToSelf();
    }
  }
  bool valid() const {
    return protected_store_user_token == nullptr || active_;
  }

 private:
  bool active_ = false;
};

bool IsAllowedKey(const std::string& key) {
  return key == "access_token" || key == "selected_location" ||
         key == "theme_mode" || key == "vpn_protocol" ||
         key == "app_language" || key == "kill_switch" ||
         key == "dns_protection" || key == "ipv6_protection" ||
         key == "automatic_reconnect" || key == "security_settings" ||
         key == "auto_connect_on_launch" ||
         key == "windows_notifications" ||
         key == "favorite_locations" || key == "recent_locations" ||
         key == "current_device_id" ||
         key == "location_migration_id" ||
         key == "location_migration_device_id" ||
         key == "location_migration_target_location_id" ||
         key == "location_migration_user_id" ||
         key == "location_migration_state";
}

std::filesystem::path UserStoreDirectory() {
  PWSTR data = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0,
                                  protected_store_user_token, &data))) return {};
  std::filesystem::path path(data);
  CoTaskMemFree(data);
  return path / kStoreName;
}

std::filesystem::path DiagnosticPathFor(const std::string& filename) {
  if (filename != "native_diagnostic.log" && filename != "native_last_error.txt" &&
      filename != "native_last_operation.txt" && filename != "native_stage.txt")
    return {};
  const auto directory = UserStoreDirectory();
  return directory.empty() ? std::filesystem::path() : directory / filename;
}

std::filesystem::path PathFor(const std::string& key) {
  if (key.empty() || key.size() > 80) return {};
  for (const char character : key) {
    if (!((character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '_')) return {};
  }
  auto path = UserStoreDirectory();
  if (path.empty()) return {};
  path /= std::wstring(key.begin(), key.end()) + L".bin";
  return path;
}

const std::string* StringArgument(const flutter::EncodableMap& args, const char* name) {
  const auto it = args.find(flutter::EncodableValue(name));
  return it == args.end() ? nullptr : std::get_if<std::string>(&it->second);
}

bool WriteSecret(const std::string& key, const std::string& value) {
  if (value.size() > kMaximumStoreBytes / 2) return false;
  ScopedStoreImpersonation impersonation;
  if (!impersonation.valid()) return false;
  const auto path = PathFor(key);
  if (path.empty()) return false;
  DATA_BLOB input{static_cast<DWORD>(value.size()), reinterpret_cast<BYTE*>(const_cast<char*>(value.data()))};
  DATA_BLOB encrypted{};
  if (!CryptProtectData(&input, L"FuzeVPN", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) return false;
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    LocalFree(encrypted.pbData);
    return false;
  }
  auto temporary_path = path;
  temporary_path += L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
                    std::to_wstring(GetCurrentThreadId()) + L"." +
                    std::to_wstring(GetTickCount64()) + L"." +
                    std::to_wstring(temporary_sequence.fetch_add(1));
  bool ok = false;
  HANDLE file = CreateFileW(temporary_path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    ok = WriteFile(file, encrypted.pbData, encrypted.cbData, &written, nullptr) &&
         written == encrypted.cbData && FlushFileBuffers(file);
    CloseHandle(file);
  }
  LocalFree(encrypted.pbData);
  if (!ok) {
    std::filesystem::remove(temporary_path, error);
    return false;
  }
  if (!MoveFileExW(temporary_path.c_str(), path.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    std::filesystem::remove(temporary_path, error);
    return false;
  }
  return true;
}

ProtectedValueReadStatus ReadSecret(const std::string& key, std::string* value) {
  using Status = ProtectedValueReadStatus;
  if (value == nullptr) return Status::io_error;
  if (!value->empty()) SecureZeroMemory(value->data(), value->size());
  value->clear();
  ScopedStoreImpersonation impersonation;
  if (!impersonation.valid()) return Status::access_denied;
  const auto path = PathFor(key);
  if (path.empty()) return Status::io_error;
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
      return Status::not_found;
    return error == ERROR_ACCESS_DENIED ? Status::access_denied : Status::io_error;
  }
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file, &size)) {
    CloseHandle(file);
    return Status::io_error;
  }
  if (size.QuadPart <= 0 || size.QuadPart > kMaximumStoreBytes) {
    CloseHandle(file);
    return Status::corrupt;
  }
  std::vector<BYTE> encrypted(static_cast<size_t>(size.QuadPart));
  DWORD read = 0;
  const bool complete = ReadFile(file, encrypted.data(),
      static_cast<DWORD>(encrypted.size()), &read, nullptr) &&
      read == encrypted.size();
  CloseHandle(file);
  if (!complete) return Status::io_error;
  DATA_BLOB input{static_cast<DWORD>(encrypted.size()), encrypted.data()};
  DATA_BLOB decrypted{};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &decrypted))
    return Status::decryption_failed;
  value->assign(reinterpret_cast<char*>(decrypted.pbData), decrypted.cbData);
  SecureZeroMemory(decrypted.pbData, decrypted.cbData);
  LocalFree(decrypted.pbData);
  return Status::found;
}
}  // namespace

ScopedProtectedStoreUser::ScopedProtectedStoreUser(
    void* impersonation_token)
    : previous_token_(protected_store_user_token) {
  protected_store_user_token = static_cast<HANDLE>(impersonation_token);
}

ScopedProtectedStoreUser::~ScopedProtectedStoreUser() {
  protected_store_user_token = static_cast<HANDLE>(previous_token_);
}

bool ReadProtectedValue(const std::string& key, std::string* value) {
  return ReadSecret(key, value) == ProtectedValueReadStatus::found;
}

ProtectedValueReadStatus ReadProtectedValueStatus(const std::string& key,
                                                std::string* value) {
  return ReadSecret(key, value);
}

bool WriteProtectedValue(const std::string& key, const std::string& value) {
  return WriteSecret(key, value);
}

bool DeleteProtectedValue(const std::string& key) {
  ScopedStoreImpersonation impersonation;
  if (!impersonation.valid()) return false;
  const auto path = PathFor(key);
  if (path.empty()) return false;
  if (DeleteFileW(path.c_str())) return true;
  const DWORD error = GetLastError();
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

std::string ProtectedStoreUserId() {
  HANDLE token = protected_store_user_token;
  const bool owns_token = token == nullptr;
  if (owns_token && !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return {};
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<BYTE> storage(size);
  std::string result;
  if (size != 0 && GetTokenInformation(token, TokenUser, storage.data(), size,
                                      &size)) {
    LPSTR sid = nullptr;
    if (ConvertSidToStringSidA(
            reinterpret_cast<const TOKEN_USER*>(storage.data())->User.Sid,
            &sid)) {
      result = sid;
      LocalFree(sid);
    }
  }
  if (owns_token) CloseHandle(token);
  return result;
}

bool WriteUserDiagnostic(const std::string& filename, const std::string& text,
                         bool append) {
  if (text.size() > 4096 ||
      (protected_store_user_token == nullptr && IsVpnServiceRuntime())) return false;
  ScopedStoreImpersonation impersonation;
  if (!impersonation.valid()) return false;
  const auto path = DiagnosticPathFor(filename);
  if (path.empty()) return false;
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) return false;
  if (append && std::filesystem::exists(path, error) && !error &&
      std::filesystem::file_size(path, error) >= 256 * 1024 && !error) {
    auto previous = path;
    previous += L".previous";
    std::filesystem::remove(previous, error);
    error.clear();
    std::filesystem::rename(path, previous, error);
    if (error) return false;
  }
  HANDLE file = CreateFileW(path.c_str(), append ? FILE_APPEND_DATA : GENERIC_WRITE,
      FILE_SHARE_READ, nullptr, append ? OPEN_ALWAYS : CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  const bool complete = WriteFile(file, text.data(), static_cast<DWORD>(text.size()),
                                  &written, nullptr) && written == text.size();
  CloseHandle(file);
  return complete;
}

#ifndef FUZEVPN_SERVICE_PROCESS
void RegisterSecureStoreChannel(flutter::FlutterEngine* engine) {
  auto channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      engine->messenger(), "com.fuzevpn/windows_secure_store", &flutter::StandardMethodCodec::GetInstance());
  channel->SetMethodCallHandler([](const auto& call, auto result) {
    const auto* args = std::get_if<flutter::EncodableMap>(call.arguments());
    const auto* key = args ? StringArgument(*args, "key") : nullptr;
    if (!key || !IsAllowedKey(*key)) { result->Error("invalid_argument", "Invalid secure-store key."); return; }
    if (call.method_name() == "read") {
      std::string value;
      const auto status = ReadSecret(*key, &value);
      if (status == ProtectedValueReadStatus::found) {
        result->Success(flutter::EncodableValue(value));
        if (!value.empty()) SecureZeroMemory(value.data(), value.size());
      } else if (status == ProtectedValueReadStatus::not_found) {
        result->Success();
      } else {
        const char* code = status == ProtectedValueReadStatus::access_denied
            ? "storage_access_denied" : status == ProtectedValueReadStatus::corrupt
            ? "storage_corrupt" : status == ProtectedValueReadStatus::decryption_failed
            ? "storage_decryption_failed" : "storage_io_error";
        result->Error(code, "The protected value could not be read; it has been preserved.");
      }
      return;
    }
    if (call.method_name() == "write") {
      const auto* value = StringArgument(*args, "value");
      if (!value || !WriteSecret(*key, *value)) { result->Error("storage_error", "Unable to protect the value."); return; }
      result->Success(); return;
    }
    if (call.method_name() == "delete") {
      if (!DeleteProtectedValue(*key)) {
        result->Error("storage_error", "Unable to remove the protected value.");
      } else {
        result->Success();
      }
      return;
    }
    result->NotImplemented();
  });
}
#endif
