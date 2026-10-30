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
// A replacement or deletion can meet a transient holder: another FuzeVPN
// process reading the value, an antivirus or indexer scan. The total backoff
// stays near 300 ms because callers include the Flutter platform thread and
// the broker's tunnel mutex.
constexpr DWORD kStoreRetryDelaysMs[] = {10, 20, 40, 80, 160};
constexpr int kMaximumStoreAttempts =
    1 + static_cast<int>(std::size(kStoreRetryDelaysMs));

class ScopedStoreImpersonation final {
 public:
  ScopedStoreImpersonation() {
    if (protected_store_user_token != nullptr) {
      active_ = ImpersonateLoggedOnUser(protected_store_user_token) != FALSE;
      if (!active_) error_ = GetLastError();
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
  DWORD error() const { return error_; }

 private:
  bool active_ = false;
  DWORD error_ = ERROR_SUCCESS;
};

bool StoreFailed(ProtectedStoreFailure* failure, const char* stage,
                 DWORD error, int attempts = 1) {
  if (failure != nullptr) *failure = {stage, error, attempts};
  return false;
}

// std::filesystem reports Win32 codes in the system category. Any other
// category (an errno value) has no Win32 meaning and is reported as a
// missing path rather than as an unrelated Windows error.
DWORD FilesystemWin32Error(const std::error_code& error) {
  return error.category() == std::system_category()
      ? static_cast<DWORD>(error.value()) : static_cast<DWORD>(ERROR_PATH_NOT_FOUND);
}

bool IsTransientStoreError(DWORD error) {
  return error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED ||
         error == ERROR_LOCK_VIOLATION;
}

template <typename Operation>
bool RetryTransient(const Operation& operation, DWORD* error, int* attempts) {
  for (int attempt = 1;; ++attempt) {
    *attempts = attempt;
    if (operation()) {
      *error = ERROR_SUCCESS;
      return true;
    }
    *error = GetLastError();
    if (attempt == kMaximumStoreAttempts || !IsTransientStoreError(*error))
      return false;
    Sleep(kStoreRetryDelaysMs[attempt - 1]);
  }
}

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
  const HRESULT folder = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0,
                                              protected_store_user_token, &data);
  // The buffer is freed whether the lookup succeeded or not. A failure keeps
  // its raw HRESULT, as the protect stage keeps DPAPI's NTE_* codes.
  std::filesystem::path path;
  if (SUCCEEDED(folder)) path = data;
  CoTaskMemFree(data);
  if (FAILED(folder)) {
    SetLastError(static_cast<DWORD>(folder));
    return {};
  }
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
  const auto invalid = [] {
    SetLastError(ERROR_INVALID_NAME);
    return std::filesystem::path();
  };
  if (key.empty() || key.size() > 80) return invalid();
  for (const char character : key) {
    if (!((character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') || character == '_')) return invalid();
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

// Each failure reports its step and the Win32 error read before any cleanup.
bool WriteSecret(const std::string& key, const std::string& value,
                 ProtectedStoreFailure* failure) {
  if (failure != nullptr) *failure = {};
  if (value.size() > kMaximumStoreBytes / 2)
    return StoreFailed(failure, "secure_store_protect", ERROR_FILE_TOO_LARGE);
  ScopedStoreImpersonation impersonation;
  if (!impersonation.valid())
    return StoreFailed(failure, "secure_store_impersonation", impersonation.error());
  const auto path = PathFor(key);
  if (path.empty()) return StoreFailed(failure, "secure_store_path", GetLastError());
  DATA_BLOB input{static_cast<DWORD>(value.size()), reinterpret_cast<BYTE*>(const_cast<char*>(value.data()))};
  DATA_BLOB encrypted{};
  if (!CryptProtectData(&input, L"FuzeVPN", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encrypted))
    return StoreFailed(failure, "secure_store_protect", GetLastError());
  std::error_code error;
  std::filesystem::create_directories(path.parent_path(), error);
  if (error) {
    LocalFree(encrypted.pbData);
    return StoreFailed(failure, "secure_store_directory", FilesystemWin32Error(error));
  }
  auto temporary_path = path;
  temporary_path += L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
                    std::to_wstring(GetCurrentThreadId()) + L"." +
                    std::to_wstring(GetTickCount64()) + L"." +
                    std::to_wstring(temporary_sequence.fetch_add(1));
  const char* stage = nullptr;
  DWORD stage_error = ERROR_SUCCESS;
  HANDLE file = CreateFileW(temporary_path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    stage = "secure_store_create";
    stage_error = GetLastError();
  } else {
    DWORD written = 0;
    if (!WriteFile(file, encrypted.pbData, encrypted.cbData, &written, nullptr)) {
      stage = "secure_store_write";
      stage_error = GetLastError();
    } else if (written != encrypted.cbData) {
      stage = "secure_store_write";
      stage_error = ERROR_WRITE_FAULT;
    } else if (!FlushFileBuffers(file)) {
      stage = "secure_store_flush";
      stage_error = GetLastError();
    }
    CloseHandle(file);
  }
  LocalFree(encrypted.pbData);
  if (stage != nullptr) {
    if (file != INVALID_HANDLE_VALUE) DeleteFileW(temporary_path.c_str());
    return StoreFailed(failure, stage, stage_error);
  }
  // The encrypted temporary stays in place across retries, so a late success
  // still publishes the complete value atomically.
  DWORD replace_error = ERROR_SUCCESS;
  int attempts = 0;
  if (!RetryTransient([&] {
        return MoveFileExW(temporary_path.c_str(), path.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
      }, &replace_error, &attempts)) {
    DeleteFileW(temporary_path.c_str());
    return StoreFailed(failure, "secure_store_replace", replace_error, attempts);
  }
  if (failure != nullptr) failure->attempts = attempts;
  return true;
}

bool DeleteSecret(const std::string& key, ProtectedStoreFailure* failure) {
  if (failure != nullptr) *failure = {};
  ScopedStoreImpersonation impersonation;
  if (!impersonation.valid())
    return StoreFailed(failure, "secure_store_impersonation", impersonation.error());
  const auto path = PathFor(key);
  if (path.empty()) return StoreFailed(failure, "secure_store_path", GetLastError());
  DWORD error = ERROR_SUCCESS;
  int attempts = 0;
  if (!RetryTransient([&] { return DeleteFileW(path.c_str()) != FALSE; },
                      &error, &attempts) &&
      error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
    return StoreFailed(failure, "secure_store_delete", error, attempts);
  if (failure != nullptr) failure->attempts = attempts;
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
  // Delete sharing lets a concurrent deletion proceed while this handle keeps
  // reading the complete previous ciphertext. It does not help a replacement:
  // MoveFileExW still fails with ERROR_ACCESS_DENIED while this handle is
  // open, and the writer relies on its bounded retry. Writers stay excluded.
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_DELETE,
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

// Only the fixed stage, the numeric Windows error and the attempt count leave
// the process: never a path, a value or a system message.
flutter::EncodableValue StoreFailureDetails(const ProtectedStoreFailure& failure) {
  return flutter::EncodableValue(flutter::EncodableMap{
      {flutter::EncodableValue("stage"),
       flutter::EncodableValue(failure.stage != nullptr ? failure.stage : "")},
      {flutter::EncodableValue("win32_error"),
       flutter::EncodableValue(static_cast<int64_t>(failure.win32_error))},
      {flutter::EncodableValue("attempts"),
       flutter::EncodableValue(static_cast<int32_t>(failure.attempts))}});
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
  return WriteSecret(key, value, nullptr);
}

bool WriteProtectedValueDetailed(const std::string& key,
                                 const std::string& value,
                                 ProtectedStoreFailure* failure) {
  return WriteSecret(key, value, failure);
}

bool DeleteProtectedValue(const std::string& key) {
  return DeleteSecret(key, nullptr);
}

bool DeleteProtectedValueDetailed(const std::string& key,
                                  ProtectedStoreFailure* failure) {
  return DeleteSecret(key, failure);
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
      if (!value) { result->Error("storage_error", "Unable to protect the value."); return; }
      ProtectedStoreFailure failure;
      if (!WriteSecret(*key, *value, &failure)) {
        result->Error("storage_error", "Unable to protect the value.", StoreFailureDetails(failure));
        return;
      }
      result->Success(); return;
    }
    if (call.method_name() == "delete") {
      ProtectedStoreFailure failure;
      if (!DeleteSecret(*key, &failure)) {
        result->Error("storage_error", "Unable to remove the protected value.",
                      StoreFailureDetails(failure));
      } else {
        result->Success();
      }
      return;
    }
    result->NotImplemented();
  });
}
#endif
