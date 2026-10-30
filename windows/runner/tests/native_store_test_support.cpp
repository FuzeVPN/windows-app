// A shell boundary spy checks that the production path resolver passes the
// selected user token, including nested scopes, and always frees the shell's
// buffer. File and DPAPI calls are spies; write tests only create the store
// folder inside a per-run temporary fixture.
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {
HANDLE observed_folder_token = nullptr;
HANDLE observed_impersonation_token = nullptr;
bool fail_store_impersonation = false;
unsigned observed_store_reverts = 0;
DWORD store_open_error = ERROR_FILE_NOT_FOUND;
DWORD observed_read_share = 0;
LONGLONG store_file_size = 4;
bool store_short_read = false;
HANDLE store_file_handle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(103));
// A failed LocalAppData lookup still returns a buffer, which must be freed.
HRESULT known_folder_error = S_OK;
void* known_folder_output = nullptr;
unsigned known_folder_frees = 0;
// Write spies. Scripted replace/delete errors are returned once each, in
// order, then the operation succeeds.
DWORD store_protect_error = ERROR_SUCCESS;
DWORD store_create_error = ERROR_SUCCESS;
DWORD store_write_error = ERROR_SUCCESS;
bool store_short_write = false;
DWORD store_flush_error = ERROR_SUCCESS;
std::vector<DWORD> store_replace_errors;
std::vector<DWORD> store_delete_errors;
std::wstring store_temporary;
std::wstring store_replace_source;
std::wstring store_replace_target;
DWORD store_replace_flags = 0;
size_t store_replace_calls = 0;
size_t store_delete_calls = 0;
size_t store_replaces_at_cleanup = 0;
std::vector<std::wstring> store_deleted;
std::vector<DWORD> store_sleeps;
// The resolved LocalAppData is a per-run folder under the test's temporary
// directory, so the only real write (the FuzeVPN folder) never lands in C:\.
const std::wstring& StoreFixtureRoot() {
  static const std::wstring root = [] {
    std::wstring temporary(MAX_PATH + 1, L'\0');
    const DWORD length = GetTempPathW(static_cast<DWORD>(temporary.size()), temporary.data());
    temporary.resize(length < temporary.size() ? length : 0);
    return temporary + L"FuzeVPNStoreProbe-" + std::to_wstring(GetCurrentProcessId()) +
           L"-" + std::to_wstring(GetTickCount64());
  }();
  return root;
}
HANDLE WINAPI ObserveStoreFileOpen(LPCWSTR name, DWORD, DWORD share, LPSECURITY_ATTRIBUTES,
                                  DWORD disposition, DWORD, HANDLE) {
  if (disposition == CREATE_NEW) {
    // Only WriteSecret creates: its encrypted temporary beside the value.
    store_temporary = name;
    if (store_create_error != ERROR_SUCCESS) {
      SetLastError(store_create_error);
      return INVALID_HANDLE_VALUE;
    }
    return store_file_handle;
  }
  observed_read_share = share;
  if (store_open_error != ERROR_SUCCESS) {
    SetLastError(store_open_error);
    return INVALID_HANDLE_VALUE;
  }
  return store_file_handle;
}
BOOL WINAPI ObserveStoreFileSize(HANDLE, PLARGE_INTEGER size) {
  size->QuadPart = store_file_size;
  return TRUE;
}
BOOL WINAPI ObserveStoreRead(HANDLE, LPVOID bytes, DWORD size, LPDWORD read,
                             LPOVERLAPPED) {
  ZeroMemory(bytes, size);
  *read = store_short_read ? 0 : size;
  return TRUE;
}
BOOL WINAPI ObserveStoreWrite(HANDLE, LPCVOID, DWORD size, LPDWORD written,
                              LPOVERLAPPED) {
  if (store_write_error != ERROR_SUCCESS) {
    SetLastError(store_write_error);
    return FALSE;
  }
  *written = store_short_write && size != 0 ? size - 1 : size;
  return TRUE;
}
BOOL WINAPI ObserveStoreFlush(HANDLE) {
  if (store_flush_error == ERROR_SUCCESS) return TRUE;
  SetLastError(store_flush_error);
  return FALSE;
}
BOOL WINAPI ObserveStoreClose(HANDLE handle) {
  return handle == store_file_handle ? TRUE : CloseHandle(handle);
}
BOOL WINAPI ObserveStoreProtect(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID,
                                CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB* output) {
  if (store_protect_error != ERROR_SUCCESS) {
    SetLastError(store_protect_error);
    return FALSE;
  }
  // The production path releases the ciphertext with LocalFree, as for DPAPI.
  output->pbData = static_cast<BYTE*>(LocalAlloc(LPTR, 4));
  output->cbData = output->pbData == nullptr ? 0 : 4;
  return output->pbData != nullptr;
}
BOOL WINAPI ObserveStoreUnprotect(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID,
                                  CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) {
  SetLastError(ERROR_INVALID_DATA);
  return FALSE;
}
BOOL WINAPI ObserveStoreReplace(LPCWSTR source, LPCWSTR target, DWORD flags) {
  store_replace_source = source;
  store_replace_target = target;
  store_replace_flags = flags;
  const size_t call = store_replace_calls++;
  if (call >= store_replace_errors.size()) return TRUE;
  SetLastError(store_replace_errors[call]);
  return FALSE;
}
BOOL WINAPI ObserveStoreDelete(LPCWSTR name) {
  store_deleted.push_back(name);
  if (!store_temporary.empty() && store_temporary == name) {
    store_replaces_at_cleanup = store_replace_calls;
    return TRUE;
  }
  const size_t call = store_delete_calls++;
  if (call >= store_delete_errors.size()) return TRUE;
  SetLastError(store_delete_errors[call]);
  return FALSE;
}
VOID WINAPI ObserveStoreSleep(DWORD milliseconds) {
  store_sleeps.push_back(milliseconds);
}
BOOL WINAPI ObserveStoreImpersonation(HANDLE token) {
  observed_impersonation_token = token;
  if (!fail_store_impersonation) return TRUE;
  SetLastError(ERROR_CANNOT_IMPERSONATE);
  return FALSE;
}
BOOL WINAPI ObserveStoreRevert() {
  ++observed_store_reverts;
  return TRUE;
}
HRESULT WINAPI ObserveKnownFolder(REFKNOWNFOLDERID, DWORD, HANDLE token,
                                 PWSTR* output) {
  observed_folder_token = token;
  const std::wstring path = known_folder_error == S_OK ? StoreFixtureRoot() : std::wstring();
  const size_t bytes = (path.size() + 1) * sizeof(wchar_t);
  *output = static_cast<PWSTR>(CoTaskMemAlloc(bytes));
  known_folder_output = *output;
  if (*output == nullptr) return E_OUTOFMEMORY;
  CopyMemory(*output, path.c_str(), bytes);
  return known_folder_error;
}
void WINAPI ObserveStoreTaskFree(LPVOID memory) {
  if (memory != nullptr && memory == known_folder_output) {
    ++known_folder_frees;
    known_folder_output = nullptr;
  }
  CoTaskMemFree(memory);
}
}
#define FUZEVPN_SERVICE_PROCESS
#define SHGetKnownFolderPath ObserveKnownFolder
#define ImpersonateLoggedOnUser ObserveStoreImpersonation
#define RevertToSelf ObserveStoreRevert
#define CreateFileW ObserveStoreFileOpen
#define GetFileSizeEx ObserveStoreFileSize
#define ReadFile ObserveStoreRead
#define WriteFile ObserveStoreWrite
#define FlushFileBuffers ObserveStoreFlush
#define CloseHandle ObserveStoreClose
#define CryptProtectData ObserveStoreProtect
#define CryptUnprotectData ObserveStoreUnprotect
#define MoveFileExW ObserveStoreReplace
#define DeleteFileW ObserveStoreDelete
#define Sleep ObserveStoreSleep
#define CoTaskMemFree ObserveStoreTaskFree
#include "../secure_store_channel.cpp"
#undef SHGetKnownFolderPath
#undef ImpersonateLoggedOnUser
#undef RevertToSelf
#undef CreateFileW
#undef GetFileSizeEx
#undef ReadFile
#undef WriteFile
#undef FlushFileBuffers
#undef CloseHandle
#undef CryptProtectData
#undef CryptUnprotectData
#undef MoveFileExW
#undef DeleteFileW
#undef Sleep
#undef CoTaskMemFree

bool TestProtectedStoreReadFailures() {
  using Status = ProtectedValueReadStatus;
  std::string value = "discarded previous plaintext";
  store_open_error = ERROR_FILE_NOT_FOUND;
  observed_read_share = 0;
  if (ReadProtectedValueStatus("access_token", &value) != Status::not_found || !value.empty()) return false;
  // Readers share delete so a concurrent deletion proceeds; a replacement
  // still meets ERROR_ACCESS_DENIED while they read and relies on the writer's
  // bounded retry. Writers to the protected value stay excluded.
  if ((observed_read_share & FILE_SHARE_DELETE) == 0 ||
      (observed_read_share & FILE_SHARE_WRITE) != 0) return false;
  store_open_error = ERROR_ACCESS_DENIED;
  if (ReadProtectedValueStatus("access_token", &value) != Status::access_denied) return false;
  store_open_error = ERROR_SHARING_VIOLATION;
  if (ReadProtectedValueStatus("access_token", &value) != Status::io_error) return false;
  store_open_error = ERROR_SUCCESS;
  store_file_size = 0;
  if (ReadProtectedValueStatus("access_token", &value) != Status::corrupt) return false;
  store_file_size = 1024 * 1024 + 1;
  if (ReadProtectedValueStatus("access_token", &value) != Status::corrupt) return false;
  store_file_size = 4;
  store_short_read = true;
  if (ReadProtectedValueStatus("access_token", &value) != Status::io_error) return false;
  store_short_read = false;
  if (ReadProtectedValueStatus("access_token", &value) != Status::decryption_failed) return false;
  store_open_error = ERROR_FILE_NOT_FOUND;
  return true;
}

namespace {
void ResetStoreWriteSpies() {
  known_folder_error = S_OK;
  known_folder_output = nullptr;
  known_folder_frees = 0;
  store_protect_error = ERROR_SUCCESS;
  store_create_error = ERROR_SUCCESS;
  store_write_error = ERROR_SUCCESS;
  store_short_write = false;
  store_flush_error = ERROR_SUCCESS;
  store_replace_errors.clear();
  store_delete_errors.clear();
  store_temporary.clear();
  store_replace_source.clear();
  store_replace_target.clear();
  store_replace_flags = 0;
  store_replace_calls = 0;
  store_delete_calls = 0;
  store_replaces_at_cleanup = 0;
  store_deleted.clear();
  store_sleeps.clear();
}
bool StoreStage(const ProtectedStoreFailure& failure, const char* stage) {
  return failure.stage != nullptr && std::strcmp(failure.stage, stage) == 0;
}
bool OnlyTemporaryRemoved() {
  return !store_temporary.empty() && store_deleted.size() == 1 &&
         store_deleted[0] == store_temporary;
}
// The channel error carries exactly the fixed stage, the numeric Windows error
// and the attempt count, never a path or a value.
bool StoreDetails(const ProtectedStoreFailure& failure, const char* stage,
                  int64_t win32_error, int32_t attempts) {
  const auto details = StoreFailureDetails(failure);
  const auto* map = std::get_if<flutter::EncodableMap>(&details);
  if (map == nullptr || map->size() != 3) return false;
  const auto field = [map](const char* name) -> const flutter::EncodableValue* {
    const auto found = map->find(flutter::EncodableValue(name));
    return found == map->end() ? nullptr : &found->second;
  };
  const auto* stage_value = field("stage");
  const auto* error_value = field("win32_error");
  const auto* attempts_value = field("attempts");
  const auto* stage_text = stage_value ? std::get_if<std::string>(stage_value) : nullptr;
  const auto* error_number = error_value ? std::get_if<int64_t>(error_value) : nullptr;
  const auto* attempts_number = attempts_value ? std::get_if<int32_t>(attempts_value) : nullptr;
  return stage_text != nullptr && *stage_text == stage && error_number != nullptr &&
         *error_number == win32_error && attempts_number != nullptr &&
         *attempts_number == attempts;
}
static_assert(kMaximumStoreAttempts == 6, "one attempt plus five bounded retries");
bool RunStoreWriteFailureCases() {
  using Delays = std::vector<DWORD>;
  const Delays backoff{10, 20, 40, 80, 160};
  DWORD total_backoff = 0;
  for (const DWORD delay : kStoreRetryDelaysMs) total_backoff += delay;
  // The bound runs on the Flutter platform thread and in the tunnel mutex.
  if (total_backoff >= 350) return false;
  ProtectedStoreFailure failure;

  // Two transient sharing violations: the same encrypted temporary is kept
  // and the third replacement publishes it over the value.
  ResetStoreWriteSpies();
  store_replace_errors = {ERROR_SHARING_VIOLATION, ERROR_SHARING_VIOLATION};
  if (!WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      failure.stage != nullptr || failure.win32_error != ERROR_SUCCESS ||
      failure.attempts != 3 || store_replace_calls != 3 || !store_deleted.empty() ||
      store_sleeps != Delays{10, 20} || store_temporary.empty() ||
      store_replace_source != store_temporary ||
      std::filesystem::path(store_replace_target).filename() != L"current_device_id.bin" ||
      std::filesystem::path(store_temporary).parent_path() !=
          std::filesystem::path(store_replace_target).parent_path() ||
      store_replace_flags != (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    return false;
  for (const DWORD transient : {static_cast<DWORD>(ERROR_ACCESS_DENIED),
                                static_cast<DWORD>(ERROR_LOCK_VIOLATION)}) {
    ResetStoreWriteSpies();
    store_replace_errors = {transient};
    if (!WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
        failure.attempts != 2 || store_sleeps != Delays{10} || !store_deleted.empty())
      return false;
  }

  // A persistent holder exhausts the bounded backoff; the temporary survives
  // every attempt and is removed only after the last one.
  ResetStoreWriteSpies();
  store_replace_errors.assign(10, ERROR_SHARING_VIOLATION);
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_replace") ||
      failure.win32_error != ERROR_SHARING_VIOLATION ||
      failure.attempts != kMaximumStoreAttempts ||
      store_replace_calls != static_cast<size_t>(kMaximumStoreAttempts) ||
      store_sleeps != backoff || !OnlyTemporaryRemoved() ||
      store_replaces_at_cleanup != static_cast<size_t>(kMaximumStoreAttempts) ||
      !StoreDetails(failure, "secure_store_replace", ERROR_SHARING_VIOLATION, 6))
    return false;
  ResetStoreWriteSpies();
  store_replace_errors.assign(10, ERROR_SHARING_VIOLATION);
  if (WriteProtectedValue("current_device_id", "device") ||
      store_replace_calls != static_cast<size_t>(kMaximumStoreAttempts)) return false;

  // Any other replacement error is final at once.
  ResetStoreWriteSpies();
  store_replace_errors = {ERROR_NOT_SAME_DEVICE};
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_replace") ||
      failure.win32_error != ERROR_NOT_SAME_DEVICE || failure.attempts != 1 ||
      !store_sleeps.empty() || !OnlyTemporaryRemoved()) return false;

  // DPAPI failures keep their HRESULT-style code intact and create no file.
  ResetStoreWriteSpies();
  store_protect_error = static_cast<DWORD>(NTE_BAD_KEY_STATE);
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_protect") ||
      failure.win32_error != static_cast<DWORD>(NTE_BAD_KEY_STATE) ||
      failure.attempts != 1 || !store_temporary.empty() || store_replace_calls != 0 ||
      !store_deleted.empty() ||
      !StoreDetails(failure, "secure_store_protect",
                    static_cast<int64_t>(static_cast<DWORD>(NTE_BAD_KEY_STATE)), 1))
    return false;

  // A short write is a write failure even though WriteFile succeeded.
  ResetStoreWriteSpies();
  store_short_write = true;
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_write") ||
      failure.win32_error != ERROR_WRITE_FAULT || store_replace_calls != 0 ||
      !OnlyTemporaryRemoved()) return false;
  ResetStoreWriteSpies();
  store_write_error = ERROR_DISK_FULL;
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_write") ||
      failure.win32_error != ERROR_DISK_FULL || !store_sleeps.empty() ||
      store_replace_calls != 0 || !OnlyTemporaryRemoved()) return false;
  ResetStoreWriteSpies();
  store_flush_error = ERROR_IO_DEVICE;
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_flush") ||
      failure.win32_error != ERROR_IO_DEVICE || store_replace_calls != 0 ||
      !OnlyTemporaryRemoved()) return false;

  // A temporary that was never created is never deleted, and a create
  // failure is final even for an otherwise transient error.
  ResetStoreWriteSpies();
  store_create_error = ERROR_ACCESS_DENIED;
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_create") ||
      failure.win32_error != ERROR_ACCESS_DENIED || failure.attempts != 1 ||
      store_temporary.empty() || store_replace_calls != 0 || !store_deleted.empty() ||
      !store_sleeps.empty() ||
      !StoreDetails(failure, "secure_store_create", ERROR_ACCESS_DENIED, 1))
    return false;

  // A failed LocalAppData lookup reports its raw HRESULT (E_FAIL has no Win32
  // facility and is not a missing path) and frees the shell buffer either way.
  ResetStoreWriteSpies();
  known_folder_error = E_FAIL;
  if (WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      !StoreStage(failure, "secure_store_path") ||
      failure.win32_error != static_cast<DWORD>(E_FAIL) || known_folder_frees != 1 ||
      known_folder_output != nullptr || !store_temporary.empty() ||
      !StoreDetails(failure, "secure_store_path",
                    static_cast<int64_t>(static_cast<DWORD>(E_FAIL)), 1))
    return false;
  ResetStoreWriteSpies();
  if (!WriteProtectedValueDetailed("current_device_id", "device", &failure) ||
      known_folder_frees != 1 || known_folder_output != nullptr) return false;
  // Only system-category filesystem errors are Win32 codes.
  if (FilesystemWin32Error(std::error_code(static_cast<int>(ERROR_DISK_FULL),
                                           std::system_category())) != ERROR_DISK_FULL ||
      FilesystemWin32Error(std::make_error_code(std::errc::not_a_directory)) !=
          ERROR_PATH_NOT_FOUND)
    return false;

  ResetStoreWriteSpies();
  if (WriteProtectedValueDetailed("../escape", "device", &failure) ||
      !StoreStage(failure, "secure_store_path") ||
      failure.win32_error != ERROR_INVALID_NAME || !store_temporary.empty()) return false;
  {
    ScopedProtectedStoreUser user(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(101)));
    fail_store_impersonation = true;
    ResetStoreWriteSpies();
    const bool refused =
        !WriteProtectedValueDetailed("current_device_id", "device", &failure) &&
        StoreStage(failure, "secure_store_impersonation") &&
        failure.win32_error == ERROR_CANNOT_IMPERSONATE && store_temporary.empty();
    ProtectedStoreFailure deletion;
    const bool delete_refused =
        !DeleteProtectedValueDetailed("current_device_id", &deletion) &&
        StoreStage(deletion, "secure_store_impersonation") &&
        deletion.win32_error == ERROR_CANNOT_IMPERSONATE && store_deleted.empty();
    fail_store_impersonation = false;
    if (!refused || !delete_refused) return false;
  }

  // Deletion uses the same bounded retry; a value that vanished meanwhile
  // (for example a pending delete completing) is already removed.
  ResetStoreWriteSpies();
  store_delete_errors = {ERROR_SHARING_VIOLATION, ERROR_SHARING_VIOLATION};
  if (!DeleteProtectedValueDetailed("current_device_id", &failure) ||
      failure.stage != nullptr || failure.attempts != 3 || store_sleeps != Delays{10, 20} ||
      store_deleted.size() != 3 ||
      std::filesystem::path(store_deleted[0]).filename() != L"current_device_id.bin")
    return false;
  ResetStoreWriteSpies();
  store_delete_errors = {ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND};
  if (!DeleteProtectedValueDetailed("current_device_id", &failure) ||
      failure.attempts != 2) return false;
  ResetStoreWriteSpies();
  store_delete_errors = {ERROR_FILE_NOT_FOUND};
  if (!DeleteProtectedValueDetailed("current_device_id", &failure) ||
      failure.attempts != 1 || !store_sleeps.empty()) return false;
  ResetStoreWriteSpies();
  store_delete_errors.assign(10, ERROR_LOCK_VIOLATION);
  if (DeleteProtectedValueDetailed("current_device_id", &failure) ||
      !StoreStage(failure, "secure_store_delete") ||
      failure.win32_error != ERROR_LOCK_VIOLATION ||
      failure.attempts != kMaximumStoreAttempts || store_sleeps != backoff ||
      !StoreDetails(failure, "secure_store_delete", ERROR_LOCK_VIOLATION, 6))
    return false;
  ResetStoreWriteSpies();
  store_delete_errors.assign(10, ERROR_LOCK_VIOLATION);
  if (DeleteProtectedValue("current_device_id")) return false;
  ResetStoreWriteSpies();
  store_delete_errors = {ERROR_WRITE_PROTECT};
  if (DeleteProtectedValueDetailed("current_device_id", &failure) ||
      !StoreStage(failure, "secure_store_delete") ||
      failure.win32_error != ERROR_WRITE_PROTECT || failure.attempts != 1 ||
      !store_sleeps.empty()) return false;

  // A file where the store folder belongs fails before any temporary exists.
  ResetStoreWriteSpies();
  const std::filesystem::path folder = std::filesystem::path(StoreFixtureRoot()) / L"FuzeVPN";
  std::error_code error;
  std::filesystem::remove(folder, error);
  std::filesystem::create_directories(folder.parent_path(), error);
  { std::ofstream blocker(folder, std::ios::binary | std::ios::trunc); blocker << "x"; }
  return !WriteProtectedValueDetailed("current_device_id", "device", &failure) &&
         StoreStage(failure, "secure_store_directory") && failure.win32_error != 0 &&
         store_temporary.empty() && store_replace_calls == 0;
}
}  // namespace

bool TestProtectedStoreWriteFailures() {
  const bool passed = RunStoreWriteFailureCases();
  ResetStoreWriteSpies();
  fail_store_impersonation = false;
  std::error_code error;
  std::filesystem::remove_all(StoreFixtureRoot(), error);
  return passed;
}

bool TestProtectedStoreTokenRouting() {
  const auto first = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(101));
  const auto second = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(102));
  if (PathFor("wireguard_private_key").filename() != L"wireguard_private_key.bin" ||
      observed_folder_token != nullptr) return false;
  {
    ScopedProtectedStoreUser user(first);
    PathFor("wireguard_private_key");
    if (observed_folder_token != first) return false;
    {
      ScopedProtectedStoreUser nested(second);
      PathFor("openvpn_identity_v1");
      if (observed_folder_token != second) return false;
    }
    PathFor("openvpn_identity_v1");
    if (observed_folder_token != first) return false;
  }
  PathFor("access_token");
  return observed_folder_token == nullptr && PathFor("../escape").empty();
}

bool TestProtectedDiagnosticRouting() {
  const auto user = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(101));
  {
    ScopedProtectedStoreUser selected(user);
    if (DiagnosticPathFor("native_stage.txt").filename() != L"native_stage.txt" ||
        observed_folder_token != user || !DiagnosticPathFor("../escape").empty())
      return false;
    observed_impersonation_token = nullptr;
    observed_store_reverts = 0;
    // A rejected filename still exercises the complete short impersonation
    // lifetime, while no filesystem operation is performed.
    if (WriteUserDiagnostic("../escape", "safe", false) ||
        observed_impersonation_token != user || observed_store_reverts != 1)
      return false;
    fail_store_impersonation = true;
    observed_folder_token = nullptr;
    const bool refused = !WriteUserDiagnostic("native_stage.txt", "safe", false) &&
        observed_folder_token == nullptr && observed_store_reverts == 1;
    fail_store_impersonation = false;
    if (!refused) return false;
  }
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::vpn_service);
  observed_folder_token = user;
  const bool refused_service_profile =
      !WriteUserDiagnostic("native_stage.txt", "safe", false) &&
      observed_folder_token == user;
  SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::user_interface);
  return refused_service_profile;
}
