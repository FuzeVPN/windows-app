// A shell boundary spy checks that the production path resolver passes the
// selected user token, including nested scopes. No actual store I/O is invoked.
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <string>

namespace {
HANDLE observed_folder_token = nullptr;
HANDLE observed_impersonation_token = nullptr;
bool fail_store_impersonation = false;
unsigned observed_store_reverts = 0;
DWORD store_open_error = ERROR_FILE_NOT_FOUND;
LONGLONG store_file_size = 4;
bool store_short_read = false;
HANDLE store_file_handle = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(103));
HANDLE WINAPI ObserveStoreFileOpen(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                  DWORD, DWORD, HANDLE) {
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
BOOL WINAPI ObserveStoreClose(HANDLE handle) {
  return handle == store_file_handle ? TRUE : CloseHandle(handle);
}
BOOL WINAPI ObserveStoreUnprotect(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID,
                                  CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) {
  SetLastError(ERROR_INVALID_DATA);
  return FALSE;
}
BOOL WINAPI ObserveStoreImpersonation(HANDLE token) {
  observed_impersonation_token = token;
  return fail_store_impersonation ? FALSE : TRUE;
}
BOOL WINAPI ObserveStoreRevert() {
  ++observed_store_reverts;
  return TRUE;
}
HRESULT WINAPI ObserveKnownFolder(REFKNOWNFOLDERID, DWORD, HANDLE token,
                                 PWSTR* output) {
  observed_folder_token = token;
  constexpr wchar_t path[] = L"C:\\AuditStoreProbe";
  *output = static_cast<PWSTR>(CoTaskMemAlloc(sizeof(path)));
  if (*output == nullptr) return E_OUTOFMEMORY;
  CopyMemory(*output, path, sizeof(path));
  return S_OK;
}
}
#define FUZEVPN_SERVICE_PROCESS
#define SHGetKnownFolderPath ObserveKnownFolder
#define ImpersonateLoggedOnUser ObserveStoreImpersonation
#define RevertToSelf ObserveStoreRevert
#define CreateFileW ObserveStoreFileOpen
#define GetFileSizeEx ObserveStoreFileSize
#define ReadFile ObserveStoreRead
#define CloseHandle ObserveStoreClose
#define CryptUnprotectData ObserveStoreUnprotect
#include "../secure_store_channel.cpp"
#undef SHGetKnownFolderPath
#undef ImpersonateLoggedOnUser
#undef RevertToSelf
#undef CreateFileW
#undef GetFileSizeEx
#undef ReadFile
#undef CloseHandle
#undef CryptUnprotectData

bool TestProtectedStoreReadFailures() {
  using Status = ProtectedValueReadStatus;
  std::string value = "discarded previous plaintext";
  store_open_error = ERROR_FILE_NOT_FOUND;
  if (ReadProtectedValueStatus("access_token", &value) != Status::not_found || !value.empty()) return false;
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
