// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_CONFIG_STORAGE_H_
#define RUNNER_WIREGUARD_CONFIG_STORAGE_H_
#include "installation_security.h"

namespace fuzevpn_installation {
inline bool WriteWireGuardConfiguration(const std::string& configuration,
                                       RuntimeStorageFailure* failure) {
  *failure = {};
  ProtectedRuntimeDirectory directory;
  if (!directory.Open(true, failure)) return false;
  const auto config_path = directory.path() / L"FuzeVPN.conf";
  auto temporary = config_path;
  temporary += L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
               std::to_wstring(GetTickCount64());
  struct TemporaryCleanup {
    const std::filesystem::path& path;
    bool created = false;
    ~TemporaryCleanup() { if (created) DeleteFileW(path.c_str()); }
  } temporary_cleanup{temporary};
  PSECURITY_DESCRIPTOR private_descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"D:P(A;;FA;;;BA)(A;;FA;;;SY)", SDDL_REVISION_1,
      &private_descriptor, nullptr))
    return failure->Set("config", "descriptor", GetLastError());
  SECURITY_ATTRIBUTES private_security{sizeof(SECURITY_ATTRIBUTES), private_descriptor, FALSE};
  HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE | READ_CONTROL, 0, &private_security,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  const DWORD creation_error = file == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
  LocalFree(private_descriptor);
  if (file == INVALID_HANDLE_VALUE)
    return failure->Set("config", "create", creation_error);
  temporary_cleanup.created = true;
  bool complete = true;
  PSECURITY_DESCRIPTOR actual_descriptor = nullptr;
  const DWORD security_error = GetSecurityInfo(file, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr,
      nullptr, nullptr, nullptr, &actual_descriptor);
  if (security_error != ERROR_SUCCESS)
    complete = failure->Set("config", "security", security_error);
  else if (!IsPrivateRuntimeFileDescriptor(actual_descriptor))
    complete = failure->Set("config", "acl", ERROR_ACCESS_DENIED);
  if (actual_descriptor != nullptr) LocalFree(actual_descriptor);
  DWORD written = 0;
  if (!complete) {
    CloseHandle(file);
    return false;
  }
  if (configuration.size() > MAXDWORD)
    complete = failure->Set("config", "write", ERROR_FILE_TOO_LARGE);
  else if (!WriteFile(file, configuration.data(), static_cast<DWORD>(configuration.size()),
                     &written, nullptr))
    complete = failure->Set("config", "write", GetLastError());
  else if (written != configuration.size())
    complete = failure->Set("config", "write", ERROR_WRITE_FAULT);
  else if (!FlushFileBuffers(file))
    complete = failure->Set("config", "flush", GetLastError());
  const BOOL closed = CloseHandle(file);
  if (complete && !closed) complete = failure->Set("config", "close", GetLastError());
  if (!complete) return false;
  if (!MoveFileExW(temporary.c_str(), config_path.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    return failure->Set("config", "replace", GetLastError());
  return true;
}
}  // namespace fuzevpn_installation
#endif  // RUNNER_WIREGUARD_CONFIG_STORAGE_H_
