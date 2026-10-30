// SPDX-License-Identifier: MPL-2.0
// All filesystem APIs are substituted: no real ProgramData/profile/VPN access.
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <filesystem>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

namespace {
enum class Failure { none, lookup, open, metadata, type, path, alias, security,
                     policy, acl, create, file_descriptor, file_create,
                     file_security, file_read_users, file_read_everyone,
                     file_read_third_party, file_unprotected, file_owner,
                     write, short_write, flush, close, replace };
Failure fail = Failure::none;
std::map<HANDLE, std::wstring> handles;
unsigned next_handle = 100, writes = 0, deletes = 0;
bool readable_runtime = false, private_attributes_seen = false;
bool Config(HANDLE handle) { return handles.at(handle).find(L".conf.tmp.") != std::wstring::npos; }
bool Target(HANDLE handle) { return handles.at(handle) == L"C:\\ProgramData\\FuzeVPN"; }
HRESULT WINAPI StorageTestFolder(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR* output) {
  if (fail == Failure::lookup) return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
  const std::wstring path = L"C:\\ProgramData";
  *output = static_cast<PWSTR>(CoTaskMemAlloc((path.size() + 1) * sizeof(wchar_t)));
  wcscpy_s(*output, path.size() + 1, path.c_str()); return S_OK;
}
HANDLE WINAPI Open(LPCWSTR path, DWORD access, DWORD, LPSECURITY_ATTRIBUTES security, DWORD creation, DWORD, HANDLE) {
  const std::wstring name(path);
  if (creation == CREATE_NEW) {
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    private_attributes_seen = security != nullptr && security->lpSecurityDescriptor != nullptr &&
        !security->bInheritHandle && (access & READ_CONTROL) != 0 &&
        GetSecurityDescriptorControl(security->lpSecurityDescriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) != 0;
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    if (!private_attributes_seen || !GetSecurityDescriptorDacl(security->lpSecurityDescriptor,
        &present, &acl, &defaulted) || !present || !acl)
      throw std::runtime_error("config creation must supply protected private security");
    for (DWORD index = 0; index < acl->AceCount; ++index) {
      void* raw = nullptr;
      if (!GetAce(acl, index, &raw)) throw std::runtime_error("invalid creation ACL");
      const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
      if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
          (!IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinLocalSystemSid) &&
           !IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinBuiltinAdministratorsSid)))
        throw std::runtime_error("config creation grants access outside BA/SY");
    }
  }
  if ((fail == Failure::open && name == L"C:\\ProgramData\\FuzeVPN") ||
      (fail == Failure::file_create && creation == CREATE_NEW)) {
    SetLastError(ERROR_SHARING_VIOLATION); return INVALID_HANDLE_VALUE;
  }
  const auto handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(++next_handle));
  handles[handle] = name; return handle;
}
BOOL WINAPI Info(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION info) {
  if (fail == Failure::metadata && Target(handle)) { SetLastError(ERROR_READ_FAULT); return FALSE; }
  *info = {};
  info->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
  if (fail == Failure::type && Target(handle)) info->dwFileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
  return TRUE;
}
DWORD WINAPI FinalPath(HANDLE handle, LPWSTR output, DWORD size, DWORD) {
  if (fail == Failure::path && Target(handle)) { SetLastError(ERROR_INVALID_NAME); return 0; }
  const auto path = fail == Failure::alias && Target(handle) ? L"C:\\redirected" : handles.at(handle);
  wcscpy_s(output, size, path.c_str()); return static_cast<DWORD>(path.size());
}
DWORD WINAPI Security(HANDLE handle, SE_OBJECT_TYPE, SECURITY_INFORMATION,
    PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR* descriptor) {
  if (fail == Failure::security && Target(handle)) return ERROR_PRIVILEGE_NOT_HELD;
  if (Config(handle) && fail == Failure::file_security) return ERROR_PRIVILEGE_NOT_HELD;
  if (Config(handle)) {
    const wchar_t* file_sddl = fail == Failure::file_read_users ?
        L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)" :
        fail == Failure::file_read_everyone ? L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;WD)" :
        fail == Failure::file_read_third_party ? L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;S-1-5-21-1-2-3-1001)" :
        fail == Failure::file_unprotected ? L"O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)" :
        fail == Failure::file_owner ? L"O:BUG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)" :
        L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(file_sddl, SDDL_REVISION_1,
        descriptor, nullptr) ? ERROR_SUCCESS : GetLastError();
  }
  const wchar_t* sddl = fail == Failure::policy && Target(handle) ?
      L"O:BUG:SYD:P(A;;FA;;;SY)(A;;FA;;;BU)" : fail == Failure::acl && Target(handle) ?
      L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BU)" : readable_runtime ?
      L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)" :
      L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
  return ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
      descriptor, nullptr) ? ERROR_SUCCESS : GetLastError();
}
BOOL WINAPI Directory(LPCWSTR path, LPSECURITY_ATTRIBUTES) {
  if (fail == Failure::create && std::wstring_view(path) == L"C:\\ProgramData\\FuzeVPN") {
    SetLastError(ERROR_ACCESS_DENIED); return FALSE;
  }
  SetLastError(ERROR_ALREADY_EXISTS); return FALSE;
}
BOOL WINAPI Write(HANDLE, LPCVOID, DWORD size, LPDWORD written, LPOVERLAPPED) {
  ++writes;
  if (fail == Failure::write) { SetLastError(ERROR_DISK_FULL); return FALSE; }
  *written = fail == Failure::short_write ? size - 1 : size; return TRUE;
}
BOOL WINAPI Flush(HANDLE) {
  if (fail == Failure::flush) { SetLastError(ERROR_WRITE_FAULT); return FALSE; }
  return TRUE;
}
BOOL WINAPI Close(HANDLE handle) {
  const bool failed = fail == Failure::close && Config(handle);
  handles.erase(handle);
  SetLastError(failed ? ERROR_INVALID_HANDLE : 9999); return failed ? FALSE : TRUE;
}
BOOL WINAPI Move(LPCWSTR, LPCWSTR, DWORD flags) {
  if (flags != (MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) throw std::runtime_error("atomic write flags lost");
  if (fail == Failure::replace) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
  return TRUE;
}
BOOL WINAPI Delete(LPCWSTR) { ++deletes; SetLastError(ERROR_FILE_NOT_FOUND); return FALSE; }
BOOL WINAPI Descriptor(LPCWSTR text, DWORD revision, PSECURITY_DESCRIPTOR* output, PULONG size) {
  if (fail == Failure::file_descriptor && std::wstring_view(text) == L"D:P(A;;FA;;;BA)(A;;FA;;;SY)") {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE;
  }
  return ConvertStringSecurityDescriptorToSecurityDescriptorW(text, revision, output, size);
}
}
#define SHGetKnownFolderPath ::StorageTestFolder
#define CreateFileW ::Open
#define GetFileInformationByHandle Info
#define GetFinalPathNameByHandleW FinalPath
#define GetSecurityInfo Security
#define CreateDirectoryW Directory
#define WriteFile Write
#define FlushFileBuffers Flush
#define CloseHandle Close
#define MoveFileExW Move
#define DeleteFileW Delete
#define ConvertStringSecurityDescriptorToSecurityDescriptorW Descriptor
#include "wireguard_config_storage.h"
#undef SHGetKnownFolderPath
#undef CreateFileW
#undef GetFileInformationByHandle
#undef GetFinalPathNameByHandleW
#undef GetSecurityInfo
#undef CreateDirectoryW
#undef WriteFile
#undef FlushFileBuffers
#undef CloseHandle
#undef MoveFileExW
#undef DeleteFileW
#undef ConvertStringSecurityDescriptorToSecurityDescriptorW

int main() {
  using namespace fuzevpn_installation;
  try {
    struct Case { Failure failure; const char* stage; DWORD code; };
    for (const auto& test : {
        Case{Failure::lookup, "program_data_lookup", ERROR_PATH_NOT_FOUND},
        Case{Failure::open, "fuzevpn_open", ERROR_SHARING_VIOLATION},
        Case{Failure::metadata, "fuzevpn_metadata", ERROR_READ_FAULT},
        Case{Failure::type, "fuzevpn_type", ERROR_ACCESS_DENIED},
        Case{Failure::path, "fuzevpn_path", ERROR_INVALID_NAME},
        Case{Failure::alias, "fuzevpn_path", ERROR_ACCESS_DENIED},
        Case{Failure::security, "fuzevpn_security", ERROR_PRIVILEGE_NOT_HELD},
        Case{Failure::policy, "fuzevpn_owner", ERROR_ACCESS_DENIED},
        Case{Failure::acl, "fuzevpn_acl", ERROR_ACCESS_DENIED},
        Case{Failure::create, "fuzevpn_create", ERROR_ACCESS_DENIED},
        Case{Failure::file_descriptor, "config_descriptor", ERROR_NOT_ENOUGH_MEMORY},
        Case{Failure::file_create, "config_create", ERROR_SHARING_VIOLATION},
        Case{Failure::file_security, "config_security", ERROR_PRIVILEGE_NOT_HELD},
        Case{Failure::file_read_users, "config_acl", ERROR_ACCESS_DENIED},
        Case{Failure::file_read_everyone, "config_acl", ERROR_ACCESS_DENIED},
        Case{Failure::file_read_third_party, "config_acl", ERROR_ACCESS_DENIED},
        Case{Failure::file_unprotected, "config_acl", ERROR_ACCESS_DENIED},
        Case{Failure::file_owner, "config_acl", ERROR_ACCESS_DENIED},
        Case{Failure::write, "config_write", ERROR_DISK_FULL},
        Case{Failure::short_write, "config_write", ERROR_WRITE_FAULT},
        Case{Failure::flush, "config_flush", ERROR_WRITE_FAULT},
        Case{Failure::close, "config_close", ERROR_INVALID_HANDLE},
        Case{Failure::replace, "config_replace", ERROR_ACCESS_DENIED}}) {
      fail = test.failure; writes = deletes = 0; private_attributes_seen = false;
      RuntimeStorageFailure failure;
      if (WriteWireGuardConfiguration("private-test-configuration", &failure) ||
          failure.stage != std::string("wg_storage_") + test.stage || failure.win32_error != test.code)
        throw std::runtime_error(std::string("failure details lost: ") + test.stage);
      if (fail <= Failure::file_owner && writes != 0) throw std::runtime_error("unsafe write after security rejection");
      if (fail <= Failure::file_create && deletes != 0) throw std::runtime_error("removed a file not created by this operation");
      if (!handles.empty()) throw std::runtime_error("pinned handle leaked");
    }
    fail = Failure::none;
    readable_runtime = true;
    private_attributes_seen = false;
    RuntimeStorageFailure success{"stale", ERROR_ACCESS_DENIED};
    if (!WriteWireGuardConfiguration("private-test-configuration", &success) ||
        !success.stage.empty() || success.win32_error != ERROR_SUCCESS || !handles.empty() ||
        !private_attributes_seen)
      throw std::runtime_error("success retains stale failure or handles");
    std::cout << "WireGuard storage: 23 failures preserve errors; private file ACL verified before writes even below Users-readable runtime\n";
    return 0;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
