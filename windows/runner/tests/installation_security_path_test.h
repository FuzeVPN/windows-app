#pragma once
#include <map>
#include <stdexcept>

// Read-only filesystem APIs are replaced in this second compilation of the
// production validator. Tests never create files or change Windows ACLs.
namespace installation_path_fixture {
struct Node { bool directory = true; bool reparse = false; bool writable = false; };
struct Open { std::wstring path; std::vector<std::wstring> entries; size_t index = 0; };
inline std::map<std::wstring, Node> nodes;
inline std::map<ULONG_PTR, Open> opened;
inline ULONG_PTR next_handle = 1000;
inline UINT drive_type = DRIVE_FIXED;
inline bool persistent_acls = true;
inline std::wstring alias_path;
inline bool pinned_without_writes = true;
inline std::wstring Root() { return L"D:\\Protected\\FuzeVPN"; }
inline HANDLE Save(Open value) {
  const auto id = ++next_handle;
  opened.emplace(id, std::move(value));
  return reinterpret_cast<HANDLE>(id);
}
inline Open& Get(HANDLE handle) { return opened.at(reinterpret_cast<ULONG_PTR>(handle)); }
inline DWORD Attributes(const Node& node) {
  return (node.directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL) |
      (node.reparse ? FILE_ATTRIBUTE_REPARSE_POINT : 0);
}
inline HANDLE WINAPI Create(LPCWSTR path, DWORD, DWORD sharing,
    LPSECURITY_ATTRIBUTES, DWORD creation, DWORD flags, HANDLE) {
  if (nodes.find(path) == nodes.end()) { SetLastError(ERROR_PATH_NOT_FOUND); return INVALID_HANDLE_VALUE; }
  pinned_without_writes &= sharing == FILE_SHARE_READ && creation == OPEN_EXISTING &&
      (flags & FILE_FLAG_OPEN_REPARSE_POINT) != 0;
  return Save({path, {}, 0});
}
inline BOOL WINAPI Close(HANDLE handle) { return opened.erase(reinterpret_cast<ULONG_PTR>(handle)) == 1; }
inline DWORD WINAPI FileAttributes(LPCWSTR path) {
  const auto it = nodes.find(path);
  if (it == nodes.end()) { SetLastError(ERROR_PATH_NOT_FOUND); return INVALID_FILE_ATTRIBUTES; }
  return Attributes(it->second);
}
inline BOOL WINAPI Information(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION output) {
  *output = {}; output->dwFileAttributes = Attributes(nodes.at(Get(handle).path)); return TRUE;
}
inline DWORD WINAPI FinalPath(HANDLE handle, LPWSTR output, DWORD count, DWORD) {
  const auto& path = Get(handle).path;
  const std::wstring value = L"\\\\?\\" + (path == alias_path ? L"D:\\Another" : path);
  if (count <= value.size()) return static_cast<DWORD>(value.size() + 1);
  std::copy(value.begin(), value.end(), output); output[value.size()] = L'\0';
  return static_cast<DWORD>(value.size());
}
inline DWORD WINAPI Security(HANDLE handle, SE_OBJECT_TYPE, SECURITY_INFORMATION,
    PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR* descriptor) {
  const auto& node = nodes.at(Get(handle).path);
  const wchar_t* sddl = node.writable ? L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;BU)"
      : L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GRGX;;;BU)";
  return ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
      descriptor, nullptr) ? ERROR_SUCCESS : GetLastError();
}
inline void Entry(const std::wstring& path, LPWIN32_FIND_DATAW output) {
  *output = {}; output->dwFileAttributes = Attributes(nodes.at(path));
  const auto name = std::filesystem::path(path).filename().wstring();
  std::copy(name.begin(), name.end(), output->cFileName); output->cFileName[name.size()] = L'\0';
}
inline HANDLE WINAPI FindFirst(LPCWSTR pattern, LPWIN32_FIND_DATAW output) {
  Open state;
  const auto directory = std::filesystem::path(pattern).parent_path();
  for (const auto& [path, node] : nodes) {
    (void)node;
    if (std::filesystem::path(path).parent_path() == directory && path != directory.wstring())
      state.entries.push_back(path);
  }
  if (state.entries.empty()) { SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
  Entry(state.entries.front(), output); return Save(std::move(state));
}
inline BOOL WINAPI FindNext(HANDLE handle, LPWIN32_FIND_DATAW output) {
  auto& state = Get(handle);
  if (++state.index == state.entries.size()) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
  Entry(state.entries[state.index], output); return TRUE;
}
inline UINT WINAPI DriveType(LPCWSTR) { return drive_type; }
inline BOOL WINAPI VolumeInfo(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD flags, LPWSTR, DWORD) {
  *flags = persistent_acls ? FILE_PERSISTENT_ACLS : 0; return TRUE;
}
inline void Reset() {
  if (!opened.empty()) throw std::runtime_error("installation validator leaked pinned handles");
  nodes = {{L"D:\\", {}}, {L"D:\\Protected", {}}, {Root(), {}},
      {Root() + L"\\fuzevpn-service.exe", {false}}, {Root() + L"\\fuzevpn_windows.exe", {false}}};
  drive_type = DRIVE_FIXED; persistent_acls = true; alias_path.clear(); pinned_without_writes = true;
}
}  // namespace installation_path_fixture

#undef RUNNER_INSTALLATION_SECURITY_H_
#define fuzevpn_installation fuzevpn_installation_fixture
#define CreateFileW installation_path_fixture::Create
#define CloseHandle installation_path_fixture::Close
#define GetFileAttributesW installation_path_fixture::FileAttributes
#define GetFileInformationByHandle installation_path_fixture::Information
#define GetFinalPathNameByHandleW installation_path_fixture::FinalPath
#define GetSecurityInfo installation_path_fixture::Security
#define FindFirstFileW installation_path_fixture::FindFirst
#define FindNextFileW installation_path_fixture::FindNext
#define FindClose installation_path_fixture::Close
#define GetDriveTypeW installation_path_fixture::DriveType
#define GetVolumeInformationW installation_path_fixture::VolumeInfo
#include "../installation_security.h"
#undef fuzevpn_installation
#undef CreateFileW
#undef CloseHandle
#undef GetFileAttributesW
#undef GetFileInformationByHandle
#undef GetFinalPathNameByHandleW
#undef GetSecurityInfo
#undef FindFirstFileW
#undef FindNextFileW
#undef FindClose
#undef GetDriveTypeW
#undef GetVolumeInformationW

inline void TestInstallationPathSecurity() {
  using namespace installation_path_fixture;
  const auto check = [](bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
  };
  const auto validate = [](bool engine_only = false) {
    fuzevpn_installation_fixture::ProtectedInstallation installation;
    const auto executable = Root() + L"\\fuzevpn-service.exe";
    return engine_only ? installation.ValidateEngine(executable) : installation.Validate(executable);
  };
  Reset(); check(validate() && pinned_without_writes, "protected custom bundle is pinned and accepted");
  Reset(); nodes.erase(Root() + L"\\fuzevpn_windows.exe");
  check(validate(true) && !validate(), "engine cache needs service, ordinary bundle still needs GUI");
  nodes.erase(Root() + L"\\fuzevpn-service.exe");
  check(!validate(true), "engine cache must contain service executable");
  Reset(); nodes[L"D:\\Protected"].writable = true;
  check(!validate(), "replaceable ancestor is rejected");
  Reset(); nodes[Root() + L"\\fuzevpn-service.exe"].writable = true;
  check(!validate(), "writable runtime file is rejected");
  Reset(); nodes[L"D:\\Protected"].reparse = true;
  check(!validate(), "junction ancestor is rejected");
  Reset(); alias_path = Root();
  check(!validate(), "noncanonical final path is rejected");
  Reset(); drive_type = DRIVE_REMOTE;
  check(!validate(), "mapped network volume is rejected");
  Reset(); persistent_acls = false;
  check(!validate(), "volume without persistent ACLs is rejected");
  Reset();
  check(fuzevpn_installation_fixture::ValidateInstallationTarget(L"D:\\Protected\\NewVPN"),
      "new target under protected direct parent is accepted");
  nodes[L"D:\\Protected"].writable = true;
  check(!fuzevpn_installation_fixture::ValidateInstallationTarget(L"D:\\Protected\\NewVPN"),
      "new target under unprotected parent is rejected");
  Reset();
  check(!fuzevpn_installation_fixture::ValidateInstallationTarget(L"D:\\Missing\\NewVPN"),
      "missing direct parent is not trusted implicitly");
  check(opened.empty(), "all checked objects are released after validation");
}
