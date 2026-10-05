// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_INSTALLATION_SECURITY_H_
#define RUNNER_INSTALLATION_SECURITY_H_

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <filesystem>
#include <string>
#include <vector>

namespace fuzevpn_installation {

inline bool SamePath(const std::wstring& first, const std::wstring& second) {
  return CompareStringOrdinal(first.c_str(), -1, second.c_str(), -1, TRUE) ==
      CSTR_EQUAL;
}

// Lexical policy only. Existing objects are additionally checked by handle
// below; a DOS drive letter alone does not prove that its volume is local.
inline bool IsCanonicalLocalAbsolutePath(const std::filesystem::path& path) {
  const auto& value = path.native();
  if (value.size() <= 3 || value.size() > 32000 ||
      !((value[0] >= L'A' && value[0] <= L'Z') ||
        (value[0] >= L'a' && value[0] <= L'z')) ||
      value[1] != L':' || value[2] != L'\\' || !path.is_absolute()) return false;
  for (size_t start = 3; start < value.size();) {
    const size_t end = value.find(L'\\', start);
    const auto part = value.substr(start, end == std::wstring::npos ? end : end - start);
    if (part.empty() || part == L"." || part == L".." ||
        part.back() == L'.' || part.back() == L' ') return false;
    for (const wchar_t c : part) {
      if (c < 32 || c == L'/' || c == L':' || c == L'"' ||
          c == L'<' || c == L'>' || c == L'|' || c == L'?' || c == L'*') return false;
    }
    const auto stem = part.substr(0, part.find(L'.'));
    if (SamePath(stem, L"CON") || SamePath(stem, L"PRN") ||
        SamePath(stem, L"AUX") || SamePath(stem, L"NUL") ||
        (stem.size() == 4 &&
         (SamePath(stem.substr(0, 3), L"COM") || SamePath(stem.substr(0, 3), L"LPT")) &&
         ((stem[3] >= L'1' && stem[3] <= L'9') || stem[3] == L'\u00b9' ||
          stem[3] == L'\u00b2' || stem[3] == L'\u00b3'))) return false;
    if (end == std::wstring::npos) return true;
    start = end + 1;
    if (start == value.size()) return false;
  }
  return false;
}

inline bool IsLocalFixedVolume(const std::filesystem::path& path) {
  if (!IsCanonicalLocalAbsolutePath(path)) return false;
  const auto root = path.root_path().wstring();
  DWORD flags = 0;
  return GetDriveTypeW(root.c_str()) == DRIVE_FIXED &&
      GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, &flags,
                            nullptr, 0) && (flags & FILE_PERSISTENT_ACLS) != 0;
}

inline bool IsDescendant(const std::filesystem::path& candidate,
                         const std::filesystem::path& root) {
  const std::wstring child = candidate.wstring();
  std::wstring parent = root.wstring();
  while (!parent.empty() && (parent.back() == L'\\' || parent.back() == L'/'))
    parent.pop_back();
  return child.size() > parent.size() && child[parent.size()] == L'\\' &&
      CompareStringOrdinal(child.c_str(), static_cast<int>(parent.size()),
                           parent.c_str(), static_cast<int>(parent.size()),
                           TRUE) == CSTR_EQUAL;
}

inline bool IsTrustedOwner(PSID sid) {
  if (sid == nullptr || !IsValidSid(sid)) return false;
  if (IsWellKnownSid(sid, WinLocalSystemSid) ||
      IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) return true;
  // Windows owns Program Files through this fixed TrustedInstaller service SID.
  PSID installer = nullptr;
  if (!ConvertStringSidToSidW(
          L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
          &installer)) return false;
  const bool trusted = EqualSid(sid, installer) != FALSE;
  LocalFree(installer);
  return trusted;
}

// Conservative ACL policy: an installer must not leave any effective write
// grant to an ordinary account, even if a separate deny ACE might cancel it.
// Checking the owner also prevents that account from granting itself access.
inline bool IsProtectedDescriptor(PSECURITY_DESCRIPTOR descriptor,
                                   bool directory,
                                   bool containing_ancestor = false) {
  PSID owner = nullptr;
  BOOL defaulted = FALSE;
  if (descriptor == nullptr || !IsValidSecurityDescriptor(descriptor) ||
      !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
      !IsTrustedOwner(owner)) return false;
  PACL acl = nullptr;
  BOOL present = FALSE;
  if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) ||
      !present || acl == nullptr || !IsValidAcl(acl)) return false;
  const DWORD dangerous = containing_ancestor ?
      (DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER) :
      (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
       FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
       (directory ? FILE_DELETE_CHILD : 0));
  GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                           FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
  for (DWORD index = 0; index < acl->AceCount; ++index) {
    void* raw = nullptr;
    if (!GetAce(acl, index, &raw)) return false;
    const auto* header = static_cast<const ACE_HEADER*>(raw);
    if ((header->AceFlags & INHERIT_ONLY_ACE) != 0) continue;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
        header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) return false;
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
    DWORD rights = ace->Mask;
    MapGenericMask(&rights, &mapping);
    if ((rights & dangerous) != 0 &&
        !IsTrustedOwner(const_cast<DWORD*>(&ace->SidStart))) return false;
  }
  return true;
}

// Keep every checked object open without write/delete sharing until service
// registration finishes. No install-time check changes an ACL or a file.
class ProtectedInstallation final {
 public:
  ~ProtectedInstallation() {
    for (HANDLE handle : handles_) CloseHandle(handle);
  }
  ProtectedInstallation() = default;
  ProtectedInstallation(const ProtectedInstallation&) = delete;
  ProtectedInstallation& operator=(const ProtectedInstallation&) = delete;

  bool Validate(const std::filesystem::path& executable, bool require_runtime_files = true) {
    return ValidateFiles(executable, require_runtime_files, require_runtime_files);
  }

  // The protected portable-engine cache need not contain the frontend.
  bool ValidateEngine(const std::filesystem::path& executable) {
    return ValidateFiles(executable, true, false);
  }

  // New installation targets may be created only below an already-protected
  // direct parent. Checking by handle also rejects aliases and reparse paths.
  bool ValidateTarget(const std::filesystem::path& directory) {
    if (!handles_.empty() || !IsLocalFixedVolume(directory)) return false;
    const DWORD attributes = GetFileAttributesW(directory.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES)
      return ValidateFiles(directory / L"fuzevpn-service.exe", false, false);
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return false;
    const auto parent = directory.parent_path();
    return PinAncestors(parent) && Pin(parent, true);
  }

 private:
  bool PinAncestors(const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> ancestors;
    for (auto parent = directory.parent_path(); !parent.empty();) {
      if (ancestors.size() >= 64) return false;
      ancestors.push_back(parent);
      const auto next = parent.parent_path();
      if (next == parent) break;
      parent = next;
    }
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
      if (!Pin(*it, true, true)) return false;
    }
    return true;
  }

  bool ValidateFiles(const std::filesystem::path& executable,
                     bool require_service, bool require_ui) {
    if (!handles_.empty() || !IsLocalFixedVolume(executable) ||
        !SamePath(executable.filename().wstring(), L"fuzevpn-service.exe"))
      return false;
    const auto directory = executable.parent_path();
    if (!IsCanonicalLocalAbsolutePath(directory) || !PinAncestors(directory) ||
        !Pin(directory, true)) return false;
    if (!PinTree(directory, 0)) return false;
    return (!require_service || saw_service_) && (!require_ui || saw_ui_);
  }

  bool Pin(const std::filesystem::path& path, bool directory,
           bool containing_ancestor = false) {
    if (handles_.size() >= 8192) return false;
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION information{};
    std::wstring final_path(32768, L'\0');
    const DWORD final_length = GetFinalPathNameByHandleW(file, final_path.data(),
        static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    bool valid = GetFileInformationByHandle(file, &information) &&
        (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
        final_length != 0 && final_length < final_path.size();
    if (valid) {
      final_path.resize(final_length);
      if (final_path.rfind(L"\\\\?\\", 0) == 0) final_path.erase(0, 4);
      auto expected = path.wstring();
      // Windows may omit the trailing separator on a volume handle.
      while (expected.size() > 2 && expected.back() == L'\\') expected.pop_back();
      while (final_path.size() > 2 && final_path.back() == L'\\') final_path.pop_back();
      valid = SamePath(final_path, expected);
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (valid) {
      valid = GetSecurityInfo(file, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          nullptr, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
          IsProtectedDescriptor(descriptor, directory, containing_ancestor);
    }
    if (descriptor != nullptr) LocalFree(descriptor);
    if (!valid) {
      CloseHandle(file);
      return false;
    }
    handles_.push_back(file);
    return true;
  }

  bool PinTree(const std::filesystem::path& directory, unsigned depth) {
    if (depth > 16) return false;
    WIN32_FIND_DATAW entry{};
    const auto pattern = directory / L"*";
    HANDLE enumeration = FindFirstFileW(pattern.c_str(), &entry);
    if (enumeration == INVALID_HANDLE_VALUE)
      return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool valid = true;
    do {
      if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0)
        continue;
      const auto path = directory / entry.cFileName;
      const bool is_directory = (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      if (!Pin(path, is_directory) || (is_directory && !PinTree(path, depth + 1))) {
        valid = false;
        break;
      }
      if (depth == 0 && !is_directory) {
        saw_service_ |= SamePath(entry.cFileName, L"fuzevpn-service.exe");
        saw_ui_ |= SamePath(entry.cFileName, L"fuzevpn_windows.exe");
      }
    } while (FindNextFileW(enumeration, &entry));
    if (valid && GetLastError() != ERROR_NO_MORE_FILES) valid = false;
    FindClose(enumeration);
    return valid;
  }

  std::vector<HANDLE> handles_;
  bool saw_service_ = false;
  bool saw_ui_ = false;
};

inline bool ValidateInstallationTarget(const std::filesystem::path& directory) {
  ProtectedInstallation target;
  return target.ValidateTarget(directory);
}

// Machine-owned tunnel configuration must not traverse an interactive user's
// profile. Existing untrusted objects are rejected, never repaired by pathname.
class ProtectedRuntimeDirectory final {
 public:
  ~ProtectedRuntimeDirectory() {
    for (HANDLE handle : handles_) CloseHandle(handle);
  }
  ProtectedRuntimeDirectory() = default;
  ProtectedRuntimeDirectory(const ProtectedRuntimeDirectory&) = delete;
  ProtectedRuntimeDirectory& operator=(const ProtectedRuntimeDirectory&) = delete;

  bool Open(bool create) {
    if (!handles_.empty()) return false;
    PWSTR known = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &known)))
      return false;
    std::filesystem::path root(known);
    CoTaskMemFree(known);
    std::vector<std::filesystem::path> ancestors;
    for (auto path = root; !path.empty();) {
      ancestors.push_back(path);
      const auto parent = path.parent_path();
      if (parent == path) break;
      path = parent;
    }
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
      if (!Pin(*it, true)) return false;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", SDDL_REVISION_1,
        &descriptor, nullptr)) return false;
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    bool valid = true;
    for (const wchar_t* component : {L"FuzeVPN", L"Runtime", L"WireGuard"}) {
      root /= component;
      if (create && !CreateDirectoryW(root.c_str(), &security) &&
          GetLastError() != ERROR_ALREADY_EXISTS) {
        valid = false;
        break;
      }
      if (!Pin(root, false)) {
        valid = false;
        break;
      }
    }
    LocalFree(descriptor);
    if (valid) directory_ = root;
    return valid;
  }
  const std::filesystem::path& path() const { return directory_; }

 private:
  bool Pin(const std::filesystem::path& path, bool ancestor) {
    HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    std::wstring final_path(32768, L'\0');
    const DWORD length = GetFinalPathNameByHandleW(handle, final_path.data(),
        static_cast<DWORD>(final_path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    bool valid = GetFileInformationByHandle(handle, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        length != 0 && length < final_path.size();
    if (valid) {
      final_path.resize(length);
      if (final_path.rfind(L"\\\\?\\", 0) == 0) final_path.erase(0, 4);
      auto expected = path.wstring();
      while (expected.size() > 2 && expected.back() == L'\\') expected.pop_back();
      while (final_path.size() > 2 && final_path.back() == L'\\') final_path.pop_back();
      valid = SamePath(final_path, expected);
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (valid) valid = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr,
        nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
        IsProtectedDescriptor(descriptor, true, ancestor);
    if (descriptor != nullptr) LocalFree(descriptor);
    if (!valid) { CloseHandle(handle); return false; }
    handles_.push_back(handle);
    return true;
  }
  std::vector<HANDLE> handles_;
  std::filesystem::path directory_;
};

}  // namespace fuzevpn_installation
#endif  // RUNNER_INSTALLATION_SECURITY_H_
