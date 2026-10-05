// SPDX-License-Identifier: MPL-2.0
#include "portable_runtime.h"
#include "broker_development_policy.h"
#include "installation_security.h"
#include "runtime_architecture.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <softpub.h>
#include <wintrust.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <memory>
#include <set>

namespace fuzevpn_portable {
namespace {
bool Fail(DWORD code, DWORD* error) {
  if (error) *error = code;
  SetLastError(code);
  return false;
}
bool Success(DWORD* error) { if (error) *error = ERROR_SUCCESS; return true; }
std::string Lower(std::string value) {
  for (char& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return value;
}
bool HashBytes(std::string_view bytes, std::string* result) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::array<BYTE, 32> digest{};
  bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
      BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0 &&
      BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),
                     static_cast<ULONG>(bytes.size()), 0) >= 0 &&
      BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return false;
  constexpr char hex[] = "0123456789abcdef";
  result->clear();
  for (BYTE b : digest) { *result += hex[b >> 4]; *result += hex[b & 15]; }
  return true;
}
bool Decimal(std::string_view text, std::uint64_t limit, std::uint64_t* value) {
  if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;
  std::uint64_t number = 0;
  for (char c : text) {
    if (c < '0' || c > '9' || number > (limit - static_cast<unsigned>(c - '0')) / 10) return false;
    number = number * 10 + static_cast<unsigned>(c - '0');
  }
  *value = number;
  return true;
}
bool ValidRelativePath(const std::string& value) {
  if (value.empty() || value.size() > 240 || value.front() == '/' || value.back() == '/') return false;
  unsigned depth = 0;
  std::size_t position = 0;
  while (position < value.size()) {
    const auto end = value.find('/', position);
    const auto part = value.substr(position, end == std::string::npos ? end : end - position);
    if (++depth > 8 || part.empty() || part == "." || part == ".." || part.back() == '.') return false;
    for (char c : part) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return false;
    const auto base = Lower(part.substr(0, part.find('.')));
    if (base == "con" || base == "prn" || base == "aux" || base == "nul" ||
        (base.size() == 4 && (base.rfind("com", 0) == 0 || base.rfind("lpt", 0) == 0) &&
         base[3] >= '0' && base[3] <= '9')) return false;
    if (end == std::string::npos) break;
    position = end + 1;
  }
  return true;
}
bool ValidManifest(const Manifest& manifest) {
  fuzevpn_update::Version version;
  if (!fuzevpn_update::ParseVersion(manifest.version.text(), &version) ||
      manifest.ipc_version != kIpcVersion || manifest.files.empty() ||
      manifest.files.size() > kMaximumFiles || !fuzevpn_update::ValidHash(manifest.sha256)) return false;
  std::uint64_t total = 0;
  bool service = false;
  std::set<std::string> paths;
  for (const auto& file : manifest.files) {
    if (!ValidRelativePath(file.relative_path) || file.size == 0 ||
        file.size > kMaximumPayloadBytes - total || !fuzevpn_update::ValidHash(file.sha256)) return false;
    total += file.size;
    const auto name = Lower(file.relative_path);
    if (!paths.insert(name).second) return false;
    service |= name == "fuzevpn-service.exe";
  }
  for (const auto& path : paths) {
    for (auto slash = path.find('/'); slash != std::string::npos; slash = path.find('/', slash + 1))
      if (paths.find(path.substr(0, slash)) != paths.end()) return false;
  }
  constexpr const char* required[] = {
      "fuzevpn-service.exe", "lz4.dll", fuzevpn_architecture::kOpenSslDll,
      fuzevpn_architecture::kOpenCryptoDll,
      "tunnel.dll", "wireguard.dll", "concrt140.dll", "msvcp140.dll", "msvcp140_1.dll",
      "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
      "vcruntime140.dll", "openvpn-dco/notice.md",
      "openvpn-dco/win10/ovpn-dco.inf", "openvpn-dco/win10/ovpn-dco.cat",
      "openvpn-dco/win10/ovpn-dco.sys", "openvpn-dco/win11/ovpn-dco.inf",
      "openvpn-dco/win11/ovpn-dco.cat", "openvpn-dco/win11/ovpn-dco.sys",
      "third_party_notices.md", "wireguard_notice.md",
      "licenses/openvpn3-corresponding-source.zip"};
  for (const auto* name : required) if (paths.find(name) == paths.end()) return false;
  if constexpr (fuzevpn_architecture::kBuildMachine == fuzevpn_architecture::kX64Machine)
    if (paths.find("vcruntime140_1.dll") == paths.end()) return false;
  return service;
}
std::filesystem::path RelativePath(const std::string& text) {
  auto path = std::filesystem::path(std::wstring(text.begin(), text.end()));
  return path.make_preferred();
}
bool ExactPath(const std::filesystem::path& expected, HANDLE handle) {
  std::wstring path(32768, L'\0');
  const auto length = GetFinalPathNameByHandleW(handle, path.data(),
      static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!length || length >= path.size()) return false;
  path.resize(length);
  if (path.rfind(L"\\\\?\\", 0) == 0) path.erase(0, 4);
  auto name = expected.wstring();
  while (name.size() > 2 && name.back() == L'\\') name.pop_back();
  while (path.size() > 2 && path.back() == L'\\') path.pop_back();
  return fuzevpn_installation::SamePath(path, name);
}
class DirectoryPins {
 public:
  ~DirectoryPins() { for (HANDLE h : handles_) CloseHandle(h); }
  bool Pin(const std::filesystem::path& path, bool ancestor, DWORD* error) {
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return Fail(GetLastError(), error);
    BY_HANDLE_FILE_INFORMATION info{};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    bool valid = GetFileInformationByHandle(h, &info) &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && ExactPath(path, h) &&
        GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
        fuzevpn_installation::IsProtectedDescriptor(descriptor, true, ancestor);
    if (descriptor) LocalFree(descriptor);
    if (!valid) { CloseHandle(h); return Fail(ERROR_ACCESS_DENIED, error); }
    handles_.push_back(h);
    return true;
  }
  bool Ancestors(const std::filesystem::path& path, DWORD* error) {
    if (!path.is_absolute() || path.native().size() > 30000) return Fail(ERROR_INVALID_NAME, error);
    std::vector<std::filesystem::path> list;
    for (auto current = path; !current.empty();) {
      if (list.size() >= 64) return Fail(ERROR_INVALID_NAME, error);
      list.push_back(current);
      const auto parent = current.parent_path();
      if (parent == current) break;
      current = parent;
    }
    for (auto i = list.rbegin(); i != list.rend(); ++i)
      if (!Pin(*i, *i != path, error)) return false;
    return true;
  }
 private:
  std::vector<HANDLE> handles_;
};
bool PinManifest(const std::filesystem::path& root, const Manifest& manifest,
    std::vector<std::unique_ptr<fuzevpn_update::PinnedFile>>* pins, DWORD* error) {
  if (!ValidManifest(manifest) || !root.is_absolute()) return Fail(ERROR_INVALID_DATA, error);
  for (const auto& entry : manifest.files) {
    auto file = std::make_unique<fuzevpn_update::PinnedFile>();
    LARGE_INTEGER size{};
    if (!file->Open(root / RelativePath(entry.relative_path), true) ||
        !GetFileSizeEx(file->get(), &size) || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) != entry.size ||
        !fuzevpn_update::MatchesHash(file->get(), entry.sha256)) return Fail(ERROR_INVALID_DATA, error);
    pins->push_back(std::move(file));
  }
  return Success(error);
}
bool CheckTree(const std::filesystem::path& root, const std::filesystem::path& directory,
               const std::set<std::string>& files, DirectoryPins* pins, DWORD* error) {
  WIN32_FIND_DATAW item{};
  HANDLE find = FindFirstFileW((directory / L"*").c_str(), &item);
  if (find == INVALID_HANDLE_VALUE) return Fail(GetLastError(), error);
  bool ok = true;
  do {
    if (!wcscmp(item.cFileName, L".") || !wcscmp(item.cFileName, L"..")) continue;
    const auto path = directory / item.cFileName;
    const auto relative = path.lexically_relative(root).generic_string();
    if ((item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) { ok = false; break; }
    if ((item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      const std::string prefix = Lower(relative) + "/";
      const auto first = files.lower_bound(prefix);
      if (first == files.end() || first->compare(0, prefix.size(), prefix) != 0 ||
          !pins->Pin(path, false, error) || !CheckTree(root, path, files, pins, error)) { ok = false; break; }
    } else {
      if (files.find(Lower(relative)) == files.end()) { ok = false; break; }
      HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ,
          nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      PSECURITY_DESCRIPTOR descriptor = nullptr;
      ok = file != INVALID_HANDLE_VALUE && GetSecurityInfo(file, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr,
          nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
          fuzevpn_installation::IsProtectedDescriptor(descriptor, false);
      if (descriptor) LocalFree(descriptor);
      if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
      if (!ok) break;
    }
  } while (FindNextFileW(find, &item));
  if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = false;
  FindClose(find);
  return ok ? Success(error) : Fail(ERROR_ACCESS_DENIED, error);
}
bool CheckProtected(const std::filesystem::path& root, const Manifest& manifest,
                    DirectoryPins* directories,
                    std::vector<std::unique_ptr<fuzevpn_update::PinnedFile>>* files, DWORD* error) {
  if (!directories->Ancestors(root, error) || !PinManifest(root, manifest, files, error)) return false;
  std::set<std::string> allowed;
  for (const auto& file : manifest.files) allowed.insert(Lower(file.relative_path));
  return CheckTree(root, root, allowed, directories, error);
}
LONG TrustStatus(const fuzevpn_update::PinnedFile& file) {
  WINTRUST_FILE_INFO info{};
  info.cbStruct = sizeof(info); info.pcwszFilePath = file.path().c_str(); info.hFile = file.get();
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
  trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &info;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG status = WinVerifyTrust(nullptr, &action, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &action, &trust);
  return status;
}
class SecurityDescriptor {
 public:
  ~SecurityDescriptor() { if (descriptor_) LocalFree(descriptor_); }
  bool Create() {
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)",
        SDDL_REVISION_1, &descriptor_, nullptr)) return false;
    attributes_ = {sizeof(attributes_), descriptor_, FALSE};
    return true;
  }
  SECURITY_ATTRIBUTES* get() { return &attributes_; }
 private:
  PSECURITY_DESCRIPTOR descriptor_ = nullptr;
  SECURITY_ATTRIBUTES attributes_{};
};
class PreparationLock {
 public:
  ~PreparationLock() { if (owned_) ReleaseMutex(handle_); if (handle_) CloseHandle(handle_); }
  bool Acquire(DWORD* error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1, &descriptor, nullptr)) return Fail(GetLastError(), error);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    handle_ = CreateMutexW(&attributes, FALSE, L"Global\\FuzeVPN-PortableRuntime-Prepare-v1");
    LocalFree(descriptor);
    if (!handle_) return Fail(GetLastError(), error);
    const DWORD wait = WaitForSingleObject(handle_, 30000);
    owned_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
    return owned_ ? true : Fail(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError(), error);
  }
 private:
  HANDLE handle_ = nullptr;
  bool owned_ = false;
};
} // namespace

bool ParseManifest(std::string_view text, Manifest* manifest, DWORD* error) {
  if (!manifest || text.empty() || text.size() > kMaximumManifestBytes || text.back() != '\n' ||
      text.find('\0') != std::string_view::npos || text.find('\r') != std::string_view::npos)
    return Fail(ERROR_INVALID_DATA, error);
  std::vector<std::string_view> lines;
  for (std::size_t start = 0; start < text.size();) {
    const auto end = text.find('\n', start);
    lines.push_back(text.substr(start, end - start));
    if (lines.size() > kMaximumFiles + 3) return Fail(ERROR_INVALID_DATA, error);
    start = end + 1;
  }
  Manifest parsed;
  if (lines.size() < 4 || lines[0] != "FUZEVPN_RUNTIME_V1" || lines[1].rfind("version=", 0) != 0 ||
      !fuzevpn_update::ParseVersion(std::string(lines[1].substr(8)), &parsed.version) ||
      lines[2] != "ipc=1") return Fail(ERROR_INVALID_DATA, error);
  for (std::size_t i = 3; i < lines.size(); ++i) {
    const auto line = lines[i];
    const auto first = line.find('\t'), second = first == std::string_view::npos ? first : line.find('\t', first + 1);
    ManifestFile file;
    if (line.rfind("file=", 0) != 0 || first == std::string_view::npos || second == std::string_view::npos ||
        line.find('\t', second + 1) != std::string_view::npos ||
        !Decimal(line.substr(5, first - 5), kMaximumPayloadBytes, &file.size)) return Fail(ERROR_INVALID_DATA, error);
    file.sha256 = Lower(std::string(line.substr(first + 1, second - first - 1)));
    file.relative_path = std::string(line.substr(second + 1));
    parsed.files.push_back(std::move(file));
  }
  if (!HashBytes(text, &parsed.sha256) || !ValidManifest(parsed)) return Fail(ERROR_INVALID_DATA, error);
  *manifest = std::move(parsed);
  return Success(error);
}
bool ReadEmbeddedManifest(const std::filesystem::path& executable, Manifest* manifest, DWORD* error) {
  fuzevpn_update::PinnedFile pinned;
  if (!pinned.Open(executable, true)) return Fail(ERROR_ACCESS_DENIED, error);
  HMODULE resource = LoadLibraryExW(executable.c_str(), nullptr,
      LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
  if (!resource) return Fail(GetLastError(), error);
  HRSRC found = FindResourceW(resource, MAKEINTRESOURCEW(kManifestResourceId), MAKEINTRESOURCEW(10));
  const DWORD size = found ? SizeofResource(resource, found) : 0;
  HGLOBAL loaded = size && size <= kMaximumManifestBytes ? LoadResource(resource, found) : nullptr;
  const auto* bytes = loaded ? static_cast<const char*>(LockResource(loaded)) : nullptr;
  const bool valid = bytes && ParseManifest(std::string_view(bytes, size), manifest, error);
  FreeLibrary(resource);
  return valid ? Success(error) : Fail(ERROR_INVALID_DATA, error);
}
std::filesystem::path RuntimeCachePath(const Manifest& manifest) {
  if (!ValidManifest(manifest)) return {};
  PWSTR known = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &known))) return {};
  const std::filesystem::path base(known);
  CoTaskMemFree(known);
  return base / L"FuzeVPN Runtime" / fuzevpn_update::Wide(manifest.version.text() + "-" + manifest.sha256);
}
bool VerifyManifestFiles(const std::filesystem::path& root, const Manifest& manifest, DWORD* error) {
  std::vector<std::unique_ptr<fuzevpn_update::PinnedFile>> pins;
  return PinManifest(root, manifest, &pins, error);
}
bool ValidateProtectedRuntime(const std::filesystem::path& root, const Manifest& manifest, DWORD* error) {
  const auto expected = RuntimeCachePath(manifest);
  if (expected.empty() || !fuzevpn_installation::SamePath(root.wstring(), expected.wstring()))
    return Fail(ERROR_INVALID_NAME, error);
  DirectoryPins directories;
  std::vector<std::unique_ptr<fuzevpn_update::PinnedFile>> files;
  return CheckProtected(root, manifest, &directories, &files, error);
}
bool ValidatePublisherPair(const fuzevpn_update::PinnedFile& first,
    const fuzevpn_update::PinnedFile& second, const fuzevpn_update::Version& version, DWORD* error) {
  if (!fuzevpn_update::MatchesBuildArchitecture(first.get()) ||
      !fuzevpn_update::MatchesBuildArchitecture(second.get())) return Fail(ERROR_BAD_EXE_FORMAT, error);
  fuzevpn_update::Version a, b;
  if (!fuzevpn_update::ReadVersion(first.path(), &a, true) ||
      !fuzevpn_update::ReadVersion(second.path(), &b, true) || !(a == version) || !(b == version))
    return Fail(ERROR_REVISION_MISMATCH, error);
  const LONG first_status = TrustStatus(first), second_status = TrustStatus(second);
  if (first_status == TRUST_E_NOSIGNATURE || second_status == TRUST_E_NOSIGNATURE) {
    if constexpr (fuzevpn_broker::kAllowPortableDevelopment) {
      if (first_status == TRUST_E_NOSIGNATURE && second_status == TRUST_E_NOSIGNATURE) return Success(error);
    }
    return Fail(ERROR_ACCESS_DENIED, error);
  }
  std::vector<BYTE> publisher_a, publisher_b;
  if (!fuzevpn_update::TrustedPublisher(first, &publisher_a) ||
      !fuzevpn_update::TrustedPublisher(second, &publisher_b) ||
      !fuzevpn_update::SamePublisher(publisher_a, publisher_b)) return Fail(ERROR_ACCESS_DENIED, error);
  return Success(error);
}
bool PrepareRuntime(const std::filesystem::path& source_root, const Manifest& manifest,
                    std::filesystem::path* destination, DWORD* error) {
  if (!destination) return Fail(ERROR_INVALID_PARAMETER, error);
  if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return Fail(ERROR_BAD_EXE_FORMAT, error);
  const auto target = RuntimeCachePath(manifest);
  if (target.empty()) return Fail(ERROR_INVALID_DATA, error);
  PreparationLock lock;
  if (!lock.Acquire(error)) return false;
  std::vector<std::unique_ptr<fuzevpn_update::PinnedFile>> sources;
  if (!PinManifest(source_root, manifest, &sources, error)) return false;
  DirectoryPins parents;
  if (!parents.Ancestors(target.parent_path().parent_path(), error)) return false;
  SecurityDescriptor descriptor;
  if (!descriptor.Create()) return Fail(GetLastError(), error);
  if (!CreateDirectoryW(target.parent_path().c_str(), descriptor.get()) && GetLastError() != ERROR_ALREADY_EXISTS)
    return Fail(GetLastError(), error);
  if (!parents.Pin(target.parent_path(), false, error)) return false;
  const DWORD existing = GetFileAttributesW(target.c_str());
  if (existing != INVALID_FILE_ATTRIBUTES) {
    if (!ValidateProtectedRuntime(target, manifest, error)) return false;
    *destination = target;
    return Success(error);
  }
  if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
    return Fail(GetLastError(), error);
  const std::string nonce = fuzevpn_update::NewToken();
  if (nonce.empty()) return Fail(ERROR_GEN_FAILURE, error);
  const auto stage = target.parent_path() / fuzevpn_update::Wide(".staging-" + nonce);
  if (!CreateDirectoryW(stage.c_str(), descriptor.get())) return Fail(GetLastError(), error);
  // An interrupted copy leaves only a protected, unreferenced staging folder.
  // No recursive deletion/repair can be redirected through an existing object.
  {
    DirectoryPins staged;
    if (!staged.Pin(stage, false, error)) return false;
    std::set<std::filesystem::path> created{stage};
    for (std::size_t i = 0; i < manifest.files.size(); ++i) {
      const auto relative = RelativePath(manifest.files[i].relative_path);
      auto directory = stage;
      for (const auto& component : relative.parent_path()) {
        directory /= component;
        if (created.insert(directory).second) {
          if (!CreateDirectoryW(directory.c_str(), descriptor.get()) || !staged.Pin(directory, false, error))
            return Fail(GetLastError(), error);
        }
      }
      const auto output_path = stage / relative;
      HANDLE output = CreateFileW(output_path.c_str(), GENERIC_WRITE, 0, descriptor.get(), CREATE_NEW,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      if (output == INVALID_HANDLE_VALUE) return Fail(GetLastError(), error);
      const bool copied = fuzevpn_update::CopyFileContents(sources[i]->get(), output);
      const DWORD copy_error = copied ? ERROR_SUCCESS : GetLastError();
      CloseHandle(output);
      if (!copied) return Fail(copy_error ? copy_error : ERROR_WRITE_FAULT, error);
    }
    DirectoryPins checked_directories;
    std::vector<std::unique_ptr<fuzevpn_update::PinnedFile>> checked_files;
    if (!CheckProtected(stage, manifest, &checked_directories, &checked_files, error)) return false;
  }
  if (!MoveFileExW(stage.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) return Fail(GetLastError(), error);
  if (!ValidateProtectedRuntime(target, manifest, error)) return false;
  *destination = target;
  return Success(error);
}
std::wstring BootstrapPipeName(DWORD parent_pid, const std::string& nonce) {
  if (!parent_pid || !fuzevpn_update::ValidToken(nonce)) return {};
  return L"\\\\.\\pipe\\FuzeVPN-PortableBootstrap-" + std::to_wstring(parent_pid) + L"-" + fuzevpn_update::Wide(nonce);
}
} // namespace fuzevpn_portable
