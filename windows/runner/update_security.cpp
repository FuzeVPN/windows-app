// SPDX-License-Identifier: MPL-2.0
#include "update_security.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include "installation_security.h"
#include "runtime_architecture.h"

namespace fuzevpn_update {
namespace {
bool SamePath(const std::filesystem::path& expected, HANDLE handle) {
  std::wstring path(32768, L'\0');
  const DWORD length = GetFinalPathNameByHandleW(handle, path.data(),
      static_cast<DWORD>(path.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (length == 0 || length >= path.size()) return false;
  path.resize(length);
  if (path.rfind(L"\\\\?\\", 0) == 0) path.erase(0, 4);
  std::wstring value = expected.wstring();
  while (value.size() > 2 && value.back() == L'\\') value.pop_back();
  while (path.size() > 2 && path.back() == L'\\') path.pop_back();
  return fuzevpn_installation::SamePath(path, value);
}
bool PinDirectory(const std::filesystem::path& path, std::vector<HANDLE>* handles,
                  bool protected_directory = false, bool ancestor = false,
                  bool strict = false) {
  // Attribute-only directory opens do not enforce the data-sharing boundary.
  // LIST_DIRECTORY makes a strict pin participate in read/write share checks.
  HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL |
      (strict ? FILE_LIST_DIRECTORY : 0),
      FILE_SHARE_READ | (strict ? 0 : FILE_SHARE_WRITE), nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  bool valid = GetFileInformationByHandle(handle, &info) &&
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 && SamePath(path, handle);
  if (valid && protected_directory) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    valid = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
        fuzevpn_installation::IsProtectedDescriptor(descriptor, true, ancestor);
    if (descriptor) LocalFree(descriptor);
  }
  if (!valid) { CloseHandle(handle); return false; }
  handles->push_back(handle);
  return true;
}
bool PinAncestors(const std::filesystem::path& path, std::vector<HANDLE>* handles,
                  bool machine, bool strict = false) {
  if (!path.is_absolute() || path.native().size() > 30000) return false;
  std::vector<std::filesystem::path> paths;
  for (auto parent = path; !parent.empty();) {
    if (paths.size() >= 64) return false;
    paths.push_back(parent);
    const auto next = parent.parent_path();
    if (next == parent) break;
    parent = next;
  }
  for (auto it = paths.rbegin(); it != paths.rend(); ++it)
    if (!PinDirectory(*it, handles, machine, true, strict)) return false;
  return true;
}
std::wstring UserSid() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
  DWORD bytes = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
  std::vector<BYTE> data(bytes);
  const bool ok = GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes) != FALSE;
  CloseHandle(token);
  if (!ok) return {};
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &sid)) return {};
  std::wstring result(sid);
  LocalFree(sid);
  return result;
}
int Hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
void PurgeOldPackages(const std::filesystem::path& root, bool machine) {
  WIN32_FIND_DATAW entry{};
  HANDLE enumeration = FindFirstFileW((root / L"*").c_str(), &entry);
  if (enumeration == INVALID_HANDLE_VALUE) return;
  FILETIME current{}; GetSystemTimeAsFileTime(&current);
  const uint64_t now = (static_cast<uint64_t>(current.dwHighDateTime) << 32) | current.dwLowDateTime;
  constexpr uint64_t age = 48ull * 60 * 60 * 10000000;
  unsigned examined = 0;
  do {
    if (++examined > 256) break;
    std::wstring name(entry.cFileName);
    if (name.size() != 32 || !std::all_of(name.begin(), name.end(), [](wchar_t c) {
          return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
        })) continue;
    const uint64_t created = (static_cast<uint64_t>(entry.ftCreationTime.dwHighDateTime) << 32) |
        entry.ftCreationTime.dwLowDateTime;
    if (created > now || now - created < age ||
        (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) continue;
    std::vector<HANDLE> pins;
    const auto directory = root / name;
    if (!PinDirectory(directory, &pins, machine)) continue;
    const auto file = directory / L"FuzeVPN-Setup.exe";
    // Exclusive access refuses open/running packages. Delete by the inspected
    // handle, never recursively and never by following a reparse point.
    HANDLE handle = CreateFileW(file.c_str(), DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
      BY_HANDLE_FILE_INFORMATION info{};
      if (GetFileInformationByHandle(handle, &info) && SamePath(file, handle) &&
          info.nNumberOfLinks == 1 &&
          (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0) {
        FILE_DISPOSITION_INFO disposition{TRUE};
        SetFileInformationByHandle(handle, FileDispositionInfo, &disposition, sizeof(disposition));
      }
      CloseHandle(handle);
    }
    for (HANDLE pin : pins) CloseHandle(pin);
    RemoveDirectoryW(directory.c_str()); // succeeds only if empty
  } while (FindNextFileW(enumeration, &entry));
  FindClose(enumeration);
}

void WarmMachineChain(PCCERT_CONTEXT certificate) {
  CERT_CHAIN_PARA parameters{};
  parameters.cbSize = sizeof(parameters);
  parameters.dwUrlRetrievalTimeout = 15000;
  PCCERT_CHAIN_CONTEXT chain = nullptr;
  // The cumulative revocation budget prevents a series of certificate URLs
  // multiplying the normal per-URL wait. The final decision remains offline
  // Authenticode validation, never a successful download alone.
  CertGetCertificateChain(HCCE_LOCAL_MACHINE, certificate, nullptr,
      certificate->hCertStore, &parameters,
      CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
          CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT, nullptr, &chain);
  if (chain) CertFreeCertificateChain(chain);
}
}  // namespace

std::string Version::text() const {
  return std::to_string(parts[0]) + "." + std::to_string(parts[1]) + "." + std::to_string(parts[2]);
}
bool ParseVersion(const std::string& value, Version* version) {
  if (!version || value.empty() || value.size() > 13) return false;
  Version parsed;
  size_t position = 0;
  for (size_t i = 0; i < 3; ++i) {
    const size_t start = position;
    unsigned number = 0;
    while (position < value.size() && value[position] >= '0' && value[position] <= '9') {
      number = number * 10 + static_cast<unsigned>(value[position++] - '0');
      if (number > (i == 2 ? 65535u : 255u)) return false;
    }
    if (position == start || (position - start > 1 && value[start] == '0')) return false;
    parsed.parts[i] = number;
    if (i < 2 && (position == value.size() || value[position++] != '.')) return false;
  }
  if (position != value.size()) return false;
  *version = parsed;
  return true;
}
bool ValidHash(const std::string& value) {
  return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) { return Hex(c) >= 0; });
}
bool ValidToken(const std::string& value) {
  return value.size() == 32 && std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  });
}
std::string NewToken() {
  BYTE random[16]{};
  if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return {};
  constexpr char alphabet[] = "0123456789abcdef";
  std::string value;
  for (BYTE byte : random) { value += alphabet[byte >> 4]; value += alphabet[byte & 15]; }
  return value;
}
std::wstring Wide(const std::string& value) {
  if (value.empty() || value.size() > 32000 || value.find('\0') != std::string::npos) return {};
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring result(length, L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), result.data(), length) != length) return {};
  return result;
}
std::filesystem::path CurrentExecutable() {
  std::wstring path(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (!length || length >= path.size()) return {};
  path.resize(length);
  return path;
}
PinnedFile::~PinnedFile() {
  if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
  for (HANDLE directory : directories_) CloseHandle(directory);
}
bool PinnedFile::Open(const std::filesystem::path& path, bool strict_ancestors) {
  if (file_ != INVALID_HANDLE_VALUE ||
      !PinAncestors(path.parent_path(), &directories_, false, strict_ancestors)) return false;
  file_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file_ == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  LARGE_INTEGER size{};
  if (!GetFileInformationByHandle(file_, &info) ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
      info.nNumberOfLinks != 1 || GetFileType(file_) != FILE_TYPE_DISK || !SamePath(path, file_) ||
      !GetFileSizeEx(file_, &size) || size.QuadPart <= 0 ||
      static_cast<uint64_t>(size.QuadPart) > kMaximumDownloadBytes) return false;
  path_ = path;
  return true;
}
PrivateDirectory::~PrivateDirectory() {
  // Only the known file is removed; never recurse through user-controlled data.
  if (!keep_ && !path_.empty()) DeleteFileW((path_ / L"FuzeVPN-Setup.exe").c_str());
  for (HANDLE directory : directories_) CloseHandle(directory);
  if (!keep_ && !path_.empty()) RemoveDirectoryW(path_.c_str());
}
bool PrivateDirectory::Create(bool machine) {
  if (!directories_.empty()) return false;
  PWSTR known = nullptr;
  if (FAILED(SHGetKnownFolderPath(machine ? FOLDERID_ProgramData : FOLDERID_LocalAppData,
      0, nullptr, &known))) return false;
  std::filesystem::path root(known);
  CoTaskMemFree(known);
  if (!PinAncestors(root, &directories_, machine)) return false;
  const std::wstring sid = machine ? L"" : UserSid();
  if (!machine && sid.empty()) return false;
  const std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" +
      (machine ? std::wstring() : L"(A;OICI;FA;;;" + sid + L")");
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
  root /= L"FuzeVPN-Updates";
  bool valid = CreateDirectoryW(root.c_str(), &security) || GetLastError() == ERROR_ALREADY_EXISTS;
  if (valid) valid = PinDirectory(root, &directories_, machine);
  if (valid) PurgeOldPackages(root, machine);
  const std::string token = NewToken();
  if (token.empty()) valid = false;
  if (valid) {
    root /= Wide(token);
    valid = CreateDirectoryW(root.c_str(), &security) != FALSE;
    if (valid) { path_ = root; valid = PinDirectory(root, &directories_, machine); }
  }
  LocalFree(descriptor);
  return valid;
}
bool ReadVersion(const std::filesystem::path& path, Version* version, bool require_product_name) {
  DWORD ignored = 0;
  const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
  if (!size || size > 1024 * 1024) return false;
  std::vector<BYTE> data(size);
  if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return false;
  VS_FIXEDFILEINFO* info = nullptr;
  UINT bytes = 0;
  if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &bytes) ||
      bytes < sizeof(*info) || info->dwSignature != 0xfeef04bd || info->dwFileType != VFT_APP ||
      LOWORD(info->dwFileVersionLS) != 0 || HIWORD(info->dwFileVersionMS) > 255 ||
      LOWORD(info->dwFileVersionMS) > 255) return false;
  version->parts = {HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS), HIWORD(info->dwFileVersionLS)};
  if (!require_product_name) return true;
  struct Translation { WORD language; WORD codepage; };
  Translation* translations = nullptr;
  if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations), &bytes)) return false;
  for (size_t i = 0; i < bytes / sizeof(Translation); ++i) {
    wchar_t query[100]{};
    swprintf_s(query, L"\\StringFileInfo\\%04x%04x\\ProductName", translations[i].language, translations[i].codepage);
    wchar_t* name = nullptr;
    UINT length = 0;
    if (VerQueryValueW(data.data(), query, reinterpret_cast<void**>(&name), &length) &&
        length == 8 && wcscmp(name, L"FuzeVPN") == 0) return true;
  }
  return false;
}
bool TrustedPublisher(const PinnedFile& file, std::vector<BYTE>* subject,
                      LONG* trust_status, bool allow_chain_retrieval) {
  subject->clear();
  WINTRUST_FILE_INFO info{};
  info.cbStruct = sizeof(info); info.pcwszFilePath = file.path().c_str(); info.hFile = file.get();
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
  trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &info;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  // First try the cache; authorization callers may warm the machine chain
  // with a bounded retrieval. Passive window activation explicitly opts out.
  trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_CACHE_ONLY_URL_RETRIEVAL;
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = WinVerifyTrust(nullptr, &action, &trust);
  if (allow_chain_retrieval && status != ERROR_SUCCESS &&
      status != TRUST_E_NOSIGNATURE && status != TRUST_E_BAD_DIGEST) {
    auto* provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
    auto* signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
    PCCERT_CONTEXT certificate = signer && signer->csCertChain && signer->pasCertChain[0].pCert ?
        CertDuplicateCertificateContext(signer->pasCertChain[0].pCert) : nullptr;
    if (certificate) {
      trust.dwStateAction = WTD_STATEACTION_CLOSE;
      WinVerifyTrust(nullptr, &action, &trust);
      trust.hWVTStateData = nullptr;
      WarmMachineChain(certificate);
      CertFreeCertificateContext(certificate);
      trust.dwStateAction = WTD_STATEACTION_VERIFY;
      status = WinVerifyTrust(nullptr, &action, &trust);
    }
  }
  bool valid = false;
  if (status == ERROR_SUCCESS) {
    auto* provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
    auto* signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
    if (signer && signer->csCertChain != 0 && signer->pasCertChain[0].pCert) {
      // An ordinary user can add a root to CurrentUser. Such a root must not
      // authorize that user's executable to be elevated by this updater.
      HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
          CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG |
              CERT_STORE_READONLY_FLAG, L"ROOT");
      PCCERT_CONTEXT root = roots ? CertFindCertificateInStore(roots,
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_EXISTING,
          signer->pasCertChain[signer->csCertChain - 1].pCert, nullptr) : nullptr;
      const auto& name = signer->pasCertChain[0].pCert->pCertInfo->Subject;
      if (root && name.cbData != 0 && name.cbData <= 65536) {
        subject->assign(name.pbData, name.pbData + name.cbData); valid = true;
      }
      if (root) CertFreeCertificateContext(root);
      if (roots) CertCloseStore(roots, 0);
    }
  }
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &action, &trust);
  if (trust_status) *trust_status = valid ? ERROR_SUCCESS :
      (status != ERROR_SUCCESS ? status : CERT_E_UNTRUSTEDROOT);
  return valid;
}
bool SamePublisher(const std::vector<BYTE>& first, const std::vector<BYTE>& second) {
  if (first.empty() || second.empty()) return false;
  CERT_NAME_BLOB a{static_cast<DWORD>(first.size()), const_cast<BYTE*>(first.data())};
  CERT_NAME_BLOB b{static_cast<DWORD>(second.size()), const_cast<BYTE*>(second.data())};
  return CertCompareCertificateName(X509_ASN_ENCODING, &a, &b) != FALSE;
}
bool MatchesHash(HANDLE file, const std::string& expected) {
  if (!ValidHash(expected)) return false;
  LARGE_INTEGER start{};
  if (!SetFilePointerEx(file, start, nullptr, FILE_BEGIN)) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
      BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0;
  std::array<BYTE, 65536> data{};
  DWORD read = 0;
  uint64_t total = 0;
  while (ok) {
    ok = ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) != FALSE;
    if (!ok || read == 0) break;
    total += read;
    ok = total <= kMaximumDownloadBytes && BCryptHashData(hash, data.data(), read, 0) >= 0;
  }
  BYTE digest[32]{};
  ok = ok && total != 0 && BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0;
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return false;
  unsigned difference = 0;
  for (size_t i = 0; i < sizeof(digest); ++i)
    difference |= digest[i] ^ static_cast<unsigned>((Hex(expected[i * 2]) << 4) | Hex(expected[i * 2 + 1]));
  return difference == 0;
}
bool ReadPeMachine(HANDLE file, USHORT* machine) {
  if (!machine) return false;
  *machine = IMAGE_FILE_MACHINE_UNKNOWN;
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
      static_cast<uint64_t>(size.QuadPart) > kMaximumDownloadBytes) return false;
  const auto read = [&](uint64_t offset, void* output, DWORD count) {
    if (offset > static_cast<uint64_t>(size.QuadPart) ||
        count > static_cast<uint64_t>(size.QuadPart) - offset) return false;
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    DWORD actual = 0;
    return SetFilePointerEx(file, position, nullptr, FILE_BEGIN) &&
        ReadFile(file, output, count, &actual, nullptr) && actual == count;
  };
  IMAGE_DOS_HEADER dos{};
  if (!read(0, &dos, static_cast<DWORD>(sizeof(dos))) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
      dos.e_lfanew < static_cast<LONG>(sizeof(dos))) return false;
  IMAGE_NT_HEADERS64 nt{};
  if (!read(static_cast<uint64_t>(dos.e_lfanew), &nt, static_cast<DWORD>(sizeof(nt))) ||
      nt.Signature != IMAGE_NT_SIGNATURE ||
      nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
      nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > 96 ||
      (nt.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 ||
      (nt.FileHeader.Machine != fuzevpn_architecture::kX64Machine &&
       nt.FileHeader.Machine != fuzevpn_architecture::kArm64Machine)) return false;
  const uint64_t headers_end = static_cast<uint64_t>(dos.e_lfanew) + sizeof(DWORD) +
      sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader +
      static_cast<uint64_t>(nt.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
  if (headers_end > static_cast<uint64_t>(size.QuadPart)) return false;
  *machine = nt.FileHeader.Machine;
  return true;
}
bool MatchesBuildArchitecture(HANDLE file) {
  USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN;
  return ReadPeMachine(file, &machine) && machine == fuzevpn_architecture::kBuildMachine;
}
bool VerifyBundle(const PinnedFile& file, const std::string& hash,
                  const Version& target, const std::vector<BYTE>& publisher,
                  Failure* failure) {
  if (failure) *failure = {};
  const auto fail = [&](const char* code, const char* stage,
                        LONG trust_status = ERROR_SUCCESS) {
    if (failure) *failure = {code, stage, ERROR_SUCCESS, 0, trust_status};
    return false;
  };
  if (!MatchesBuildArchitecture(file.get()))
    return fail("update_package_architecture_mismatch", "package_architecture");
  if (!MatchesHash(file.get(), hash))
    return fail("update_hash_mismatch", "package_hash");
  Version actual;
  std::vector<BYTE> subject;
  LONG trust_status = ERROR_SUCCESS;
  if (!TrustedPublisher(file, &subject, &trust_status))
    return fail("update_signature_invalid", "package_signature", trust_status);
  if (!SamePublisher(subject, publisher))
    return fail("update_publisher_mismatch", "package_publisher");
  if (!ReadVersion(file.path(), &actual, true) || !(actual == target))
    return fail("update_package_version_mismatch", "package_version");
  return true;
}
bool CopyFileContents(HANDLE source, HANDLE destination) {
  LARGE_INTEGER zero{};
  if (!SetFilePointerEx(source, zero, nullptr, FILE_BEGIN)) return false;
  std::array<BYTE, 65536> data{};
  uint64_t total = 0;
  for (;;) {
    DWORD read = 0, written = 0;
    if (!ReadFile(source, data.data(), static_cast<DWORD>(data.size()), &read, nullptr)) return false;
    if (read == 0) break;
    total += read;
    if (total > kMaximumDownloadBytes || !WriteFile(destination, data.data(), read, &written, nullptr) || written != read) return false;
  }
  return total != 0 && FlushFileBuffers(destination);
}
}  // namespace fuzevpn_update
