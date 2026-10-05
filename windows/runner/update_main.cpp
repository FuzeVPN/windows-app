// SPDX-License-Identifier: MPL-2.0
#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <memory>
#include <cwctype>
#include "portable_update.h"
#include "update_security.h"
#include "installation_security.h"
#include "distribution_mode.h"
#include "runtime_architecture.h"

namespace {
std::string Ascii(const wchar_t* value) {
  std::string result;
  for (; *value; ++value) {
    if (*value > 127) return {};
    result += static_cast<char>(*value);
  }
  return result;
}
bool Elevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD bytes = 0;
  const bool result = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes) && elevation.TokenIsElevated;
  CloseHandle(token);
  return result;
}
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool Number(const wchar_t* value, uintptr_t* result) {
  if (!value || !*value) return false;
  uintptr_t parsed = 0;
  for (; *value; ++value) {
    if (*value < L'0' || *value > L'9' || parsed > (UINTPTR_MAX - (*value - L'0')) / 10) return false;
    parsed = parsed * 10 + (*value - L'0');
  }
  if (!parsed) return false;
  *result = parsed;
  return true;
}
bool PrivateCandidate(const std::filesystem::path& path) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  std::vector<BYTE> bytes(size);
  const bool valid = GetTokenInformation(token, TokenUser, bytes.data(), size, &size) != FALSE;
  CloseHandle(token);
  if (!valid) return false;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, &sid)) return false;
  const std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
  const bool created = CreateDirectoryW(path.c_str(), &security) != FALSE;
  LocalFree(descriptor);
  return created;
}
bool Restart(const std::filesystem::path& target) {
  const auto executable = target / L"fuzevpn_windows.exe";
  STARTUPINFOW startup{}; startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  std::wstring command = L"\"" + executable.wstring() + L"\"";
  if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
      nullptr, target.c_str(), &startup, &process)) return false;
  CloseHandle(process.hThread); CloseHandle(process.hProcess);
  return true;
}
int ApplyPortable(const std::filesystem::path& source, const std::string& hash,
                  const fuzevpn_update::Version& target_version,
                  const std::filesystem::path& target, HANDLE parent, HANDLE ready) {
  using namespace fuzevpn_update;
  using namespace fuzevpn_portable_update;
  Handle parent_handle{parent}, ready_handle{ready};
  const auto signal = [&](DWORD error) {
    DWORD written = 0;
    return WriteFile(ready, &error, sizeof(error), &written, nullptr) && written == sizeof(error);
  };
  auto reject = [&](DWORD error) { signal(error); return static_cast<int>(error); };
  // Inherited handles pin the initiating process and an anonymous readiness
  // pipe. A PID or a named event supplied by another process cannot take over.
  if (!fuzevpn_architecture::NativeSystemMatchesBuild() || Elevated() ||
      GetFileType(ready) != FILE_TYPE_PIPE || !GetProcessId(parent) ||
      WaitForSingleObject(parent, 0) != WAIT_TIMEOUT || !IsPortableTarget(target) ||
      source.parent_path() != CurrentExecutable().parent_path() ||
      source.filename() != L"FuzeVPN-Portable.zip")
    return reject(ERROR_ACCESS_DENIED);
  std::wstring parent_image(32768, L'\0'); DWORD image_size = static_cast<DWORD>(parent_image.size());
  if (!QueryFullProcessImageNameW(parent, 0, parent_image.data(), &image_size)) return reject(ERROR_ACCESS_DENIED);
  parent_image.resize(image_size);
  if (!fuzevpn_installation::SamePath(parent_image, (target / L"fuzevpn_windows.exe").wstring()))
    return reject(ERROR_ACCESS_DENIED);
  // Serialize updates to one canonical destination, including a second frontend
  // that might be launched while the first is waiting for its helper.
  uint64_t lock_hash = 14695981039346656037ull;
  for (wchar_t c : target.wstring()) { lock_hash ^= static_cast<unsigned>(towlower(c)); lock_hash *= 1099511628211ull; }
  const std::wstring lock_name = L"Local\\FuzeVPN-PortableUpdate-" + std::to_wstring(lock_hash);
  Handle lock{CreateMutexW(nullptr, TRUE, lock_name.c_str())};
  if (!lock.value || GetLastError() == ERROR_ALREADY_EXISTS) return reject(ERROR_BUSY);
  Handle parent_directory{CreateFileW(target.parent_path().c_str(), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  BY_HANDLE_FILE_INFORMATION parent_info{};
  if (parent_directory.value == INVALID_HANDLE_VALUE ||
      !GetFileInformationByHandle(parent_directory.value, &parent_info) ||
      !(parent_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
      (parent_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return reject(ERROR_ACCESS_DENIED);
  std::vector<BYTE> publisher;
  Version installed;
  {
    PinnedFile application, helper;
    std::vector<BYTE> helper_publisher;
    Version helper_version;
    if (!application.Open(target / L"fuzevpn_windows.exe", true) ||
        !helper.Open(CurrentExecutable(), true) || !MatchesBuildArchitecture(application.get()) ||
        !MatchesBuildArchitecture(helper.get()) || !TrustedPublisher(application, &publisher) ||
        !TrustedPublisher(helper, &helper_publisher) || !SamePublisher(publisher, helper_publisher) ||
        !ReadVersion(application.path(), &installed, true) || !ReadVersion(helper.path(), &helper_version, true) ||
        !(helper_version == installed) || !(installed < target_version)) return reject(ERROR_ACCESS_DENIED);
  }
  const auto nonce = NewToken();
  if (nonce.empty()) return reject(ERROR_GEN_FAILURE);
  const auto candidate = target.parent_path() / Wide(".FuzeVPN-update-" + nonce);
  const auto backup = target.parent_path() / Wide(".FuzeVPN-backup-" + nonce);
  if (!PrivateCandidate(candidate)) return reject(GetLastError());
  Failure failure;
  {
    PinnedFile archive;
    if (!archive.Open(source, true) || !ExtractArchive(archive, hash, candidate, &failure) ||
        !ValidateBundle(candidate, target_version, publisher, &failure)) {
      RemoveStaging(candidate);
      return reject(failure.windows_error ? failure.windows_error : ERROR_INVALID_DATA);
    }
  }
  if (!signal(ERROR_SUCCESS)) { RemoveStaging(candidate); return ERROR_BROKEN_PIPE; }
  CloseHandle(ready_handle.value); ready_handle.value = nullptr;
  // The frontend performs confirmed VPN cleanup before installUpdate and then
  // exits only after this ready acknowledgement. No files change while it runs.
  if (WaitForSingleObject(parent, 90000) != WAIT_OBJECT_0) {
    RemoveStaging(candidate); return ERROR_TIMEOUT;
  }
  bool applied = ReplaceDirectory(target, candidate, backup, &failure);
  DWORD error = failure.windows_error ? failure.windows_error : ERROR_WRITE_FAULT;
  if (applied && !Restart(target)) {
    error = GetLastError();
    // A failed restart restores the old folder before restarting that version.
    applied = false;
    if (MoveFileExW(target.c_str(), candidate.c_str(), MOVEFILE_WRITE_THROUGH) &&
        MoveFileExW(backup.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH)) Restart(target);
  } else if (!applied && failure.stage != "portable_rollback") Restart(target);
  if (!applied) {
    const std::wstring message = L"The portable update could not be applied. Your previous version remains in its original folder or in the recovery backup.\n\nReference: update_portable_replace_failed\nWindows error: " + std::to_wstring(error);
    MessageBoxW(nullptr, message.c_str(), L"FuzeVPN update", MB_OK | MB_ICONERROR);
  }
  RemoveStaging(candidate); // fails harmlessly if it was renamed into place
  DeleteFileW(source.c_str());
  return applied ? ERROR_SUCCESS : static_cast<int>(error);
}
int Apply(const std::filesystem::path& source, const std::string& hash,
          const fuzevpn_update::Version& target) {
  using namespace fuzevpn_update;
  if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return ERROR_BAD_EXE_FORMAT;
  if (!Elevated()) return ERROR_ELEVATION_REQUIRED;
  if (fuzevpn_distribution::CurrentMode() != fuzevpn_distribution::Mode::installed)
    return ERROR_ACCESS_DENIED;
  const ULONGLONG deadline = GetTickCount64() + 90000;
  const auto directory = CurrentExecutable().parent_path();
  std::vector<BYTE> publisher;
  Version installed;
  {
    fuzevpn_installation::ProtectedInstallation installation;
    PinnedFile application;
    if (!installation.Validate(directory / L"fuzevpn-service.exe") ||
        !fuzevpn_installation::SamePath(CurrentExecutable().filename().wstring(), L"fuzevpn-update.exe") ||
        !application.Open(directory / L"fuzevpn_windows.exe") ||
        !MatchesBuildArchitecture(application.get()) ||
        !TrustedPublisher(application, &publisher) || !ReadVersion(application.path(), &installed, true) ||
        !(installed < target)) return ERROR_ACCESS_DENIED;
  }
  PinnedFile input;
  if (!input.Open(source) || !VerifyBundle(input, hash, target, publisher)) return ERROR_INVALID_DATA;
  PrivateDirectory stage;
  if (!stage.Create(true)) return ERROR_ACCESS_DENIED;
  const auto destination = stage.path() / L"FuzeVPN-Setup.exe";
  HANDLE output = CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr,
      CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (output == INVALID_HANDLE_VALUE) return ERROR_WRITE_FAULT;
  const bool copied = CopyFileContents(input.get(), output);
  CloseHandle(output);
  if (!copied) return ERROR_WRITE_FAULT;
  PinnedFile verified;
  if (!verified.Open(destination) || !VerifyBundle(verified, hash, target, publisher)) return ERROR_INVALID_DATA;
  STARTUPINFOW startup{}; startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  std::wstring command = L"\"" + destination.wstring() + L"\"";
  if (GetTickCount64() >= deadline) return ERROR_TIMEOUT;
  if (!CreateProcessW(destination.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
      nullptr, stage.path().c_str(), &startup, &process)) return static_cast<int>(GetLastError());
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  // Setup runs from an administrator-owned directory and may read its own
  // payload later. Leave this one verified package for setup; a later update
  // can safely remove it after it is no longer in use.
  stage.Keep();
  return ERROR_SUCCESS;
}
}  // namespace
int APIENTRY wWinMain(HINSTANCE, HINSTANCE, wchar_t*, int) {
  int count = 0;
  wchar_t** arguments = CommandLineToArgvW(GetCommandLineW(), &count);
  if (!arguments) return ERROR_INVALID_PARAMETER;
  int result = ERROR_INVALID_PARAMETER;
  try {
    fuzevpn_update::Version version;
    if (count == 8 && wcscmp(arguments[1], L"--apply") == 0 &&
        wcscmp(arguments[2], L"--source") == 0 && wcscmp(arguments[4], L"--sha256") == 0 &&
        wcscmp(arguments[6], L"--version") == 0 &&
        fuzevpn_update::ValidHash(Ascii(arguments[5])) &&
        fuzevpn_update::ParseVersion(Ascii(arguments[7]), &version)) {
      CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
      result = Apply(arguments[3], Ascii(arguments[5]), version);
      CoUninitialize();
    } else if (count == 14 && wcscmp(arguments[1], L"--apply-portable") == 0 &&
        wcscmp(arguments[2], L"--source") == 0 && wcscmp(arguments[4], L"--sha256") == 0 &&
        wcscmp(arguments[6], L"--version") == 0 && wcscmp(arguments[8], L"--target") == 0 &&
        wcscmp(arguments[10], L"--parent-handle") == 0 && wcscmp(arguments[12], L"--ready-handle") == 0 &&
        fuzevpn_update::ValidHash(Ascii(arguments[5])) &&
        fuzevpn_update::ParseVersion(Ascii(arguments[7]), &version)) {
      uintptr_t parent = 0, ready = 0;
      if (Number(arguments[11], &parent) && Number(arguments[13], &ready) && parent != ready) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        result = ApplyPortable(arguments[3], Ascii(arguments[5]), version, arguments[9],
            reinterpret_cast<HANDLE>(parent), reinterpret_cast<HANDLE>(ready));
        CoUninitialize();
      }
    }
  } catch (...) { result = ERROR_INVALID_DATA; }
  LocalFree(arguments);
  return result;
}
