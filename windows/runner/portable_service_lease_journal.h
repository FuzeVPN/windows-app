// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_SERVICE_LEASE_JOURNAL_H_
#define RUNNER_PORTABLE_SERVICE_LEASE_JOURNAL_H_

#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include "installation_security.h"
#include "update_security.h"

namespace fuzevpn_handoff {
enum class LeasePhase : DWORD { requested = 1, yielded = 2, engine = 3, restoring = 4 };
struct LeaseProcessIdentity {
  DWORD pid = 0;
  DWORD session = 0;
  std::uint64_t created = 0;
  bool operator==(const LeaseProcessIdentity& other) const {
    return pid == other.pid && session == other.session && created == other.created;
  }
};
struct LeaseFileIdentity {
  DWORD volume = 0, index_high = 0, index_low = 0;
  bool operator==(const LeaseFileIdentity& other) const {
    return volume == other.volume && index_high == other.index_high && index_low == other.index_low;
  }
};
struct LeaseRecord {
  LeasePhase phase = LeasePhase::requested;
  std::string token;
  std::wstring command;
  LeaseProcessIdentity helper, parent, service, engine;
  LeaseFileIdentity service_file;
};
enum class LeaseProcessState { dead, alive, unknown };

// The injected implementation lets tests exercise the production lease without
// touching machine storage, the SCM, or real processes.
class LeaseJournal {
 public:
  virtual ~LeaseJournal() = default;
  virtual bool Read(std::optional<LeaseRecord>* value, DWORD* error) = 0;
  virtual bool Create(const LeaseRecord& value, DWORD* error) = 0;
  virtual bool Advance(const LeaseRecord& value, LeasePhase expected, DWORD* error) = 0;
  virtual bool Erase(const std::string& token, DWORD* error) = 0;
  virtual bool ProcessIdentity(HANDLE process, LeaseProcessIdentity* value, DWORD* error) = 0;
  virtual LeaseProcessState ProcessState(const LeaseProcessIdentity& value, DWORD* error) = 0;
  virtual bool FileIdentity(HANDLE file, LeaseFileIdentity* value, DWORD* error) = 0;
};

namespace lease_journal_detail {
inline bool Fail(DWORD value, DWORD* error) { if (error) *error = value; return false; }
class Handle {
 public:
  HANDLE value = INVALID_HANDLE_VALUE;
  ~Handle() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
};
inline bool ExactPath(HANDLE handle, const std::filesystem::path& path) {
  std::wstring actual(32768, L'\0');
  const DWORD count = GetFinalPathNameByHandleW(handle, actual.data(),
      static_cast<DWORD>(actual.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!count || count >= actual.size()) return false;
  actual.resize(count);
  if (actual.rfind(L"\\\\?\\", 0) == 0) actual.erase(0, 4);
  auto expected = path.wstring();
  while (actual.size() > 2 && actual.back() == L'\\') actual.pop_back();
  while (expected.size() > 2 && expected.back() == L'\\') expected.pop_back();
  return fuzevpn_installation::SamePath(actual, expected);
}
inline bool ProtectedObject(HANDLE handle, const std::filesystem::path& path,
                            bool directory, bool ancestor = false) {
  BY_HANDLE_FILE_INFORMATION info{};
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  bool valid = GetFileInformationByHandle(handle, &info) &&
      ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      (directory || info.nNumberOfLinks == 1) && ExactPath(handle, path) &&
      GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          nullptr, nullptr, nullptr, nullptr, &descriptor) == ERROR_SUCCESS &&
      fuzevpn_installation::IsProtectedDescriptor(descriptor, directory, ancestor);
  if (descriptor) LocalFree(descriptor);
  return valid;
}
class Directory {
 public:
  ~Directory() { for (HANDLE handle : pins_) CloseHandle(handle); }
  bool Open(bool create, DWORD* error) {
    PWSTR known = nullptr;
    const HRESULT status = SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &known);
    if (FAILED(status)) return Fail(ERROR_PATH_NOT_FOUND, error);
    const std::filesystem::path base(known);
    CoTaskMemFree(known);
    std::vector<std::filesystem::path> ancestors;
    for (auto path = base; !path.empty();) {
      if (ancestors.size() == 64) return Fail(ERROR_INVALID_NAME, error);
      ancestors.push_back(path);
      const auto parent = path.parent_path();
      if (parent == path) break;
      path = parent;
    }
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it)
      if (!Pin(*it, true, error)) return false;
    path_ = base / L"FuzeVPN Runtime";
    if (create) {
      PSECURITY_DESCRIPTOR descriptor = nullptr;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)",
          SDDL_REVISION_1, &descriptor, nullptr)) return Fail(GetLastError(), error);
      SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
      const BOOL created = CreateDirectoryW(path_.c_str(), &attributes);
      const DWORD result = created ? ERROR_SUCCESS : GetLastError();
      LocalFree(descriptor);
      if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS) return Fail(result, error);
    }
    return Pin(path_, false, error);
  }
  const std::filesystem::path& path() const { return path_; }
 private:
  bool Pin(const std::filesystem::path& path, bool ancestor, DWORD* error) {
    HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return Fail(GetLastError(), error);
    if (!ProtectedObject(handle, path, true, ancestor)) {
      CloseHandle(handle); return Fail(ERROR_ACCESS_DENIED, error);
    }
    pins_.push_back(handle);
    return true;
  }
  std::filesystem::path path_;
  std::vector<HANDLE> pins_;
};
inline bool ValidIdentity(const LeaseProcessIdentity& value) { return value.pid && value.created; }
inline bool ValidRecord(const LeaseRecord& value) {
  const DWORD phase = static_cast<DWORD>(value.phase);
  return phase >= 1 && phase <= 4 && fuzevpn_update::ValidToken(value.token) &&
      !value.command.empty() && value.command.size() < 32768 &&
      value.command.find(L'\0') == std::wstring::npos && ValidIdentity(value.helper) &&
      ValidIdentity(value.parent) && ValidIdentity(value.service) &&
      value.helper.session == value.parent.session && value.service.session == 0 &&
      (value.phase != LeasePhase::engine || ValidIdentity(value.engine)) &&
      (!value.engine.pid || (ValidIdentity(value.engine) && value.engine.session == value.helper.session));
}
struct DiskRecord {
  DWORD magic = 0x314c5a46, version = 1, phase = 0, initial_state = SERVICE_RUNNING;
  std::array<char, 33> token{};
  LeaseProcessIdentity helper{}, parent{}, service{}, engine{};
  LeaseFileIdentity service_file{};
  std::array<wchar_t, 32768> command{};
};
static_assert(sizeof(LeaseProcessIdentity) == 16 && sizeof(LeaseFileIdentity) == 12);
static_assert(sizeof(DiskRecord) == 65672, "The durable record must have the same x64/ARM64 layout");
}  // namespace lease_journal_detail

// Atomic records are kept outside the versioned runtime generation. Only
// administrators/SYSTEM can write them; existing aliases, links and ACLs are
// rejected rather than repaired. The fixed lock file serializes read/advance/
// erase across service and helper, and is released by Windows after a crash.
class ProtectedLeaseJournal final : public LeaseJournal {
 public:
  bool Read(std::optional<LeaseRecord>* value, DWORD* error) override {
    if (!value) return Fail(ERROR_INVALID_PARAMETER, error);
    lease_journal_detail::Directory directory;
    DWORD status = ERROR_SUCCESS;
    if (!directory.Open(false, &status)) {
      if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) { value->reset(); return true; }
      return Fail(status, error);
    }
    lease_journal_detail::Handle lock;
    return Lock(directory.path(), &lock, error) && ReadAt(directory.path(), value, error);
  }
  bool Create(const LeaseRecord& value, DWORD* error) override {
    lease_journal_detail::Directory directory;
    lease_journal_detail::Handle lock;
    std::optional<LeaseRecord> previous;
    return directory.Open(true, error) && Lock(directory.path(), &lock, error) &&
        ReadAt(directory.path(), &previous, error) &&
        (!previous || Fail(ERROR_ALREADY_EXISTS, error)) && WriteAt(directory.path(), value, error);
  }
  bool Advance(const LeaseRecord& value, LeasePhase expected, DWORD* error) override {
    lease_journal_detail::Directory directory;
    lease_journal_detail::Handle lock;
    std::optional<LeaseRecord> previous;
    return directory.Open(false, error) && Lock(directory.path(), &lock, error) &&
        ReadAt(directory.path(), &previous, error) &&
        ((previous && previous->token == value.token && previous->phase == expected) ||
            Fail(ERROR_INVALID_STATE, error)) && WriteAt(directory.path(), value, error);
  }
  bool Erase(const std::string& token, DWORD* error) override {
    lease_journal_detail::Directory directory;
    lease_journal_detail::Handle lock;
    std::optional<LeaseRecord> previous;
    if (!directory.Open(false, error) || !Lock(directory.path(), &lock, error) ||
        !ReadAt(directory.path(), &previous, error)) return false;
    if (!previous) return true;
    if (previous->token != token) return Fail(ERROR_INVALID_STATE, error);
    return DeleteFileW((directory.path() / kFile).c_str()) != FALSE || Fail(GetLastError(), error);
  }
  bool ProcessIdentity(HANDLE process, LeaseProcessIdentity* value, DWORD* error) override {
    FILETIME created{}, exited{}, kernel{}, user{};
    value->pid = GetProcessId(process);
    if (!value->pid || !GetProcessTimes(process, &created, &exited, &kernel, &user) ||
        !ProcessIdToSessionId(value->pid, &value->session)) return Fail(GetLastError(), error);
    value->created = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return value->created != 0 || Fail(ERROR_INVALID_DATA, error);
  }
  LeaseProcessState ProcessState(const LeaseProcessIdentity& value, DWORD* error) override {
    if (!lease_journal_detail::ValidIdentity(value)) { Fail(ERROR_INVALID_DATA, error); return LeaseProcessState::unknown; }
    lease_journal_detail::Handle process;
    process.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, value.pid);
    if (!process.value) {
      const DWORD status = GetLastError();
      if (status == ERROR_INVALID_PARAMETER) return LeaseProcessState::dead;
      Fail(status, error); return LeaseProcessState::unknown;
    }
    LeaseProcessIdentity actual;
    if (!ProcessIdentity(process.value, &actual, error)) return LeaseProcessState::unknown;
    // Reuse of the number proves the original process ended. Never wait on or
    // terminate the unrelated new process.
    if (!(actual == value)) return LeaseProcessState::dead;
    const DWORD state = WaitForSingleObject(process.value, 0);
    if (state == WAIT_OBJECT_0) return LeaseProcessState::dead;
    if (state == WAIT_TIMEOUT) return LeaseProcessState::alive;
    Fail(GetLastError(), error); return LeaseProcessState::unknown;
  }
  bool FileIdentity(HANDLE file, LeaseFileIdentity* value, DWORD* error) override {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file, &info)) return Fail(GetLastError(), error);
    *value = {info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow};
    return true;
  }
 private:
  static constexpr wchar_t kFile[] = L"portable-service-lease.v1";
  static bool Fail(DWORD value, DWORD* error) { return lease_journal_detail::Fail(value, error); }
  bool Lock(const std::filesystem::path& root, lease_journal_detail::Handle* lock, DWORD* error) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr))
      return Fail(GetLastError(), error);
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    const auto path = root / L"portable-service-lease.lock";
    const ULONGLONG deadline = GetTickCount64() + 2000;
    DWORD status = ERROR_SUCCESS;
    do {
      lock->value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
          0, &security, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      if (lock->value != INVALID_HANDLE_VALUE) break;
      status = GetLastError();
      if (status != ERROR_SHARING_VIOLATION) break;
      Sleep(10);
    } while (GetTickCount64() < deadline);
    LocalFree(descriptor);
    if (lock->value == INVALID_HANDLE_VALUE) return Fail(status, error);
    return lease_journal_detail::ProtectedObject(lock->value, path, false) || Fail(ERROR_ACCESS_DENIED, error);
  }
  bool ReadAt(const std::filesystem::path& root, std::optional<LeaseRecord>* value, DWORD* error) {
    value->reset();
    const auto path = root / kFile;
    lease_journal_detail::Handle file;
    file.value = CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file.value == INVALID_HANDLE_VALUE) {
      const DWORD status = GetLastError();
      return status == ERROR_FILE_NOT_FOUND || Fail(status, error);
    }
    LARGE_INTEGER size{};
    lease_journal_detail::DiskRecord disk{};
    DWORD bytes = 0;
    if (!lease_journal_detail::ProtectedObject(file.value, path, false) ||
        !GetFileSizeEx(file.value, &size) || size.QuadPart != sizeof(disk) ||
        !ReadFile(file.value, &disk, sizeof(disk), &bytes, nullptr) || bytes != sizeof(disk) ||
        disk.magic != 0x314c5a46 || disk.version != 1 || disk.initial_state != SERVICE_RUNNING ||
        disk.token.back() || disk.command.back()) return Fail(ERROR_INVALID_DATA, error);
    LeaseRecord record;
    record.phase = static_cast<LeasePhase>(disk.phase);
    record.token = disk.token.data(); record.command = disk.command.data();
    record.helper = disk.helper; record.parent = disk.parent; record.service = disk.service;
    record.engine = disk.engine; record.service_file = disk.service_file;
    if (!lease_journal_detail::ValidRecord(record)) return Fail(ERROR_INVALID_DATA, error);
    *value = std::move(record);
    return true;
  }
  bool WriteAt(const std::filesystem::path& root, const LeaseRecord& value, DWORD* error) {
    if (!lease_journal_detail::ValidRecord(value)) return Fail(ERROR_INVALID_DATA, error);
    lease_journal_detail::DiskRecord disk{};
    disk.phase = static_cast<DWORD>(value.phase);
    std::copy(value.token.begin(), value.token.end(), disk.token.begin());
    std::copy(value.command.begin(), value.command.end(), disk.command.begin());
    disk.helper = value.helper; disk.parent = value.parent; disk.service = value.service;
    disk.engine = value.engine; disk.service_file = value.service_file;
    const auto nonce = fuzevpn_update::NewToken();
    if (!fuzevpn_update::ValidToken(nonce)) return Fail(ERROR_GEN_FAILURE, error);
    const auto path = root / fuzevpn_update::Wide(".lease-" + nonce);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)", SDDL_REVISION_1, &descriptor, nullptr))
      return Fail(GetLastError(), error);
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    DWORD status = ERROR_SUCCESS;
    {
      lease_journal_detail::Handle output;
      output.value = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &security, CREATE_NEW,
          FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
      LocalFree(descriptor);
      if (output.value == INVALID_HANDLE_VALUE) return Fail(GetLastError(), error);
      DWORD bytes = 0;
      if (!WriteFile(output.value, &disk, sizeof(disk), &bytes, nullptr) || bytes != sizeof(disk) ||
          !FlushFileBuffers(output.value)) status = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    }
    if (status == ERROR_SUCCESS && !MoveFileExW(path.c_str(), (root / kFile).c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) status = GetLastError();
    if (status != ERROR_SUCCESS) { DeleteFileW(path.c_str()); return Fail(status, error); }
    return true;
  }
};

// Only the serialized service worker may commit its idle decision. A prepared
// request alone never authorizes recovery: an unrelated/user-requested stop
// cannot be confused with a portable handoff after the helper dies.
inline bool ConfirmInstalledServiceIdleYield(DWORD* error) {
  ProtectedLeaseJournal journal;
  std::optional<LeaseRecord> record;
  if (!journal.Read(&record, error)) return false;
  if (!record || record->phase != LeasePhase::requested) return lease_journal_detail::Fail(ERROR_INVALID_STATE, error);
  LeaseProcessIdentity current;
  if (!journal.ProcessIdentity(GetCurrentProcess(), &current, error) || !(current == record->service) ||
      journal.ProcessState(record->helper, error) != LeaseProcessState::alive ||
      journal.ProcessState(record->parent, error) != LeaseProcessState::alive)
    return lease_journal_detail::Fail(ERROR_BUSY, error);
  const auto executable = fuzevpn_update::CurrentExecutable();
  fuzevpn_update::PinnedFile file;
  LeaseFileIdentity identity;
  if (record->command != L"\"" + executable.wstring() + L"\" --fuzevpn-vpn-service" ||
      !file.Open(executable) || !journal.FileIdentity(file.get(), &identity, error) ||
      !(identity == record->service_file)) return lease_journal_detail::Fail(ERROR_BAD_CONFIGURATION, error);
  record->phase = LeasePhase::yielded;
  return journal.Advance(*record, LeasePhase::requested, error);
}
}  // namespace fuzevpn_handoff
#endif  // RUNNER_PORTABLE_SERVICE_LEASE_JOURNAL_H_
