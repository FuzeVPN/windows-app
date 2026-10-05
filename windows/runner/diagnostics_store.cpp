// SPDX-License-Identifier: MPL-2.0
#include "diagnostics_store.h"
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include "installation_security.h"

namespace fuzevpn_diagnostics {
namespace {
constexpr size_t kMaximumCipherBytes = kMaximumQueueBytes + 64 * 1024;
constexpr wchar_t kStateFile[] = L"pending.bin";
constexpr int64_t kMinimumDate = 946684800000ll;
constexpr int64_t kMaximumDate = 4133980800000ll;
constexpr char kEntropy[] = "FuzeVPN/diagnostics-store/v1";
bool Date(int64_t value) { return value >= kMinimumDate && value <= kMaximumDate; }
bool Utf8(const std::string& value) {
  return !value.empty() && value.find('\0') == std::string::npos && value.size() <= INT_MAX &&
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0) != 0;
}
void ClearBytes(std::vector<uint8_t>* bytes) {
  if (!bytes->empty()) SecureZeroMemory(bytes->data(), bytes->size());
  bytes->clear();
}
bool ValidCode(const std::string& value) {
  return value.size() <= 128 && std::all_of(value.begin(), value.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
  });
}
bool ValidReport(const Report& report) {
  return ValidReportId(report.id) && !report.body.empty() && report.body.size() <= kMaximumReportBytes &&
      Utf8(std::string(report.body.begin(), report.body.end())) && Date(report.created_at) &&
      Date(report.expires_at) && report.expires_at > report.created_at &&
      report.expires_at - report.created_at <= kRetentionMs && report.attempts <= 100 &&
      report.automatic_attempts <= 5 && report.automatic_attempts <= report.attempts &&
      (report.next_attempt_at == 0 || Date(report.next_attempt_at)) && ValidCode(report.terminal_code);
}
bool ValidState(const State& state) {
  if ((!state.account.empty() && !ValidAccount(state.account)) || state.notice_version != 1 ||
      state.reports.size() > kMaximumReports || state.rate_attempts.size() > 20 ||
      (state.last_seen != 0 && !Date(state.last_seen)) ||
      (state.retry_after_until != 0 && !Date(state.retry_after_until)) ||
      (state.account.empty() && (state.automatic_consent || !state.reports.empty() || !state.rate_attempts.empty()))) return false;
  std::set<std::string> identifiers;
  size_t bytes = 0;
  for (const auto& report : state.reports) {
    if (!ValidReport(report) || !identifiers.insert(report.id).second ||
        report.body.size() > kMaximumQueueBytes - bytes) return false;
    bytes += report.body.size();
  }
  for (const auto& attempt : state.rate_attempts) if (!Date(attempt.at)) return false;
  return true;
}
struct Writer {
  std::vector<uint8_t> bytes;
  ~Writer() { ClearBytes(&bytes); }
  void Number(uint64_t value) { for (unsigned i = 0; i != 8; ++i) bytes.push_back(static_cast<uint8_t>(value >> (i * 8))); }
  void Data(const uint8_t* data, size_t size) { Number(size); if (size) bytes.insert(bytes.end(), data, data + size); }
  void Text(const std::string& value) { Data(reinterpret_cast<const uint8_t*>(value.data()), value.size()); }
};
struct Reader {
  const std::vector<uint8_t>& bytes;
  size_t position = 0;
  bool Number(uint64_t* value) {
    if (bytes.size() - position < 8) return false;
    *value = 0;
    for (unsigned i = 0; i != 8; ++i) *value |= static_cast<uint64_t>(bytes[position++]) << (i * 8);
    return true;
  }
  bool Bound(uint64_t maximum, uint64_t* value) { return Number(value) && *value <= maximum; }
  bool Flag(bool* value) { uint64_t number = 0; if (!Bound(1, &number)) return false; *value = number != 0; return true; }
  bool Time(int64_t* value) { uint64_t number = 0; if (!Bound(kMaximumDate, &number)) return false; *value = static_cast<int64_t>(number); return true; }
  bool Data(std::vector<uint8_t>* value, size_t maximum) {
    uint64_t length = 0;
    if (!Bound(maximum, &length) || length > bytes.size() - position) return false;
    value->assign(bytes.begin() + position, bytes.begin() + position + static_cast<size_t>(length));
    position += static_cast<size_t>(length); return true;
  }
  bool Text(std::string* value, size_t maximum) {
    std::vector<uint8_t> data;
    if (!Data(&data, maximum)) return false;
    value->assign(data.begin(), data.end()); ClearBytes(&data); return true;
  }
};
struct Handle {
  HANDLE value = INVALID_HANDLE_VALUE;
  ~Handle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
};
struct Descriptor {
  PSECURITY_DESCRIPTOR value = nullptr;
  ~Descriptor() { if (value) LocalFree(value); }
};
std::vector<BYTE> UserSid() {
  Handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return {};
  DWORD bytes = 0; GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
  if (bytes == 0 || bytes > 65536) return {};
  std::vector<BYTE> data(bytes);
  if (!GetTokenInformation(token.value, TokenUser, data.data(), bytes, &bytes)) return {};
  PSID sid = reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid;
  std::vector<BYTE> result(GetLengthSid(sid));
  return CopySid(static_cast<DWORD>(result.size()), result.data(), sid) ? result : std::vector<BYTE>();
}
bool PrivateDescriptor(PSECURITY_DESCRIPTOR descriptor, PSID user) {
  PSID owner = nullptr; BOOL defaulted = FALSE, present = FALSE; PACL acl = nullptr;
  SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
  if (!descriptor || !IsValidSecurityDescriptor(descriptor) ||
      !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner || !EqualSid(owner, user) ||
      !GetSecurityDescriptorControl(descriptor, &control, &revision) || (control & SE_DACL_PROTECTED) == 0 ||
      !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || !acl || !IsValidAcl(acl)) return false;
  for (DWORD i = 0; i < acl->AceCount; ++i) {
    void* raw = nullptr;
    if (!GetAce(acl, i, &raw)) return false;
    const auto* header = static_cast<const ACE_HEADER*>(raw);
    if (header->AceFlags & INHERIT_ONLY_ACE) continue;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) return false;
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
    PSID sid = const_cast<DWORD*>(&ace->SidStart);
    if (!IsValidSid(sid) || (!EqualSid(sid, user) && !IsWellKnownSid(sid, WinLocalSystemSid))) return false;
  }
  return true;
}
bool ExactPath(HANDLE file, const std::filesystem::path& expected) {
  std::wstring actual(32768, L'\0');
  DWORD size = GetFinalPathNameByHandleW(file, actual.data(), static_cast<DWORD>(actual.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!size || size >= actual.size()) return false;
  actual.resize(size); if (actual.rfind(L"\\\\?\\", 0) == 0) actual.erase(0, 4);
  auto name = expected.wstring();
  while (name.size() > 2 && name.back() == L'\\') name.pop_back();
  while (actual.size() > 2 && actual.back() == L'\\') actual.pop_back();
  return fuzevpn_installation::SamePath(actual, name);
}
bool PrivateFile(HANDLE file, const std::filesystem::path& path, PSID user, bool directory) {
  BY_HANDLE_FILE_INFORMATION info{};
  Descriptor descriptor;
  return GetFileInformationByHandle(file, &info) &&
      !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
      ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
      (directory || (info.nNumberOfLinks == 1 && GetFileType(file) == FILE_TYPE_DISK)) &&
      ExactPath(file, path) && GetSecurityInfo(file, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &descriptor.value) == ERROR_SUCCESS &&
      PrivateDescriptor(descriptor.value, user);
}
std::string OsError(DWORD error) {
  return error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION ? "storage_access_denied" : "storage_io_error";
}
class Directory final {
 public:
  ~Directory() { for (HANDLE handle : pins_) CloseHandle(handle); }
  bool Open(const std::filesystem::path& directory, bool create) {
    user = UserSid();
    if (user.empty()) return false;
    if (!fuzevpn_installation::IsCanonicalLocalAbsolutePath(directory) ||
        !fuzevpn_installation::IsLocalFixedVolume(directory)) { SetLastError(ERROR_ACCESS_DENIED); return false; }
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(user.data(), &sid)) return false;
    const std::wstring text = L"O:" + std::wstring(sid) + L"D:P(A;OICI;FA;;;" + sid + L")(A;OICI;FA;;;SY)";
    LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(), SDDL_REVISION_1, &descriptor_.value, nullptr)) return false;
    attributes = {sizeof(attributes), descriptor_.value, FALSE};
    std::vector<std::filesystem::path> ancestors;
    for (auto path = directory.parent_path(); !path.empty();) {
      if (ancestors.size() >= 64) { SetLastError(ERROR_ACCESS_DENIED); return false; }
      ancestors.push_back(path); const auto parent = path.parent_path();
      if (parent == path) break; path = parent;
    }
    for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
      // Create only the FuzeVPN parent if missing, never a profile hierarchy.
      if (create && *it == directory.parent_path() && GetFileAttributesW(it->c_str()) == INVALID_FILE_ATTRIBUTES &&
          !CreateDirectoryW(it->c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
      HANDLE handle = CreateFileW(it->c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
          FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      if (handle == INVALID_HANDLE_VALUE) return false;
      BY_HANDLE_FILE_INFORMATION info{};
      if (!GetFileInformationByHandle(handle, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
          !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !ExactPath(handle, *it)) {
        CloseHandle(handle); SetLastError(ERROR_ACCESS_DENIED); return false;
      }
      pins_.push_back(handle);
    }
    if (create && !CreateDirectoryW(directory.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    HANDLE handle = CreateFileW(directory.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    if (!PrivateFile(handle, directory, user.data(), true)) { CloseHandle(handle); SetLastError(ERROR_ACCESS_DENIED); return false; }
    pins_.push_back(handle); return true;
  }
  SECURITY_ATTRIBUTES attributes{};
  std::vector<BYTE> user;
 private:
  Descriptor descriptor_;
  std::vector<HANDLE> pins_;
};
bool DeleteHandle(HANDLE file) {
  FILE_DISPOSITION_INFO disposition{TRUE};
  return SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
}
// A same-directory rename uses the source handle's parent. Unlike the Win32
// wrapper's absolute-name path, it does not reopen our strictly pinned parent
// for write access. The filename is fixed, contains no separator and cannot
// redirect publication to another directory.
bool PublishHandle(HANDLE file) {
  using SetInformation = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
  using StatusToError = ULONG(NTAPI*)(NTSTATUS);
  const HMODULE module = GetModuleHandleW(L"ntdll.dll");
  const auto set_information = reinterpret_cast<SetInformation>(GetProcAddress(module, "NtSetInformationFile"));
  const auto status_to_error = reinterpret_cast<StatusToError>(GetProcAddress(module, "RtlNtStatusToDosError"));
  if (!set_information || !status_to_error) { SetLastError(ERROR_PROC_NOT_FOUND); return false; }
  const std::wstring name = kStateFile;
  std::vector<BYTE> buffer(sizeof(FILE_RENAME_INFO) + name.size() * sizeof(wchar_t));
  auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
  rename->ReplaceIfExists = TRUE;
  rename->RootDirectory = nullptr;
  rename->FileNameLength = static_cast<DWORD>(name.size() * sizeof(wchar_t));
  std::memcpy(rename->FileName, name.data(), rename->FileNameLength);
  IO_STATUS_BLOCK result{};
  // The source was opened synchronously; this call completes before returning.
  const NTSTATUS status = set_information(file, &result, rename,
      static_cast<ULONG>(buffer.size()), static_cast<FILE_INFORMATION_CLASS>(10));
  if (status < 0) { SetLastError(status_to_error(status)); return false; }
  return true;
}
// A writer retains an exclusive handle until publication. Any recognized temp
// that can be opened here is therefore an abandoned encrypted file. Never
// follow or recursively delete unknown names, links or directories.
void PurgeTemporaries(const std::filesystem::path& directory, PSID user) {
  WIN32_FIND_DATAW entry{};
  HANDLE enumeration = FindFirstFileW((directory / L"pending-*.tmp").c_str(), &entry);
  if (enumeration == INVALID_HANDLE_VALUE) return;
  unsigned examined = 0;
  do {
    if (++examined > 64) break;
    const std::wstring name(entry.cFileName);
    if (name.size() != 44 || name.substr(0, 8) != L"pending-" || name.substr(40) != L".tmp" ||
        !std::all_of(name.begin() + 8, name.begin() + 40, [](wchar_t c) {
          return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
        }) || (entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) continue;
    const auto path = directory / name;
    Handle file; file.value = CreateFileW(path.c_str(), DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file.value != INVALID_HANDLE_VALUE && PrivateFile(file.value, path, user, false)) DeleteHandle(file.value);
  } while (FindNextFileW(enumeration, &entry));
  FindClose(enumeration);
}
std::string RandomName() {
  std::array<BYTE, 16> bytes{};
  if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return {};
  constexpr char hex[] = "0123456789abcdef"; std::string name;
  for (BYTE byte : bytes) { name += hex[byte >> 4]; name += hex[byte & 15]; }
  return name;
}
DATA_BLOB Entropy() { return {sizeof(kEntropy) - 1, reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))}; }
}  // namespace

int64_t NowMs() {
  FILETIME time{}; GetSystemTimeAsFileTime(&time);
  const uint64_t ticks = (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
  return static_cast<int64_t>(ticks / 10000) - 11644473600000ll;
}
bool ValidAccount(const std::string& value) { return value.size() <= 128 && Utf8(value); }
bool ValidReportId(const std::string& id) {
  if (id.size() != 36 || id == "00000000-0000-0000-0000-000000000000") return false;
  for (size_t i = 0; i < id.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { if (id[i] != '-') return false; }
    else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return false;
  }
  return true;
}
void Wipe(State* state) {
  for (auto& report : state->reports) ClearBytes(&report.body);
  if (!state->account.empty()) SecureZeroMemory(state->account.data(), state->account.size());
  *state = {};
}
bool Purge(State* state, int64_t now) {
  bool changed = false;
  const bool rollback = !Date(now) || now + kClockToleranceMs < state->last_seen;
  if (rollback) {
    changed = !state->reports.empty() || state->automatic_consent;
    for (auto& report : state->reports) ClearBytes(&report.body);
    state->reports.clear(); state->automatic_consent = false;
  } else {
    auto& reports = state->reports;
    for (auto& report : reports) if (now >= report.expires_at) { ClearBytes(&report.body); changed = true; }
    reports.erase(std::remove_if(reports.begin(), reports.end(), [now](const Report& r) { return now >= r.expires_at; }), reports.end());
  }
  auto& rates = state->rate_attempts; const auto previous = rates.size();
  if (state->retry_after_until && now >= state->retry_after_until) { state->retry_after_until = 0; changed = true; }
  rates.erase(std::remove_if(rates.begin(), rates.end(), [now](const RateAttempt& r) { return r.at <= now - kHourMs; }), rates.end());
  changed |= previous != rates.size();
  if (Date(now) && now > state->last_seen) state->last_seen = now;
  return changed;
}
std::string Enqueue(State* state, Report report, int64_t now) {
  struct IncomingCleanup { Report* report; ~IncomingCleanup() { ClearBytes(&report->body); } } incoming{&report};
  if (!ValidAccount(state->account) || !ValidReport(report) || report.attempts || report.automatic_attempts ||
      report.next_attempt_at || report.paused_for_auth || !report.terminal_code.empty()) return "invalid_argument";
  if (!Date(now) || now + kClockToleranceMs < state->last_seen) return "storage_clock_invalid";
  Purge(state, now);
  if (report.expires_at <= now || report.created_at > now + kClockToleranceMs ||
      report.expires_at > now + kRetentionMs) return "diagnostic_expired";
  if (!report.manual && !state->automatic_consent) return "diagnostic_consent_required";
  for (const auto& existing : state->reports) if (existing.id == report.id) {
    return existing.body == report.body && existing.created_at == report.created_at && existing.manual == report.manual &&
        existing.expires_at == report.expires_at ? "" : "diagnostic_conflict";
  }
  // Admission and any required evictions form one transaction. A failed
  // serialization or a queue consisting entirely of manual reports must not
  // discard previously authorized payloads.
  const bool manual = report.manual;
  State candidate = *state;
  struct CandidateCleanup { State* state; ~CandidateCleanup() { Wipe(state); } } cleanup{&candidate};
  candidate.reports.push_back(std::move(report));
  for (;;) {
    std::vector<uint8_t> encoded;
    const bool valid = Encode(candidate, &encoded); ClearBytes(&encoded);
    if (valid) {
      Wipe(state); *state = std::move(candidate);
      return {};
    }
    if (!manual) return "diagnostic_queue_full";
    auto oldest = candidate.reports.end();
    for (auto it = candidate.reports.begin(); it != candidate.reports.end(); ++it)
      if (!it->manual && (oldest == candidate.reports.end() || it->created_at < oldest->created_at)) oldest = it;
    if (oldest == candidate.reports.end()) return "diagnostic_queue_full";
    ClearBytes(&oldest->body);
    candidate.reports.erase(oldest);
  }
}
std::string MarkAttempt(State* state, const std::string& id, bool automatic, int64_t now) {
  if (!Date(now) || now + kClockToleranceMs < state->last_seen) return "storage_clock_invalid";
  Purge(state, now);
  if (state->retry_after_until > now) return "diagnostic_rate_limited";
  for (auto& report : state->reports) if (report.id == id) {
    if (report.paused_for_auth || !report.terminal_code.empty() || report.next_attempt_at > now) return "diagnostic_not_ready";
    if (automatic && ((!report.manual && !state->automatic_consent) || report.automatic_attempts >= 5)) return "diagnostic_consent_required";
    const auto automatic_count = std::count_if(state->rate_attempts.begin(), state->rate_attempts.end(), [](const RateAttempt& a) { return a.automatic; });
    if (state->rate_attempts.size() >= 20 || (automatic && automatic_count >= 10) || report.attempts >= 100) return "diagnostic_rate_limited";
    ++report.attempts; if (automatic) ++report.automatic_attempts;
    state->rate_attempts.push_back({now, automatic}); return {};
  }
  return "diagnostic_not_found";
}
std::string UpdateReport(State* state, const std::string& id, int64_t next, bool paused, const std::string& terminal, int64_t account_retry_after) {
  if ((next && !Date(next)) || (account_retry_after && !Date(account_retry_after)) || !ValidCode(terminal)) return "invalid_argument";
  for (auto& report : state->reports) if (report.id == id) {
    state->retry_after_until = (std::max)(state->retry_after_until, account_retry_after);
    report.next_attempt_at = next; report.paused_for_auth = paused; report.terminal_code = terminal; return {};
  }
  return "diagnostic_not_found";
}
bool Encode(const State& state, std::vector<uint8_t>* output) {
  if (!ValidState(state)) return false;
  Writer writer; writer.Number(0x3147414944455a46ull); writer.Text(state.account);
  writer.Number(state.automatic_consent); writer.Number(state.notice_version); writer.Number(state.last_seen); writer.Number(state.retry_after_until);
  writer.Number(state.reports.size());
  for (const auto& r : state.reports) {
    writer.Text(r.id); writer.Data(r.body.data(), r.body.size()); writer.Number(r.created_at); writer.Number(r.expires_at);
    writer.Number(r.manual); writer.Number(r.attempts); writer.Number(r.automatic_attempts); writer.Number(r.next_attempt_at);
    writer.Number(r.paused_for_auth); writer.Text(r.terminal_code);
  }
  writer.Number(state.rate_attempts.size());
  for (const auto& attempt : state.rate_attempts) { writer.Number(attempt.at); writer.Number(attempt.automatic); }
  if (writer.bytes.size() > kMaximumQueueBytes) { ClearBytes(&writer.bytes); return false; }
  *output = std::move(writer.bytes); return true;
}
bool Decode(const std::vector<uint8_t>& bytes, State* output) {
  if (bytes.empty() || bytes.size() > kMaximumQueueBytes) return false;
  State state; Reader reader{bytes}; uint64_t magic = 0, number = 0;
  if (!reader.Number(&magic) || magic != 0x3147414944455a46ull || !reader.Text(&state.account, 128) ||
      !reader.Flag(&state.automatic_consent) || !reader.Bound(1, &number) || number != 1 ||
      !reader.Time(&state.last_seen) || !reader.Time(&state.retry_after_until) || !reader.Bound(kMaximumReports, &number)) return false;
  state.reports.resize(static_cast<size_t>(number));
  bool valid = true;
  for (auto& r : state.reports) {
    valid = reader.Text(&r.id, 36) && reader.Data(&r.body, kMaximumReportBytes) && reader.Time(&r.created_at) &&
        reader.Time(&r.expires_at) && reader.Flag(&r.manual) && reader.Bound(100, &number);
    if (!valid) break; r.attempts = static_cast<unsigned>(number);
    valid = reader.Bound(5, &number); if (!valid) break; r.automatic_attempts = static_cast<unsigned>(number);
    valid = reader.Time(&r.next_attempt_at) && reader.Flag(&r.paused_for_auth) && reader.Text(&r.terminal_code, 128);
    if (!valid) break;
  }
  if (valid) valid = reader.Bound(20, &number);
  if (valid) {
    state.rate_attempts.resize(static_cast<size_t>(number));
    for (auto& attempt : state.rate_attempts) if (!reader.Time(&attempt.at) || !reader.Flag(&attempt.automatic)) { valid = false; break; }
  }
  valid = valid && reader.position == bytes.size() && ValidState(state);
  if (!valid) { Wipe(&state); return false; }
  Wipe(output); *output = std::move(state); return true;
}
FileStore::FileStore() {
  PWSTR path = nullptr;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
    directory_ = std::filesystem::path(path) / L"FuzeVPN" / L"DiagnosticsPending"; CoTaskMemFree(path);
  }
}
FileStore::FileStore(std::filesystem::path directory) : directory_(std::move(directory)) {}
std::string FileStore::Load(State* state) {
  Wipe(state); Directory directory;
  if (!directory.Open(directory_, false)) {
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? "" : OsError(error);
  }
  PurgeTemporaries(directory_, directory.user.data());
  const auto path = directory_ / kStateFile;
  Handle file; file.value = CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file.value == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND ? "" : OsError(GetLastError());
  if (!PrivateFile(file.value, path, directory.user.data(), false)) return "storage_access_denied";
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file.value, &size)) return "storage_io_error";
  if (size.QuadPart <= 0 || static_cast<uint64_t>(size.QuadPart) > kMaximumCipherBytes) return "storage_corrupt";
  std::vector<BYTE> cipher(static_cast<size_t>(size.QuadPart)); DWORD read = 0;
  if (!ReadFile(file.value, cipher.data(), static_cast<DWORD>(cipher.size()), &read, nullptr) || read != cipher.size()) return "storage_io_error";
  DATA_BLOB input{static_cast<DWORD>(cipher.size()), cipher.data()}, plain{}, entropy = Entropy();
  if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) return "storage_decryption_failed";
  std::vector<uint8_t> decoded;
  if (plain.cbData <= kMaximumQueueBytes) decoded.assign(plain.pbData, plain.pbData + plain.cbData);
  SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData);
  const bool valid = Decode(decoded, state); ClearBytes(&decoded);
  return valid ? "" : "storage_corrupt";
}
std::string FileStore::Save(const State& state, const std::function<bool()>& current) {
  if (!current()) return "operation_cancelled";
  std::vector<uint8_t> bytes;
  if (!Encode(state, &bytes)) return "diagnostic_queue_full";
  DATA_BLOB input{static_cast<DWORD>(bytes.size()), bytes.data()}, cipher{}, entropy = Entropy();
  const bool encrypted = CryptProtectData(&input, L"FuzeVPN diagnostics", &entropy, nullptr, nullptr,
      CRYPTPROTECT_UI_FORBIDDEN, &cipher) != FALSE;
  ClearBytes(&bytes);
  if (!encrypted) return "storage_encryption_failed";
  struct CipherRelease { DATA_BLOB* data; ~CipherRelease() { LocalFree(data->pbData); } } release{&cipher};
  if (cipher.cbData > kMaximumCipherBytes) return "diagnostic_queue_full";
  Directory directory;
  if (!directory.Open(directory_, true)) return OsError(GetLastError());
  PurgeTemporaries(directory_, directory.user.data());
  const auto random = RandomName(); if (random.empty()) return "storage_io_error";
  const auto temporary = directory_ / (L"pending-" + std::wstring(random.begin(), random.end()) + L".tmp");
  Handle file; file.value = CreateFileW(temporary.c_str(), GENERIC_WRITE | DELETE | READ_CONTROL, 0,
      &directory.attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file.value == INVALID_HANDLE_VALUE) return OsError(GetLastError());
  bool published = false;
  struct TempCleanup { HANDLE file; bool* published; ~TempCleanup() { if (!*published) DeleteHandle(file); } } cleanup{file.value, &published};
  DWORD written = 0;
  if (!PrivateFile(file.value, temporary, directory.user.data(), false) ||
      !WriteFile(file.value, cipher.pbData, cipher.cbData, &written, nullptr) || written != cipher.cbData || !FlushFileBuffers(file.value)) return "storage_io_error";
  if (!current()) return "operation_cancelled";
  const auto target = directory_ / kStateFile;
  { Handle existing; existing.value = CreateFileW(target.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (existing.value != INVALID_HANDLE_VALUE && !PrivateFile(existing.value, target, directory.user.data(), false)) return "storage_access_denied";
    if (existing.value == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND) return OsError(GetLastError());
  }
  if (!PublishHandle(file.value)) return OsError(GetLastError());
  published = true; return {};
}
std::string FileStore::Erase() {
  Directory directory;
  if (!directory.Open(directory_, false)) {
    const DWORD error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? "" : OsError(error);
  }
  const auto path = directory_ / kStateFile; Handle file;
  file.value = CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL, 0, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file.value == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND ? "" : OsError(GetLastError());
  if (!PrivateFile(file.value, path, directory.user.data(), false)) return "storage_access_denied";
  return DeleteHandle(file.value) ? "" : OsError(GetLastError());
}
std::string FileStore::PurgeExpired(int64_t now) {
  State state; const auto error = Load(&state);
  if (!error.empty()) {
    if (error == "storage_corrupt" || error == "storage_decryption_failed") Erase();
    return error;
  }
  const bool changed = Purge(&state, now);
  const auto saved = changed && !state.account.empty() ? Save(state, [] { return true; }) : "";
  Wipe(&state); return saved;
}
}  // namespace fuzevpn_diagnostics

#ifndef FUZEVPN_DIAGNOSTICS_STORE_NO_CHANNEL
#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace {
using flutter::EncodableList;
using flutter::EncodableMap;
using flutter::EncodableValue;
using fuzevpn_diagnostics::Report;
using fuzevpn_diagnostics::State;
const EncodableValue* Field(const EncodableMap& args, const char* key) {
  const auto item = args.find(EncodableValue(key)); return item == args.end() ? nullptr : &item->second;
}
const std::string* Text(const EncodableMap& args, const char* key) {
  const auto* value = Field(args, key); return value ? std::get_if<std::string>(value) : nullptr;
}
bool Number(const EncodableMap& args, const char* key, int64_t* result, bool optional = false) {
  const auto* value = Field(args, key);
  if (!value || std::holds_alternative<std::monostate>(*value)) { *result = 0; return optional; }
  if (const auto* integer = std::get_if<int64_t>(value)) { *result = *integer; return true; }
  if (const auto* integer = std::get_if<int32_t>(value)) { *result = *integer; return true; }
  return false;
}
bool Boolean(const EncodableMap& args, const char* key, bool* result, bool fallback = false) {
  const auto* value = Field(args, key);
  if (!value || std::holds_alternative<std::monostate>(*value)) { *result = fallback; return true; }
  const auto* boolean = std::get_if<bool>(value); if (!boolean) return false; *result = *boolean; return true;
}
EncodableValue StateValue(const State& state) {
  EncodableList reports;
  for (const auto& report : state.reports) reports.emplace_back(EncodableMap{
      {EncodableValue("report_id"), EncodableValue(report.id)}, {EncodableValue("body"), EncodableValue(report.body)},
      {EncodableValue("created_at"), EncodableValue(report.created_at)}, {EncodableValue("expires_at"), EncodableValue(report.expires_at)},
      {EncodableValue("manual"), EncodableValue(report.manual)}, {EncodableValue("attempts"), EncodableValue(static_cast<int32_t>(report.attempts))},
      {EncodableValue("automatic_attempts"), EncodableValue(static_cast<int32_t>(report.automatic_attempts))},
      {EncodableValue("next_attempt_at"), report.next_attempt_at ? EncodableValue(report.next_attempt_at) : EncodableValue()},
      {EncodableValue("paused_for_auth"), EncodableValue(report.paused_for_auth)},
      {EncodableValue("terminal_code"), report.terminal_code.empty() ? EncodableValue() : EncodableValue(report.terminal_code)}});
  EncodableList rates;
  for (const auto& rate : state.rate_attempts) rates.emplace_back(EncodableMap{
      {EncodableValue("at"), EncodableValue(rate.at)}, {EncodableValue("automatic"), EncodableValue(rate.automatic)}});
  return EncodableValue(EncodableMap{
      {EncodableValue("automatic_consent"), EncodableValue(state.automatic_consent)},
      {EncodableValue("notice_version"), EncodableValue(static_cast<int32_t>(state.notice_version))},
      {EncodableValue("retry_after_until"), state.retry_after_until ? EncodableValue(state.retry_after_until) : EncodableValue()},
      {EncodableValue("reports"), EncodableValue(std::move(reports))},
      {EncodableValue("rate_attempts"), EncodableValue(std::move(rates))}});
}
std::string ChannelError(const std::string& error) {
  if (error.rfind("storage_", 0) == 0) return "diagnostics_storage_failed";
  if (error == "operation_cancelled") return "diagnostics_stale_session";
  if (error.rfind("diagnostic_", 0) == 0) return "diagnostics_" + error.substr(11);
  return error;
}
// Serializes independent GUI instances belonging to the same Windows account.
// This mutex grants no elevated capability and lives only during an operation.
class QueueLock final {
 public:
  ~QueueLock() { if (owned_) ReleaseMutex(handle_); if (handle_) CloseHandle(handle_); }
  bool Acquire() {
    const auto user = fuzevpn_diagnostics::UserSid(); if (user.empty()) return false;
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(const_cast<BYTE*>(user.data()), &sid)) return false;
    const std::wstring name = L"Global\\FuzeVPN-DiagnosticsStore-v1-" + std::wstring(sid);
    const std::wstring acl = L"D:P(A;;GA;;;" + std::wstring(sid) + L")(A;;GA;;;SY)";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    handle_ = CreateMutexW(&attributes, FALSE, name.c_str()); LocalFree(descriptor);
    if (!handle_) return false;
    const DWORD wait = WaitForSingleObject(handle_, 5000);
    owned_ = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED; return owned_;
  }
 private:
  HANDLE handle_ = nullptr;
  bool owned_ = false;
};
}  // namespace

struct DiagnosticsStoreChannel::Impl {
  struct Job {
    std::string method, account, previous_account, id, terminal;
    int64_t generation = -1;
    uint64_t revision = 0;
    bool flag = false, second_flag = false;
    int64_t timestamp = 0;
    int64_t account_retry_after = 0;
    Report report;
    std::unique_ptr<flutter::MethodResult<EncodableValue>> result;
  };
  struct Completion {
    EncodableValue value;
    std::string error;
    std::unique_ptr<flutter::MethodResult<EncodableValue>> result;
    int64_t generation = -1;
    uint64_t revision = 0;
    bool cancellation = false;
  };
  HWND window;
  std::unique_ptr<flutter::MethodChannel<EncodableValue>> channel;
  std::atomic<bool> stopping{false};
  fuzevpn_diagnostics::SessionFence session;
  std::atomic<unsigned> pending{0};
  std::string account;  // Platform thread only; jobs capture their account.
  std::mutex mutex;
  std::condition_variable ready;
  std::deque<Job> jobs;
  std::deque<Completion> completions;
  fuzevpn_diagnostics::FileStore store;
  std::thread worker;
  Impl(flutter::FlutterEngine* engine, HWND handle) : window(handle) {
    channel = std::make_unique<flutter::MethodChannel<EncodableValue>>(
        engine->messenger(), "fuzevpn/diagnostics_store", &flutter::StandardMethodCodec::GetInstance());
    channel->SetMethodCallHandler([this](const auto& call, auto result) { Submit(call, std::move(result)); });
    worker = std::thread([this] { Work(); });
    PurgeExpired();
  }
  ~Impl() {
    channel->SetMethodCallHandler(nullptr); stopping = true; session.Invalidate();
    ready.notify_all();
    if (worker.joinable()) worker.join();
    for (auto& completion : completions) if (completion.result) completion.result->Error("diagnostics_stale_session");
  }
  bool Current(const Job& job) const {
    return !stopping && session.Matches(job.generation, job.revision);
  }
  void Submit(const flutter::MethodCall<EncodableValue>& call,
              std::unique_ptr<flutter::MethodResult<EncodableValue>> result) {
    const auto* args = std::get_if<EncodableMap>(call.arguments());
    Job job; job.method = call.method_name();
    if (!args || !Number(*args, "generation", &job.generation) || job.generation < 0) {
      result->Error("invalid_argument"); return;
    }
    const bool bind = job.method == "bindSession", clear = job.method == "clear";
    if (stopping || (bind ? job.generation <= session.generation() : job.generation != session.generation())) {
      result->Error("diagnostics_stale_session"); return;
    }
    if (pending >= 4 && !bind && !clear) { result->Error("diagnostics_busy"); return; }
    if (bind) {
      const auto* value = Field(*args, "account_id");
      if (value && !std::holds_alternative<std::monostate>(*value)) {
        const auto* name = std::get_if<std::string>(value);
        if (!name || !fuzevpn_diagnostics::ValidAccount(*name)) { result->Error("invalid_argument"); return; }
        job.account = *name;
      }
      if (!Boolean(*args, "purge_previous", &job.flag)) { result->Error("invalid_argument"); return; }
      job.previous_account = account; account = job.account;
      session.Bind(job.generation); job.revision = session.revision();
    } else {
      job.account = account;
      if (job.account.empty()) { result->Error("diagnostics_stale_session"); return; }
      job.revision = session.revision();
      if (clear) {
        if (!Boolean(*args, "revoke_consent", &job.flag, true)) { result->Error("invalid_argument"); return; }
        session.Invalidate(); job.revision = session.revision();
      } else if (job.method == "setConsent") {
        int64_t notice = 0;
        if (!Boolean(*args, "enabled", &job.flag) || !Number(*args, "notice_version", &notice) || notice != 1) {
          result->Error("invalid_argument"); return;
        }
      } else if (job.method == "enqueue") {
        const auto* id = Text(*args, "report_id"); const auto* value = Field(*args, "body");
        const auto* body = value ? std::get_if<std::vector<uint8_t>>(value) : nullptr;
        if (!id || !fuzevpn_diagnostics::ValidReportId(*id) || !body || body->empty() || body->size() > fuzevpn_diagnostics::kMaximumReportBytes ||
            !Number(*args, "created_at", &job.report.created_at) || !Number(*args, "expires_at", &job.report.expires_at) ||
            !Boolean(*args, "manual", &job.report.manual, true)) { result->Error("invalid_argument"); return; }
        job.report.id = *id; job.report.body = *body;
      } else if (job.method == "markAttempt" || job.method == "updateReport" || job.method == "remove") {
        const auto* id = Text(*args, "report_id");
        if (!id || !fuzevpn_diagnostics::ValidReportId(*id)) { result->Error("invalid_argument"); return; }
        job.id = *id;
        if (job.method == "markAttempt") {
          if (!Boolean(*args, "automatic", &job.flag)) { result->Error("invalid_argument"); return; }
        } else if (job.method == "updateReport") {
          if (!Number(*args, "next_attempt_at", &job.timestamp, true) || !Number(*args, "account_retry_after", &job.account_retry_after, true) ||
              !Boolean(*args, "paused_for_auth", &job.flag)) {
            result->Error("invalid_argument"); return;
          }
          const auto* terminal = Field(*args, "terminal_code");
          if (terminal && !std::holds_alternative<std::monostate>(*terminal)) {
            const auto* code = std::get_if<std::string>(terminal);
            if (!code || !fuzevpn_diagnostics::ValidCode(*code)) { result->Error("invalid_argument"); return; }
            job.terminal = *code;
          }
        }
      } else if (job.method != "readState") { result->NotImplemented(); return; }
    }
    job.result = std::move(result); ++pending;
    { std::lock_guard<std::mutex> lock(mutex); jobs.push_back(std::move(job)); }
    ready.notify_one();
  }
  void PurgeExpired() {
    if (stopping) return;
    Job job; job.method = "purge";
    { std::lock_guard<std::mutex> lock(mutex); if (jobs.size() >= 8) return; jobs.push_back(std::move(job)); }
    ready.notify_one();
  }
  std::string Execute(Job& job, EncodableValue* value) {
    using namespace fuzevpn_diagnostics;
    const bool clearing = job.method == "clear" || (job.method == "bindSession" && job.flag);
    if (job.method != "purge" && !clearing && !Current(job)) return "operation_cancelled";
    QueueLock lock; if (!lock.Acquire()) return "storage_access_denied";
    if (job.method == "purge") return store.PurgeExpired(NowMs());
    State state;
    struct StateCleanup { State* state; ~StateCleanup() { Wipe(state); } } cleanup{&state};
    auto error = store.Load(&state);
    if (!error.empty()) {
      // Explicit erasure may recover an unreadable encrypted queue, but normal
      // reads never reinterpret corruption/decryption failure as no consent.
      if (clearing && (error == "storage_corrupt" || error == "storage_decryption_failed")) return store.Erase();
      return error;
    }
    const auto now = NowMs(); bool changed = Purge(&state, now);
    if (clearing) {
      const auto& owner = job.method == "clear" ? job.account : job.previous_account;
      if (!state.account.empty() && (job.method == "bindSession" || state.account == owner)) {
        for (auto& report : state.reports) ClearBytes(&report.body);
        state.reports.clear();
        if (job.method == "bindSession" || job.flag) state.automatic_consent = false;
        error = store.Save(state, [] { return true; });
        if (!error.empty()) return error;
      }
      if (!Current(job)) return "operation_cancelled";
    }
    if (!Current(job)) return "operation_cancelled";
    if (job.method == "bindSession") {
      if (job.account.empty()) return {};
      if (state.account != job.account) { Wipe(&state); state.account = job.account; state.last_seen = now; changed = true; }
    } else {
      if (state.account.empty()) { state.account = job.account; state.last_seen = now; }
      if (state.account != job.account) return "operation_cancelled";
      if (job.method == "setConsent") {
        state.automatic_consent = job.flag;
        if (!job.flag) {
          for (auto& report : state.reports) if (!report.manual) ClearBytes(&report.body);
          state.reports.erase(std::remove_if(state.reports.begin(), state.reports.end(), [](const Report& r) { return !r.manual; }), state.reports.end());
        }
        changed = true;
      } else if (job.method == "enqueue") { error = Enqueue(&state, std::move(job.report), now); changed = error.empty() || changed; }
      else if (job.method == "markAttempt") { error = MarkAttempt(&state, job.id, job.flag, now); changed = error.empty() || changed; }
      else if (job.method == "updateReport") { error = UpdateReport(&state, job.id, job.timestamp, job.flag, job.terminal, job.account_retry_after); changed = error.empty() || changed; }
      else if (job.method == "remove") {
        for (auto& report : state.reports) if (report.id == job.id) ClearBytes(&report.body);
        state.reports.erase(std::remove_if(state.reports.begin(), state.reports.end(), [&](const Report& r) { return r.id == job.id; }), state.reports.end()); changed = true;
      }
    }
    if (changed) {
      const auto saved = store.Save(state, [&] { return Current(job); });
      if (!saved.empty()) return saved;
    }
    if (error.empty() && job.method == "readState") *value = StateValue(state);
    return error;
  }
  void Work() {
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    for (;;) {
      Job job;
      {
        std::unique_lock<std::mutex> lock(mutex);
        if (!ready.wait_for(lock, std::chrono::minutes(1), [&] { return stopping || !jobs.empty(); })) {
          job.method = "purge";
        } else {
          if (jobs.empty() && stopping) break;
          if (jobs.empty()) continue;
          job = std::move(jobs.front()); jobs.pop_front();
        }
      }
      Completion completion; completion.generation = job.generation; completion.revision = job.revision;
      completion.cancellation = job.method == "clear" || (job.method == "bindSession" && job.flag);
      try { completion.error = Execute(job, &completion.value); }
      catch (...) { completion.error = "storage_io_error"; }
      fuzevpn_diagnostics::ClearBytes(&job.report.body);
      if (!job.result) continue;
      completion.result = std::move(job.result);
      { std::lock_guard<std::mutex> lock(mutex); completions.push_back(std::move(completion)); }
      PostMessageW(window, kDiagnosticsStoreCompletedMessage, 0, 0);
    }
    if (SUCCEEDED(initialized)) CoUninitialize();
  }
};
DiagnosticsStoreChannel::DiagnosticsStoreChannel(flutter::FlutterEngine* engine, HWND window)
    : impl_(std::make_unique<Impl>(engine, window)) {}
DiagnosticsStoreChannel::~DiagnosticsStoreChannel() = default;
void DiagnosticsStoreChannel::PurgeExpired() { impl_->PurgeExpired(); }
void DiagnosticsStoreChannel::ProcessCompletions() {
  std::deque<Impl::Completion> completions;
  { std::lock_guard<std::mutex> lock(impl_->mutex); completions.swap(impl_->completions); }
  for (auto& completion : completions) {
    --impl_->pending;
    if (!completion.cancellation && !impl_->session.Matches(completion.generation, completion.revision))
      completion.error = "operation_cancelled";
    if (completion.error.empty()) completion.result->Success(completion.value);
    else completion.result->Error(ChannelError(completion.error), "", EncodableValue(EncodableMap{
        {EncodableValue("reason"), EncodableValue(completion.error)}}));
  }
}
#endif
