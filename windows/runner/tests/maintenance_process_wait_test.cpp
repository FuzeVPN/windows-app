// Runs the production process-disappearance reader against synthetic Toolhelp
// entries. It never opens, stops or terminates a process, changes privileges,
// accesses SCM/registry, or launches an application.
#include <windows.h>
#include <tlhelp32.h>
#include <cstring>
#include <iostream>
#include <vector>

namespace {
constexpr DWORD kSelfPid = 404;
constexpr DWORD kServicePid = 123;
std::vector<DWORD> fixture_pids;
size_t fixture_position = 0;
DWORD fixture_create_error = ERROR_SUCCESS;
DWORD fixture_first_error = ERROR_SUCCESS;
DWORD fixture_next_error = ERROR_NO_MORE_FILES;
unsigned fixture_creations = 0;
unsigned fixture_closes = 0;
bool fixture_recycled_name = false;
bool fixture_invalid_arguments = false;

HANDLE WINAPI FixtureSnapshot(DWORD flags, DWORD pid) {
  ++fixture_creations;
  fixture_invalid_arguments |= flags != TH32CS_SNAPPROCESS || pid != 0;
  if (fixture_create_error != ERROR_SUCCESS) {
    SetLastError(fixture_create_error);
    return INVALID_HANDLE_VALUE;
  }
  return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(17));
}

void FillEntry(PROCESSENTRY32W* entry) {
  fixture_invalid_arguments |= entry->dwSize != sizeof(PROCESSENTRY32W);
  entry->th32ProcessID = fixture_pids[fixture_position];
  if (fixture_recycled_name && entry->th32ProcessID == kServicePid) {
    const wchar_t name[] = L"unrelated-recycled-pid.exe";
    std::memcpy(entry->szExeFile, name, sizeof(name));
  }
}

BOOL WINAPI FixtureFirst(HANDLE, LPPROCESSENTRY32W entry) {
  if (fixture_first_error != ERROR_SUCCESS) {
    SetLastError(fixture_first_error);
    return FALSE;
  }
  fixture_position = 0;
  if (fixture_pids.empty()) {
    SetLastError(ERROR_NO_MORE_FILES);
    return FALSE;
  }
  FillEntry(entry);
  return TRUE;
}

BOOL WINAPI FixtureNext(HANDLE, LPPROCESSENTRY32W entry) {
  if (fixture_position + 1 < fixture_pids.size()) {
    ++fixture_position;
    FillEntry(entry);
    return TRUE;
  }
  SetLastError(fixture_next_error);
  return FALSE;
}

BOOL WINAPI FixtureClose(HANDLE value) {
  fixture_invalid_arguments |= value != reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(17));
  ++fixture_closes;
  return TRUE;
}
DWORD WINAPI FixtureSelfPid() { return kSelfPid; }

void Reset(std::vector<DWORD> entries = {kSelfPid}) {
  fixture_pids = std::move(entries);
  fixture_position = 0;
  fixture_create_error = fixture_first_error = ERROR_SUCCESS;
  fixture_next_error = ERROR_NO_MORE_FILES;
  fixture_creations = fixture_closes = 0;
  fixture_recycled_name = fixture_invalid_arguments = false;
}

bool Check(bool condition, const char* message) {
  if (!condition) std::cerr << "Maintenance snapshot regression: " << message << '\n';
  return condition;
}
}

#define CreateToolhelp32Snapshot FixtureSnapshot
#define Process32FirstW FixtureFirst
#define Process32NextW FixtureNext
#define CloseHandle FixtureClose
#define GetCurrentProcessId FixtureSelfPid
#include "../maintenance_process_wait.h"
#undef CreateToolhelp32Snapshot
#undef Process32FirstW
#undef Process32NextW
#undef CloseHandle
#undef GetCurrentProcessId

int main() {
  using fuzevpn_maintenance::ServiceProcessExitedBySnapshot;
  unsigned passed = 0;
  DWORD error = ERROR_ACCESS_DENIED;
  Reset();
  auto result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(result.has_value() && *result && error == ERROR_SUCCESS &&
      fixture_creations == 1 && fixture_closes == 1 && !fixture_invalid_arguments,
      "complete self-visible snapshot proves original PID absent without a process handle")) return 1;
  ++passed;

  Reset({kSelfPid, kServicePid});
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(result.has_value() && !*result && error == ERROR_SUCCESS,
      "original service PID still visible blocks replacement")) return 1;
  ++passed;

  Reset({kServicePid, kSelfPid}); fixture_recycled_name = true;
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(result.has_value() && !*result && error == ERROR_SUCCESS,
      "recycled PID with a different executable name remains blocking")) return 1;
  ++passed;

  Reset();
  result = ServiceProcessExitedBySnapshot(kSelfPid, &error);
  if (!Check(result.has_value() && !*result,
      "live current process cannot be classified absent")) return 1;
  ++passed;

  Reset({405});
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(!result.has_value() && error == ERROR_INVALID_DATA && fixture_closes == 1,
      "missing current process invalidates apparent absence")) return 1;
  ++passed;

  Reset({});
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(!result.has_value() && error == ERROR_NO_MORE_FILES && fixture_closes == 1,
      "empty snapshot never proves disappearance")) return 1;
  ++passed;

  for (DWORD status : {ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH}) {
    Reset(); fixture_create_error = status;
    result = ServiceProcessExitedBySnapshot(kServicePid, &error);
    if (!Check(!result.has_value() && error == status && fixture_closes == 0,
        "snapshot creation failure preserves error and never proves absence")) return 1;
    ++passed;
  }

  Reset(); fixture_first_error = ERROR_ACCESS_DENIED;
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(!result.has_value() && error == ERROR_ACCESS_DENIED && fixture_closes == 1,
      "first enumeration failure closes snapshot and fails closed")) return 1;
  ++passed;

  Reset(); fixture_next_error = ERROR_ACCESS_DENIED;
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(!result.has_value() && error == ERROR_ACCESS_DENIED && fixture_closes == 1,
      "partial self-visible enumeration failure cannot prove absence")) return 1;
  ++passed;

  Reset(); fixture_next_error = ERROR_SUCCESS;
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(!result.has_value(),
      "ambiguous enumeration end requires ERROR_NO_MORE_FILES")) return 1;
  ++passed;

  Reset();
  result = ServiceProcessExitedBySnapshot(0, &error);
  if (!Check(!result.has_value() && error == ERROR_INVALID_DATA,
      "zero initial PID is invalid proof")) return 1;
  ++passed;

  Reset({kServicePid});
  result = ServiceProcessExitedBySnapshot(kServicePid, &error);
  if (!Check(!result.has_value() && error == ERROR_INVALID_DATA,
      "initial PID visibility does not excuse a snapshot omitting the current process")) return 1;
  ++passed;

  Reset();
  result = ServiceProcessExitedBySnapshot(kServicePid, nullptr);
  if (!Check(result.has_value() && *result && !fixture_invalid_arguments,
      "optional error output does not weaken the absence proof")) return 1;
  ++passed;

  std::cout << passed << " maintenance process snapshot cases passed; synthetic APIs only.\n";
  return 0;
}
