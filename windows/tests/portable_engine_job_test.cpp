// SPDX-License-Identifier: MPL-2.0
// No real job, process, wait, launch or termination is performed.
#include <windows.h>
#include <iostream>
#include <string>
namespace {
bool create_ok = true, configure_ok = true, assign_ok = true, invalid = false;
std::string order;
HANDLE Job() { return reinterpret_cast<HANDLE>(11); }
HANDLE Engine() { return reinterpret_cast<HANDLE>(12); }
HANDLE WINAPI FixtureCreate(LPSECURITY_ATTRIBUTES security, LPCWSTR name) {
  order += 'C'; invalid |= security != nullptr || name != nullptr;
  if (!create_ok) { SetLastError(ERROR_ACCESS_DENIED); return nullptr; }
  return Job();
}
BOOL WINAPI FixtureConfigure(HANDLE job, JOBOBJECTINFOCLASS type, LPVOID value, DWORD size) {
  order += 'L';
  const auto* limits = static_cast<JOBOBJECT_EXTENDED_LIMIT_INFORMATION*>(value);
  invalid |= job != Job() || type != JobObjectExtendedLimitInformation || size != sizeof(*limits) ||
      limits->BasicLimitInformation.LimitFlags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!configure_ok) SetLastError(ERROR_ACCESS_DENIED);
  return configure_ok;
}
BOOL WINAPI FixtureAssign(HANDLE job, HANDLE process) {
  order += 'A'; invalid |= job != Job() || process != Engine();
  if (!assign_ok) SetLastError(ERROR_ACCESS_DENIED);
  return assign_ok;
}
BOOL WINAPI FixtureTerminate(HANDLE process, UINT reason) {
  order += 'T'; invalid |= process != Engine() || reason != ERROR_ACCESS_DENIED; return TRUE;
}
DWORD WINAPI FixtureWait(HANDLE process, DWORD timeout) {
  order += 'W'; invalid |= process != Engine() || timeout != INFINITE; return WAIT_OBJECT_0;
}
BOOL WINAPI FixtureClose(HANDLE job) { order += 'X'; invalid |= job != Job(); return TRUE; }
void Reset() { create_ok = configure_ok = assign_ok = true; invalid = false; order.clear(); }
}
#define CreateJobObjectW FixtureCreate
#define SetInformationJobObject FixtureConfigure
#define AssignProcessToJobObject FixtureAssign
#define TerminateProcess FixtureTerminate
#define WaitForSingleObject FixtureWait
#define CloseHandle FixtureClose
#include "../runner/portable_engine_job.h"
#undef CreateJobObjectW
#undef SetInformationJobObject
#undef AssignProcessToJobObject
#undef TerminateProcess
#undef WaitForSingleObject
#undef CloseHandle

int main() {
  using fuzevpn_portable::EngineJob;
  DWORD error = ERROR_SUCCESS;
  Reset();
  { EngineJob job;
    if (!job.Create(&error) || !job.AssignSuspended(Engine(), &error) || invalid || order != "CLA") return 1;
    // The job handle remains owned through engine lifetime; only destruction
    // closes it. KILL_ON_JOB_CLOSE covers a helper crash before ResumeThread.
  }
  if (invalid || order != "CLAX") return 1;
  Reset(); assign_ok = false;
  { EngineJob job;
    if (!job.Create(&error) || job.AssignSuspended(Engine(), &error) || error != ERROR_ACCESS_DENIED ||
        order != "CLATW") return 1;
  }
  if (invalid || order != "CLATWX") return 1;
  Reset(); create_ok = false;
  { EngineJob job; if (job.Create(&error) || error != ERROR_ACCESS_DENIED) return 1; }
  if (invalid || order != "C") return 1;
  Reset(); configure_ok = false;
  { EngineJob job; if (job.Create(&error) || error != ERROR_ACCESS_DENIED) return 1; }
  if (invalid || order != "CLX") return 1;
  std::cout << "4 portable engine job cases passed; synthetic job/process APIs only.\n";
  return 0;
}
