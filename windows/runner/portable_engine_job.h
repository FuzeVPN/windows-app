// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_ENGINE_JOB_H_
#define RUNNER_PORTABLE_ENGINE_JOB_H_
#include <windows.h>

namespace fuzevpn_portable {
// Private, non-inherited job. The helper retains its only job handle through
// engine exit, so a hard helper crash also releases its assigned suspended or
// active engine.
// Persistent network protection is recovered separately; never kill a PID found
// by enumeration or a process not created suspended by this helper.
class EngineJob final {
 public:
  EngineJob() = default;
  ~EngineJob() { if (job_) CloseHandle(job_); }
  EngineJob(const EngineJob&) = delete;
  EngineJob& operator=(const EngineJob&) = delete;
  bool Create(DWORD* error) {
    if (job_) return Fail(ERROR_INVALID_STATE, error);
    job_ = CreateJobObjectW(nullptr, nullptr);
    if (!job_) return Fail(GetLastError(), error);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    return SetInformationJobObject(job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE ||
        Fail(GetLastError(), error);
  }
  bool AssignSuspended(HANDLE engine, DWORD* error) {
    if (job_ && AssignProcessToJobObject(job_, engine)) return true;
    const DWORD status = job_ ? GetLastError() : ERROR_INVALID_STATE;
    // Nested-job restrictions must fail before publication, journal registration
    // or ResumeThread. This is the exact owned, never-resumed process handle.
    TerminateProcess(engine, status);
    WaitForSingleObject(engine, INFINITE);
    return Fail(status, error);
  }
 private:
  static bool Fail(DWORD value, DWORD* error) { if (error) *error = value; return false; }
  HANDLE job_ = nullptr;
};
}  // namespace fuzevpn_portable
#endif  // RUNNER_PORTABLE_ENGINE_JOB_H_
