// SPDX-License-Identifier: MPL-2.0
#include "portable_service_lease.h"
#include "service_idle_handoff.h"
#include <shellapi.h>
#include <sddl.h>
#include <vector>

namespace fuzevpn_handoff {
namespace {
constexpr wchar_t kService[] = L"FuzeVPNService";
bool Fail(DWORD value, DWORD* error) { if (error) *error = value; return false; }
bool ReadConfiguration(SC_HANDLE service, std::wstring* command, DWORD* error) {
  DWORD bytes = 0;
  QueryServiceConfigW(service, nullptr, 0, &bytes);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(QUERY_SERVICE_CONFIGW) || bytes > 65536)
    return Fail(ERROR_BAD_CONFIGURATION, error);
  std::vector<BYTE> storage(bytes);
  auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
  if (!QueryServiceConfigW(service, config, bytes, &bytes)) return Fail(GetLastError(), error);
  if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || !config->lpBinaryPathName ||
      !config->lpServiceStartName || _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0)
    return Fail(ERROR_BAD_CONFIGURATION, error);
  *command = config->lpBinaryPathName;
  return true;
}
}

bool ValidateInstalledService(SC_HANDLE service, const fuzevpn_update::PinnedFile& helper,
    fuzevpn_update::PinnedFile* installed, fuzevpn_installation::ProtectedInstallation* tree,
    std::wstring* command, DWORD* error) {
  if (!ReadConfiguration(service, command, error)) return false;
  int count = 0;
  LPWSTR* arguments = CommandLineToArgvW(command->c_str(), &count);
  if (!arguments) return Fail(GetLastError(), error);
  std::filesystem::path executable;
  if (count == 2 && std::wstring(arguments[1]) == L"--fuzevpn-vpn-service") executable = arguments[0];
  LocalFree(arguments);
  if (executable.empty() || !fuzevpn_installation::IsCanonicalLocalAbsolutePath(executable) ||
      !fuzevpn_installation::SamePath(executable.filename().wstring(), L"fuzevpn-service.exe") ||
      *command != L"\"" + executable.wstring() + L"\" --fuzevpn-vpn-service" ||
      !tree->ValidateEngine(executable) || !installed->Open(executable))
    return Fail(ERROR_BAD_CONFIGURATION, error);
  fuzevpn_update::Version version;
  std::vector<BYTE> first, second;
  // The previous service silently ignored unrecognised SCM user controls.
  // Never request a lease from a build without this bounded idle protocol.
  if (!fuzevpn_update::ReadVersion(executable, &version, true) || version.parts < std::array<unsigned, 3>{1, 0, 3} ||
      !fuzevpn_update::MatchesBuildArchitecture(installed->get()) ||
      !fuzevpn_update::TrustedPublisher(helper, &first) ||
      !fuzevpn_update::TrustedPublisher(*installed, &second) ||
      !fuzevpn_update::SamePublisher(first, second)) return Fail(ERROR_NOT_SUPPORTED, error);
  return true;
}

InstalledServiceLease::~InstalledServiceLease() {
  DWORD ignored = ERROR_SUCCESS;
  Restore(&ignored);
  if (engine_) CloseHandle(engine_);
  if (old_process_) CloseHandle(old_process_);
  if (service_) CloseServiceHandle(service_);
  if (manager_) CloseServiceHandle(manager_);
}
bool InstalledServiceLease::Query(SERVICE_STATUS_PROCESS* state, DWORD* error) {
  DWORD bytes = 0;
  return QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
      reinterpret_cast<BYTE*>(state), sizeof(*state), &bytes) != FALSE || Fail(GetLastError(), error);
}
bool InstalledServiceLease::SameConfiguration(DWORD* error) {
  std::wstring current;
  return ReadConfiguration(service_, &current, error) &&
      (current == command_ || Fail(ERROR_BAD_CONFIGURATION, error));
}
bool InstalledServiceLease::Acquire(const fuzevpn_update::PinnedFile& helper, HANDLE parent, DWORD* error) {
  if (!reservation_.Acquire()) return Fail(GetLastError(), error);
  manager_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager_) return Fail(GetLastError(), error);
  service_ = OpenServiceW(manager_, kService,
      SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_USER_DEFINED_CONTROL | SERVICE_START);
  if (!service_) {
    const DWORD status = GetLastError();
    return status == ERROR_SERVICE_DOES_NOT_EXIST || Fail(status, error);
  }
  SERVICE_STATUS_PROCESS state{};
  if (!Query(&state, error)) return false;
  if (state.dwCurrentState == SERVICE_STOPPED && state.dwProcessId == 0) return true;
  if (state.dwCurrentState != SERVICE_RUNNING || state.dwProcessId == 0) return Fail(ERROR_BUSY, error);
  if (!validate_(service_, helper, &installed_, &tree_, &command_, error)) return false;
  old_process_ = OpenProcess(SYNCHRONIZE, FALSE, state.dwProcessId);
  if (!old_process_) return Fail(GetLastError(), error);
  SERVICE_STATUS ignored{};
  if (!ControlService(service_, kYieldIdleControl, &ignored)) return Fail(GetLastError(), error);
  requested_ = true;
  // SCM can delay delivery; the worker starts its shorter queue TTL inside
  // the control handler, so the helper deadline starts after delivery.
  deadline_ = GetTickCount64() + kHelperWaitMs;
  do {
    if (parent && WaitForSingleObject(parent, 0) != WAIT_TIMEOUT) return Fail(ERROR_CANCELLED, error);
    if (!Query(&state, error)) return false;
    if (state.dwCurrentState == SERVICE_STOPPED && state.dwProcessId == 0 &&
        WaitForSingleObject(old_process_, 0) == WAIT_OBJECT_0)
      return state.dwWin32ExitCode == ERROR_SUCCESS && state.dwServiceSpecificExitCode == 0 ||
          Fail(ERROR_SERVICE_SPECIFIC_ERROR, error);
    Sleep(50);
  } while (GetTickCount64() < deadline_);
  return Fail(ERROR_BUSY, error);
}
bool InstalledServiceLease::TrackEngine(HANDLE engine, DWORD* error) {
  if (!requested_) return true;
  return DuplicateHandle(GetCurrentProcess(), engine, GetCurrentProcess(), &engine_,
      SYNCHRONIZE, FALSE, 0) != FALSE || Fail(GetLastError(), error);
}
bool InstalledServiceLease::Restore(DWORD* error) {
  if (!requested_) return true;
  // A failed ACK/Resume path terminates only a never-resumed process. Its
  // actual exit (not TerminateProcess's acknowledgement) precedes restoration.
  if (engine_ && WaitForSingleObject(engine_, INFINITE) != WAIT_OBJECT_0) return Fail(GetLastError(), error);
  SERVICE_STATUS_PROCESS state{};
  bool accepted = false;
  // Wait past the service request's TTL even on a cancelled bootstrap. An
  // early RUNNING snapshot is not proof that a queued yield was rejected.
  do {
    if (!Query(&state, error)) {
      if (!accepted && GetTickCount64() >= deadline_) return false;
      Sleep(50);
      continue;
    }
    accepted = accepted || state.dwCurrentState == SERVICE_STOP_PENDING ||
        state.dwCurrentState == SERVICE_STOPPED;
    if (state.dwCurrentState == SERVICE_STOPPED && state.dwProcessId == 0 &&
        WaitForSingleObject(old_process_, 0) == WAIT_OBJECT_0) break;
    if (!accepted && GetTickCount64() >= deadline_) {
      if (state.dwCurrentState == SERVICE_RUNNING) { requested_ = false; return true; }
      return Fail(ERROR_BUSY, error);
    }
    Sleep(50);
  } while (true);
  if (!SameConfiguration(error)) return false;
  // Another runtime (including an orphan left by a killed helper) must never
  // be interrupted. If it owns the mutex, retain the stopped service safely.
  {
    fuzevpn_ipc::ExclusiveRuntimeLock idle;
    if (!idle.AcquireMachineRuntime()) return Fail(ERROR_BUSY, error);
  }
  if (!StartServiceW(service_, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    return Fail(GetLastError(), error);
  requested_ = false;
  if (error) *error = ERROR_SUCCESS;
  return true;
}
}  // namespace fuzevpn_handoff
