// SPDX-License-Identifier: MPL-2.0
#include "portable_runtime.h"
#include "installation_security.h"
#include "runtime_architecture.h"
#include "portable_service_lease.h"
#include <shellapi.h>
#include <array>
#include <limits>

namespace {
class Handle {
 public:
  explicit Handle(HANDLE handle = nullptr) : value(handle) {}
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  HANDLE value;
};
class InspectionPrivilege {
 public:
  InspectionPrivilege() {
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token_.value)) return;
    TOKEN_PRIVILEGES requested{};
    requested.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &requested.Privileges[0].Luid)) return;
    requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    DWORD bytes = 0;
    restore_ = AdjustTokenPrivileges(token_.value, FALSE, &requested, sizeof(previous_), &previous_, &bytes) != FALSE;
  }
  ~InspectionPrivilege() { if (restore_) AdjustTokenPrivileges(token_.value, FALSE, &previous_, 0, nullptr, nullptr); }
 private:
  Handle token_;
  TOKEN_PRIVILEGES previous_{};
  bool restore_ = false;
};
bool Elevated() {
  Handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return false;
  TOKEN_ELEVATION elevation{};
  DWORD bytes = 0;
  return GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &bytes) && elevation.TokenIsElevated;
}
bool ParsePid(const wchar_t* text, DWORD* pid) {
  if (!text || !*text || *text == L'0') return false;
  std::uint64_t number = 0;
  for (; *text; ++text) {
    if (*text < L'0' || *text > L'9') return false;
    number = number * 10 + static_cast<unsigned>(*text - L'0');
    if (number > (std::numeric_limits<DWORD>::max)()) return false;
  }
  *pid = static_cast<DWORD>(number);
  return true;
}
std::string Ascii(const wchar_t* text) {
  std::string result;
  for (; *text; ++text) {
    if (*text > 127 || result.size() >= 32) return {};
    result += static_cast<char>(*text);
  }
  return result;
}
bool ProcessImage(HANDLE process, std::filesystem::path* path) {
  std::wstring text(32768, L'\0');
  DWORD size = static_cast<DWORD>(text.size());
  if (!QueryFullProcessImageNameW(process, 0, text.data(), &size) || !size || size >= text.size()) return false;
  text.resize(size);
  *path = text;
  return true;
}
bool SendResult(HANDLE pipe, HANDLE parent, const fuzevpn_portable::BootstrapResult& result) {
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event.value) return false;
  OVERLAPPED operation{};
  operation.hEvent = event.value;
  DWORD bytes = 0;
  if (WriteFile(pipe, &result, sizeof(result), &bytes, &operation)) return bytes == sizeof(result);
  if (GetLastError() != ERROR_IO_PENDING) return false;
  HANDLE waits[]{event.value, parent};
  if (WaitForMultipleObjects(2, waits, FALSE, 10000) != WAIT_OBJECT_0) {
    CancelIoEx(pipe, &operation);
    // The stack buffer must remain alive until this cancelled I/O completes.
    GetOverlappedResult(pipe, &operation, &bytes, TRUE);
    return false;
  }
  return GetOverlappedResult(pipe, &operation, &bytes, FALSE) && bytes == sizeof(result);
}
bool ReadAck(HANDLE pipe, HANDLE parent) {
  Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event.value) return false;
  OVERLAPPED operation{};
  operation.hEvent = event.value;
  std::uint32_t ack = 0;
  DWORD bytes = 0;
  if (!ReadFile(pipe, &ack, sizeof(ack), &bytes, &operation)) {
    if (GetLastError() != ERROR_IO_PENDING) return false;
    HANDLE waits[]{event.value, parent};
    if (WaitForMultipleObjects(2, waits, FALSE, 120000) != WAIT_OBJECT_0) {
      CancelIoEx(pipe, &operation);
      GetOverlappedResult(pipe, &operation, &bytes, TRUE);
      return false;
    }
    if (!GetOverlappedResult(pipe, &operation, &bytes, FALSE)) return false;
  }
  return bytes == sizeof(ack) && ack == fuzevpn_portable::kBootstrapMagic &&
      WaitForSingleObject(parent, 0) == WAIT_TIMEOUT;
}
std::vector<wchar_t> EngineEnvironment() {
  std::wstring windows(32768, L'\0');
  const UINT length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  if (!length || length >= windows.size()) return {};
  windows.resize(length);
  // Do not inherit user-controlled OpenSSL/provider/DLL configuration into an
  // elevated engine. The parent's identity travels through authenticated IPC.
  const std::array<std::wstring, 6> values{
      L"PATH=" + windows + L"\\System32", L"SystemDrive=" + windows.substr(0, 2),
      L"SystemRoot=" + windows, L"TEMP=" + windows + L"\\Temp",
      L"TMP=" + windows + L"\\Temp", L"windir=" + windows};
  std::vector<wchar_t> result;
  for (const auto& value : values) { result.insert(result.end(), value.begin(), value.end()); result.push_back(L'\0'); }
  result.push_back(L'\0');
  return result;
}
void CloseRemoteHandle(HANDLE parent, HANDLE remote) {
  HANDLE local = nullptr;
  if (remote && DuplicateHandle(parent, remote, GetCurrentProcess(), &local, 0, FALSE,
      DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS) && local) CloseHandle(local);
}
void StopSuspendedEngine(HANDLE engine, DWORD error) {
  if (!engine) return;
  // Only called before successful ResumeThread: no VPN work has begun.
  TerminateProcess(engine, error);
  WaitForSingleObject(engine, INFINITE);
}
DWORD Prepare(DWORD parent_pid, const std::string& nonce) {
  using namespace fuzevpn_portable;
  using fuzevpn_update::PinnedFile;
  if (!Elevated()) return ERROR_ELEVATION_REQUIRED;
  if (parent_pid == GetCurrentProcessId()) return ERROR_INVALID_PARAMETER;
  Handle parent;
  {
    InspectionPrivilege privilege;
    parent.value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, parent_pid);
  }
  DWORD parent_session = 0, helper_session = 0;
  if (!parent.value || WaitForSingleObject(parent.value, 0) != WAIT_TIMEOUT ||
      !ProcessIdToSessionId(parent_pid, &parent_session) ||
      !ProcessIdToSessionId(GetCurrentProcessId(), &helper_session) || parent_session != helper_session)
    return ERROR_ACCESS_DENIED;
  std::filesystem::path gui_path;
  const auto self_path = fuzevpn_update::CurrentExecutable();
  if (!ProcessImage(parent.value, &gui_path) ||
      !fuzevpn_installation::SamePath(gui_path.filename().wstring(), L"fuzevpn_windows.exe") ||
      !fuzevpn_installation::SamePath(self_path.filename().wstring(), L"fuzevpn-runtime.exe") ||
      !fuzevpn_installation::SamePath(gui_path.parent_path().wstring(), self_path.parent_path().wstring()))
    return ERROR_ACCESS_DENIED;
  PinnedFile self, gui, source_service;
  Manifest manifest;
  DWORD error = ERROR_SUCCESS;
  if (!self.Open(self_path, true) || !gui.Open(gui_path, true) ||
      !ReadEmbeddedManifest(self_path, &manifest, &error) ||
      !ValidatePublisherPair(self, gui, manifest.version, &error) ||
      !source_service.Open(self_path.parent_path() / L"fuzevpn-service.exe", true) ||
      !ValidatePublisherPair(self, source_service, manifest.version, &error)) return error ? error : ERROR_ACCESS_DENIED;
  const auto name = BootstrapPipeName(parent_pid, nonce);
  // Identification-only prevents a malicious pipe server from impersonating
  // the elevated bootstrap token. The server must also be the held GUI process.
  Handle pipe(CreateFileW(name.c_str(), FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES, 0, nullptr,
      OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
  ULONG server_pid = 0;
  if (pipe.value == INVALID_HANDLE_VALUE || !GetNamedPipeServerProcessId(pipe.value, &server_pid) ||
      server_pid != parent_pid || WaitForSingleObject(parent.value, 0) != WAIT_TIMEOUT) return ERROR_ACCESS_DENIED;
  BootstrapResult result;
  fuzevpn_handoff::InstalledServiceLease installed_service;
  std::filesystem::path cached;
  HANDLE remote = nullptr;
  Handle engine;
  Handle engine_thread;
  if (!PrepareRuntime(self_path.parent_path(), manifest, &cached, &error)) {
    result.error = error;
  } else {
    PinnedFile service;
    if (!service.Open(cached / L"fuzevpn-service.exe") ||
        !ValidatePublisherPair(self, service, manifest.version, &error) ||
        !ValidateProtectedRuntime(cached, manifest, &error)) {
      result.error = error ? error : ERROR_ACCESS_DENIED;
    } else if (WaitForSingleObject(parent.value, 0) != WAIT_TIMEOUT) {
      result.error = ERROR_CANCELLED;
    } else if (!installed_service.Acquire(self, parent.value, &error)) {
      result.error = error ? error : ERROR_BUSY;
    } else {
      auto environment = EngineEnvironment();
      const auto executable = cached / L"fuzevpn-service.exe";
      std::wstring command = L"\"" + executable.wstring() + L"\" --fuzevpn-portable-broker " + std::to_wstring(parent_pid);
      STARTUPINFOW startup{}; startup.cb = sizeof(startup);
      PROCESS_INFORMATION process{};
      if (environment.empty() || !CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
          CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
          environment.data(), cached.c_str(), &startup, &process)) {
        result.error = environment.empty() ? ERROR_BAD_ENVIRONMENT : GetLastError();
      } else {
        engine_thread.value = process.hThread;
        engine.value = process.hProcess;
        if (!installed_service.TrackEngine(engine.value, &error)) {
          result.error = error;
        } else if (!DuplicateHandle(GetCurrentProcess(), engine.value, parent.value, &remote,
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0)) {
          result.error = GetLastError();
        } else {
          result.pid = process.dwProcessId;
          result.handle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(remote));
        }
      }
    }
  }
  if (!SendResult(pipe.value, parent.value, result)) {
    CloseRemoteHandle(parent.value, remote);
    StopSuspendedEngine(engine.value, ERROR_CANCELLED);
    return ERROR_BROKEN_PIPE;
  }
  if (result.error != ERROR_SUCCESS) {
    StopSuspendedEngine(engine.value, result.error);
    return result.error;
  }
  if (!ReadAck(pipe.value, parent.value)) {
    StopSuspendedEngine(engine.value, ERROR_CANCELLED);
    return ERROR_CANCELLED;
  }
  if (ResumeThread(engine_thread.value) == static_cast<DWORD>(-1)) {
    const DWORD resume_error = GetLastError();
    StopSuspendedEngine(engine.value, resume_error);
    return resume_error;
  }
  // Keep the authenticated helper alive as the lease owner. Engine shutdown
  // completes VPN cleanup and releases its runtime mutex before restoration.
  if (WaitForSingleObject(engine.value, INFINITE) != WAIT_OBJECT_0) return GetLastError();
  return installed_service.Restore(&error) ? result.error : error;
}
} // namespace

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, wchar_t*, int) {
  if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return ERROR_BAD_EXE_FORMAT;
  int count = 0;
  wchar_t** arguments = CommandLineToArgvW(GetCommandLineW(), &count);
  if (!arguments) return ERROR_INVALID_PARAMETER;
  DWORD result = ERROR_INVALID_PARAMETER;
  try {
    DWORD parent_pid = 0;
    if (count == 4 && wcscmp(arguments[1], L"--prepare-runtime") == 0 && ParsePid(arguments[2], &parent_pid)) {
      const auto nonce = Ascii(arguments[3]);
      if (fuzevpn_update::ValidToken(nonce)) {
        const HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        result = Prepare(parent_pid, nonce);
        if (SUCCEEDED(initialized)) CoUninitialize();
      }
    }
  } catch (...) { result = ERROR_INVALID_DATA; }
  LocalFree(arguments);
  return static_cast<int>(result);
}
