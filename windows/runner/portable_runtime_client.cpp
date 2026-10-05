// SPDX-License-Identifier: MPL-2.0
#include "portable_runtime_client.h"
#include "portable_runtime.h"
#include "installation_security.h"
#include <sddl.h>
#include <shellapi.h>
#include <vector>

namespace {
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool WaitIo(HANDLE pipe, OVERLAPPED* io, HANDLE helper, HANDLE cancelled,
            DWORD* transferred) {
  HANDLE waits[] = {io->hEvent, helper, cancelled};
  const DWORD count = cancelled ? 3 : 2;
  const DWORD state = WaitForMultipleObjects(count, waits, FALSE, 120000);
  if (state == WAIT_OBJECT_0 && GetOverlappedResult(pipe, io, transferred, FALSE))
    return true;
  // Completion can race the helper's exit. Consume a completed operation first.
  if (GetOverlappedResult(pipe, io, transferred, FALSE)) return true;
  CancelIoEx(pipe, io);
  GetOverlappedResult(pipe, io, transferred, TRUE);
  SetLastError(state == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_CANCELLED);
  return false;
}
bool Transfer(HANDLE pipe, void* bytes, DWORD size, bool write,
              HANDLE helper, HANDLE cancelled) {
  Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
  if (!event.value) return false;
  auto* cursor = static_cast<BYTE*>(bytes);
  while (size) {
    if (cancelled && WaitForSingleObject(cancelled, 0) == WAIT_OBJECT_0) {
      SetLastError(ERROR_CANCELLED);
      return false;
    }
    ResetEvent(event.value);
    OVERLAPPED io{};
    io.hEvent = event.value;
    DWORD transferred = 0;
    const BOOL immediate = write
        ? WriteFile(pipe, cursor, size, &transferred, &io)
        : ReadFile(pipe, cursor, size, &transferred, &io);
    if (!immediate && (GetLastError() != ERROR_IO_PENDING ||
        !WaitIo(pipe, &io, helper, cancelled, &transferred))) return false;
    if (transferred == 0 || transferred > size) return false;
    size -= transferred;
    cursor += transferred;
  }
  return true;
}
bool PipeDescriptor(PSECURITY_DESCRIPTOR* descriptor) {
  Handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return false;
  DWORD size = 0;
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
  if (!size) return false;
  std::vector<BYTE> bytes(size);
  if (!GetTokenInformation(token.value, TokenUser, bytes.data(), size, &size)) return false;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, &sid))
    return false;
  const std::wstring text = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" +
      std::wstring(sid) + L")";
  LocalFree(sid);
  return ConvertStringSecurityDescriptorToSecurityDescriptorW(
      text.c_str(), SDDL_REVISION_1, descriptor, nullptr) != FALSE;
}
bool ExpectedProcess(HANDLE process, DWORD pid, const std::filesystem::path& path) {
  if (!process || process == INVALID_HANDLE_VALUE || !pid || GetProcessId(process) != pid ||
      WaitForSingleObject(process, 0) != WAIT_TIMEOUT) return false;
  std::wstring actual(32768, L'\0');
  DWORD count = static_cast<DWORD>(actual.size());
  if (!QueryFullProcessImageNameW(process, 0, actual.data(), &count)) return false;
  actual.resize(count);
  // Still suspended: its token has not yet granted UI query access. Elevation
  // is checked again when authenticating the running broker's own pipe.
  return fuzevpn_installation::SamePath(actual, path.wstring());
}
}

HANDLE LaunchPortableRuntime(HANDLE cancelled, std::filesystem::path* engine_path) {
  using namespace fuzevpn_portable;
  if (!engine_path) return nullptr;
  engine_path->clear();
  // Static-import System32 enforcement (/DEPENDENTLOADFLAG) starts with RS1.
  // Refuse before elevating a helper on an OS that would ignore that boundary.
  using GetVersion = LONG(WINAPI*)(OSVERSIONINFOEXW*);
  const auto get_version = reinterpret_cast<GetVersion>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
  OSVERSIONINFOEXW version{};
  version.dwOSVersionInfoSize = sizeof(version);
  if (!get_version || get_version(&version) != 0 || version.dwMajorVersion < 10 ||
      (version.dwMajorVersion == 10 && version.dwBuildNumber < 14393)) {
    SetLastError(ERROR_OLD_WIN_VERSION);
    return nullptr;
  }
  if (cancelled && WaitForSingleObject(cancelled, 0) == WAIT_OBJECT_0) return nullptr;
  const auto ui_path = fuzevpn_update::CurrentExecutable();
  const auto helper_path = ui_path.parent_path() / L"fuzevpn-runtime.exe";
  fuzevpn_update::PinnedFile ui, helper;
  Manifest manifest;
  if (!ui.Open(ui_path, true) || !helper.Open(helper_path, true) ||
      !ReadEmbeddedManifest(helper_path, &manifest) ||
      !ValidatePublisherPair(ui, helper, manifest.version)) return nullptr;
  const auto expected = RuntimeCachePath(manifest) / L"fuzevpn-service.exe";
  if (expected.parent_path().empty()) return nullptr;
  const auto nonce = fuzevpn_update::NewToken();
  if (!fuzevpn_update::ValidToken(nonce)) return nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!PipeDescriptor(&descriptor)) return nullptr;
  SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
  Handle pipe{CreateNamedPipeW(BootstrapPipeName(GetCurrentProcessId(), nonce).c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1, 1024, 1024, 0, &security)};
  LocalFree(descriptor);
  if (pipe.value == INVALID_HANDLE_VALUE) return nullptr;
  Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
  if (!event.value) return nullptr;
  OVERLAPPED connect{};
  connect.hEvent = event.value;
  const BOOL connected = ConnectNamedPipe(pipe.value, &connect);
  const DWORD connect_error = connected ? ERROR_SUCCESS : GetLastError();
  if (!connected && connect_error != ERROR_IO_PENDING && connect_error != ERROR_PIPE_CONNECTED)
    return nullptr;
  const std::wstring parameters = L"--prepare-runtime " +
      std::to_wstring(GetCurrentProcessId()) + L" " + fuzevpn_update::Wide(nonce);
  SHELLEXECUTEINFOW launch{};
  launch.cbSize = sizeof(launch);
  launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  launch.lpVerb = L"runas";
  launch.lpFile = helper_path.c_str();
  launch.lpParameters = parameters.c_str();
  launch.nShow = SW_HIDE;
  if (!ShellExecuteExW(&launch) || !launch.hProcess) {
    DWORD ignored = 0;
    CancelIoEx(pipe.value, &connect);
    GetOverlappedResult(pipe.value, &connect, &ignored, TRUE);
    return nullptr;
  }
  Handle launched{launch.hProcess};
  DWORD ignored = 0;
  if (connect_error == ERROR_IO_PENDING &&
      !WaitIo(pipe.value, &connect, launched.value, cancelled, &ignored)) return nullptr;
  ULONG helper_pid = 0;
  if (!GetNamedPipeClientProcessId(pipe.value, &helper_pid) ||
      helper_pid != GetProcessId(launched.value)) return nullptr;
  BootstrapResult response;
  // Drain the authenticated response even on cancellation so an already
  // transferred engine handle is closed. Cancellation still prevents the ACK.
  if (!Transfer(pipe.value, &response, sizeof(response), false, launched.value, nullptr))
    return nullptr;
  // Only the authenticated helper may send an already duplicated handle.
  Handle engine{reinterpret_cast<HANDLE>(static_cast<uintptr_t>(response.handle))};
  if (response.magic != kBootstrapMagic || response.version != kIpcVersion ||
      response.error != ERROR_SUCCESS ||
      !ExpectedProcess(engine.value, response.pid, expected) ||
      !ValidateProtectedRuntime(expected.parent_path(), manifest)) {
    SetLastError(response.error ? response.error : ERROR_ACCESS_DENIED);
    return nullptr;
  }
  std::uint32_t ack = kBootstrapMagic;
  if (!Transfer(pipe.value, &ack, sizeof(ack), true, launched.value, cancelled)) return nullptr;
  *engine_path = expected;
  const auto retained = engine.value;
  engine.value = nullptr;
  return retained;
}
