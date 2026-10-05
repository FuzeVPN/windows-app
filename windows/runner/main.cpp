#include <cwchar>
#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <string>
#include <vector>
#include <windows.h>

#include "flutter_window.h"
#include "openvpn_tunnel.h"
#include "privileged_broker.h"
#include "single_instance.h"
#include "single_instance_identity.h"
#include "utils.h"
#include "wireguard_tunnel.h"

namespace {

std::wstring CurrentExecutablePath() {
  std::wstring path(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                          static_cast<DWORD>(path.size()));
  if (length == 0 || length >= path.size()) {
    return {};
  }
  path.resize(length);
  return path;
}

bool BelongsToFuzeVpnUi(HWND window,
                       const FuzeVpnActivationIdentity& identity) {
  DWORD process_id = 0;
  GetWindowThreadProcessId(window, &process_id);
  if (process_id == 0) {
    return false;
  }

  HANDLE process =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
  if (process == nullptr) {
    return false;
  }

  std::wstring target_path(32768, L'\0');
  DWORD target_length = static_cast<DWORD>(target_path.size());
  const BOOL queried = QueryFullProcessImageNameW(
      process, 0, target_path.data(), &target_length);
  CloseHandle(process);
  if (!queried) {
    return false;
  }

  target_path.resize(target_length);
  return identity.Matches(target_path);
}

HWND FindExistingFuzeVpnWindow(const FuzeVpnActivationIdentity& identity) {
  HWND previous = nullptr;
  while (true) {
    HWND candidate = FindWindowExW(nullptr, previous,
                                   L"FLUTTER_RUNNER_WIN32_WINDOW", L"FuzeVPN");
    if (candidate == nullptr) {
      return nullptr;
    }
    previous = candidate;
    if (BelongsToFuzeVpnUi(candidate, identity)) {
      return candidate;
    }
  }
}

void ActivateExistingInstance() {
  const FuzeVpnActivationIdentity identity(CurrentExecutablePath());
  // The first instance can hold the mutex before Flutter has created its
  // window. Retry briefly so a double-click during startup remains silent.
  for (int attempt = 0; attempt < 40; ++attempt) {
    const HWND window = FindExistingFuzeVpnWindow(identity);
    const UINT message = FuzeVpnSingleInstanceMessage();
    if (window != nullptr && message != 0 &&
        PostMessageW(window, message, 0, 0)) {
      return;
    }
    Sleep(50);
  }
}

}  // namespace

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  HANDLE instance_mutex =
      CreateMutexW(nullptr, TRUE, kFuzeVpnSingleInstanceMutexName);
  if (instance_mutex == nullptr) {
    return EXIT_FAILURE;
  }
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    ActivateExistingInstance();
    CloseHandle(instance_mutex);
    return EXIT_SUCCESS;
  }

  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1080, 680);
  if (!window.Create(L"FuzeVPN", origin, size)) {
    CloseHandle(instance_mutex);
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  if (!IsPersistentVpnServiceRunning()) {
    // Unsigned development builds still use the per-UI elevated broker and
    // must clean it up with the UI. A signed production service owns the
    // tunnel and kill switch independently; only an explicit Disconnect
    // command may remove those protections.
    // The authenticated, exclusive broker owns cleanup. A UI with no broker
    // must never start a new elevated runtime merely to stop another session.
    ShutdownPrivilegedBroker();
  }
  ::CoUninitialize();
  CloseHandle(instance_mutex);
  return EXIT_SUCCESS;
}
