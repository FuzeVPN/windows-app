// SPDX-License-Identifier: MPL-2.0
// Explicitly invoked integration probe. The custom Dart entrypoint is limited
// to passive channels; this native entrypoint never starts/stops a VPN runtime.
#include <windows.h>
#include <shellapi.h>
#include <flutter/dart_project.h>
#include <memory>
#include <string>
#include <vector>
#include "flutter_window.h"
#include "utils.h"

// Only this unrelated persistence channel is inert in the probe: production
// FileStore uses SHGetKnownFolderPath and would purge the real account's queue
// even if LOCALAPPDATA were redirected. VPN/snapshot/update channels are real.
struct DiagnosticsStoreChannel::Impl {};
DiagnosticsStoreChannel::DiagnosticsStoreChannel(flutter::FlutterEngine*, HWND)
    : impl_(std::make_unique<Impl>()) {}
DiagnosticsStoreChannel::~DiagnosticsStoreChannel() = default;
void DiagnosticsStoreChannel::PurgeExpired() {}
void DiagnosticsStoreChannel::ProcessCompletions() {}

namespace {
class HiddenProbeWindow final : public FlutterWindow {
 public:
  explicit HiddenProbeWindow(const flutter::DartProject& project) : FlutterWindow(project) {}
 protected:
  LRESULT MessageHandler(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept override {
    if (message == WM_CLOSE) {
      // The passive Dart entrypoint closes after writing its JSON report. It
      // has no application exit listener or VPN cleanup workflow to complete.
      PostQuitMessage(EXIT_SUCCESS);
      return 0;
    }
    // Keep production registration and its first-frame callback intact while
    // preventing the callback's Show() from displaying the probe window.
    if (message == WM_WINDOWPOSCHANGING && lparam)
      reinterpret_cast<WINDOWPOS*>(lparam)->flags &= ~SWP_SHOWWINDOW;
    return FlutterWindow::MessageHandler(window, message, wparam, lparam);
  }
};
void CALLBACK Deadline(HWND, UINT, UINT_PTR, DWORD) { PostQuitMessage(ERROR_TIMEOUT); }
}

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, wchar_t*, int) {
  int count = 0;
  auto** values = CommandLineToArgvW(GetCommandLineW(), &count);
  if (!values || count < 3) { if (values) LocalFree(values); return ERROR_INVALID_PARAMETER; }
  const std::wstring data = values[1];
  std::vector<std::string> dart_arguments;
  for (int index = 2; index < count; ++index) dart_arguments.push_back(Utf8FromUtf16(values[index]));
  LocalFree(values);
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  int result = EXIT_FAILURE;
  {
    flutter::DartProject project(data);
    project.set_dart_entrypoint_arguments(std::move(dart_arguments));
    HiddenProbeWindow window(project);
    if (window.Create(L"FuzeVPN passive startup bridge test", {10, 10}, {640, 360})) {
      window.SetQuitOnClose(true);
      const auto timer = SetTimer(nullptr, 0, 30000, Deadline);
      MSG message{};
      while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
      }
      if (timer) KillTimer(nullptr, timer);
      result = static_cast<int>(message.wParam);
      window.Destroy();
    }
  }
  // Intentionally no application single-instance mutex, RunBroker,
  // ShutdownPrivilegedBroker, StopWireGuardTunnel, or tunnel cleanup call.
  CoUninitialize();
  return result;
}
