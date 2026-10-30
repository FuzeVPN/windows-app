// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SINGLE_INSTANCE_H_
#define RUNNER_SINGLE_INSTANCE_H_

#include <windows.h>

inline constexpr wchar_t kFuzeVpnSingleInstanceMutexName[] =
    L"Local\\FuzeVPN.Windows.SingleInstance";
inline constexpr wchar_t kFuzeVpnSingleInstanceMessageName[] =
    L"FuzeVPN.Windows.SingleInstance.Activate";

inline UINT FuzeVpnSingleInstanceMessage() noexcept {
  static const UINT message =
      RegisterWindowMessageW(kFuzeVpnSingleInstanceMessageName);
  return message;
}

enum class FuzeVpnSingleInstanceDecision { primary, activated, unavailable };

// An existing kernel object is only a signal to look for a genuine UI. It
// cannot establish that activation succeeded, or authorize a second primary.
template <typename Activate, typename ReportUnavailable>
FuzeVpnSingleInstanceDecision FuzeVpnDecideSingleInstanceStartup(
    HANDLE mutex, DWORD creation_error, Activate activate,
    ReportUnavailable report_unavailable) {
  if (mutex != nullptr) {
    if (creation_error != ERROR_ALREADY_EXISTS)
      return FuzeVpnSingleInstanceDecision::primary;
    if (activate()) return FuzeVpnSingleInstanceDecision::activated;
  }
  report_unavailable();
  return FuzeVpnSingleInstanceDecision::unavailable;
}

template <typename FindWindow, typename PostActivation, typename Wait>
bool FuzeVpnTryActivateExistingWindow(FindWindow find_window,
                                      PostActivation post_activation,
                                      Wait wait, unsigned attempts = 100) {
  for (unsigned attempt = 0; attempt < attempts; ++attempt) {
    const HWND window = find_window();
    if (window != nullptr && post_activation(window)) return true;
    if (attempt + 1 < attempts) wait();
  }
  return false;
}

inline void ActivateFuzeVpnWindow(HWND window) noexcept {
  if (window == nullptr || !IsWindow(window)) {
    return;
  }

  ShowWindow(window, IsIconic(window) ? SW_RESTORE : SW_SHOW);
  SetForegroundWindow(window);

  // Windows may temporarily refuse foreground activation because the request
  // comes from another process. Flashing the taskbar still gives the user a
  // visible indication that the already-running instance is being reused.
  if (GetForegroundWindow() != window) {
    FLASHWINFO flash = {};
    flash.cbSize = sizeof(flash);
    flash.hwnd = window;
    flash.dwFlags = FLASHW_ALL;
    flash.uCount = 3;
    flash.dwTimeout = 0;
    FlashWindowEx(&flash);
  }
}

#endif  // RUNNER_SINGLE_INSTANCE_H_
