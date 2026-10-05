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
