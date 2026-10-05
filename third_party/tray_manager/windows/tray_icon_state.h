#pragma once

#include <windows.h>
#include <shellapi.h>

namespace fuzevpn_tray {

using NotifyIcon = decltype(&Shell_NotifyIconW);

// The caller supplies zero-initialized structures and retains icon ownership.
// A failed Shell call must never turn into an available notification icon.
inline bool ApplyIcon(NOTIFYICONDATAW& data,
                      NOTIFYICONIDENTIFIER& identity,
                      bool& available,
                      HWND window,
                      UINT callback,
                      NotifyIcon notify = &Shell_NotifyIconW) {
  if (data.hIcon == nullptr || window == nullptr) {
    available = false;
    return false;
  }
  data.cbSize = sizeof(data);
  data.hWnd = window;
  data.uID = 1;
  data.uCallbackMessage = callback;
  data.uFlags = NIF_MESSAGE | NIF_ICON;
  if (data.szTip[0] != L'\0') data.uFlags |= NIF_TIP;
  bool applied = notify(available ? NIM_MODIFY : NIM_ADD, &data) != FALSE;
  if (!applied && available) applied = notify(NIM_ADD, &data) != FALSE;
  available = applied;
  identity = {};
  if (applied) {
    identity.cbSize = sizeof(identity);
    identity.hWnd = data.hWnd;
    identity.uID = data.uID;
  }
  return applied;
}

}  // namespace fuzevpn_tray
