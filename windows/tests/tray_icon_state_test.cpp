// SPDX-License-Identifier: MPL-2.0
#include "../../third_party/tray_manager/windows/tray_icon_state.h"

#include <cstdlib>
#include <iostream>

namespace {
int calls = 0;
DWORD last_operation = 0;
bool succeeds = false;
bool add_only = false;
BOOL WINAPI Notify(DWORD operation, PNOTIFYICONDATAW data) {
  ++calls;
  last_operation = operation;
  if (data->cbSize != sizeof(*data) || data->hWnd == nullptr ||
      data->hIcon == nullptr || data->uID != 1) std::abort();
  return succeeds && (!add_only || operation == NIM_ADD);
}
void Require(bool condition) {
  if (!condition) std::abort();
}
}

int main() {
  NOTIFYICONDATAW data{};
  NOTIFYICONIDENTIFIER identity{};
  bool available = false;
  const HWND window = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(1));
  Require(data.hIcon == nullptr && data.szTip[0] == L'\0');
  Require(!fuzevpn_tray::ApplyIcon(data, identity, available, window, WM_APP, Notify));
  Require(calls == 0 && !available);
  data.hIcon = reinterpret_cast<HICON>(static_cast<ULONG_PTR>(2));
  Require(!fuzevpn_tray::ApplyIcon(data, identity, available, window, WM_APP, Notify));
  Require(calls == 1 && !available && identity.cbSize == 0);
  succeeds = true;
  Require(fuzevpn_tray::ApplyIcon(data, identity, available, window, WM_APP, Notify));
  Require(available && last_operation == NIM_ADD && identity.uID == 1);
  Require(fuzevpn_tray::ApplyIcon(data, identity, available, window, WM_APP, Notify));
  Require(last_operation == NIM_MODIFY);
  add_only = true;
  calls = 0;
  Require(fuzevpn_tray::ApplyIcon(data, identity, available, window, WM_APP, Notify));
  Require(calls == 2 && available && last_operation == NIM_ADD);
  succeeds = false;
  Require(!fuzevpn_tray::ApplyIcon(data, identity, available, window, WM_APP, Notify));
  Require(!available && identity.cbSize == 0);
  std::cout << "Tray icon state checks passed\n";
}
