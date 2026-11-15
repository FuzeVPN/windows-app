// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WINDOW_CLOSE_POLICY_H_
#define RUNNER_WINDOW_CLOSE_POLICY_H_

namespace fuzevpn_window {

// The close button (X, Alt+F4) never ends the process and never touches the
// VPN or a running operation. With a tray icon the window hides and the tray
// keeps "Show" and "Quit". Without one a hidden window could not be reopened
// and no Quit entry would remain, so the window stays and Dart is asked to
// open its Quit dialog.
enum class CloseAction { hide_to_tray, keep_window_and_ask_to_quit };

constexpr CloseAction DecideClose(bool tray_available) {
  return tray_available ? CloseAction::hide_to_tray
                        : CloseAction::keep_window_and_ask_to_quit;
}

}  // namespace fuzevpn_window

#endif  // RUNNER_WINDOW_CLOSE_POLICY_H_
