import 'package:menu_base/menu_base.dart';

abstract mixin class TrayListener {
  /// Windows could not create or restore the notification-area icon.
  void onTrayIconUnavailable() {}
  /// Windows restored the icon after an Explorer restart or resume.
  void onTrayIconAvailable() {}

  /// Emitted when the mouse clicks the tray icon.
  void onTrayIconMouseDown() {}

  /// Emitted when the mouse is released from clicking the tray icon.
  void onTrayIconMouseUp() {}

  void onTrayIconRightMouseDown() {}

  void onTrayIconRightMouseUp() {}

  void onTrayMenuItemClick(MenuItem menuItem) {}
}
