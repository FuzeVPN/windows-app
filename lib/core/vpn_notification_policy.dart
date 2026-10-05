// SPDX-License-Identifier: MPL-2.0
import 'models.dart';

enum VpnNotificationEvent { connected, unexpectedDisconnection, importantError }

/// Keeps Windows notifications intentionally rare and predictable.
VpnNotificationEvent? vpnNotificationEventFor({
  required VpnStatus previous,
  required VpnStatus current,
  required bool initialized,
  required bool enabled,
}) {
  if (!initialized || !enabled || previous == current) return null;
  if (current == VpnStatus.connected) {
    return VpnNotificationEvent.connected;
  }
  if (previous == VpnStatus.connected &&
      (current == VpnStatus.disconnected || current == VpnStatus.blocked)) {
    return VpnNotificationEvent.unexpectedDisconnection;
  }
  if (current == VpnStatus.error) {
    return VpnNotificationEvent.importantError;
  }
  return null;
}
