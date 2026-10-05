// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/vpn_notification_policy.dart';

void main() {
  test('notifie uniquement une connexion confirmée', () {
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.connecting,
        current: VpnStatus.connected,
        initialized: true,
        enabled: true,
      ),
      VpnNotificationEvent.connected,
    );
  });

  test('une déconnexion volontaire ne produit aucune notification', () {
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.connected,
        current: VpnStatus.disconnecting,
        initialized: true,
        enabled: true,
      ),
      isNull,
    );
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.disconnecting,
        current: VpnStatus.disconnected,
        initialized: true,
        enabled: true,
      ),
      isNull,
    );
  });

  test('notifie une interruption directe et une erreur importante', () {
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.connected,
        current: VpnStatus.blocked,
        initialized: true,
        enabled: true,
      ),
      VpnNotificationEvent.unexpectedDisconnection,
    );
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.connected,
        current: VpnStatus.disconnected,
        initialized: true,
        enabled: true,
      ),
      VpnNotificationEvent.unexpectedDisconnection,
    );
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.connecting,
        current: VpnStatus.error,
        initialized: true,
        enabled: true,
      ),
      VpnNotificationEvent.importantError,
    );
  });

  test('respecte le démarrage et la préférence utilisateur', () {
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.disconnected,
        current: VpnStatus.connected,
        initialized: false,
        enabled: true,
      ),
      isNull,
    );
    expect(
      vpnNotificationEventFor(
        previous: VpnStatus.disconnected,
        current: VpnStatus.connected,
        initialized: true,
        enabled: false,
      ),
      isNull,
    );
  });
}
