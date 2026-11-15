// SPDX-License-Identifier: MPL-2.0
// The connection page always offers the stop of what is running or
// blocking: Cancel before anything is armed, Disconnect afterwards.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

const _unknownMessage =
    'FuzeVPN ne peut pas vérifier l’état du VPN. Réessayez la vérification.';
const _progressNotice =
    'La préparation continue. Internet reste bloqué jusqu’à la connexion ou à l’arrêt des protections.';

/// Only what the page reads, set directly by each test, and a count of the
/// commands its buttons send.
class _HeroController extends ConnectionUxController {
  bool busy = false;
  bool cancellable = false;
  bool stopping = false;
  bool unknown = false;
  bool retained = false;
  bool commandRunning = false;
  bool otherSession = false;
  int stopRequests = 0;
  int connectRequests = 0;
  int retryRequests = 0;

  @override
  bool get isConnectionBusy => busy || stopping;
  @override
  bool get canCancelConnection => cancellable && !stopping && !otherSession;
  @override
  bool get isStoppingVpn => stopping;
  @override
  bool get isConnectionCommandRunning => commandRunning;
  @override
  bool get runtimeVerificationPending => unknown;
  @override
  bool get runtimeOwnedByAnotherUser => otherSession;
  @override
  bool get requiresExplicitDisconnect =>
      retained ||
      vpnStatus == VpnStatus.connected ||
      vpnStatus == VpnStatus.blocked;
  @override
  bool get canDisconnectVpn =>
      canCancelConnection ||
      (!isConnectionBusy &&
          !otherSession &&
          (requiresExplicitDisconnect || unknown));

  @override
  Future<void> disconnectVpn() async {
    stopRequests++;
  }

  @override
  Future<void> quickConnect() async {
    connectRequests++;
  }

  @override
  Future<void> retryRuntimeVerification({bool automatic = false}) async {
    retryRequests++;
  }

  /// A connection, reconnection or renewal in progress.
  void runOperation(VpnStatus status, {required bool protectionArmed}) {
    busy = true;
    cancellable = true;
    commandRunning = true;
    retained = protectionArmed;
    vpnStatus = status;
  }

  void showUnknownState({required bool withNotice}) {
    unknown = true;
    vpnStatus = VpnStatus.error;
    errorMessage = withNotice ? _unknownMessage : null;
  }
}

final _primary = find.byKey(const ValueKey('connection-primary-action'));
final _forced = find.byKey(const ValueKey('connection-force-disconnect'));

Future<void> _pump(WidgetTester tester, _HeroController app) async {
  await tester.pumpWidget(FuzeVpnApp(controller: app));
  await tester.pumpAndSettle();
}

Future<void> _dispose(WidgetTester tester, _HeroController app) async {
  expect(tester.takeException(), isNull);
  await tester.pumpWidget(const SizedBox.shrink());
  app.dispose();
}

String _primaryLabel(WidgetTester tester) => tester
    .widget<Text>(find.descendant(of: _primary, matching: find.byType(Text)))
    .data!;

IconData? _primaryIcon(WidgetTester tester) => tester
    .widget<Icon>(find.descendant(of: _primary, matching: find.byType(Icon)))
    .icon;

bool _primaryEnabled(WidgetTester tester) =>
    tester.widget<FilledButton>(_primary).onPressed != null;

void main() {
  void window(WidgetTester tester, Size size) {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = size;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
  }

  for (final status in [VpnStatus.preparing, VpnStatus.connecting]) {
    testWidgets('an operation running under the kill switch offers an '
        'enabled Disconnect (${status.name})', (tester) async {
      window(tester, const Size(1080, 640));
      final app = _HeroController()
        ..runOperation(status, protectionArmed: true);
      await _pump(tester, app);

      expect(
        find.text(
          status == VpnStatus.preparing
              ? 'Préparation de la connexion'
              : 'Connexion en cours',
        ),
        findsOneWidget,
      );
      expect(_primaryLabel(tester), 'Déconnecter');
      expect(_primaryIcon(tester), Icons.lock_open_outlined);
      expect(_primaryEnabled(tester), isTrue);
      expect(_forced, findsNothing);

      await tester.tap(_primary);
      await tester.pump();
      expect(app.stopRequests, 1);
      expect(app.connectRequests, 0);
      await _dispose(tester, app);
    });
  }

  testWidgets('before anything is armed the same button says Cancel', (
    tester,
  ) async {
    window(tester, const Size(1080, 640));
    final app = _HeroController()
      ..activeProtocol = null
      ..runOperation(VpnStatus.preparing, protectionArmed: false);
    await _pump(tester, app);

    expect(find.text('Préparation de la connexion'), findsOneWidget);
    expect(_primaryLabel(tester), 'Annuler');
    expect(_primaryIcon(tester), Icons.close);
    expect(_primaryEnabled(tester), isTrue);

    await tester.tap(_primary);
    await tester.pump();
    expect(app.stopRequests, 1);
    expect(app.connectRequests, 0);
    await _dispose(tester, app);
  });

  testWidgets('a location change that begins by disconnecting offers '
      'Disconnect, never Cancel nor a connection', (tester) async {
    window(tester, const Size(1080, 640));
    // Nothing is retained (kill switch off) while the old tunnel stops.
    final app = _HeroController()
      ..activeProtocol = null
      ..runOperation(VpnStatus.disconnecting, protectionArmed: false);
    await _pump(tester, app);

    expect(find.text('Déconnexion en cours'), findsOneWidget);
    expect(_primaryLabel(tester), 'Déconnecter');
    expect(_primaryIcon(tester), Icons.lock_open_outlined);
    expect(_primaryEnabled(tester), isTrue);
    await tester.tap(_primary);
    await tester.pump();
    expect(app.stopRequests, 1);
    expect(app.connectRequests, 0);
    await _dispose(tester, app);
  });

  testWidgets('the progress notice keeps its text and the stop stays '
      'available beside it', (tester) async {
    window(tester, const Size(1080, 640));
    final app = _HeroController()
      ..runOperation(VpnStatus.blocked, protectionArmed: true)
      ..errorMessage =
          'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.';
    await _pump(tester, app);

    expect(find.text(_progressNotice), findsOneWidget);
    expect(find.text('Trafic bloqué'), findsOneWidget);
    expect(_primaryLabel(tester), 'Déconnecter');
    expect(_primaryEnabled(tester), isTrue);
    await tester.tap(_primary);
    await tester.pump();
    expect(app.stopRequests, 1);
    await _dispose(tester, app);
  });

  testWidgets('while the stop runs the page says Disconnecting and the '
      'button is off', (tester) async {
    window(tester, const Size(1080, 640));
    final app = _HeroController()
      ..stopping = true
      ..retained = true
      ..vpnStatus = VpnStatus.disconnecting;
    await _pump(tester, app);

    expect(find.text('Déconnexion en cours'), findsOneWidget);
    expect(
      find.text('Nous arrêtons le tunnel VPN en toute sécurité.'),
      findsOneWidget,
    );
    expect(_primaryLabel(tester), 'Déconnecter');
    expect(_primaryEnabled(tester), isFalse);
    await tester.tap(_primary, warnIfMissed: false);
    await tester.pump();
    expect(app.stopRequests, 0);
    expect(app.connectRequests, 0);
    await _dispose(tester, app);
  });

  testWidgets('a command that only disconnects keeps the button off', (
    tester,
  ) async {
    window(tester, const Size(1080, 640));
    final app = _HeroController()
      ..busy = true
      ..commandRunning = true
      ..retained = true
      ..vpnStatus = VpnStatus.disconnecting;
    await _pump(tester, app);
    expect(_primaryLabel(tester), 'Déconnecter');
    expect(_primaryEnabled(tester), isFalse);
    await _dispose(tester, app);
  });

  for (final withNotice in [true, false]) {
    testWidgets('the unknown state shows Retry and a separate Disconnect '
        '(${withNotice ? 'with' : 'without'} its notice)', (tester) async {
      window(tester, const Size(1080, 640));
      final app = _HeroController()..showUnknownState(withNotice: withNotice);
      await _pump(tester, app);

      expect(find.text('État VPN inconnu'), findsOneWidget);
      expect(_primaryLabel(tester), 'Réessayer');
      expect(_primaryEnabled(tester), isTrue);
      expect(
        find.descendant(of: _forced, matching: find.text('Déconnecter')),
        findsOneWidget,
      );
      // Both fit the panel, the stop under or beside the retry.
      final panel = tester.getRect(
        find.byKey(const ValueKey('connection-control-panel')),
      );
      for (final button in [_primary, _forced]) {
        expect(button.hitTestable(), findsOneWidget);
        final rect = tester.getRect(button);
        expect(rect.left, greaterThanOrEqualTo(panel.left));
        expect(rect.right, lessThanOrEqualTo(panel.right));
        expect(rect.height, greaterThanOrEqualTo(48));
      }
      expect(
        tester.getRect(_primary).overlaps(tester.getRect(_forced)),
        isFalse,
      );

      // Retrying stays passive; only the second button stops.
      await tester.tap(_primary);
      await tester.pump();
      expect(app.retryRequests, 1);
      expect(app.stopRequests, 0);
      await tester.tap(_forced);
      await tester.pump();
      expect(app.stopRequests, 1);
      expect(app.connectRequests, 0);

      // While the passive verification runs, neither is offered.
      app
        ..busy = true
        ..selectSection(AppSection.connection);
      await tester.pump();
      expect(_forced, findsNothing);
      expect(_primaryEnabled(tester), isFalse);
      await _dispose(tester, app);
    });
  }

  testWidgets('the extra Disconnect appears in no known state', (tester) async {
    window(tester, const Size(1080, 640));
    for (final status in VpnStatus.values) {
      final app = _HeroController()..vpnStatus = status;
      await _pump(tester, app);
      expect(_forced, findsNothing, reason: status.name);
      await _dispose(tester, app);
    }
  });

  testWidgets('the startup attempt shows its live state and an enabled '
      'Disconnect before the controller is initialized', (tester) async {
    window(tester, const Size(1080, 640));
    final app = _HeroController()
      ..isInitialized = false
      ..vpnStatus = VpnStatus.blocked;
    await _pump(tester, app);
    // Nothing runs yet: the state is still being read, nothing to act on.
    expect(find.text('Vérification de la protection…'), findsOneWidget);
    expect(_primaryEnabled(tester), isFalse);

    app
      ..runOperation(VpnStatus.preparing, protectionArmed: true)
      ..selectSection(AppSection.connection);
    await tester.pump();
    expect(find.text('Vérification de la protection…'), findsNothing);
    expect(find.text('Préparation de la connexion'), findsOneWidget);
    expect(_primaryLabel(tester), 'Déconnecter');
    expect(_primaryEnabled(tester), isTrue);
    await tester.tap(_primary);
    await tester.pump();
    expect(app.stopRequests, 1);

    // The stop that follows keeps the live state on screen too.
    app
      ..busy = false
      ..cancellable = false
      ..commandRunning = false
      ..stopping = true
      ..vpnStatus = VpnStatus.disconnecting
      ..selectSection(AppSection.connection);
    await tester.pump();
    expect(find.text('Déconnexion en cours'), findsOneWidget);
    expect(_primaryEnabled(tester), isFalse);
    await _dispose(tester, app);
  });

  testWidgets('a VPN owned by another Windows session offers no stop', (
    tester,
  ) async {
    window(tester, const Size(1080, 640));
    final app = _HeroController()
      ..runOperation(VpnStatus.preparing, protectionArmed: true)
      ..otherSession = true;
    await _pump(tester, app);
    expect(_primaryEnabled(tester), isFalse);
    await tester.tap(_primary, warnIfMissed: false);
    await tester.pump();
    expect(app.stopRequests, 0);

    // Nor does the unknown state under another session.
    app
      ..busy = false
      ..cancellable = false
      ..unknown = true
      ..selectSection(AppSection.connection);
    await tester.pump();
    expect(_forced, findsNothing);
    await _dispose(tester, app);
  });

  testWidgets('the stop controls fit narrow and wide windows at large text '
      'sizes', (tester) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final arrangements = <String, void Function(_HeroController)>{
      'cancel': (app) => app
        ..activeProtocol = null
        ..runOperation(VpnStatus.preparing, protectionArmed: false),
      'disconnect beside a notice': (app) => app
        ..runOperation(VpnStatus.blocked, protectionArmed: true)
        ..errorMessage =
            'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.',
      'unknown with its notice': (app) =>
          app.showUnknownState(withNotice: true),
      'unknown without notice': (app) =>
          app.showUnknownState(withNotice: false),
    };
    for (final size in [
      const Size(640, 360),
      const Size(900, 700),
      const Size(1280, 720),
    ]) {
      tester.view.physicalSize = size;
      for (final scale in [1.0, 2.0]) {
        tester.platformDispatcher.textScaleFactorTestValue = scale;
        for (final language in [
          AppLanguage.french,
          AppLanguage.english,
          AppLanguage.german,
          AppLanguage.russian,
          AppLanguage.arabic,
          AppLanguage.japanese,
          AppLanguage.tamil,
          AppLanguage.finnish,
        ]) {
          for (final entry in arrangements.entries) {
            final reason = '$size / $scale / $language / ${entry.key}';
            final app = _HeroController()..language = language;
            entry.value(app);
            await tester.pumpWidget(FuzeVpnApp(controller: app));
            await tester.pump();
            expect(tester.takeException(), isNull, reason: reason);
            final buttons = [
              _primary,
              if (entry.key.startsWith('unknown')) _forced,
            ];
            for (final button in buttons) {
              expect(button, findsOneWidget, reason: reason);
              await tester.ensureVisible(button);
              await tester.pump();
              final rect = tester.getRect(button);
              expect(rect.left, greaterThanOrEqualTo(0), reason: reason);
              expect(rect.right, lessThanOrEqualTo(size.width), reason: reason);
              expect(rect.height, greaterThanOrEqualTo(48), reason: reason);
            }
            if (buttons.length == 2) {
              expect(
                tester.getRect(_primary).overlaps(tester.getRect(_forced)),
                isFalse,
                reason: reason,
              );
            }
            expect(tester.takeException(), isNull, reason: reason);
            await tester.pumpWidget(const SizedBox.shrink());
            app.dispose();
          }
        }
      }
    }
  });
}
