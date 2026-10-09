// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/generated_catalogs.dart';
import 'package:fuzevpn_windows/main.dart';
import 'package:fuzevpn_windows/windows_update_panel.dart';

import 'support/audit_fixtures.dart';

final release = WindowsUpdateRelease(
  version: WindowsUpdateVersion.parse('0.2.0'),
  downloadUrl: Uri.https('downloads.example.invalid', '/FuzeVPN-Setup.exe'),
  sha256: List.filled(64, 'a').join(),
  releaseNotes: 'Correction de stabilité.',
);
final portableRelease = WindowsUpdateRelease(
  version: release.version,
  downloadUrl: Uri.https('downloads.example.invalid', '/FuzeVPN-portable.zip'),
  sha256: release.sha256,
  releaseNotes: release.releaseNotes,
  package: WindowsUpdatePackage.portable,
);

Widget localizedHost(Widget child) => MaterialApp(
  locale: const Locale('fr'),
  supportedLocales: AppStrings.supportedLocales,
  localizationsDelegates: const [
    AppLocalizations.delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
  ],
  home: Scaffold(body: child),
);

class UpdateApi extends ApiClient {
  WindowsUpdateRelease? candidate = release;
  @override
  Future<WindowsUpdateRelease?> latestWindowsUpdate({
    String arch = 'x64',
    String channel = 'stable',
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
    bool revalidate = false,
  }) async => candidate;
}

class UpdateBridge extends WindowsUpdateBridge {
  int installs = 0;
  int preparations = 0;
  WindowsInstallationMode installationMode = WindowsInstallationMode.installed;
  Completer<void>? installGate;
  bool cancelInstallation = false;
  Object? prepareFailure;
  @override
  Future<WindowsUpdateEnvironment> getEnvironment() async =>
      WindowsUpdateEnvironment(
        version: WindowsUpdateVersion.parse('0.1.0'),
        windowsBuild: 22631,
        arch: 'x64',
        installationMode: installationMode,
      );
  @override
  Future<String> prepareUpdate(WindowsUpdateRelease release) async {
    preparations++;
    final failure = prepareFailure;
    if (failure != null) throw failure;
    return 'opaque-token';
  }

  @override
  Future<void> discardUpdate(String token) async {}
  @override
  Future<void> installUpdate(String token) async {
    installs++;
    await installGate?.future;
    if (cancelInstallation) throw PlatformException(code: 'update_cancelled');
  }
}

class UpdateWindow extends ProbeWindow {
  int quits = 0;
  @override
  Future<void> quit() async {
    quits++;
  }
}

class UpdateWireGuard extends ProbeWireGuard {
  Completer<void>? disconnectGate;
  bool cleanupFails = false;
  @override
  Future<void> disconnect() async {
    await disconnectGate?.future;
    if (cleanupFails) throw StateError('Simulated cleanup failure');
    await super.disconnect();
  }
}

class Fixture {
  Fixture() {
    updates = WindowsUpdateController(api: api, bridge: bridge);
    app =
        AppController(
            api: ProbeApi(),
            store: ProbeStore(),
            window: window,
            wireguard: wg,
            openVpn: ProbeOpenVpn(),
            updates: updates,
          )
          ..isInitialized = true
          ..profile = account
          ..vpnStatus = VpnStatus.connected
          ..activeProtocol = VpnProtocol.wireGuard;
    wg.connected = true;
    wg.protectionActive = true;
  }
  final api = UpdateApi();
  final bridge = UpdateBridge();
  final wg = UpdateWireGuard();
  final window = UpdateWindow();
  late final WindowsUpdateController updates;
  late final AppController app;
  Future<void> prepare() async {
    await updates.checkForUpdates();
    await updates.prepareUpdate();
    expect(updates.status, WindowsUpdateStatus.ready);
  }

  void dispose() {
    app.dispose();
    api.close();
  }
}

void main() {
  testWidgets('newer MSI offers the official website without automatic install', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(640, 360);
    tester.view.devicePixelRatio = 1;
    tester.platformDispatcher.textScaleFactorTestValue = 2;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    const launcher = MethodChannel('plugins.flutter.io/url_launcher');
    final urls = <String>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(launcher, (call) async {
          if (call.method == 'launch') {
            urls.add((call.arguments as Map)['url'] as String);
          }
          return true;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(launcher, null),
    );
    final api = UpdateApi()
      ..candidate = WindowsUpdateRelease.fromJson({
        'version': '0.2.0',
        'download_url': 'https://downloads.example.invalid/FuzeVPN.msi',
        'sha256': 'a' * 64,
        'release_notes': 'Correction de stabilité.',
      });
    final bridge = UpdateBridge();
    final updates = WindowsUpdateController(api: api, bridge: bridge);
    addTearDown(() {
      updates.dispose();
      api.close();
    });
    await updates.checkForUpdates();
    var installCalls = 0;
    await tester.pumpWidget(
      localizedHost(
        SingleChildScrollView(
          child: WindowsUpdatePanel(
            controller: updates,
            onInstall: () async => installCalls++,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(
      find.text(
        'Cette mise à jour nécessite une installation manuelle depuis le site FuzeVPN.',
      ),
      findsOneWidget,
    );
    expect(
      find.text('Cette mise à jour n’est pas compatible avec cet ordinateur.'),
      findsNothing,
    );
    expect(find.text('Télécharger la mise à jour'), findsNothing);
    expect(find.text('Installer maintenant'), findsNothing);
    expect(urls, isEmpty);
    final website = find.widgetWithText(
      OutlinedButton,
      'Ouvrir le site FuzeVPN',
    );
    await tester.ensureVisible(website);
    await tester.tap(website);
    await tester.pumpAndSettle();
    expect(urls, ['https://fuzevpn.com/fr/']);
    expect(bridge.preparations, 0);
    expect(bridge.installs, 0);
    expect(installCalls, 0);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'unsigned installed application explains manual migration with trust code',
    (tester) async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.updates.checkForUpdates();
      f.bridge.prepareFailure = PlatformException(
        code: 'update_unsigned_application',
        message: 'secret application path',
        details: {
          'stage': 'application_signature',
          'trust_status': -2146762496,
          'path': r'C:\Users\private\FuzeVPN.exe',
        },
      );
      await f.updates.prepareUpdate();
      await tester.pumpWidget(
        localizedHost(
          SingleChildScrollView(
            child: WindowsUpdatePanel(
              controller: f.updates,
              onInstall: f.app.installPreparedUpdate,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Version actuelle : 0.1.0'), findsOneWidget);
      expect(find.text('Échec de la mise à jour'), findsOneWidget);
      expect(
        find.text(
          'Cette version de FuzeVPN n’est pas signée. Installez manuellement la version officielle signée pour activer les mises à jour.',
        ),
        findsOneWidget,
      );
      expect(
        find.textContaining('update_unsigned_application'),
        findsOneWidget,
      );
      expect(find.textContaining('application_signature'), findsOneWidget);
      expect(find.textContaining('0x800B0100'), findsOneWidget);
      expect(
        find.text(
          'La signature de cette mise à jour n’a pas pu être vérifiée.',
        ),
        findsNothing,
      );
      expect(find.textContaining('secret'), findsNothing);
      expect(find.textContaining('private'), findsNothing);
      expect(f.bridge.installs, 0);
      expect(f.wg.connected, isTrue);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'download HTTP failure and integrity mismatch remain distinct and selectable',
    (tester) async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.updates.checkForUpdates();
      f.bridge.prepareFailure = PlatformException(
        code: 'update_download_http_error',
        details: {'stage': 'download_http', 'http_status': 403},
      );
      await f.updates.prepareUpdate();
      await tester.pumpWidget(
        localizedHost(
          SingleChildScrollView(
            child: WindowsUpdatePanel(
              controller: f.updates,
              onInstall: f.app.installPreparedUpdate,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        find.text('Le serveur de téléchargement a refusé la demande.'),
        findsOneWidget,
      );
      expect(find.textContaining('HTTP : 403'), findsOneWidget);
      expect(find.textContaining('download_http'), findsOneWidget);
      expect(
        find.byWidgetPredicate(
          (widget) =>
              widget is SelectableText &&
              (widget.data?.contains('HTTP : 403') ?? false),
        ),
        findsOneWidget,
      );
      f.bridge.prepareFailure = PlatformException(
        code: 'update_hash_mismatch',
        details: {'stage': 'package_hash'},
      );
      await f.updates.prepareUpdate();
      await tester.pumpAndSettle();
      expect(
        find.text('Le SHA-256 du fichier reçu diffère de celui annoncé.'),
        findsOneWidget,
      );
      expect(find.textContaining('update_hash_mismatch'), findsOneWidget);
      expect(find.textContaining('HTTP : 403'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  test(
    'disconnect is confirmed before install and reconnect stays reserved',
    () async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.prepare();
      f.bridge.installGate = Completer<void>();
      final installing = f.app.installPreparedUpdate();
      for (var i = 0; i < 100 && f.bridge.installs == 0; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(f.bridge.installs, 1);
      expect(f.wg.connected, isFalse);
      expect(f.wg.protectionActive, isFalse);
      expect(f.app.isConnectionBusy, isTrue);
      await f.app.quickConnect();
      await f.app.signOut();
      expect(f.wg.prepareCalls, 0);
      expect(f.app.profile, account);
      f.bridge.installGate!.complete();
      await installing;
      expect(f.window.quits, 1);
      expect(f.updates.status, WindowsUpdateStatus.launched);
      expect(f.app.isInstallingUpdate, isTrue);
    },
  );

  test('withdrawal never stops VPN and never launches installer', () async {
    final f = Fixture();
    addTearDown(f.dispose);
    await f.prepare();
    f.api.candidate = null;
    await f.app.installPreparedUpdate();
    expect(f.wg.connected, isTrue);
    expect(f.bridge.installs, 0);
    expect(f.window.quits, 0);
    expect(f.app.isInstallingUpdate, isFalse);
  });

  test(
    'a prepared installation that becomes portable leaves the VPN connected',
    () async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.prepare();
      f.bridge.installationMode = WindowsInstallationMode.portable;
      await f.app.installPreparedUpdate();
      expect(f.wg.connected, isTrue);
      expect(f.bridge.installs, 0);
      expect(f.window.quits, 0);
      expect(f.app.isInstallingUpdate, isFalse);
      expect(f.updates.error?.code, 'update_changed');
    },
  );

  testWidgets('portable update panel offers verified ZIP download', (
    tester,
  ) async {
    final f = Fixture();
    addTearDown(f.dispose);
    f.bridge.installationMode = WindowsInstallationMode.portable;
    f.api.candidate = portableRelease;
    await f.updates.checkForUpdates();
    await tester.pumpWidget(
      localizedHost(
        WindowsUpdatePanel(
          controller: f.updates,
          onInstall: f.app.installPreparedUpdate,
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Version actuelle : 0.1.0'), findsOneWidget);
    expect(find.text('Version disponible : 0.2.0'), findsOneWidget);
    expect(find.text('Rechercher une mise à jour'), findsOneWidget);
    expect(find.text('Télécharger la mise à jour'), findsOneWidget);
    expect(find.text('Installer maintenant'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  test(
    'portable replacement stops VPN and closes window after helper is ready',
    () async {
      final f = Fixture();
      addTearDown(f.dispose);
      f.bridge.installationMode = WindowsInstallationMode.portable;
      f.api.candidate = portableRelease;
      await f.prepare();
      f.bridge.installGate = Completer<void>();
      final updating = f.app.installPreparedUpdate();
      for (var attempt = 0; attempt < 40 && f.bridge.installs == 0; attempt++) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(f.bridge.installs, 1);
      expect(f.wg.connected, isFalse);
      expect(f.wg.protectionActive, isFalse);
      expect(f.window.quits, 0);
      f.bridge.installGate!.complete();
      await updating;
      expect(f.window.quits, 1);
      expect(f.updates.status, WindowsUpdateStatus.launched);
    },
  );

  test(
    'unconfirmed VPN cleanup blocks installation and preserves runtime',
    () async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.prepare();
      f.wg.cleanupFails = true;
      await f.app.installPreparedUpdate();
      expect(f.bridge.installs, 0);
      expect(f.window.quits, 0);
      expect(f.wg.connected, isTrue);
      expect(f.app.requiresExplicitDisconnect, isTrue);
      expect(f.updates.error?.code, 'update_vpn_cleanup_failed');
      expect(f.app.isInstallingUpdate, isFalse);
    },
  );

  test(
    'portable update cannot close app while VPN cleanup remains unconfirmed',
    () async {
      final f = Fixture();
      addTearDown(f.dispose);
      f.bridge.installationMode = WindowsInstallationMode.portable;
      f.api.candidate = portableRelease;
      await f.prepare();
      f.wg.cleanupFails = true;
      await f.app.installPreparedUpdate();
      expect(f.bridge.installs, 0);
      expect(f.window.quits, 0);
      expect(f.wg.connected, isTrue);
      expect(f.updates.error?.code, 'update_vpn_cleanup_failed');
      expect(f.app.isInstallingUpdate, isFalse);
    },
  );

  test(
    'UAC cancellation keeps the interface open and releases reservation',
    () async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.prepare();
      f.bridge.cancelInstallation = true;
      await f.app.installPreparedUpdate();
      expect(f.window.quits, 0);
      expect(f.app.isInstallingUpdate, isFalse);
      expect(f.app.vpnStatus, VpnStatus.disconnected);
      expect(f.updates.error?.code, 'update_cancelled');
    },
  );

  testWidgets(
    'no publication is a normal visible state with no install action',
    (tester) async {
      final f = Fixture();
      addTearDown(f.dispose);
      f.api.candidate = null;
      await f.updates.checkForUpdates();
      await tester.pumpWidget(
        localizedHost(
          WindowsUpdatePanel(
            controller: f.updates,
            onInstall: f.app.installPreparedUpdate,
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Aucune mise à jour disponible.'), findsOneWidget);
      expect(find.text('Installer maintenant'), findsNothing);
      expect(find.text('Télécharger la mise à jour'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'installation requires confirmation and Later leaves VPN untouched',
    (tester) async {
      final f = Fixture();
      addTearDown(f.dispose);
      await f.prepare();
      await tester.pumpWidget(
        localizedHost(
          WindowsUpdatePanel(
            controller: f.updates,
            onInstall: f.app.installPreparedUpdate,
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Installer maintenant'));
      await tester.pumpAndSettle();
      expect(find.text('Installer la mise à jour ?'), findsOneWidget);
      await tester.tap(find.text('Plus tard'));
      await tester.pumpAndSettle();
      expect(f.bridge.installs, 0);
      expect(f.wg.connected, isTrue);
    },
  );

  testWidgets('update controls remain reachable without signing in', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final api = UpdateApi()..candidate = null;
    final updates = WindowsUpdateController(api: api, bridge: UpdateBridge());
    final controller = SignedOutController(updates: updates)
      ..language = AppLanguage.french
      ..isInitialized = true;
    addTearDown(() {
      controller.dispose();
      api.close();
    });
    await updates.checkForUpdates();
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pumpAndSettle();
    expect(find.text('Créer un compte sur le Web'), findsOneWidget);
    expect(find.text('Mises à jour').hitTestable(), findsOneWidget);
    await tester.tap(find.text('Mises à jour'));
    await tester.pumpAndSettle();
    expect(find.text('Aucune mise à jour disponible.'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  test('update texts cover all supported languages and preserve placeholders', () {
    const messages = [
      'Version actuelle : {version}',
      'Version disponible : {version}',
      'Installer la mise à jour ?',
      'Le VPN sera déconnecté et FuzeVPN se fermera pendant l’installation. Vos préférences seront conservées.',
      'Version portable : pour mettre à jour, fermez FuzeVPN et remplacez son dossier par celui de la nouvelle archive portable.',
      'Le type d’installation ne peut pas être vérifié. Le téléchargement et l’installation des mises à jour sont désactivés.',
      'L’arrêt du VPN n’a pas pu être confirmé. La mise à jour est interrompue.',
      'La signature de cette mise à jour n’a pas pu être vérifiée.',
      'Le fichier reçu ne correspond pas à la mise à jour annoncée.',
      'Cette version de FuzeVPN n’est pas signée. Installez manuellement la version officielle signée pour activer les mises à jour.',
      'Le serveur de téléchargement a refusé la demande.',
      'Le SHA-256 du fichier reçu diffère de celui annoncé.',
      'Code d’erreur',
      'Code Windows : {code}',
      'Code de confiance : {code}',
      'Fermez FuzeVPN pour terminer la mise à jour.',
      'Le dossier portable ne peut pas être mis à jour. Déplacez FuzeVPN dans un dossier accessible en écriture et réessayez.',
      'Cette mise à jour nécessite une installation manuelle depuis le site FuzeVPN.',
      'Ouvrir le site FuzeVPN',
    ];
    expect(translationCatalogs, hasLength(30));
    for (final key in messages) {
      expect(sourceCatalog, contains(key), reason: key);
      for (final language in AppLanguage.values.where(
        (value) => value != AppLanguage.system,
      )) {
        final translated = translationCatalogs[language.storageValue]![key];
        expect(
          translated?.trim(),
          isNotEmpty,
          reason: '${language.name}: $key',
        );
        expect(AppStrings.forLanguage(language).text(key), translated);
        if (sourceCatalog[key]!.contains('{version}')) {
          expect(translated, contains('{version}'), reason: language.name);
        }
      }
    }
  });
}

class SignedOutController extends AppController {
  SignedOutController({required super.updates});
  @override
  Future<void> initialize() async {}
}
