// SPDX-License-Identifier: MPL-2.0
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

const _frankfurt = Location(
  id: 'de-1',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  p2pAllowed: true,
);
const _berlin = Location(
  id: 'de-berlin',
  city: 'Berlin',
  countryCode: 'DE',
  displayName: 'Berlin 1',
);
const _paris = Location(
  id: 'fr-paris',
  city: 'Paris',
  countryCode: 'FR',
  displayName: 'Paris 1',
  p2pAllowed: true,
);
const _london = Location(
  id: 'gb-london',
  city: 'London',
  countryCode: 'GB',
  displayName: 'London 1',
);
const _chisinau = Location(
  id: 'md-chisinau',
  city: 'Chisinau',
  countryCode: 'MD',
  displayName: 'chisinau-01',
  p2pAllowed: true,
);

class _P2pController extends ConnectionUxController {
  _P2pController() {
    section = AppSection.locations;
    locations = [_frankfurt, _berlin, _paris, _london];
    selectedLocation = _berlin;
    vpnProtocol = VpnProtocol.wireGuard;
    protocolPreference = VpnProtocolPreference.wireGuard;
    activeProtocol = null;
  }

  @override
  Future<void> toggleFavoriteLocation(Location location) async {
    if (!favoriteLocationIds.add(location.id)) {
      favoriteLocationIds.remove(location.id);
    }
    notifyListeners();
  }
}

Finder _key(String key) => find.byKey(ValueKey(key));

Finder _badgeIn(String serverId) => find.descendant(
  of: _key('location-server-$serverId'),
  matching: find.text('P2P'),
);

Finder _countryBadge(String countryCode) => find.descendant(
  of: _key('location-select-country-$countryCode'),
  matching: find.text('P2P'),
);

String? _label(WidgetTester tester, String key) =>
    tester.widget<Text>(_key(key)).data;

Future<void> _tap(WidgetTester tester, String key) async {
  await tester.ensureVisible(_key(key));
  await tester.pumpAndSettle();
  await tester.tap(_key(key));
  await tester.pumpAndSettle();
}

Future<void> _pump(WidgetTester tester, _P2pController controller) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(1080, 680);
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(controller.dispose);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
}

List<String> _visibleServers(WidgetTester tester) => [
  for (final id in ['de-1', 'de-berlin', 'fr-paris', 'gb-london'])
    if (_key('location-server-$id').evaluate().isNotEmpty) id,
];

void main() {
  test('p2p_allowed is read from the catalogue and blocked by default', () {
    Location parse(Object? value, {bool present = true}) => Location.fromJson({
      'id': 'node',
      'city': 'Paris',
      'country_code': 'FR',
      'display_name': 'Paris',
      if (present) 'p2p_allowed': value,
    });
    expect(parse(true).p2pAllowed, isTrue);
    expect(parse(false).p2pAllowed, isFalse);
    expect(parse(null, present: false).p2pAllowed, isFalse);
    expect(parse(null).p2pAllowed, isFalse);
    expect(parse('true').p2pAllowed, isFalse);
    expect(parse(1).p2pAllowed, isFalse);
  });

  testWidgets('the P2P choice counts and filters allowed servers only', (
    tester,
  ) async {
    final controller = _P2pController();
    await _pump(tester, controller);
    expect(_label(tester, 'location-filter-all'), 'Tous · 4');
    expect(_label(tester, 'location-filter-favorites'), 'Favoris · 0');
    expect(_label(tester, 'location-list-title'), 'Tous les pays');
    expect(_label(tester, 'location-filter-p2p'), 'P2P · 2');
    expect(_visibleServers(tester), isEmpty);

    await _tap(tester, 'location-filter-p2p');
    expect(_visibleServers(tester), ['de-1', 'fr-paris']);
    expect(_label(tester, 'location-list-title'), 'P2P');
    expect(_badgeIn('de-1'), findsOneWidget);
    expect(_badgeIn('fr-paris'), findsOneWidget);

    // A single choice: tapping the selected filter again keeps it.
    await _tap(tester, 'location-filter-p2p');
    expect(_visibleServers(tester), ['de-1', 'fr-paris']);

    await _tap(tester, 'location-filter-all');
    expect(_visibleServers(tester), isEmpty);
    expect(_key('location-open-country-DE'), findsOneWidget);
    expect(controller.selectedLocation, _berlin);

    // Choosing a filter inside a country returns Tous to all countries.
    await _tap(tester, 'location-open-country-DE');
    expect(_key('location-back-countries'), findsOneWidget);
    await _tap(tester, 'location-filter-p2p');
    await _tap(tester, 'location-filter-all');
    expect(_key('location-back-countries'), findsNothing);
    expect(_key('location-open-country-FR'), findsOneWidget);
  });

  testWidgets('filters are exclusive and search narrows the chosen one', (
    tester,
  ) async {
    final controller = _P2pController()
      ..favoriteLocationIds = {'de-1', 'de-berlin'};
    final semantics = tester.ensureSemantics();
    try {
      await _pump(tester, controller);

      await _tap(tester, 'location-filter-favorites');
      expect(_visibleServers(tester), ['de-1', 'de-berlin']);
      expect(_label(tester, 'location-list-title'), 'Favoris');
      await _tap(tester, 'location-filter-p2p');
      expect(_visibleServers(tester), ['de-1', 'fr-paris']);
      expect(
        tester.getSemantics(_key('location-filter-p2p')),
        isSemantics(isInMutuallyExclusiveGroup: true, isSelected: true),
      );
      expect(
        tester.getSemantics(_key('location-filter-favorites')),
        isSemantics(isInMutuallyExclusiveGroup: true, isSelected: false),
      );

      await tester.enterText(_key('location-search'), 'Paris');
      await tester.pumpAndSettle();
      expect(_visibleServers(tester), ['fr-paris']);
      await tester.enterText(_key('location-search'), 'Berlin');
      await tester.pumpAndSettle();
      expect(_visibleServers(tester), isEmpty);
      expect(find.text('Aucun emplacement trouvé'), findsOneWidget);

      // The empty state offers the way back to every server.
      await tester.tap(find.text('Tous'));
      await tester.pumpAndSettle();
      expect(_visibleServers(tester), ['de-berlin']);
      expect(_label(tester, 'location-list-title'), 'Tous les pays');
      expect(
        tester.getSemantics(_key('location-filter-all')),
        isSemantics(isInMutuallyExclusiveGroup: true, isSelected: true),
      );
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('country rows name every country and badge a P2P choice', (
    tester,
  ) async {
    final controller = _P2pController()
      ..locations = [_frankfurt, _berlin, _paris, _london, _chisinau];
    await _pump(tester, controller);

    expect(find.textContaining('Moldavie'), findsOneWidget);
    expect(find.text('MD'), findsNothing);
    // Berlin is selected, so Germany would keep a server without P2P.
    expect(_countryBadge('DE'), findsNothing);
    expect(_countryBadge('FR'), findsOneWidget);
    expect(_countryBadge('MD'), findsOneWidget);
    expect(_countryBadge('GB'), findsNothing);

    controller
      ..selectedLocation = _frankfurt
      ..notifyListeners();
    await tester.pumpAndSettle();
    expect(_countryBadge('DE'), findsOneWidget);

    controller
      ..language = AppLanguage.english
      ..notifyListeners();
    await tester.pumpAndSettle();
    expect(find.textContaining('Moldova'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('only allowed servers carry the badge and its spoken label', (
    tester,
  ) async {
    final controller = _P2pController();
    final semantics = tester.ensureSemantics();
    try {
      await _pump(tester, controller);
      await tester.enterText(_key('location-search'), '1');
      await tester.pumpAndSettle();
      expect(_visibleServers(tester), [
        'de-1',
        'de-berlin',
        'fr-paris',
        'gb-london',
      ]);
      expect(_badgeIn('de-1'), findsOneWidget);
      expect(_badgeIn('fr-paris'), findsOneWidget);
      expect(_badgeIn('de-berlin'), findsNothing);
      expect(_badgeIn('gb-london'), findsNothing);
      expect(
        find.bySemanticsLabel(RegExp(r'^Frankfurt 1, .*P2P autorisé')),
        findsOneWidget,
      );
      expect(
        find.bySemanticsLabel(RegExp(r'^Berlin 1, .*P2P autorisé')),
        findsNothing,
      );
      expect(tester.takeException(), isNull);
    } finally {
      semantics.dispose();
    }
  });

  testWidgets(
    'both filters and badges fit narrow windows with large text in every language and theme',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(640, 360);
      tester.platformDispatcher.textScaleFactorTestValue = 2;
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      for (final language in AppLanguage.values.where(
        (value) => value != AppLanguage.system,
      )) {
        for (final theme in [ThemeMode.light, ThemeMode.dark]) {
          final controller = _P2pController()
            ..language = language
            ..themeMode = theme
            ..favoriteLocationIds = {'fr-paris'};
          await tester.pumpWidget(FuzeVpnApp(controller: controller));
          await tester.pumpAndSettle();
          await _tap(tester, 'location-filter-p2p');
          await _tap(tester, 'location-filter-favorites');
          expect(_visibleServers(tester), ['fr-paris']);
          expect(tester.takeException(), isNull, reason: '$language/$theme');
          await tester.pumpWidget(const SizedBox.shrink());
          controller.dispose();
        }
      }
    },
  );

  testWidgets('render P2P previews at the normal window size', (tester) async {
    // Widget tests default to Ahem squares. Use local fonts for readable
    // preview artifacts without adding fonts or dependencies to the app.
    await tester.runAsync(() async {
      const fontFiles = {
        'Archivo': 'assets/fonts/Archivo-Variable.ttf',
        'Segoe UI': 'C:/Windows/Fonts/segoeui.ttf',
        'Roboto': 'C:/Windows/Fonts/segoeui.ttf',
        'MaterialIcons':
            '.toolchain/flutter/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
      };
      for (final entry in fontFiles.entries) {
        final file = File(entry.value);
        if (!await file.exists()) continue;
        final loader = FontLoader(entry.key);
        loader.addFont(
          Future.value(ByteData.sublistView(await file.readAsBytes())),
        );
        await loader.load();
      }
    });
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1080, 680);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    for (final theme in [ThemeMode.light, ThemeMode.dark]) {
      final controller = _P2pController()
        ..themeMode = theme
        ..locations = [_frankfurt, _berlin, _paris, _london, _chisinau]
        ..favoriteLocationIds = {'de-1'};
      final boundaryKey = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: boundaryKey,
          child: FuzeVpnApp(controller: controller),
        ),
      );
      await tester.pumpAndSettle();
      Future<void> capture(String name) async {
        final boundary =
            boundaryKey.currentContext!.findRenderObject()!
                as RenderRepaintBoundary;
        await tester.runAsync(() async {
          final image = await boundary.toImage(pixelRatio: 1);
          try {
            final bytes = await image.toByteData(
              format: ui.ImageByteFormat.png,
            );
            final file = File('build/previews/locations/$name.png');
            await file.parent.create(recursive: true);
            await file.writeAsBytes(bytes!.buffer.asUint8List());
          } finally {
            image.dispose();
          }
        });
      }

      await capture('countries-${theme.name}');
      await tester.enterText(_key('location-search'), '1');
      await tester.pumpAndSettle();
      await capture('p2p-all-${theme.name}');
      await _tap(tester, 'location-filter-p2p');
      await capture('p2p-filter-${theme.name}');
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    }
  });
}
