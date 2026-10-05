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

const _frankfurt1 = Location(
  id: 'de-1',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
);
const _frankfurt2 = Location(
  id: 'de-2',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 2',
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
);

class _HierarchyController extends ConnectionUxController {
  _HierarchyController() {
    section = AppSection.locations;
    locations = [_frankfurt1, _frankfurt2, _berlin, _paris];
    selectedLocation = _frankfurt1;
    vpnProtocol = VpnProtocol.wireGuard;
    protocolPreference = VpnProtocolPreference.wireGuard;
    activeProtocol = null;
  }

  final requested = <Location>[];
  int confirmations = 0;
  bool confirmationRequired = false;

  @override
  Future<LocationChangePreparation> prepareLocationChange(
    Location target,
  ) async {
    requested.add(target);
    if (confirmationRequired) {
      pendingTargetLocation = target;
      return LocationChangePreparation.confirmationRequired;
    }
    selectedLocation = target;
    notifyListeners();
    return LocationChangePreparation.selectedLocally;
  }

  @override
  Future<void> confirmPreparedLocationChange() async {
    confirmations++;
    selectedLocation = pendingTargetLocation;
    pendingTargetLocation = null;
    notifyListeners();
  }

  @override
  Future<void> toggleFavoriteLocation(Location location) async {
    if (!favoriteLocationIds.add(location.id)) {
      favoriteLocationIds.remove(location.id);
    }
    notifyListeners();
  }

  void publish(List<Location> next) {
    locations = next;
    notifyListeners();
  }
}

Finder _key(String key) => find.byKey(ValueKey(key));

Future<void> _tap(WidgetTester tester, String key) async {
  final target = _key(key);
  await tester.ensureVisible(target);
  await tester.pumpAndSettle();
  await tester.tap(target);
  await tester.pumpAndSettle();
}

Future<void> _pump(WidgetTester tester, _HierarchyController controller) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(1080, 680);
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(controller.dispose);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
}

bool _hasFocusWithin(Finder finder) {
  final target = finder.evaluate().single;
  final focused = FocusManager.instance.primaryFocus?.context;
  if (focused == target) return true;
  var found = false;
  focused?.visitAncestorElements((ancestor) {
    if (ancestor == target) found = true;
    return !found;
  });
  return found;
}

Future<void> _activateByKeyboard(WidgetTester tester, String key) async {
  for (var tab = 0; tab < 40 && !_hasFocusWithin(_key(key)); tab++) {
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
  }
  expect(
    _hasFocusWithin(_key(key)),
    isTrue,
    reason: '$key must accept keyboard focus',
  );
  await tester.sendKeyEvent(LogicalKeyboardKey.enter);
  await tester.pumpAndSettle();
}

void main() {
  testWidgets(
    'countries and cities open independently of the server selection',
    (tester) async {
      final controller = _HierarchyController();
      await _pump(tester, controller);
      expect(find.text('Allemagne'), findsOneWidget);
      expect(find.text('France'), findsOneWidget);
      expect(_key('location-server-de-1'), findsNothing);
      expect(_key('location-select-city-DE-frankfurt'), findsNothing);

      await _tap(tester, 'location-open-country-DE');
      expect(_key('location-select-city-DE-frankfurt'), findsOneWidget);
      expect(_key('location-select-city-DE-berlin'), findsOneWidget);
      expect(_key('location-open-city-DE-berlin'), findsNothing);
      expect(controller.requested, isEmpty);
      expect(controller.selectedLocation, _frankfurt1);

      await _tap(tester, 'location-open-city-DE-frankfurt');
      expect(_key('location-server-de-1'), findsOneWidget);
      expect(_key('location-server-de-2'), findsOneWidget);
      expect(controller.requested, isEmpty);
      await _tap(tester, 'location-server-de-2');
      expect(controller.requested, [_frankfurt2]);
      expect(controller.selectedLocation, _frankfurt2);
      await _tap(tester, 'location-back-cities');
      expect(_key('location-select-city-DE-berlin'), findsOneWidget);
      await _tap(tester, 'location-back-countries');
      expect(_key('location-open-country-FR'), findsOneWidget);
    },
  );

  testWidgets(
    'country and city select the proposed server without opening a list',
    (tester) async {
      final controller = _HierarchyController();
      await _pump(tester, controller);
      expect(find.textContaining('Sélectionné : Frankfurt 1'), findsOneWidget);
      await _tap(tester, 'location-select-country-DE');
      expect(controller.requested, [_frankfurt1]);
      expect(_key('location-open-country-FR'), findsOneWidget);
      await _tap(tester, 'location-open-country-DE');
      await _tap(tester, 'location-select-city-DE-berlin');
      expect(controller.requested, [_frankfurt1, _berlin]);
      expect(controller.selectedLocation, _berlin);
      expect(_key('location-open-city-DE-frankfurt'), findsOneWidget);
    },
  );

  testWidgets(
    'group selection preserves confirmation before changing the active VPN',
    (tester) async {
      final controller = _HierarchyController()
        ..confirmationRequired = true
        ..vpnStatus = VpnStatus.connected
        ..activeProtocol = VpnProtocol.wireGuard
        ..tunnelLocationId = _frankfurt1.id;
      await _pump(tester, controller);
      await _tap(tester, 'location-select-country-FR');
      expect(find.text('Changer de serveur ?'), findsOneWidget);
      expect(controller.confirmations, 0);
      expect(controller.selectedLocation, _frankfurt1);
      await tester.tap(find.widgetWithText(TextButton, 'Annuler'));
      await tester.pumpAndSettle();
      expect(controller.confirmations, 0);
      expect(controller.selectedLocation, _frankfurt1);
      await _tap(tester, 'location-select-country-FR');
      await tester.tap(find.widgetWithText(FilledButton, 'Changer de serveur'));
      await tester.pumpAndSettle();
      expect(controller.confirmations, 1);
      expect(controller.selectedLocation, _paris);
    },
  );

  testWidgets(
    'search reaches another country directly and clearing restores navigation',
    (tester) async {
      final controller = _HierarchyController()
        ..favoriteLocationIds = {'missing-full-node'}
        ..recentLocationIds = ['missing-full-node'];
      await _pump(tester, controller);
      await _tap(tester, 'location-open-country-DE');
      await tester.enterText(_key('location-search'), 'Paris');
      await tester.pumpAndSettle();
      expect(_key('location-server-fr-paris'), findsOneWidget);
      expect(_key('location-server-de-1'), findsNothing);
      expect(_key('location-server-missing-full-node'), findsNothing);
      await _tap(tester, 'location-server-fr-paris');
      expect(controller.selectedLocation, _paris);
      await tester.tap(find.byTooltip('Effacer la recherche'));
      await tester.pumpAndSettle();
      expect(_key('location-select-city-DE-frankfurt'), findsOneWidget);
      expect(_key('location-select-city-DE-berlin'), findsOneWidget);
      expect(_key('location-server-fr-paris'), findsNothing);
    },
  );

  testWidgets(
    'a refreshed catalogue returns from a removed city to its surviving parent',
    (tester) async {
      final controller = _HierarchyController();
      await _pump(tester, controller);
      await _tap(tester, 'location-open-country-DE');
      await _tap(tester, 'location-open-city-DE-frankfurt');
      controller.publish([_berlin, _paris]);
      await tester.pumpAndSettle();
      expect(_key('location-select-city-DE-berlin'), findsOneWidget);
      expect(_key('location-server-de-1'), findsNothing);
      expect(_key('location-server-de-2'), findsNothing);
      controller.publish([_paris]);
      await tester.pumpAndSettle();
      expect(_key('location-open-country-FR'), findsOneWidget);
      expect(_key('location-open-country-DE'), findsNothing);
      expect(controller.requested, isEmpty);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'incompatible groups permit browsing without choosing a different protocol',
    (tester) async {
      final controller = _HierarchyController()
        ..protocolPreference = VpnProtocolPreference.openVpn
        ..vpnProtocol = VpnProtocol.openVpn
        ..openVpnRuntimeAvailable = true;
      await _pump(tester, controller);
      await _tap(tester, 'location-select-country-DE');
      expect(controller.requested, isEmpty);
      await _tap(tester, 'location-open-country-DE');
      await _tap(tester, 'location-select-city-DE-frankfurt');
      expect(controller.requested, isEmpty);
      await _tap(tester, 'location-open-city-DE-frankfurt');
      expect(_key('location-server-de-1'), findsOneWidget);
      expect(
        find.text('Aucun serveur compatible avec le protocole choisi.'),
        findsNWidgets(2),
      );
      await _tap(tester, 'location-server-de-2');
      expect(controller.requested, isEmpty);
      expect(controller.protocolPreference, VpnProtocolPreference.openVpn);
    },
  );

  testWidgets(
    'navigation and selection both remain available from the keyboard',
    (tester) async {
      final controller = _HierarchyController();
      final semantics = tester.ensureSemantics();
      try {
        await _pump(tester, controller);
        await _activateByKeyboard(tester, 'location-select-country-FR');
        expect(controller.requested, [_paris]);
        controller.requested.clear();
        await _activateByKeyboard(tester, 'location-open-country-DE');
        expect(controller.requested, isEmpty);
        await _activateByKeyboard(tester, 'location-open-city-DE-frankfurt');
        expect(controller.requested, isEmpty);
        await _activateByKeyboard(tester, 'location-server-de-2');
        expect(controller.selectedLocation, _frankfurt2);
        expect(tester.takeException(), isNull);
      } finally {
        semantics.dispose();
      }
    },
  );

  testWidgets(
    'opening a city after scrolling returns to the search and heading',
    (tester) async {
      final controller = _HierarchyController()
        ..locations = [
          for (var city = 0; city < 12; city++)
            for (var server = 1; server <= 2; server++)
              Location(
                id: 'city-$city-$server',
                city: 'City ${city.toString().padLeft(2, '0')}',
                countryCode: 'DE',
                displayName: 'City $city server $server',
              ),
        ];
      await _pump(tester, controller);
      await _tap(tester, 'location-open-country-DE');
      await _tap(tester, 'location-open-city-DE-city 11');
      final search = tester.getRect(_key('location-search'));
      expect(search.top, greaterThanOrEqualTo(64));
      expect(search.bottom, lessThanOrEqualTo(680));
      expect(_key('location-server-city-11-1'), findsOneWidget);
      expect(controller.requested, isEmpty);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'all hierarchy levels fit narrow windows with large text in every language and theme',
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
          final controller = _HierarchyController()
            ..language = language
            ..themeMode = theme;
          await tester.pumpWidget(FuzeVpnApp(controller: controller));
          await tester.pumpAndSettle();
          expect(
            tester.takeException(),
            isNull,
            reason: '$language/$theme/countries',
          );
          await _tap(tester, 'location-open-country-DE');
          expect(
            tester.takeException(),
            isNull,
            reason: '$language/$theme/cities',
          );
          await _tap(tester, 'location-open-city-DE-frankfurt');
          expect(
            tester.takeException(),
            isNull,
            reason: '$language/$theme/servers',
          );
          await tester.pumpWidget(const SizedBox.shrink());
          controller.dispose();
        }
      }
    },
  );

  testWidgets('render hierarchy previews at the normal window size', (
    tester,
  ) async {
    // Widget tests default to Ahem squares. Use local fonts for readable
    // preview artifacts without adding fonts or dependencies to the app.
    await tester.runAsync(() async {
      const fontFiles = {
        'Archivo': 'assets/fonts/Archivo-Variable.ttf',
        'Segoe UI Variable Display': 'C:/Windows/Fonts/segoeui.ttf',
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
    final controller = _HierarchyController();
    addTearDown(controller.dispose);
    final boundaryKey = GlobalKey();
    await tester.pumpWidget(
      RepaintBoundary(
        key: boundaryKey,
        child: FuzeVpnApp(controller: controller),
      ),
    );
    await tester.pumpAndSettle();

    Future<void> capture(String name) async {
      final searchRect = tester.getRect(_key('location-search'));
      expect(
        searchRect.top,
        greaterThanOrEqualTo(64),
        reason: '$name navigation must keep search below the navigation bar',
      );
      expect(
        searchRect.bottom,
        lessThanOrEqualTo(680),
        reason: '$name navigation must leave search visible',
      );
      final boundary =
          boundaryKey.currentContext!.findRenderObject()!
              as RenderRepaintBoundary;
      await tester.runAsync(() async {
        final image = await boundary.toImage(pixelRatio: 1);
        try {
          final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
          final file = File('build/previews/locations/$name.png');
          await file.parent.create(recursive: true);
          await file.writeAsBytes(bytes!.buffer.asUint8List());
        } finally {
          image.dispose();
        }
      });
    }

    await capture('countries');
    await _tap(tester, 'location-open-country-DE');
    await capture('cities');
    await _tap(tester, 'location-open-city-DE-frankfurt');
    await capture('servers');
    expect(tester.takeException(), isNull);
  });
}
