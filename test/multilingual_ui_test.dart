// SPDX-License-Identifier: MPL-2.0
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

class _LanguageController extends ConnectionUxController {}

void main() {
  testWidgets('language selector shows every language in alphabetical order', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1080, 680);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    tester.platformDispatcher.localeTestValue = const Locale('en');
    tester.platformDispatcher.localesTestValue = const [Locale('en')];
    addTearDown(tester.platformDispatcher.clearLocaleTestValue);
    addTearDown(tester.platformDispatcher.clearLocalesTestValue);
    final app = _LanguageController()
      ..section = AppSection.settings
      ..language = AppLanguage.system;
    addTearDown(app.dispose);
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
    final dropdown = tester.widget<DropdownButton<AppLanguage>>(
      find.byType(DropdownButton<AppLanguage>),
    );
    expect(dropdown.items!.map((item) => item.value), AppLanguage.sortedValues);
    expect(dropdown.items, hasLength(31));
    expect(dropdown.items!.first.value, AppLanguage.system);
    expect(find.text('System'), findsWidgets);
    expect(find.text('Système'), findsNothing);
    expect(dropdown.menuMaxHeight, 440);
    await tester.tap(find.byType(DropdownButton<AppLanguage>));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });

  testWidgets('RTL mirrors location navigation and keeps email input LTR', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1080, 680);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    for (final language in [
      AppLanguage.arabic,
      AppLanguage.persian,
      AppLanguage.urdu,
    ]) {
      final app = _LanguageController()
        ..language = language
        ..section = AppSection.locations;
      await tester.pumpWidget(FuzeVpnApp(controller: app));
      await tester.pumpAndSettle();
      final context = tester.element(find.byType(Scaffold).first);
      expect(Directionality.of(context), TextDirection.rtl);
      final select = find.byKey(const ValueKey('location-select-country-DE'));
      final open = find.byKey(const ValueKey('location-open-country-DE'));
      expect(tester.getCenter(open).dx, lessThan(tester.getCenter(select).dx));
      expect(
        find.descendant(of: open, matching: find.byIcon(Icons.chevron_left)),
        findsOneWidget,
      );
      await tester.tap(open);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull, reason: language.name);
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();

      final loggedOut = _LanguageController()
        ..language = language
        ..profile = null;
      await tester.pumpWidget(FuzeVpnApp(controller: loggedOut));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsOneWidget);
      final email = find.byWidgetPredicate(
        (widget) =>
            widget is TextField &&
            widget.keyboardType == TextInputType.emailAddress,
      );
      expect(tester.widget<TextField>(email).textDirection, TextDirection.ltr);
      await tester.enterText(email, 'test@example.invalid');
      expect(
        tester.widget<TextField>(email).controller!.text,
        'test@example.invalid',
      );
      expect(tester.takeException(), isNull, reason: language.name);
      await tester.pumpWidget(const SizedBox.shrink());
      loggedOut.dispose();
    }
  });

  testWidgets('Windows Chinese variants select different catalogs and fonts', (
    tester,
  ) async {
    for (final region in ['CN', 'TW']) {
      tester.platformDispatcher.localeTestValue = Locale('zh', region);
      tester.platformDispatcher.localesTestValue = [Locale('zh', region)];
      addTearDown(tester.platformDispatcher.clearLocaleTestValue);
      addTearDown(tester.platformDispatcher.clearLocalesTestValue);
      final app = _LanguageController()..language = AppLanguage.system;
      await tester.pumpWidget(FuzeVpnApp(controller: app));
      await tester.pumpAndSettle();
      final context = tester.element(find.byType(Scaffold).first);
      expect(
        Localizations.localeOf(context).scriptCode,
        region == 'TW' ? 'Hant' : 'Hans',
      );
      expect(Directionality.of(context), TextDirection.ltr);
      expect(Theme.of(context).textTheme.headlineMedium!.letterSpacing, 0);
      for (final style in [
        Theme.of(context).textTheme.bodyMedium!,
        Theme.of(context).textTheme.bodySmall!,
        Theme.of(context).textTheme.labelMedium!,
      ]) {
        expect(style.fontFamily, 'Archivo');
        expect(
          style.fontFamilyFallback,
          contains(
            region == 'TW' ? 'Microsoft JhengHei UI' : 'Microsoft YaHei UI',
          ),
        );
      }
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();
    }
  });

  testWidgets('render multilingual previews with installed Windows fonts', (
    tester,
  ) async {
    await tester.runAsync(() async {
      const fonts = {
        'Archivo': 'assets/fonts/Archivo-Variable.ttf',
        'Segoe UI Variable Display': 'C:/Windows/Fonts/SegUIVar.ttf',
        'Segoe UI': 'C:/Windows/Fonts/segoeui.ttf',
        'Roboto': 'C:/Windows/Fonts/segoeui.ttf',
        'Tahoma': 'C:/Windows/Fonts/tahoma.ttf',
        'Nirmala UI': 'C:/Windows/Fonts/Nirmala.ttf',
        'Yu Gothic UI': 'C:/Windows/Fonts/YuGothR.ttc',
        'Malgun Gothic': 'C:/Windows/Fonts/malgun.ttf',
        'Microsoft JhengHei UI': 'C:/Windows/Fonts/msjh.ttc',
        'Microsoft YaHei UI': 'C:/Windows/Fonts/msyh.ttc',
        'Leelawadee UI': 'C:/Windows/Fonts/LeelawUI.ttf',
        'MaterialIcons':
            '.toolchain/flutter/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
      };
      for (final entry in fonts.entries) {
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
    for (final scenario in [
      (AppLanguage.arabic, AppSection.settings, ThemeMode.light, false),
      (AppLanguage.japanese, AppSection.connection, ThemeMode.light, false),
      (
        AppLanguage.traditionalChinese,
        AppSection.locations,
        ThemeMode.dark,
        false,
      ),
      (AppLanguage.urdu, AppSection.connection, ThemeMode.light, true),
    ]) {
      const requested = String.fromEnvironment('PREVIEW_LOCALES');
      if (requested.isNotEmpty &&
          !requested.split(',').contains(scenario.$1.storageValue)) {
        continue;
      }
      final app = _LanguageController()
        ..language = scenario.$1
        ..section = scenario.$2
        ..themeMode = scenario.$3;
      if (scenario.$4) app.profile = null;
      final boundaryKey = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: boundaryKey,
          child: FuzeVpnApp(controller: app),
        ),
      );
      await tester.pumpAndSettle();
      await tester.runAsync(
        () => precacheImage(
          const AssetImage('assets/branding/fuzevpn-emblem-512.png'),
          boundaryKey.currentContext!,
        ),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull, reason: scenario.$1.name);
      final boundary =
          boundaryKey.currentContext!.findRenderObject()!
              as RenderRepaintBoundary;
      await tester.runAsync(() async {
        final image = await boundary.toImage(pixelRatio: 1);
        try {
          final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
          final file = File(
            'build/previews/locales/${scenario.$1.storageValue}-${scenario.$2.name}.png',
          );
          await file.parent.create(recursive: true);
          await file.writeAsBytes(bytes!.buffer.asUint8List());
        } finally {
          image.dispose();
        }
      });
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();
    }
  });
}
