// SPDX-License-Identifier: MPL-2.0
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _SettingsController extends AppController {
  _SettingsController(ThemeMode mode)
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
      ) {
    profile = fixtures.account;
    language = AppLanguage.french;
    section = AppSection.settings;
    isInitialized = true;
    themeMode = mode;
  }
  @override
  Future<void> initialize() async {}
  void rebuildFromObservation() => notifyListeners();
}

Finder _category(String name) =>
    find.byKey(ValueKey('settings-category-$name'));

// Sample the final painted frame, including the chip's parent-drawn selection
// overlay. Looking only at Icon/RichText properties would miss that overlay.
Future<Set<int>> _paintedGlyph(
  WidgetTester tester,
  GlobalKey boundaryKey,
  String category,
  IconData iconData,
) async {
  final icon = find.descendant(
    of: _category(category),
    matching: find.byIcon(iconData),
  );
  expect(icon, findsOneWidget);
  final iconWidget = tester.widget<Icon>(icon);
  final foreground =
      iconWidget.color ?? IconTheme.of(tester.element(icon)).color!;
  final render =
      boundaryKey.currentContext!.findRenderObject()! as RenderRepaintBoundary;
  final iconRect = tester
      .getRect(icon)
      .shift(-render.localToGlobal(Offset.zero));
  final captured = await tester.runAsync(() async {
    final image = await render.toImage(pixelRatio: 1);
    final pixels = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
    final width = image.width;
    image.dispose();
    return (pixels: pixels!, width: width);
  });
  final ByteData pixels = captured!.pixels;
  final foregroundArgb = foreground.toARGB32();
  final red = (foregroundArgb >> 16) & 255;
  final green = (foregroundArgb >> 8) & 255;
  final blue = foregroundArgb & 255;
  final mask = <int>{};
  for (var y = 0; y < iconRect.height.ceil(); y++) {
    for (var x = 0; x < iconRect.width.ceil(); x++) {
      final offset =
          ((iconRect.top.floor() + y) * captured.width +
              iconRect.left.floor() +
              x) *
          4;
      // Opaque glyph interiors remain recognizable independently of the chip's
      // animated surface color and the theme's legitimate foreground color.
      if ((pixels.getUint8(offset) - red).abs() <= 8 &&
          (pixels.getUint8(offset + 1) - green).abs() <= 8 &&
          (pixels.getUint8(offset + 2) - blue).abs() <= 8 &&
          pixels.getUint8(offset + 3) == 255) {
        mask.add(y * iconRect.width.ceil() + x);
      }
    }
  }
  expect(
    mask.length,
    greaterThan(8),
    reason: 'The real Material icon must be visible, not a missing font.',
  );
  return mask;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    final bytes = await File(
      '.toolchain/flutter/bin/cache/artifacts/material_fonts/materialicons-regular.otf',
    ).readAsBytes();
    final loader = FontLoader('MaterialIcons')
      ..addFont(Future.value(ByteData.sublistView(bytes)));
    await loader.load();
  });

  for (final size in [const Size(900, 800), const Size(1440, 900)]) {
    for (final mode in [ThemeMode.light, ThemeMode.dark]) {
      testWidgets(
        'settings category emblems remain painted through selection, hover and rebuild at $size/$mode',
        (tester) async {
          tester.view.physicalSize = size;
          tester.view.devicePixelRatio = 1;
          addTearDown(tester.view.resetPhysicalSize);
          addTearDown(tester.view.resetDevicePixelRatio);
          final app = _SettingsController(mode);
          addTearDown(app.dispose);
          final boundaryKey = GlobalKey();
          await tester.pumpWidget(
            RepaintBoundary(
              key: boundaryKey,
              child: FuzeVpnApp(controller: app),
            ),
          );
          await tester.pumpAndSettle();
          final mouse = await tester.createGesture(
            kind: PointerDeviceKind.mouse,
          );
          await mouse.addPointer(location: Offset.zero);
          addTearDown(mouse.removePointer);
          for (final category in <({String name, IconData icon})>[
            (name: 'general', icon: Icons.palette_outlined),
            (name: 'connection', icon: Icons.sync_outlined),
            (name: 'privacy', icon: Icons.shield_outlined),
            (name: 'updates', icon: Icons.system_update_alt),
          ]) {
            // Start with this emblem unselected and without an active ink ripple.
            final other = category.name == 'general' ? 'connection' : 'general';
            tester.widget<ChoiceChip>(_category(other)).onSelected!(true);
            await tester.pumpAndSettle();
            final baseline = await _paintedGlyph(
              tester,
              boundaryKey,
              category.name,
              category.icon,
            );
            tester.widget<ChoiceChip>(_category(category.name)).onSelected!(
              true,
            );
            for (final milliseconds in [0, 16, 35, 70, 180]) {
              app.rebuildFromObservation();
              await tester.pump(Duration(milliseconds: milliseconds));
              final frame = await _paintedGlyph(
                tester,
                boundaryKey,
                category.name,
                category.icon,
              );
              expect(
                frame,
                baseline,
                reason:
                    '${category.name}: glyph changed during selection frame $milliseconds',
              );
            }
            await mouse.moveTo(tester.getCenter(_category(category.name)));
            for (final milliseconds in [16, 100, 200]) {
              app.rebuildFromObservation();
              await tester.pump(Duration(milliseconds: milliseconds));
              expect(
                await _paintedGlyph(
                  tester,
                  boundaryKey,
                  category.name,
                  category.icon,
                ),
                baseline,
                reason:
                    '${category.name}: glyph changed during hover/observation',
              );
            }
            await mouse.moveTo(Offset.zero);
            tester.widget<ChoiceChip>(_category(other)).onSelected!(true);
            for (final milliseconds in [0, 16, 70, 180]) {
              await tester.pump(Duration(milliseconds: milliseconds));
              expect(
                await _paintedGlyph(
                  tester,
                  boundaryKey,
                  category.name,
                  category.icon,
                ),
                baseline,
                reason: '${category.name}: glyph changed during deselection',
              );
            }
          }
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        },
      );
    }
  }
}
