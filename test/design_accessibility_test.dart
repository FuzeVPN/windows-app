// SPDX-License-Identifier: MPL-2.0
// Exercises the actual app controls with synthetic state. No initialization,
// account submission, API call or VPN operation is permitted in this fixture.
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _DesignController extends AppController {
  _DesignController()
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
      ) {
    isInitialized = true;
    isLoadingLocations = false;
    profile = fixtures.account;
    language = AppLanguage.french;
    section = AppSection.settings;
    locations = const [fixtures.source, fixtures.target];
    selectedLocation = fixtures.source;
  }

  @override
  Future<void> initialize() async {}

  @override
  Future<void> quickConnect() =>
      throw StateError('An accessibility test cannot operate a VPN.');

  @override
  Future<void> toggleConnection() =>
      throw StateError('An accessibility test cannot operate a VPN.');

  @override
  Future<void> refreshLocations([String? savedLocation]) =>
      throw StateError('An accessibility test cannot contact the API.');

  @override
  Future<void> refreshDevices() =>
      throw StateError('An accessibility test cannot contact the API.');

  @override
  Future<bool> signIn({required String email, required String password}) =>
      throw StateError('An accessibility test cannot submit credentials.');

  @override
  Future<void> signOut() =>
      throw StateError('An accessibility test cannot change an account.');
}

double _contrast(Color foreground, Color background) {
  final opaque = Color.alphaBlend(foreground, background);
  final a = opaque.computeLuminance();
  final b = background.computeLuminance();
  return (math.max(a, b) + 0.05) / (math.min(a, b) + 0.05);
}

Color _materialBackground(Element element) {
  Color? result;
  element.visitAncestorElements((ancestor) {
    final widget = ancestor.widget;
    if (widget is Material && widget.color?.a == 1) {
      result = widget.color;
      return false;
    }
    return true;
  });
  return result ?? Theme.of(element).colorScheme.surface;
}

bool _hasKeyboardFocus(Element target) {
  final focusedContext = FocusManager.instance.primaryFocus?.context;
  if (focusedContext == null) return false;
  if (focusedContext == target) return true;
  var found = false;
  (focusedContext as Element).visitAncestorElements((ancestor) {
    found = ancestor == target;
    return !found;
  });
  return found;
}

BorderSide _visibleOutline(WidgetTester tester, Finder control) {
  final containers = tester.widgetList<Container>(
    find.descendant(of: control, matching: find.byType(Container)),
  );
  final outlines = containers
      .map((container) => container.decoration)
      .whereType<BoxDecoration>()
      .map((decoration) => decoration.border)
      .whereType<Border>();
  expect(outlines, hasLength(1));
  return outlines.single.top;
}

Future<void> _tabTo(WidgetTester tester, Finder control) async {
  for (var step = 0; step < 18; step++) {
    await tester.sendKeyEvent(LogicalKeyboardKey.tab);
    await tester.pumpAndSettle();
    if (_hasKeyboardFocus(tester.element(control))) return;
  }
  fail('The requested control was not reachable by pressing Tab.');
}

void main() {
  Future<void> mount(WidgetTester tester, _DesignController app) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1280, 720);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(app.dispose);
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
  }

  for (final theme in [ThemeMode.light, ThemeMode.dark]) {
    testWidgets('sign-in field boundaries have sufficient contrast in $theme', (
      tester,
    ) async {
      final app = _DesignController()
        ..themeMode = theme
        ..profile = null;
      await mount(tester, app);
      final fields = find.byType(TextField);
      expect(fields, findsNWidgets(2));
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pumpAndSettle();

      for (final field in fields.evaluate()) {
        final decoratorFinder = find.descendant(
          of: find.byWidget(field.widget),
          matching: find.byType(InputDecorator),
        );
        final decorator = tester.widget<InputDecorator>(decoratorFinder);
        final decoration = decorator.decoration;
        final outside = _materialBackground(tester.element(decoratorFinder));
        final inside = Color.alphaBlend(decoration.fillColor!, outside);
        expect(decorator.isFocused, isFalse);
        expect(decoration.enabled, isTrue);
        for (final border in [
          decoration.enabledBorder!,
          decoration.focusedBorder!,
        ]) {
          expect(border.borderSide.style, BorderStyle.solid);
          expect(border.borderSide.width, greaterThan(0));
          expect(
            _contrast(border.borderSide.color, outside),
            greaterThanOrEqualTo(3),
            reason: '${decoration.labelText}: border against outer surface',
          );
          expect(
            _contrast(border.borderSide.color, inside),
            greaterThanOrEqualTo(3),
            reason: '${decoration.labelText}: border against field fill',
          );
        }
      }
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('Tab and Enter expose navigation and account focus in $theme', (
      tester,
    ) async {
      final app = _DesignController()..themeMode = theme;
      await mount(tester, app);
      final navigation = find.widgetWithText(InkWell, 'Emplacements');
      expect(navigation, findsOneWidget);
      final background = _materialBackground(tester.element(navigation));
      final before = _visibleOutline(tester, navigation);
      expect(_contrast(before.color, background), lessThan(3));

      await _tabTo(tester, navigation);
      final focused = _visibleOutline(tester, navigation);
      expect(focused.width, greaterThan(0));
      expect(_contrast(focused.color, background), greaterThanOrEqualTo(3));
      expect(app.section, AppSection.settings);

      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(app.section, AppSection.locations);

      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      expect(_hasKeyboardFocus(tester.element(navigation)), isFalse);
      expect(
        _contrast(_visibleOutline(tester, navigation).color, background),
        lessThan(_contrast(focused.color, background)),
      );

      final account = find.widgetWithText(InkWell, fixtures.account.firstName);
      expect(account, findsOneWidget);
      await _tabTo(tester, account);
      final accountOutline = _visibleOutline(tester, account);
      expect(accountOutline.width, greaterThan(0));
      expect(
        _contrast(
          accountOutline.color,
          _materialBackground(tester.element(account)),
        ),
        greaterThanOrEqualTo(3),
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(
        find.descendant(
          of: find.byType(AlertDialog),
          matching: find.text('Mon compte'),
        ),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }
}
