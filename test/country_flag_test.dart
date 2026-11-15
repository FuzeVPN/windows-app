// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/country_flag_assets.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

const _pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const _badgeBackground = Color(0xffe4e7ea);

void main() {
  group('bundled flag images', () {
    test('the compiled code set equals the files of assets/flags exactly', () {
      final entries = Directory(
        countryFlagAssetDirectory,
      ).listSync(followLinks: false);
      expect(
        entries.whereType<File>().length,
        entries.length,
        reason:
            'Only regular files: the whole directory ships in the '
            'application.',
      );
      // Asset names are case-sensitive even on a case-insensitive disk.
      expect(entries.map((entry) => entry.uri.pathSegments.last).toSet(), {
        for (final code in bundledCountryFlagCodes) '${code.toLowerCase()}.png',
      });
      expect(
        bundledCountryFlagCodes.where(
          (code) => !RegExp(r'^[A-Z]{2}$').hasMatch(code),
        ),
        isEmpty,
      );
      expect(bundledCountryFlagCodes, contains('RU'));
      expect(countryFlagAsset('RU'), 'assets/flags/ru.png');
      expect(countryFlagAsset('ZZ'), isNull);
    });

    test('every bundled file is the recorded 160-pixel PNG', () {
      final recorded = _recordedFlagDigests();
      expect(recorded.keys.toSet(), {
        for (final code in bundledCountryFlagCodes) '${code.toLowerCase()}.png',
      });
      for (final entry in recorded.entries) {
        final bytes = File(
          '$countryFlagAssetDirectory/${entry.key}',
        ).readAsBytesSync();
        expect(
          sha256.convert(bytes).toString(),
          entry.value,
          reason: entry.key,
        );
        expect(bytes.length, lessThanOrEqualTo(64 * 1024), reason: entry.key);
        expect(bytes.sublist(0, 8), _pngSignature, reason: entry.key);
        expect(ascii.decode(bytes.sublist(12, 16)), 'IHDR', reason: entry.key);
        final header = ByteData.sublistView(bytes, 16, 24);
        expect(header.getUint32(0), countryFlagImageWidth, reason: entry.key);
        expect(
          header.getUint32(4),
          inInclusiveRange(40, 240),
          reason: entry.key,
        );
      }
    });

    testWidgets('the application bundle carries the flags and nothing else '
        'from their directory', (tester) async {
      final recorded = _recordedFlagDigests();
      // The test bundle is rebuilt only when pubspec.yaml or an asset is newer
      // than it: a deleted flag, or one replaced by an older file, leaves it
      // stale.
      const staleBundle =
          'If assets/flags is as expected, delete build/unit_test_assets and '
          'run the test again.';
      await tester.runAsync(() async {
        final manifest = await AssetManifest.loadFromAssetBundle(rootBundle);
        expect(
          manifest
              .listAssets()
              .where((asset) => asset.startsWith('$countryFlagAssetDirectory/'))
              .toSet(),
          {for (final code in bundledCountryFlagCodes) countryFlagAsset(code)},
          reason: staleBundle,
        );
        for (final code in bundledCountryFlagCodes) {
          final data = await rootBundle.load(countryFlagAsset(code)!);
          final bytes = Uint8List.sublistView(data);
          expect(
            sha256.convert(bytes).toString(),
            recorded['${code.toLowerCase()}.png'],
            reason: '$code. $staleBundle',
          );
          final codec = await ui.instantiateImageCodec(bytes);
          final frame = await codec.getNextFrame();
          expect(frame.image.width, countryFlagImageWidth, reason: code);
          frame.image.dispose();
          codec.dispose();
        }
      });
    });
  });

  group('country flag', () {
    testWidgets('a country added by the service shows its bundled flag', (
      tester,
    ) async {
      await _pumpApp(tester, locations: [_location('RU')]);

      final flag = _flag('RU');
      expect(flag, findsOneWidget);
      final image = _imageOf(tester, flag);
      expect(_source(image).asset, 'assets/flags/ru.png');
      expect(image.fit, BoxFit.cover);
      expect(image.filterQuality, FilterQuality.medium);
      expect(image.excludeFromSemantics, isTrue);
      expect(_semanticsLabel(tester, flag), 'Drapeau : RU');
      expect(_within(flag, find.byType(CustomPaint)), findsNothing);
      expect(_within(flag, find.byIcon(Icons.flag_outlined)), findsNothing);

      final box = tester.widget<Container>(
        _within(flag, find.byType(Container)),
      );
      expect(box.clipBehavior, Clip.antiAlias);
      final decoration = box.decoration! as BoxDecoration;
      expect(decoration.borderRadius, BorderRadius.circular(4));
      expect(decoration.border, isNotNull);

      final semantics = tester.ensureSemantics();
      expect(find.bySemanticsLabel('Drapeau : RU'), findsOneWidget);
      semantics.dispose();
    });

    testWidgets('a formerly hand-painted country uses the same flag images', (
      tester,
    ) async {
      await _pumpApp(tester, locations: [_location('FR')]);

      final flag = _flag('FR');
      expect(_source(_imageOf(tester, flag)).asset, 'assets/flags/fr.png');
      expect(_semanticsLabel(tester, flag), 'Drapeau : France');
      expect(_within(flag, find.byType(CustomPaint)), findsNothing);
    });

    testWidgets('lower-case and padded codes resolve to the same flag', (
      tester,
    ) async {
      for (final code in [' ru ', 'ru', '\tRu\n']) {
        await _pumpApp(tester, locations: [_location(code)]);

        final flag = _flag('RU');
        expect(flag, findsOneWidget, reason: '"$code"');
        expect(
          _source(_imageOf(tester, flag)).asset,
          'assets/flags/ru.png',
          reason: '"$code"',
        );
        expect(_semanticsLabel(tester, flag), 'Drapeau : RU');
        await tester.pumpWidget(const SizedBox.shrink());
      }
    });

    testWidgets('an ISO-shaped code without an image shows its code badge', (
      tester,
    ) async {
      expect(bundledCountryFlagCodes, isNot(contains('ZZ')));
      await _pumpApp(tester, locations: [_location('zz')]);

      final flag = _flag('ZZ');
      expect(flag, findsOneWidget);
      expect(_within(flag, find.byType(Image)), findsNothing);
      expect(_within(flag, find.byIcon(Icons.flag_outlined)), findsNothing);
      expect(
        _within(flag, find.byType(CustomPaint)),
        paints
          ..rect(color: _badgeBackground)
          ..paragraph(),
      );
      expect(_semanticsLabel(tester, flag), 'ZZ');
    });

    testWidgets('a value that is not an ISO code shows the generic icon', (
      tester,
    ) async {
      for (final code in ['EUR', 'R1', 'éé', '']) {
        await _pumpApp(tester, locations: [_location(code)]);

        final flag = _flag(code.toUpperCase());
        expect(flag, findsOneWidget, reason: '"$code"');
        expect(
          _within(flag, find.byIcon(Icons.flag_outlined)),
          findsOneWidget,
          reason: '"$code"',
        );
        expect(_within(flag, find.byType(Image)), findsNothing);
        expect(_within(flag, find.byType(CustomPaint)), findsNothing);
        await tester.pumpWidget(const SizedBox.shrink());
      }
    });

    testWidgets('an unreadable flag image falls back to the code badge', (
      tester,
    ) async {
      await _pumpApp(
        tester,
        locations: [_location('RU')],
        bundle: _MissingFlagsBundle(),
      );
      await tester.pump();

      final flag = _flag('RU');
      expect(tester.takeException(), isNull);
      expect(_within(flag, find.byType(RawImage)), findsNothing);
      expect(
        _within(flag, find.byType(CustomPaint)),
        paints
          ..rect(color: _badgeBackground)
          ..paragraph(),
      );
    });

    testWidgets('the flag fills each of its three boxes', (tester) async {
      await _pumpApp(
        tester,
        devicePixelRatio: 2,
        locations: [
          _location('RU', id: 'moscow-1', city: 'Moscow'),
          _location('RU', id: 'moscow-2', city: 'Moscow'),
          _location('QA', id: 'doha-1', city: 'Doha'),
        ],
      );

      // Connection page.
      _expectFlagBox(tester, 'RU', const Size(34, 23), cacheWidth: 92);

      // Country rows, then server rows.
      await tester.tap(find.byTooltip('Emplacements'));
      await tester.pumpAndSettle();
      _expectFlagBox(tester, 'RU', const Size(36, 24), cacheWidth: 96);
      _expectFlagBox(tester, 'QA', const Size(36, 24), cacheWidth: 96);
      await tester.tap(find.byKey(const ValueKey('location-open-country-RU')));
      await tester.pumpAndSettle();
      await tester.tap(
        find.byKey(const ValueKey('location-open-city-RU-moscow')),
      );
      await tester.pumpAndSettle();
      expect(_flag('RU'), findsNWidgets(2));
      _expectFlagBox(tester, 'RU', const Size(36, 24), cacheWidth: 96);

      // Language list.
      await tester.tap(find.byTooltip('Réglages'));
      await tester.pumpAndSettle();
      expect(_flag('FR'), findsOneWidget);
      _expectFlagBox(tester, 'FR', const Size(24, 16), cacheWidth: 80);
    });

    testWidgets('the decoded width follows the screen density', (tester) async {
      // 34 by 23 box: a 2:1 flag covers 46 logical pixels.
      for (final (devicePixelRatio, cacheWidth) in <(double, int?)>[
        (1, 80),
        (1.25, 80),
        (1.75, 81),
        (2, 92),
        (3, 138),
        (3.5, null),
        (4, null),
      ]) {
        await _pumpApp(
          tester,
          devicePixelRatio: devicePixelRatio,
          locations: [_location('RU')],
        );

        expect(
          _source(_imageOf(tester, _flag('RU'))).cacheWidth,
          cacheWidth,
          reason: 'devicePixelRatio $devicePixelRatio',
        );
        await tester.pumpWidget(const SizedBox.shrink());
      }
    });

    testWidgets('the bundled image is decoded and painted in the box', (
      tester,
    ) async {
      // An earlier test may have left the decoded flag in the image cache.
      imageCache.clear();
      imageCache.clearLiveImages();
      await _pumpApp(tester, locations: [_location('RU')]);

      final flag = _flag('RU');
      final image = _within(flag, find.byType(Image));
      expect(
        tester.widget<RawImage>(_within(flag, find.byType(RawImage))).image,
        isNull,
        reason: 'Nothing is decoded before the real asynchronous work runs.',
      );
      await tester.runAsync(
        () => precacheImage(
          tester.widget<Image>(image).image,
          tester.element(image),
        ),
      );
      await tester.pump();

      expect(tester.takeException(), isNull);
      final painted = tester.widget<RawImage>(
        _within(flag, find.byType(RawImage)),
      );
      expect(painted.image, isNotNull);
      expect(painted.image!.width, 80);
      // ru.png is 160 by 107.
      expect(painted.image!.height, inInclusiveRange(53, 54));
      expect(painted.fit, BoxFit.cover);
      expect(painted.filterQuality, FilterQuality.medium);
      expect(
        tester.getSize(_within(flag, find.byType(RawImage))),
        const Size(32, 21),
      );
    });
  });
}

Map<String, String> _recordedFlagDigests() {
  final payload =
      jsonDecode(
            File('third_party/flags/payload-sha256.json').readAsStringSync(),
          )
          as Map<String, dynamic>;
  expect(payload['Directory'], countryFlagAssetDirectory);
  final files = (payload['Files'] as List).cast<Map<String, dynamic>>();
  expect(payload['FileCount'], files.length);
  final digests = {
    for (final file in files) file['Path'] as String: file['Sha256'] as String,
  };
  expect(digests.length, files.length, reason: 'Duplicate recorded path.');
  return digests;
}

Location _location(
  String countryCode, {
  String id = 'node-1',
  String city = 'Ville',
}) => Location(
  id: id,
  city: city,
  countryCode: countryCode,
  displayName: '$city $id',
);

Finder _flag(String normalizedCode) =>
    find.byKey(ValueKey('country-flag-$normalizedCode'));

Finder _within(Finder flag, Finder matching) =>
    find.descendant(of: flag, matching: matching);

Image _imageOf(WidgetTester tester, Finder flag) =>
    tester.widget<Image>(_within(flag.first, find.byType(Image)));

String? _semanticsLabel(WidgetTester tester, Finder flag) =>
    tester.widget<Semantics>(flag.first).properties.label;

({String? asset, int? cacheWidth}) _source(Image image) {
  final provider = image.image;
  if (provider is ResizeImage) {
    expect(provider.height, isNull);
    final original = provider.imageProvider;
    return (
      asset: original is AssetImage ? original.assetName : null,
      cacheWidth: provider.width,
    );
  }
  return (
    asset: provider is AssetImage ? provider.assetName : null,
    cacheWidth: null,
  );
}

void _expectFlagBox(
  WidgetTester tester,
  String code,
  Size size, {
  required int? cacheWidth,
}) {
  final flags = _flag(code);
  expect(flags, findsWidgets, reason: code);
  for (final element in flags.evaluate()) {
    final flag = find.byElementPredicate((candidate) => candidate == element);
    expect(tester.getSize(flag), size, reason: code);
    final image = _imageOf(tester, flag);
    expect(
      _source(image).asset,
      'assets/flags/${code.toLowerCase()}.png',
      reason: code,
    );
    expect(_source(image).cacheWidth, cacheWidth, reason: '$code $size');
    expect(image.fit, BoxFit.cover);
    // The image fills the box inside its one-pixel border.
    expect(
      tester.getSize(_within(flag, find.byType(Image))),
      Size(size.width - 2, size.height - 2),
      reason: code,
    );
  }
}

Future<void> _pumpApp(
  WidgetTester tester, {
  required List<Location> locations,
  double devicePixelRatio = 1,
  AssetBundle? bundle,
}) async {
  const size = Size(1280, 720);
  tester.view.physicalSize = size * devicePixelRatio;
  tester.view.devicePixelRatio = devicePixelRatio;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final controller = _FlagController()
    ..language = AppLanguage.french
    ..locations = locations
    ..selectedLocation = locations.first
    ..isLoadingLocations = false;
  final app = FuzeVpnApp(controller: controller);
  await tester.pumpWidget(
    bundle == null ? app : DefaultAssetBundle(bundle: bundle, child: app),
  );
  await tester.pump();
}

/// Serves everything but the flag images, as a damaged installation would.
class _MissingFlagsBundle extends CachingAssetBundle {
  @override
  Future<ByteData> load(String key) =>
      key.startsWith('$countryFlagAssetDirectory/')
      ? Future<ByteData>.error(FlutterError('Unable to load asset: "$key".'))
      : rootBundle.load(key);
}

class _FlagController extends AppController {
  _FlagController() {
    profile = const UserProfile(
      userId: 'user-flags',
      email: 'flags@example.invalid',
      firstName: 'Test',
      emailVerified: true,
    );
  }

  @override
  Future<void> initialize() async {
    isInitialized = true;
    notifyListeners();
  }

  @override
  Future<void> refreshLocations([String? savedLocation]) async {
    isLoadingLocations = false;
    notifyListeners();
  }

  @override
  Future<void> selectLocation(Location value) async {
    selectedLocation = value;
    notifyListeners();
  }

  @override
  Future<LocationChangePreparation> prepareLocationChange(
    Location value,
  ) async {
    await selectLocation(value);
    return LocationChangePreparation.selectedLocally;
  }
}
