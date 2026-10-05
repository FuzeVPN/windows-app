// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/location_directory.dart';
import 'package:fuzevpn_windows/core/models.dart';

Location _location(
  String id, {
  String country = 'DE',
  String city = 'Frankfurt',
  String? label,
  Set<VpnProtocol> protocols = const {VpnProtocol.wireGuard},
}) => Location(
  id: id,
  countryCode: country,
  city: city,
  displayName: label ?? id,
  supportedProtocols: protocols,
);

Location? _choose(
  List<Location> candidates, {
  String? selected,
  VpnProtocolPreference preference = VpnProtocolPreference.automatic,
  bool openVpnAvailable = true,
}) => preferredLocationForGroup(
  candidates,
  selectedLocationId: selected,
  protocolPreference: preference,
  openVpnRuntimeAvailable: openVpnAvailable,
);

void main() {
  group('Location directory', () {
    test('normalizes country and city keys, preserves actual city label', () {
      final first = _location('de-1', country: ' de ', city: ' Frankfurt ');
      final second = _location('de-2', country: 'DE', city: 'frankfurt');
      final directory = buildLocationDirectory([first, second]);

      expect(directory, hasLength(1));
      expect(directory.single.countryCode, 'DE');
      expect(directory.single.cities, hasLength(1));
      expect(directory.single.cities.single.city, 'Frankfurt');
      expect(directory.single.cities.single.locations, [first, second]);
    });

    test(
      'does not combine identically named cities in different countries',
      () {
        final german = _location('de-1', city: 'Same city');
        final french = _location('fr-1', country: 'FR', city: 'Same city');
        final directory = buildLocationDirectory([german, french]);

        expect(directory.map((country) => country.countryCode), ['DE', 'FR']);
        expect(directory.first.cities.single.locations, [german]);
        expect(directory.last.cities.single.locations, [french]);
      },
    );

    test('keeps first encountered countries, cities, and server order', () {
      final paris = _location('paris', country: 'FR', city: 'Paris');
      final frankfurt1 = _location('frankfurt-1');
      final berlin = _location('berlin', city: 'Berlin');
      final frankfurt2 = _location('frankfurt-2');
      final directory = buildLocationDirectory([
        paris,
        frankfurt1,
        berlin,
        frankfurt2,
      ]);

      expect(directory.map((country) => country.countryCode), ['FR', 'DE']);
      expect(directory.last.cities.map((city) => city.city), [
        'Frankfurt',
        'Berlin',
      ]);
      expect(directory.last.locations, [frankfurt1, berlin, frankfurt2]);
      expect(directory.last.cities.first.locations, [frankfurt1, frankfurt2]);
    });

    test('uses the trimmed server name if its city is absent', () {
      final server = _location('unknown-1', city: ' ', label: ' Node 1 ');
      expect(
        buildLocationDirectory([server]).single.cities.single.city,
        'Node 1',
      );
    });

    test('does not infer city names by removing numbers', () {
      final first = _location('first', city: 'District 1');
      final second = _location('second', city: 'District 2');
      final directory = buildLocationDirectory([first, second]);
      expect(directory.single.cities.map((city) => city.city), [
        'District 1',
        'District 2',
      ]);
    });

    test(
      'rebuilding after capacity filtering retains only published servers',
      () {
        final omitted = _location('full-server');
        final available = _location('available-server');
        expect(
          buildLocationDirectory([omitted, available]).single.locations,
          hasLength(2),
        );
        final refreshed = buildLocationDirectory([available]);
        expect(refreshed.single.locations, [available]);
        expect(refreshed.single.cities.single.locations, [available]);
        expect(
          _choose(refreshed.single.locations, selected: omitted.id),
          same(available),
        );
      },
    );

    test('empty catalogue has no invented groups', () {
      expect(buildLocationDirectory([]), isEmpty);
    });

    test('directory is immutable and independent of its input list', () {
      final server = _location('server');
      final input = [server];
      final directory = buildLocationDirectory(input);
      input.clear();
      expect(directory.single.locations, [server]);
      expect(() => directory.clear(), throwsUnsupportedError);
      expect(() => directory.single.cities.clear(), throwsUnsupportedError);
      expect(() => directory.single.locations.clear(), throwsUnsupportedError);
      expect(
        () => directory.single.cities.single.locations.clear(),
        throwsUnsupportedError,
      );
    });
  });

  group('Group server selection', () {
    final wireGuard = _location('wg');
    final secondWireGuard = _location('wg-2');
    final openVpn = _location('ovpn', protocols: {VpnProtocol.openVpn});
    final both = _location(
      'both',
      protocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
    );
    final unsupported = _location('unsupported', protocols: {});

    test('retains a selected compatible server before applying ordering', () {
      expect(
        _choose([wireGuard, secondWireGuard], selected: secondWireGuard.id),
        same(secondWireGuard),
      );
    });

    test('retains compatible OpenVPN selection in automatic mode', () {
      expect(
        _choose([wireGuard, openVpn], selected: openVpn.id),
        same(openVpn),
      );
    });

    test('ignores a selected ID outside the supplied group', () {
      expect(
        _choose([wireGuard, secondWireGuard], selected: 'omitted-server'),
        same(wireGuard),
      );
    });

    test('ignores selection incompatible with the explicit protocol', () {
      expect(
        _choose(
          [openVpn, wireGuard],
          selected: openVpn.id,
          preference: VpnProtocolPreference.wireGuard,
        ),
        same(wireGuard),
      );
    });

    test('preserves caller favourites ordering among compatible servers', () {
      expect(_choose([secondWireGuard, wireGuard]), same(secondWireGuard));
      expect(_choose([wireGuard, secondWireGuard]), same(wireGuard));
    });

    test('automatic prefers WireGuard before an earlier OpenVPN candidate', () {
      expect(_choose([openVpn, wireGuard]), same(wireGuard));
    });

    test('automatic permits available OpenVPN when no WireGuard exists', () {
      expect(_choose([unsupported, openVpn]), same(openVpn));
    });

    test('automatic does not choose OpenVPN without its runtime', () {
      expect(_choose([openVpn], openVpnAvailable: false), isNull);
    });

    test('automatic ignores selected OpenVPN without its runtime', () {
      expect(
        _choose(
          [openVpn, wireGuard],
          selected: openVpn.id,
          openVpnAvailable: false,
        ),
        same(wireGuard),
      );
    });

    test(
      'explicit WireGuard accepts a dual-protocol server without OpenVPN',
      () {
        expect(
          _choose(
            [openVpn, both],
            preference: VpnProtocolPreference.wireGuard,
            openVpnAvailable: false,
          ),
          same(both),
        );
      },
    );

    test(
      'explicit OpenVPN skips WireGuard-only nodes and preserves ordering',
      () {
        expect(
          _choose([
            wireGuard,
            openVpn,
            both,
          ], preference: VpnProtocolPreference.openVpn),
          same(openVpn),
        );
      },
    );

    test('explicit OpenVPN cannot select a node while runtime unavailable', () {
      expect(
        _choose(
          [both, openVpn],
          selected: both.id,
          preference: VpnProtocolPreference.openVpn,
          openVpnAvailable: false,
        ),
        isNull,
      );
    });

    test('no matching protocol leaves the group unselected', () {
      expect(
        _choose([wireGuard], preference: VpnProtocolPreference.openVpn),
        isNull,
      );
      expect(_choose([unsupported]), isNull);
    });

    test('empty group has no preferred server', () {
      expect(_choose([], selected: wireGuard.id), isNull);
    });
  });
}
