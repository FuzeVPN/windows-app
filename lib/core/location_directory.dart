// SPDX-License-Identifier: MPL-2.0
import 'models.dart';

/// A country and its currently published locations, in catalogue order.
class CountryLocationGroup {
  CountryLocationGroup({
    required this.countryCode,
    required List<CityLocationGroup> cities,
    required List<Location> locations,
  }) : cities = List.unmodifiable(cities),
       locations = List.unmodifiable(locations);

  final String countryCode;
  final List<CityLocationGroup> cities;
  final List<Location> locations;
}

class CityLocationGroup {
  CityLocationGroup({required this.city, required List<Location> locations})
    : locations = List.unmodifiable(locations);

  final String city;
  final List<Location> locations;
}

/// Groups only the supplied catalogue. Grouping never restores an omitted node.
///
/// Countries and cities keep their first encountered order. Each group's server
/// order is retained so callers can supply their existing favourites ordering.
List<CountryLocationGroup> buildLocationDirectory(
  Iterable<Location> orderedLocations,
) {
  final countryLocations = <String, List<Location>>{};
  for (final location in orderedLocations) {
    final countryCode = location.countryCode.trim().toUpperCase();
    (countryLocations[countryCode] ??= []).add(location);
  }

  return List.unmodifiable(
    countryLocations.entries.map((country) {
      final cityLocations = <String, List<Location>>{};
      final cityLabels = <String, String>{};
      for (final location in country.value) {
        final trimmedCity = location.city.trim();
        final city = trimmedCity.isEmpty
            ? location.displayName.trim()
            : trimmedCity;
        final cityKey = city.toLowerCase();
        cityLabels.putIfAbsent(cityKey, () => city);
        (cityLocations[cityKey] ??= []).add(location);
      }
      return CountryLocationGroup(
        countryCode: country.key,
        cities: cityLocations.entries
            .map(
              (city) => CityLocationGroup(
                city: cityLabels[city.key]!,
                locations: city.value,
              ),
            )
            .toList(),
        locations: country.value,
      );
    }),
  );
}

/// Chooses a compatible published server without making a network request.
///
/// An existing compatible selection wins. Otherwise automatic mode prefers
/// WireGuard; ties preserve the supplied order, without inferring performance.
Location? preferredLocationForGroup(
  List<Location> orderedCandidates, {
  String? selectedLocationId,
  required VpnProtocolPreference protocolPreference,
  required bool openVpnRuntimeAvailable,
}) {
  bool supportsPreference(Location location) => switch (protocolPreference) {
    VpnProtocolPreference.automatic =>
      location.supportedProtocols.contains(VpnProtocol.wireGuard) ||
          (openVpnRuntimeAvailable &&
              location.supportedProtocols.contains(VpnProtocol.openVpn)),
    VpnProtocolPreference.wireGuard => location.supportedProtocols.contains(
      VpnProtocol.wireGuard,
    ),
    VpnProtocolPreference.openVpn =>
      openVpnRuntimeAvailable &&
          location.supportedProtocols.contains(VpnProtocol.openVpn),
  };

  if (selectedLocationId != null) {
    for (final location in orderedCandidates) {
      if (location.id == selectedLocationId && supportsPreference(location)) {
        return location;
      }
    }
  }
  if (protocolPreference == VpnProtocolPreference.automatic) {
    for (final location in orderedCandidates) {
      if (location.supportedProtocols.contains(VpnProtocol.wireGuard)) {
        return location;
      }
    }
  }
  for (final location in orderedCandidates) {
    if (supportsPreference(location)) return location;
  }
  return null;
}
