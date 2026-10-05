// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';

import 'package:flutter/services.dart';

import 'models.dart';

class SecuritySettings {
  const SecuritySettings({
    required this.killSwitch,
    required this.dnsProtection,
    required this.webRtcProtection,
    required this.automaticReconnect,
  });

  static const secureDefaults = SecuritySettings(
    killSwitch: true,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: true,
  );

  final bool killSwitch;
  final bool dnsProtection;
  final bool webRtcProtection;
  final bool automaticReconnect;

  String toStorageValue() =>
      'v3|${killSwitch ? 1 : 0}|${dnsProtection ? 1 : 0}|'
      '${webRtcProtection ? 1 : 0}|'
      '${automaticReconnect ? 1 : 0}';

  static SecuritySettings? tryParse(String? value) {
    final parts = value?.split('|');
    if (parts == null) return null;
    if (parts.length == 5 && parts.first == 'v3') {
      final values = parts.skip(1).map(_parseBoolean).toList();
      if (values.any((value) => value == null)) return null;
      return SecuritySettings(
        killSwitch: values[0]!,
        dnsProtection: values[1]!,
        webRtcProtection: values[2]!,
        automaticReconnect: values[3]!,
      );
    }
    if (parts.length == 6 && parts.first == 'v2') {
      final values = parts.skip(1).map(_parseBoolean).toList();
      if (values.any((value) => value == null)) return null;
      return SecuritySettings(
        killSwitch: values[0]!,
        dnsProtection: values[1]!,
        webRtcProtection: values[3]!,
        automaticReconnect: values[4]!,
      );
    }
    if (parts.length == 5 && parts.first == 'v1') {
      final values = parts.skip(1).map(_parseBoolean).toList();
      if (values.any((value) => value == null)) return null;
      return SecuritySettings(
        killSwitch: values[0]!,
        dnsProtection: values[1]!,
        webRtcProtection: true,
        automaticReconnect: values[3]!,
      );
    }
    return null;
  }

  static bool? _parseBoolean(String value) => switch (value) {
    '1' => true,
    '0' => false,
    _ => null,
  };
}

class SecureStore {
  static const _token = 'access_token';
  static const _selectedLocation = 'selected_location';
  static const _themeMode = 'theme_mode';
  static const _vpnProtocol = 'vpn_protocol';
  static const _appLanguage = 'app_language';
  static const _killSwitch = 'kill_switch';
  static const _dnsProtection = 'dns_protection';
  static const _automaticReconnect = 'automatic_reconnect';
  static const _autoConnectOnLaunch = 'auto_connect_on_launch';
  static const _windowsNotifications = 'windows_notifications';
  static const _favoriteLocations = 'favorite_locations';
  static const _recentLocations = 'recent_locations';
  static const _securitySettings = 'security_settings';
  static const _currentDeviceId = 'current_device_id';
  static const _migrationId = 'location_migration_id';
  static const _migrationDeviceId = 'location_migration_device_id';
  static const _migrationTargetLocationId =
      'location_migration_target_location_id';
  static const _migrationUserId = 'location_migration_user_id';
  static const _migrationState = 'location_migration_state';
  static const _channel = MethodChannel('com.fuzevpn/windows_secure_store');
  Future<String?> token() => _read(_token);
  Future<void> saveToken(String value) => _write(_token, value);
  Future<void> clearToken() => _delete(_token);
  Future<String?> selectedLocation() => _read(_selectedLocation);
  Future<void> saveSelectedLocation(String value) =>
      _write(_selectedLocation, value);
  Future<String?> themeMode() => _read(_themeMode);
  Future<void> saveThemeMode(String value) => _write(_themeMode, value);
  Future<String?> vpnProtocol() => _read(_vpnProtocol);
  Future<void> saveVpnProtocol(String value) => _write(_vpnProtocol, value);
  Future<String?> appLanguage() => _read(_appLanguage);
  Future<void> saveAppLanguage(String value) => _write(_appLanguage, value);
  Future<String?> killSwitch() => _read(_killSwitch);
  Future<void> saveKillSwitch(bool value) =>
      _write(_killSwitch, value ? 'true' : 'false');
  Future<String?> dnsProtection() => _read(_dnsProtection);
  Future<void> saveDnsProtection(bool value) =>
      _write(_dnsProtection, value ? 'true' : 'false');
  Future<String?> automaticReconnect() => _read(_automaticReconnect);
  Future<void> saveAutomaticReconnect(bool value) =>
      _write(_automaticReconnect, value ? 'true' : 'false');
  Future<String?> autoConnectOnLaunch() => _read(_autoConnectOnLaunch);
  Future<void> saveAutoConnectOnLaunch(bool value) =>
      _write(_autoConnectOnLaunch, value ? 'true' : 'false');
  Future<String?> windowsNotifications() => _read(_windowsNotifications);
  Future<void> saveWindowsNotifications(bool value) =>
      _write(_windowsNotifications, value ? 'true' : 'false');
  Future<List<String>> favoriteLocationIds() async =>
      _decodeLocationIds(await _read(_favoriteLocations));
  Future<void> saveFavoriteLocationIds(Iterable<String> values) =>
      _write(_favoriteLocations, _encodeLocationIds(values));
  Future<List<String>> recentLocationIds() async =>
      _decodeLocationIds(await _read(_recentLocations));
  Future<void> saveRecentLocationIds(Iterable<String> values) =>
      _write(_recentLocations, _encodeLocationIds(values));
  Future<SecuritySettings> securitySettings() async {
    // A failed read is not an absent value: never overwrite an unreadable
    // record with legacy settings or a weaker default.
    final storedValue = await _read(_securitySettings);
    final stored = SecuritySettings.tryParse(storedValue);
    if (stored != null) {
      if (!(storedValue?.startsWith('v3|') ?? false)) {
        try {
          await saveSecuritySettings(stored);
        } catch (_) {
          // Older secure values remain usable if their v3 migration fails.
        }
      }
      return stored;
    }
    if (storedValue != null) {
      throw const FormatException('Préférences de sécurité illisibles.');
    }

    // Migrate the remaining legacy preferences once. IPv6 protection is no
    // longer a preference: it is mandatory in the native tunnel layer.
    // WebRTC did not have a legacy key, so it receives the secure default.
    final legacyValues = await Future.wait([
      _readLegacySetting(killSwitch),
      _readLegacySetting(dnsProtection),
      _readLegacySetting(automaticReconnect),
    ]);
    final migrated = SecuritySettings(
      killSwitch: legacyValues[0] != 'false',
      dnsProtection: legacyValues[1] != 'false',
      webRtcProtection: true,
      automaticReconnect: legacyValues[2] != 'false',
    );
    try {
      await saveSecuritySettings(migrated);
    } catch (_) {
      // Reading remains possible even if the one-time migration cannot be
      // committed. The controller will still use the recovered values.
    }
    return migrated;
  }

  Future<void> saveSecuritySettings(SecuritySettings value) =>
      _write(_securitySettings, value.toStorageValue());

  Future<String?> _readLegacySetting(Future<String?> Function() reader) async {
    try {
      return await reader();
    } catch (_) {
      return null;
    }
  }

  Future<String?> currentDeviceId() => _read(_currentDeviceId);
  Future<void> saveCurrentDeviceId(String value) =>
      _write(_currentDeviceId, value);
  Future<void> clearCurrentDeviceId() => _delete(_currentDeviceId);
  Future<StoredLocationMigration?> locationMigration() async {
    final state = await _read(_migrationState);
    if (state != null) {
      final value = jsonDecode(state);
      if (value is! Map<String, dynamic> ||
          value['version'] != 1 ||
          !value.containsKey('migration')) {
        throw const FormatException(
          'Reprise de changement de serveur invalide.',
        );
      }
      final migration = value['migration'];
      if (migration == null) return null;
      if (migration is! Map<String, dynamic>) {
        throw const FormatException(
          'Reprise de changement de serveur invalide.',
        );
      }
      final fields = ['id', 'device', 'target', 'user'];
      if (fields.any(
        (key) =>
            migration[key] is! String || (migration[key] as String).isEmpty,
      )) {
        throw const FormatException(
          'Reprise de changement de serveur incomplète.',
        );
      }
      return StoredLocationMigration(
        migrationId: migration['id'] as String,
        deviceId: migration['device'] as String,
        targetLocationId: migration['target'] as String,
        userId: migration['user'] as String,
      );
    }
    final values = await Future.wait([
      _read(_migrationId),
      _read(_migrationDeviceId),
      _read(_migrationTargetLocationId),
      _read(_migrationUserId),
    ]);
    if (values.any((value) => value == null || value.isEmpty)) return null;
    return StoredLocationMigration(
      migrationId: values[0]!,
      deviceId: values[1]!,
      targetLocationId: values[2]!,
      userId: values[3]!,
    );
  }

  Future<void> saveLocationMigration(StoredLocationMigration value) async {
    await _write(
      _migrationState,
      jsonEncode({
        'version': 1,
        'migration': {
          'id': value.migrationId,
          'device': value.deviceId,
          'target': value.targetLocationId,
          'user': value.userId,
        },
      }),
    );
  }

  Future<void> clearLocationMigration() async {
    // Keep an atomic tombstone so incomplete legacy cleanup cannot resurrect
    // an older migration on the next launch.
    await _write(
      _migrationState,
      jsonEncode({'version': 1, 'migration': null}),
    );
    for (final key in [
      _migrationId,
      _migrationDeviceId,
      _migrationTargetLocationId,
      _migrationUserId,
    ]) {
      try {
        await _delete(key);
      } catch (_) {
        // The authoritative tombstone has already committed the deletion.
      }
    }
  }

  static String _encodeLocationIds(Iterable<String> values) => values
      .where((value) => value.isNotEmpty && !value.contains('\n'))
      .toSet()
      .join('\n');
  static List<String> _decodeLocationIds(String? value) =>
      value
          ?.split('\n')
          .where((item) => item.isNotEmpty)
          .toSet()
          .toList(growable: false) ??
      const [];
  Future<String?> _read(String key) =>
      _channel.invokeMethod<String>('read', {'key': key});
  Future<void> _write(String key, String value) =>
      _channel.invokeMethod<void>('write', {'key': key, 'value': value});
  Future<void> _delete(String key) =>
      _channel.invokeMethod<void>('delete', {'key': key});
}
