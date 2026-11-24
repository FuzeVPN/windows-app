// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';

import 'package:flutter/services.dart';

import 'models.dart';
import 'split_tunnel.dart';

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
  static const _renewableSession = 'renewable_session';
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
  static const _splitTunnelSettings = 'split_tunnel_settings';
  static const _currentDeviceId = 'current_device_id';
  static const _migrationId = 'location_migration_id';
  static const _migrationDeviceId = 'location_migration_device_id';
  static const _migrationTargetLocationId =
      'location_migration_target_location_id';
  static const _migrationUserId = 'location_migration_user_id';
  static const _migrationState = 'location_migration_state';
  // The OpenVPN renewal marker shares the migration record: both mark a
  // server operation to resume for a device after a restart, neither holds a
  // secret, and the native store only accepts its fixed key list.
  static const _openVpnRenewalDevice = 'openvpn_renewal_device';
  static const _openVpnRenewalCsr = 'openvpn_renewal_csr_sha256';
  static const _openVpnEntries = [_openVpnRenewalDevice, _openVpnRenewalCsr];
  static const _channel = MethodChannel('com.fuzevpn/windows_secure_store');
  // Serializes the record's read-modify-write updates.
  Future<void> _migrationStateUpdates = Future.value();

  /// The renewable session's access token when one is stored, else the
  /// classic session token.
  Future<String?> token() async =>
      (await renewableSession())?.accessToken ?? await _read(_token);

  /// Stores a classic session, which replaces any renewable one.
  Future<void> saveToken(String value) async {
    await _delete(_renewableSession);
    await _write(_token, value);
  }

  Future<void> clearToken() async {
    await _delete(_renewableSession);
    await _delete(_token);
  }

  Future<RenewableSession?> renewableSession() async {
    final value = await _read(_renewableSession);
    return value == null ? null : RenewableSession.decode(value);
  }

  /// One atomic replacement of the record (see secure_store_channel.cpp).
  Future<void> saveRenewableSession(RenewableSession value) =>
      _write(_renewableSession, value.encode());

  /// Returns to the classic session, whose token stays stored.
  Future<void> clearRenewableSession() => _delete(_renewableSession);
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

  /// Absent means never configured: split tunneling stays off. A present
  /// but unreadable record is an error, never silently replaced.
  Future<SplitTunnelSettings> splitTunnelSettings() async {
    final stored = await _read(_splitTunnelSettings);
    if (stored == null) return SplitTunnelSettings.disabled;
    final parsed = SplitTunnelSettings.tryParse(stored);
    if (parsed == null) {
      throw const FormatException('Réglages du tunnel fractionné illisibles.');
    }
    return parsed;
  }

  Future<void> saveSplitTunnelSettings(SplitTunnelSettings value) =>
      _write(_splitTunnelSettings, value.toStorageValue());

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

  Future<void> saveLocationMigration(StoredLocationMigration value) =>
      _updateMigrationState((state) async {
        state['migration'] = _encodeMigration(value);
        return true;
      }, keepUnreadable: false);

  Future<void> clearLocationMigration() async {
    // Keep an atomic tombstone so incomplete legacy cleanup cannot resurrect
    // an older migration on the next launch.
    await _updateMigrationState((state) async {
      state['migration'] = null;
      return true;
    }, keepUnreadable: false);
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

  /// The device whose OpenVPN renewal was requested but whose renewed
  /// certificate has not connected yet. Only identifiers are stored.
  Future<String?> openVpnRenewalDeviceId() async {
    final value = await _openVpnRecord();
    final deviceId = value?[_openVpnRenewalDevice];
    return deviceId is String && deviceId.isNotEmpty ? deviceId : null;
  }

  /// The SHA-256 of the pending CSR that renewal was requested for, when the
  /// marker recorded it.
  Future<String?> openVpnRenewalCsrSha256() async {
    final value = await _openVpnRecord();
    final fingerprint = value?[_openVpnRenewalCsr];
    return value?[_openVpnRenewalDevice] is String && _isSha256(fingerprint)
        ? fingerprint as String
        : null;
  }

  Future<void> saveOpenVpnRenewalDeviceId(
    String deviceId, {
    String? csrSha256,
  }) => _updateMigrationState((state) async {
    if (state[_openVpnRenewalDevice] == deviceId &&
        state[_openVpnRenewalCsr] == csrSha256) {
      return false;
    }
    await _commitLegacyMigration(state);
    state[_openVpnRenewalDevice] = deviceId;
    if (csrSha256 == null) {
      state.remove(_openVpnRenewalCsr);
    } else {
      state[_openVpnRenewalCsr] = csrSha256;
    }
    return true;
  }, keepUnreadable: true);

  Future<void> clearOpenVpnRenewalDeviceId() =>
      _updateMigrationState((state) async {
        final device = state.remove(_openVpnRenewalDevice);
        final fingerprint = state.remove(_openVpnRenewalCsr);
        return device != null || fingerprint != null;
      }, keepUnreadable: true);

  Future<Map<String, dynamic>?> _openVpnRecord() async {
    final state = await _read(_migrationState);
    if (state == null) return null;
    final value = jsonDecode(state);
    if (value is! Map<String, dynamic> || value['version'] != 1) {
      throw const FormatException('Reprise de changement de serveur invalide.');
    }
    return value;
  }

  static bool _isSha256(Object? value) =>
      value is String && RegExp(r'^[0-9a-f]{64}$').hasMatch(value);

  /// A first write of the record commits the legacy migration it would
  /// otherwise hide.
  Future<void> _commitLegacyMigration(Map<String, dynamic> state) async {
    if (state.containsKey('migration')) return;
    final legacy = await locationMigration();
    state['migration'] = legacy == null ? null : _encodeMigration(legacy);
  }

  /// Applies [update] to the record and writes it when [update] reports a
  /// change. With [keepUnreadable], an unreadable record is never replaced
  /// (a renewal marker never discards a migration); otherwise the migration
  /// replaces it, as it always did. Every entry this version knows is kept;
  /// entries an earlier version wrote and this one no longer reads are not
  /// written again.
  Future<void> _updateMigrationState(
    Future<bool> Function(Map<String, dynamic> state) update, {
    required bool keepUnreadable,
  }) {
    final result = _migrationStateUpdates.then((_) async {
      Map<String, dynamic> state;
      try {
        final stored = await _read(_migrationState);
        final value = stored == null ? null : jsonDecode(stored);
        if (stored != null &&
            (value is! Map<String, dynamic> || value['version'] != 1)) {
          throw const FormatException(
            'Reprise de changement de serveur invalide.',
          );
        }
        state = value == null ? {'version': 1} : value as Map<String, dynamic>;
      } catch (_) {
        if (keepUnreadable) rethrow;
        state = {'version': 1};
      }
      if (!await update(state)) return;
      await _write(
        _migrationState,
        jsonEncode({
          'version': 1,
          'migration': state['migration'],
          for (final key in _openVpnEntries)
            if (state[key] case final String value) key: value,
        }),
      );
    });
    _migrationStateUpdates = result.then<void>((_) {}, onError: (_) {});
    return result;
  }

  static Map<String, String> _encodeMigration(StoredLocationMigration value) =>
      {
        'id': value.migrationId,
        'device': value.deviceId,
        'target': value.targetLocationId,
        'user': value.userId,
      };

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
