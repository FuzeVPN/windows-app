// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

export 'subscription_models.dart';

enum VpnStatus {
  disconnected,
  preparing,
  connecting,
  connected,
  disconnecting,
  blocked,
  error,
}

enum VpnProtocol { wireGuard, openVpn }

/// Applied native policy, independently of the preferences in this window.
/// A WFP session can exist solely for IPv6/DNS/UDP protection and therefore
/// does not by itself prove that ordinary IPv4 traffic is blocked.
class NetworkProtectionStatus {
  const NetworkProtectionStatus({
    required this.active,
    required this.killSwitch,
    required this.phase,
    this.ownedByAnotherUser = false,
  });

  final bool active;
  final bool killSwitch;
  final String phase;
  final bool ownedByAnotherUser;
  bool get blocksTraffic => active && killSwitch;

  factory NetworkProtectionStatus.fromMap(Map<Object?, Object?> value) {
    final active = value['active'];
    final killSwitch = value['killSwitch'];
    final phase = value['phase'];
    final ownedByAnotherUser = value['ownedByAnotherUser'] ?? false;
    if (active is! bool ||
        killSwitch is! bool ||
        phase is! String ||
        ownedByAnotherUser is! bool ||
        !{'inactive', 'prepared', 'tunnel'}.contains(phase) ||
        active != (phase != 'inactive')) {
      throw const FormatException('État de protection réseau invalide.');
    }
    return NetworkProtectionStatus(
      active: active,
      killSwitch: killSwitch,
      phase: phase,
      ownedByAnotherUser: ownedByAnotherUser,
    );
  }
}

enum IpFamily { ipv4, ipv6 }

const dualStackIpFamilies = <IpFamily>[IpFamily.ipv4, IpFamily.ipv6];

IpFamily? ipFamilyFromApi(String value) => switch (value) {
  'ipv4' => IpFamily.ipv4,
  'ipv6' => IpFamily.ipv6,
  _ => null,
};

extension IpFamilyApiValue on IpFamily {
  String get apiValue => switch (this) {
    IpFamily.ipv4 => 'ipv4',
    IpFamily.ipv6 => 'ipv6',
  };
}

/// User preference. `automatic` is resolved locally to a concrete protocol
/// before any API or native tunnel call is made.
enum VpnProtocolPreference { automatic, wireGuard, openVpn }

enum LocationMigrationStatus { draining, activating, ready, blocked }

const _maxOpenVpnCertificatePemBytes = 64 * 1024;
const _maxOpenVpnTlsCryptV2KeyBytes = 8 * 1024;

bool _isStrictPemSequence(
  String value, {
  required String label,
  required int maxBytes,
  required bool allowMultiple,
}) {
  if (value.isEmpty ||
      utf8.encode(value).length > maxBytes ||
      value.contains('\u0000')) {
    return false;
  }

  final normalized = value.replaceAll('\r\n', '\n');
  if (normalized.contains('\r')) return false;

  final lines = normalized.split('\n');
  final begin = '-----BEGIN $label-----';
  final end = '-----END $label-----';
  var index = 0;
  var blockCount = 0;

  while (index < lines.length && lines[index].isNotEmpty) {
    if (lines[index++] != begin) return false;

    final payload = StringBuffer();
    var payloadLines = 0;
    while (index < lines.length && lines[index] != end) {
      final line = lines[index++];
      if (line.isEmpty ||
          line.length > 64 ||
          !RegExp(r'^[A-Za-z0-9+/]*={0,2}$').hasMatch(line)) {
        return false;
      }
      payload.write(line);
      payloadLines++;
    }
    if (payloadLines == 0 || index >= lines.length || lines[index++] != end) {
      return false;
    }

    try {
      if (base64Decode(payload.toString()).isEmpty) return false;
    } on FormatException {
      return false;
    }

    blockCount++;
    while (index < lines.length && lines[index].isEmpty) {
      index++;
    }
    if (!allowMultiple && index < lines.length) return false;
  }

  return blockCount > 0 && (allowMultiple || blockCount == 1);
}

LocationMigrationStatus? locationMigrationStatusFromApi(String value) =>
    switch (value) {
      'draining' => LocationMigrationStatus.draining,
      'activating' => LocationMigrationStatus.activating,
      'ready' => LocationMigrationStatus.ready,
      'blocked' => LocationMigrationStatus.blocked,
      _ => null,
    };

/// Public, non-secret state of an asynchronous device location change.
class LocationMigration {
  const LocationMigration({
    required this.migrationId,
    required this.deviceId,
    required this.sourceLocationId,
    required this.targetLocationId,
    required this.status,
    required this.retryAfterSeconds,
  });

  final String migrationId;
  final String deviceId;
  final String sourceLocationId;
  final String targetLocationId;
  final LocationMigrationStatus status;
  final int retryAfterSeconds;

  factory LocationMigration.fromJson(
    Map<String, dynamic> json, {
    required String expectedDeviceId,
    int? retryAfterSeconds,
  }) {
    String requiredIdentifier(String key) {
      final value = json[key];
      if (value is! String ||
          !RegExp(r'^[A-Za-z0-9_-]{1,128}$').hasMatch(value)) {
        throw const FormatException('Migration d’emplacement invalide.');
      }
      return value;
    }

    final deviceId = requiredIdentifier('device_id');
    final statusValue = json['status'];
    final status = statusValue is String
        ? locationMigrationStatusFromApi(statusValue)
        : null;
    if (deviceId != expectedDeviceId || status == null) {
      throw const FormatException('Migration d’emplacement invalide.');
    }
    final bodyRetryAfter = json['retry_after_seconds'];
    final bodySeconds = bodyRetryAfter is int
        ? bodyRetryAfter
        : bodyRetryAfter is num &&
              bodyRetryAfter == bodyRetryAfter.roundToDouble()
        ? bodyRetryAfter.toInt()
        : null;
    final seconds = retryAfterSeconds ?? bodySeconds ?? 2;
    if (seconds < 0 || seconds > 120) {
      throw const FormatException('Migration d’emplacement invalide.');
    }
    return LocationMigration(
      migrationId: requiredIdentifier('migration_id'),
      deviceId: deviceId,
      sourceLocationId: requiredIdentifier('source_location_id'),
      targetLocationId: requiredIdentifier('target_location_id'),
      status: status,
      retryAfterSeconds: seconds,
    );
  }
}

/// DPAPI-protected resume marker. It contains only opaque public identifiers.
class StoredLocationMigration {
  const StoredLocationMigration({
    required this.migrationId,
    required this.deviceId,
    required this.targetLocationId,
    required this.userId,
  });

  final String migrationId;
  final String deviceId;
  final String targetLocationId;
  final String userId;
}

VpnProtocol? vpnProtocolFromApi(String value) => switch (value) {
  'wireguard' => VpnProtocol.wireGuard,
  'openvpn' => VpnProtocol.openVpn,
  _ => null,
};

class Location {
  const Location({
    required this.id,
    required this.city,
    required this.countryCode,
    required this.displayName,
    this.supportedProtocols = const {VpnProtocol.wireGuard},
    this.supportedIpFamilies = const {IpFamily.ipv4},
  });
  final String id;
  final String city;
  final String countryCode;
  final String displayName;
  final Set<VpnProtocol> supportedProtocols;
  final Set<IpFamily> supportedIpFamilies;

  bool get supportsIpv6 => supportedIpFamilies.contains(IpFamily.ipv6);

  factory Location.fromJson(Map<String, dynamic> json) {
    final protocols = (json['supported_protocols'] as List? ?? const [])
        .whereType<String>()
        .map(vpnProtocolFromApi)
        .whereType<VpnProtocol>()
        .toSet();
    final families = (json['supported_ip_families'] as List? ?? const [])
        .whereType<String>()
        .map(ipFamilyFromApi)
        .whereType<IpFamily>()
        .toSet();
    return Location(
      id: json['id'] as String,
      city: json['city'] as String,
      countryCode: json['country_code'] as String,
      displayName: json['display_name'] as String,
      supportedProtocols: protocols.isEmpty
          ? const {VpnProtocol.wireGuard}
          : protocols,
      supportedIpFamilies: families.isEmpty ? const {IpFamily.ipv4} : families,
    );
  }
}

class _TunnelIpConfiguration {
  const _TunnelIpConfiguration({
    required this.addresses,
    required this.allowedIps,
    required this.ipFamilies,
  });

  final List<String> addresses;
  final List<String> allowedIps;
  final List<IpFamily> ipFamilies;
}

bool _isIpv4Cidr(String value) {
  final parts = value.split('/');
  final prefix = parts.length == 2 ? int.tryParse(parts[1]) : null;
  return parts.length == 2 &&
      prefix != null &&
      prefix >= 0 &&
      prefix <= 32 &&
      InternetAddress.tryParse(parts[0])?.type == InternetAddressType.IPv4;
}

bool _isUlaIpv6HostCidr(String value) {
  final parts = value.split('/');
  if (parts.length != 2 || parts[1] != '128') return false;
  final address = InternetAddress.tryParse(parts[0]);
  return address?.type == InternetAddressType.IPv6 &&
      address!.rawAddress.isNotEmpty &&
      (address.rawAddress.first & 0xfe) == 0xfc;
}

List<String> _stringList(Object? value) {
  if (value is! List || value.any((item) => item is! String)) {
    throw const FormatException('Configuration réseau invalide.');
  }
  return value.cast<String>().toList(growable: false);
}

_TunnelIpConfiguration _parseTunnelIpConfiguration(
  Map<String, dynamic> json, {
  required String address,
  required List<String> historicalAllowedIps,
}) {
  if (!_isIpv4Cidr(address)) {
    throw const FormatException('Configuration réseau invalide.');
  }

  final hasAddresses = json.containsKey('addresses');
  final hasFamilies = json.containsKey('ip_families');
  if (!hasAddresses && !hasFamilies) {
    return _TunnelIpConfiguration(
      addresses: List.unmodifiable([address]),
      allowedIps: List.unmodifiable(historicalAllowedIps),
      ipFamilies: const [IpFamily.ipv4],
    );
  }
  if (!hasAddresses || !hasFamilies) {
    throw const FormatException('Configuration réseau invalide.');
  }

  final addresses = _stringList(json['addresses']);
  final rawFamilies = _stringList(json['ip_families']);
  final allowedIps = json.containsKey('allowed_ips')
      ? _stringList(json['allowed_ips'])
      : historicalAllowedIps;

  if (rawFamilies.length == 1 &&
      rawFamilies[0] == 'ipv4' &&
      addresses.length == 1 &&
      addresses[0] == address &&
      allowedIps.length == 1 &&
      allowedIps[0] == '0.0.0.0/0') {
    return _TunnelIpConfiguration(
      addresses: List.unmodifiable(addresses),
      allowedIps: List.unmodifiable(allowedIps),
      ipFamilies: const [IpFamily.ipv4],
    );
  }

  if (rawFamilies.length != 2 ||
      rawFamilies[0] != 'ipv4' ||
      rawFamilies[1] != 'ipv6' ||
      addresses.length != 2 ||
      addresses[0] != address ||
      !_isIpv4Cidr(addresses[0]) ||
      !_isUlaIpv6HostCidr(addresses[1]) ||
      allowedIps.length != 2 ||
      allowedIps[0] != '0.0.0.0/0' ||
      allowedIps[1] != '::/0') {
    throw const FormatException('Configuration réseau invalide.');
  }
  return _TunnelIpConfiguration(
    addresses: List.unmodifiable(addresses),
    allowedIps: List.unmodifiable(allowedIps),
    ipFamilies: dualStackIpFamilies,
  );
}

class DeviceConfiguration {
  const DeviceConfiguration({
    required this.deviceId,
    required this.address,
    required this.dns,
    required this.serverPublicKey,
    required this.endpoint,
    required this.allowedIps,
    this.addresses = const [],
    this.ipFamilies = const [IpFamily.ipv4],
  });
  final String deviceId;
  final String address;
  final List<String> dns;
  final String serverPublicKey;
  final String endpoint;
  final List<String> allowedIps;
  final List<String> addresses;
  final List<IpFamily> ipFamilies;

  List<String> get effectiveAddresses =>
      addresses.isEmpty ? List.unmodifiable([address]) : addresses;
  bool get supportsIpv6 =>
      ipFamilies.length == 2 &&
      ipFamilies[0] == IpFamily.ipv4 &&
      ipFamilies[1] == IpFamily.ipv6;

  factory DeviceConfiguration.fromJson(Map<String, dynamic> json) {
    final address = json['address'] as String;
    final historicalAllowedIps = _stringList(json['allowed_ips']);
    final tunnel = _parseTunnelIpConfiguration(
      json,
      address: address,
      historicalAllowedIps: historicalAllowedIps,
    );
    return DeviceConfiguration(
      deviceId: json['device_id'] as String,
      address: address,
      dns: _stringList(json['dns']),
      serverPublicKey: json['server_public_key'] as String,
      endpoint: json['endpoint'] as String,
      allowedIps: tunnel.allowedIps,
      addresses: tunnel.addresses,
      ipFamilies: tunnel.ipFamilies,
    );
  }
}

/// A device enrolled on the signed-in FuzeVPN account.
///
/// This deliberately contains no WireGuard key, tunnel address, endpoint, or
/// other connection secret. Those values are only used transiently by the
/// native tunnel bridge when a connection is requested.
class VpnDevice {
  const VpnDevice({
    required this.deviceId,
    required this.name,
    required this.location,
    required this.createdAt,
  });

  final String deviceId;
  final String name;

  /// Some account devices, such as browser extensions, do not have a VPN
  /// location. The device list must remain usable when that metadata is null.
  final Location? location;
  final DateTime? createdAt;

  factory VpnDevice.fromJson(Map<String, dynamic> json) {
    final createdAtValue = json['created_at'];
    final locationValue = json['location'];
    return VpnDevice(
      deviceId: json['device_id'] as String,
      name: json['name'] as String? ?? 'Appareil sans nom',
      location: locationValue is Map
          ? Location.fromJson(Map<String, dynamic>.from(locationValue))
          : null,
      createdAt: createdAtValue is String
          ? DateTime.tryParse(createdAtValue)?.toLocal()
          : null,
    );
  }
}

class DeviceList {
  const DeviceList({required this.limit, required this.devices});

  final int limit;
  final List<VpnDevice> devices;

  factory DeviceList.fromJson(Map<String, dynamic> json) {
    final items = json['devices'];
    final limit = json['limit'] ?? 2;
    if (items is! List || limit is! int || limit <= 0) {
      throw const FormatException('Liste des appareils invalide.');
    }
    final devices = items
        .map((item) {
          if (item is! Map<String, dynamic> ||
              item['device_id'] is! String ||
              (item['device_id'] as String).isEmpty) {
            throw const FormatException('Appareil invalide.');
          }
          return VpnDevice.fromJson(item);
        })
        .toList(growable: false);
    if (devices.map((device) => device.deviceId).toSet().length !=
        devices.length) {
      throw const FormatException('Identifiants d’appareil dupliqués.');
    }
    return DeviceList(limit: limit, devices: devices);
  }
}

class VpnProfile {
  const VpnProfile({required this.protocol, required this.status});

  final VpnProtocol protocol;
  final String status;

  factory VpnProfile.fromJson(Map<String, dynamic> json) {
    final protocol = json['protocol'];
    final parsedProtocol = protocol is String
        ? vpnProtocolFromApi(protocol)
        : null;
    if (parsedProtocol == null) {
      throw const FormatException('Profil VPN invalide.');
    }
    final status = json['status'];
    return VpnProfile(
      protocol: parsedProtocol,
      status: status is String && RegExp(r'^[a-z0-9_]{1,64}$').hasMatch(status)
          ? status
          : 'unknown',
    );
  }
}

class DeviceProfiles {
  const DeviceProfiles({required this.profiles});

  final List<VpnProfile> profiles;

  factory DeviceProfiles.fromJson(Map<String, dynamic> json) => DeviceProfiles(
    profiles: (json['profiles'] as List? ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(VpnProfile.fromJson)
        .toList(growable: false),
  );
}

/// Activation data is intentionally short-lived. It is handed straight to
/// the Windows OpenVPN bridge and is never displayed, logged or persisted by
/// Dart. The native bridge encrypts its own copy with DPAPI.
class OpenVpnActivation {
  const OpenVpnActivation({
    required this.deviceId,
    required this.protocol,
    required this.certificatePem,
    required this.caCertificatePem,
    required this.tlsCryptV2ClientKey,
    required this.endpoint,
    required this.dns,
    required this.address,
    required this.serverName,
    required this.remoteCertTlsServer,
    required this.ciphers,
    required this.notAfter,
    this.addresses = const [],
    this.allowedIps = const [],
    this.ipFamilies = const [IpFamily.ipv4],
  });

  final String deviceId;
  final String protocol;
  final String certificatePem;
  final String caCertificatePem;
  final String tlsCryptV2ClientKey;
  final String endpoint;
  final List<String> dns;
  final String address;
  final String serverName;
  final bool remoteCertTlsServer;
  final List<String> ciphers;
  final DateTime notAfter;
  final List<String> addresses;
  final List<String> allowedIps;
  final List<IpFamily> ipFamilies;

  List<String> get effectiveAddresses =>
      addresses.isEmpty ? List.unmodifiable([address]) : addresses;
  bool get supportsIpv6 =>
      ipFamilies.length == 2 &&
      ipFamilies[0] == IpFamily.ipv4 &&
      ipFamilies[1] == IpFamily.ipv6;

  factory OpenVpnActivation.fromJson(
    Map<String, dynamic> json, {
    required String expectedDeviceId,
  }) {
    String requiredValue(String key) {
      final value = json[key];
      if (value is! String || value.isEmpty || value.contains('\u0000')) {
        throw const FormatException('Profil OpenVPN invalide.');
      }
      return value;
    }

    final deviceId = requiredValue('device_id');
    if (deviceId != expectedDeviceId ||
        !RegExp(r'^[A-Za-z0-9_-]{1,128}$').hasMatch(deviceId) ||
        json['protocol'] != 'openvpn') {
      throw const FormatException('Profil OpenVPN invalide.');
    }

    final endpoint = requiredValue('endpoint');
    if (InternetAddress.tryParse(endpoint)?.type != InternetAddressType.IPv4) {
      throw const FormatException('Profil OpenVPN invalide.');
    }
    final serverName = requiredValue('server_name');
    if (!RegExp(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$').hasMatch(serverName)) {
      throw const FormatException('Profil OpenVPN invalide.');
    }
    final rawCiphers = json['ciphers'];
    if (rawCiphers is! List || rawCiphers.isEmpty) {
      throw const FormatException('Profil OpenVPN invalide.');
    }
    final ciphers = rawCiphers
        .map((item) {
          if (item is! String ||
              !RegExp(r'^[A-Za-z0-9_-]{1,64}$').hasMatch(item)) {
            throw const FormatException('Profil OpenVPN invalide.');
          }
          return item;
        })
        .toList(growable: false);

    final rawDns = json['dns'];
    if (rawDns is! List || rawDns.isEmpty || rawDns.length > 8) {
      throw const FormatException('Profil OpenVPN invalide.');
    }
    final dns = rawDns
        .map((item) {
          if (item is! String ||
              item.contains('\u0000') ||
              InternetAddress.tryParse(item)?.type !=
                  InternetAddressType.IPv4) {
            throw const FormatException('Profil OpenVPN invalide.');
          }
          return item;
        })
        .toList(growable: false);

    final address = requiredValue('address');
    final cidr = address.split('/');
    final prefix = cidr.length == 2 ? int.tryParse(cidr[1]) : null;
    if (cidr.length != 2 ||
        prefix == null ||
        prefix < 0 ||
        prefix > 32 ||
        InternetAddress.tryParse(cidr.first)?.type !=
            InternetAddressType.IPv4 ||
        json['remote_cert_tls_server'] != true) {
      throw const FormatException('Profil OpenVPN invalide.');
    }
    final historicalAllowedIps = json.containsKey('allowed_ips')
        ? _stringList(json['allowed_ips'])
        : const <String>[];
    final tunnel = _parseTunnelIpConfiguration(
      json,
      address: address,
      historicalAllowedIps: historicalAllowedIps,
    );
    final notAfterRaw = requiredValue('not_after');
    final notAfter = DateTime.tryParse(notAfterRaw);
    if (!RegExp(r'^\d{4}-\d{2}-\d{2}T').hasMatch(notAfterRaw) ||
        notAfter == null) {
      throw const FormatException('Profil OpenVPN invalide.');
    }

    final certificatePem = requiredValue('certificate_pem');
    final caCertificatePem = requiredValue('ca_certificate_pem');
    final tlsCryptV2ClientKey = requiredValue('tls_crypt_v2_client_key');
    if (!_isStrictPemSequence(
          certificatePem,
          label: 'CERTIFICATE',
          maxBytes: _maxOpenVpnCertificatePemBytes,
          allowMultiple: false,
        ) ||
        !_isStrictPemSequence(
          caCertificatePem,
          label: 'CERTIFICATE',
          maxBytes: _maxOpenVpnCertificatePemBytes,
          allowMultiple: true,
        ) ||
        !_isStrictPemSequence(
          tlsCryptV2ClientKey,
          label: 'OpenVPN tls-crypt-v2 client key',
          maxBytes: _maxOpenVpnTlsCryptV2KeyBytes,
          allowMultiple: false,
        )) {
      throw const FormatException('Profil OpenVPN invalide.');
    }

    return OpenVpnActivation(
      deviceId: deviceId,
      protocol: 'openvpn',
      certificatePem: certificatePem,
      caCertificatePem: caCertificatePem,
      tlsCryptV2ClientKey: tlsCryptV2ClientKey,
      endpoint: endpoint,
      dns: dns,
      address: address,
      serverName: serverName,
      remoteCertTlsServer: true,
      ciphers: ciphers,
      notAfter: notAfter.toUtc(),
      addresses: tunnel.addresses,
      allowedIps: tunnel.allowedIps,
      ipFamilies: tunnel.ipFamilies,
    );
  }
}

class AuthSession {
  const AuthSession({required this.accessToken});

  final String accessToken;

  factory AuthSession.fromJson(Map<String, dynamic> json) {
    final accessToken = json['access_token'] as String?;
    if (accessToken == null || accessToken.isEmpty) {
      throw const FormatException('Réponse d’authentification invalide.');
    }
    return AuthSession(accessToken: accessToken);
  }
}

class UserProfile {
  const UserProfile({
    required this.userId,
    required this.email,
    required this.firstName,
    required this.emailVerified,
  });

  final String userId;
  final String email;
  final String firstName;
  final bool emailVerified;

  factory UserProfile.fromJson(Map<String, dynamic> json) => UserProfile(
    userId: json['user_id'] as String? ?? '',
    email: json['email'] as String? ?? '',
    firstName: json['first_name'] as String? ?? '',
    emailVerified: json['email_verified'] as bool? ?? false,
  );
}
