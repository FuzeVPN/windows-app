// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';

import '../brand_config.dart';
import 'diagnostic_log.dart';
import 'diagnostics_models.dart';
import 'models.dart';
import 'wireguard_bridge.dart';
import 'windows_update_models.dart';

/// A deliberately small representation of an API error.
///
/// It keeps only the stable fields the UI is allowed to act upon. Response
/// bodies, headers other than Retry-After, credentials and VPN configuration
/// are intentionally discarded.
const _apiTraceZoneKey = #fuzeApiTraceRequest;

class ApiException implements Exception, DiagnosticFailureDetails {
  const ApiException({
    required this.statusCode,
    required this.errorCode,
    this.retryAfterSeconds,
    this.observedHttpStatus,
    this.localErrorCode,
    this.windowsError,
  });

  final int statusCode;
  final String errorCode;
  final int? retryAfterSeconds;

  /// Null for locally synthesized transport failures, not an observed HTTP reply.
  final int? observedHttpStatus;

  /// Allowlisted local failure, never native exception text or credentials.
  final String? localErrorCode;
  final int? windowsError;

  String get diagnosticErrorCode => localErrorCode ?? errorCode;

  @override
  String get diagnosticFailureCode =>
      localErrorCode ?? diagnosticCode(errorCode);
  @override
  int? get diagnosticWindowsError => windowsError;
  @override
  int? get diagnosticHttpStatus => observedHttpStatus;

  static const _resolverLocalCodes = <String>{
    'api_bootstrap_unavailable',
    'api_resolver_invalid_response',
    'native_bridge_unavailable',
    'native_operation_failed',
    'broker_busy',
    'broker_protocol_error',
    'broker_response_timeout',
    'broker_unavailable',
    'broker_write_failed',
    'maintenance_in_progress',
    'permission_denied',
    'runtime_owned_by_another_user',
    'runtime_detection_failed',
    'runtime_status_unavailable',
    'runtime_unavailable',
    'service_configuration_mismatch',
    'service_unavailable',
  };

  static ApiException _resolverFailure(Object error) {
    String? code;
    int? windowsError;
    if (error is PlatformException &&
        _resolverLocalCodes.contains(error.code)) {
      code = error.code;
      final details = error.details;
      final value = details is Map ? details['win32_error'] : null;
      if (value is int && value >= 0 && value <= 0xffffffff) {
        windowsError = value;
      }
    } else if (error is MissingPluginException) {
      code = 'native_bridge_unavailable';
    } else if (error is FormatException || error is TypeError) {
      code = 'api_resolver_invalid_response';
    } else if (error is TimeoutException) {
      code = 'network_timeout';
    } else {
      code = 'native_operation_failed';
    }
    return ApiException(
      statusCode: 503,
      errorCode: 'api_resolution_unavailable',
      localErrorCode: code,
      windowsError: windowsError,
    );
  }

  /// An intermediary status or an inconsistent body cannot revoke a session.
  bool get isUnauthorized =>
      statusCode == HttpStatus.unauthorized && errorCode == 'unauthorized';

  factory ApiException.fromResponse({
    required int statusCode,
    required String body,
    String? retryAfterHeader,
    DateTime? now,
  }) {
    var errorCode = 'api_error';
    int? retryAfterSeconds = _retryAfter(retryAfterHeader, now: now);
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map<String, dynamic>) {
        final candidate = decoded['error'];
        if (candidate is String && _isStableErrorCode(candidate)) {
          errorCode = candidate;
        }
        retryAfterSeconds ??= _retryAfterValue(decoded['retry_after_seconds']);
      }
    } catch (_) {
      // A malformed error response is still represented without retaining it.
    }
    return ApiException(
      statusCode: statusCode,
      errorCode: errorCode,
      retryAfterSeconds: retryAfterSeconds,
      observedHttpStatus: statusCode,
    );
  }

  static bool _isStableErrorCode(String value) =>
      RegExp(r'^[a-z0-9_]{1,64}$').hasMatch(value);

  static int? _retryAfter(String? value, {DateTime? now}) {
    if (value == null) return null;
    final numeric = int.tryParse(value.trim());
    if (numeric != null) return _retryAfterValue(numeric);
    try {
      final clock = (now ?? DateTime.now()).toUtc();
      final text = value.trim();
      var date = HttpDate.parse(text).toUtc();
      final shortYear = RegExp(
        r'^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), '
        r'\d{2}-[A-Za-z]{3}-(\d{2}) \d{2}:\d{2}:\d{2} GMT$',
      ).firstMatch(text);
      if (shortYear != null) {
        // Dart leaves RFC 850's two-digit year unexpanded. RFC 9110 section
        // 5.6.7 maps it to the most recent matching year at most 50 years ahead.
        final latest = DateTime.utc(
          clock.year + 50,
          clock.month,
          clock.day,
          clock.hour,
          clock.minute,
          clock.second,
          clock.millisecond,
          clock.microsecond,
        );
        var year = ((clock.year + 50) ~/ 100) * 100 + date.year;
        DateTime expand() => DateTime.utc(
          year,
          date.month,
          date.day,
          date.hour,
          date.minute,
          date.second,
        );
        var expanded = expand();
        if (expanded.isAfter(latest)) {
          year -= 100;
          expanded = expand();
        }
        date = expanded;
      }
      final difference = date.difference(clock);
      if (difference <= Duration.zero) return 0;
      // Round up so a fractional remaining second cannot resume an upload early.
      // Pending reports expire within 24 hours; a later date suspends them
      // through their entire remaining lifetime without an unbounded timer.
      final seconds = (difference.inMicroseconds + 999999) ~/ 1000000;
      return seconds > 86400 ? 86400 : seconds;
    } on HttpException {
      return null;
    } on FormatException {
      return null;
    }
  }

  static int? _retryAfterValue(Object? value) {
    final seconds = switch (value) {
      int value => value,
      num value => value.toInt(),
      String value => int.tryParse(value),
      _ => null,
    };
    return seconds != null && seconds >= 0 && seconds <= 86400 ? seconds : null;
  }

  @override
  String toString() => retryAfterSeconds == null
      ? 'ApiException(statusCode: $statusCode, errorCode: $errorCode)'
      : 'ApiException(statusCode: $statusCode, errorCode: $errorCode, retryAfterSeconds: $retryAfterSeconds)';
}

/// Cancels one diagnostics request without closing the shared API transport.
class DiagnosticRequestCancellation {
  final _cancelled = Completer<void>();
  void Function()? _abort;
  bool get isCancelled => _cancelled.isCompleted;
  void cancel() {
    if (isCancelled) return;
    _cancelled.complete();
    _abort?.call();
  }

  void check() {
    if (isCancelled) throw const DiagnosticsFailure('diagnostic_cancelled');
  }

  Future<T> wait<T>(Future<T> work) => Future.any([
    work,
    _cancelled.future.then<T>(
      (_) => throw const DiagnosticsFailure('diagnostic_cancelled'),
    ),
  ]);
}

class _WindowsUpdateCache {
  WindowsUpdateRelease? release;
  String? etag;
  Duration? cachedAt;
  Duration freshness = const Duration(seconds: 60);
  Future<WindowsUpdateRelease?>? request;
  bool requestRevalidates = false;
}

class ApiClient {
  ApiClient({
    HttpClient? client,
    Uri? baseUri,
    Duration connectionTimeout = const Duration(seconds: 10),
    Duration requestTimeout = const Duration(seconds: 20),
    int maxResponseBytes = 1024 * 1024,
    Future<List<String>> Function()? resolveApiAddresses,
    SecurityContext? securityContext,
    DateTime Function()? retryAfterClock,
    this.windowsUpdateClock,
  }) : assert(connectionTimeout > Duration.zero),
       assert(requestTimeout > Duration.zero),
       assert(maxResponseBytes > 0),
       _client = client ?? HttpClient(context: securityContext),
       _baseUri = baseUri ?? Uri.parse(baseUrl),
       _requestTimeout = requestTimeout,
       _maxResponseBytes = maxResponseBytes,
       _retryAfterClock = retryAfterClock ?? DateTime.now,
       _securityContext = securityContext {
    _client.connectionTimeout = connectionTimeout;
    _resolveApiAddresses =
        resolveApiAddresses ??
        (Platform.isWindows && _baseUri.origin == Uri.parse(baseUrl).origin
            ? WireGuardBridge().resolveApiAddresses
            : null);
    if (_resolveApiAddresses != null) {
      // HttpClient's custom connection factory owns TLS as well as TCP.
      // Connect to a native-resolved IP, then authenticate the ORIGINAL URI
      // hostname with RawSecureSocket.secure (including SNI). Never accept an
      // invalid certificate or fall back to the shared Windows DNS resolver.
      _client.connectionFactory = (uri, proxyHost, proxyPort) async {
        if (uri.origin != _baseUri.origin ||
            uri.scheme != 'https' ||
            proxyHost != null ||
            proxyPort != null) {
          throw const ApiException(
            statusCode: 502,
            errorCode: 'api_transport_unsupported',
          );
        }
        final attempt = _ResolvedApiConnection(
          uri: uri,
          resolve: _resolvedAddresses,
          context: _securityContext,
          timeout: connectionTimeout,
          onFailure: invalidateBootstrapCache,
        );
        final socket = attempt.connect();
        // A resolver may fail in the microtask that precedes HttpClient's
        // subscription to the returned ConnectionTask. Observe that future
        // immediately while preserving the same error for HttpClient.
        unawaited(
          socket.then<void>((_) {}, onError: (Object _, StackTrace _) {}),
        );
        return ConnectionTask.fromSocket(socket, attempt.cancel);
      };
    }
  }
  static const baseUrl = BrandConfig.apiBaseUrl;
  final HttpClient _client;
  final Uri _baseUri;
  final Duration _requestTimeout;
  final int _maxResponseBytes;
  final DateTime Function() _retryAfterClock;
  final _responseClocks = Expando<Stopwatch>();
  final _responseRequestIds = Expando<int>();
  final SecurityContext? _securityContext;
  Future<List<String>> Function()? _resolveApiAddresses;
  Future<List<InternetAddress>>? _addressResolution;
  Stopwatch? _addressAge;
  int _addressGeneration = 0;
  final Duration Function()? windowsUpdateClock;
  final Stopwatch _windowsUpdateLifetime = Stopwatch()..start();
  final _windowsUpdateCaches = <String, _WindowsUpdateCache>{};

  Duration get _windowsUpdateNow =>
      windowsUpdateClock?.call() ?? _windowsUpdateLifetime.elapsed;

  /// Public release discovery. It never reads or changes account credentials.
  Future<WindowsUpdateRelease?> latestWindowsUpdate({
    String arch = 'x64',
    String channel = 'stable',
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
    bool revalidate = false,
  }) async {
    if (!const {'x64', 'arm64'}.contains(arch)) {
      throw const FormatException('Unsupported Windows update architecture.');
    }
    if (!const {'stable', 'beta'}.contains(channel)) {
      throw const FormatException('Unsupported Windows update channel.');
    }
    final cache = _windowsUpdateCaches.putIfAbsent(
      '$arch/$channel/${package.name}',
      _WindowsUpdateCache.new,
    );
    final cachedAt = cache.cachedAt;
    final age = cachedAt == null ? null : _windowsUpdateNow - cachedAt;
    if (!revalidate &&
        age != null &&
        age >= Duration.zero &&
        age < cache.freshness) {
      return cache.release;
    }
    final running = cache.request;
    if (running != null) {
      if (!revalidate || cache.requestRevalidates) return running;
      // A safety revalidation must not be satisfied by an ordinary in-flight
      // request that an intermediary could serve from its own cache.
      try {
        await running;
      } catch (_) {}
      return latestWindowsUpdate(
        arch: arch,
        channel: channel,
        package: package,
        revalidate: true,
      );
    }
    cache.requestRevalidates = revalidate;
    final request = _fetchWindowsUpdate(
      cache: cache,
      arch: arch,
      channel: channel,
      package: package,
      revalidate: revalidate,
    );
    cache.request = request;
    try {
      return await request;
    } finally {
      if (identical(cache.request, request)) {
        cache.request = null;
      }
    }
  }

  void _clearWindowsUpdateCache(_WindowsUpdateCache cache) {
    cache.release = null;
    cache.etag = null;
    cache.cachedAt = null;
    cache.freshness = const Duration(seconds: 60);
  }

  Future<WindowsUpdateRelease?> _fetchWindowsUpdate({
    required _WindowsUpdateCache cache,
    required String arch,
    required String channel,
    required WindowsUpdatePackage package,
    required bool revalidate,
  }) async {
    final previous = cache.release;
    final previousEtag = cache.etag;
    try {
      final response = await _request(
        'GET',
        '/v1/updates/windows/latest?arch=$arch&channel=$channel'
            '&package=${package.name}',
        cacheControl: revalidate ? 'no-cache' : 'max-age=60',
        ifNoneMatch: previousEtag,
        allowNotModified: true,
      );
      final body = await _readResponseBody(response);
      final etag = response.headers.value(HttpHeaders.etagHeader);
      if (etag != null &&
          (etag.length > 512 ||
              !RegExp(r'^(W/)?"[\x21\x23-\x7e]*"$').hasMatch(etag))) {
        throw const FormatException('Invalid update ETag.');
      }
      late final WindowsUpdateRelease release;
      if (response.statusCode == HttpStatus.notModified) {
        if (previous == null ||
            previousEtag == null ||
            body.isNotEmpty ||
            (etag != null && etag != previousEtag)) {
          throw const FormatException(
            'Unexpected update revalidation response.',
          );
        }
        release = previous;
      } else {
        if (response.statusCode != HttpStatus.ok) {
          throw const FormatException('Invalid update response status.');
        }
        final decoded = jsonDecode(body);
        if (decoded is! Map<String, dynamic>) {
          throw const FormatException('Invalid update manifest.');
        }
        release = WindowsUpdateRelease.fromJson(decoded, package: package);
      }
      final cacheDirectives =
          response.headers
              .value(HttpHeaders.cacheControlHeader)
              ?.toLowerCase()
              .split(',')
              .map((value) => value.trim())
              .toList() ??
          const <String>[];
      if (cacheDirectives.contains('no-store')) {
        _clearWindowsUpdateCache(cache);
      } else {
        cache.release = release;
        cache.etag =
            etag ??
            (response.statusCode == HttpStatus.notModified
                ? previousEtag
                : null);
        cache.cachedAt = _windowsUpdateNow;
        // A response may already have spent part of its lifetime in a CDN.
        // Do not add another full minute after receiving an aged response.
        var seconds = cacheDirectives.contains('no-cache') ? 0 : 60;
        for (final directive in cacheDirectives) {
          if (!directive.startsWith('max-age=')) continue;
          final maximum = int.tryParse(directive.substring(8));
          if (maximum == null || maximum < 0) {
            seconds = 0;
          } else if (maximum < seconds) {
            seconds = maximum;
          }
        }
        final ageHeader = response.headers.value(HttpHeaders.ageHeader);
        final responseAge = ageHeader == null ? 0 : int.tryParse(ageHeader);
        seconds = responseAge == null || responseAge < 0
            ? 0
            : (seconds - responseAge).clamp(0, 60);
        cache.freshness = Duration(seconds: seconds);
      }
      return release;
    } on ApiException catch (error) {
      _clearWindowsUpdateCache(cache);
      if (error.statusCode == HttpStatus.notFound &&
          error.errorCode == 'update_not_available') {
        cache.cachedAt = _windowsUpdateNow;
        return null;
      }
      rethrow;
    } catch (_) {
      _clearWindowsUpdateCache(cache);
      rethrow;
    }
  }

  void invalidateBootstrapCache() {
    _addressGeneration++;
    _addressResolution = null;
    _addressAge = null;
  }

  void close() => _client.close(force: true);

  Future<List<InternetAddress>> _resolvedAddresses() {
    final traceId = Zone.current[_apiTraceZoneKey] as int?;
    if (_addressResolution != null &&
        _addressAge != null &&
        _addressAge!.elapsed < const Duration(seconds: 30)) {
      DiagnosticLog.record(
        area: 'api_transport',
        event: 'resolver_cache_hit',
        stage: 'native_resolution',
        requestId: traceId,
      );
      return _addressResolution!;
    }
    final generation = _addressGeneration;
    final resolving = () async {
      final timer = Stopwatch()..start();
      DiagnosticLog.record(
        area: 'api_transport',
        event: 'native_resolution_started',
        stage: 'native_resolution',
        requestId: traceId,
      );
      try {
        final values = await _resolveApiAddresses!().timeout(_requestTimeout);
        if (values.length > 16) {
          throw const FormatException('Invalid API address list.');
        }
        if (values.isEmpty && generation == _addressGeneration) {
          // Exclusive native signal: no VPN runtime exists, so normal DNS is
          // safe and login must not start a privileged service. Never cache
          // this absence across a later protection/connection operation.
          _addressAge = null;
        }
        final addresses = <InternetAddress>[];
        final seen = <String>{};
        for (final value in values) {
          final address = InternetAddress.tryParse(value);
          if (address == null) {
            throw const FormatException('Invalid API address.');
          }
          if (seen.add(address.address)) addresses.add(address);
        }
        DiagnosticLog.record(
          area: 'api_transport',
          event: 'native_resolution_completed',
          stage: 'native_resolution',
          requestId: traceId,
          durationMs: timer.elapsedMilliseconds,
          count: addresses.length,
        );
        return addresses;
      } catch (error) {
        DiagnosticLog.recordFailure(
          area: 'api_transport',
          event: 'native_resolution_failed',
          error: error,
          stage: 'native_resolution',
          requestId: traceId,
          durationMs: timer.elapsedMilliseconds,
        );
        if (generation == _addressGeneration) invalidateBootstrapCache();
        throw ApiException._resolverFailure(error);
      }
    }();
    _addressAge = Stopwatch()..start();
    _addressResolution = resolving;
    return resolving;
  }

  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    final response = await _request(
      'POST',
      '/v1/auth/login',
      body: {'email': email, 'password': password},
    );
    final body = await _readJsonObject(response);
    return AuthSession.fromJson(body);
  }

  Future<List<Location>> locations() async {
    final response = await _request('GET', '/v1/locations');
    final body = await _readJsonObject(response);
    return (body['locations'] as List)
        .map((item) => Location.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    final response = await _request(
      'POST',
      '/v1/devices',
      token: token,
      body: {
        'name': name,
        'public_key': publicKey,
        'location_id': locationId,
        if (ipFamilies != null)
          'ip_families': ipFamilies.map((family) => family.apiValue).toList(),
      },
    );
    final body = await _readJsonObject(response);
    try {
      final configuration = DeviceConfiguration.fromJson(body);
      if (ipFamilies?.contains(IpFamily.ipv6) == true &&
          !configuration.supportsIpv6) {
        throw const FormatException('Configuration double pile absente.');
      }
      return configuration;
    } on FormatException {
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_device_configuration',
      );
    } on TypeError {
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_device_configuration',
      );
    }
  }

  Future<DeviceList> devices(String token) async {
    final response = await _request('GET', '/v1/devices', token: token);
    final body = await _readJsonObject(response);
    return DeviceList.fromJson(body);
  }

  Future<void> revokeDevice({
    required String token,
    required String deviceId,
  }) async {
    final response = await _request(
      'DELETE',
      '/v1/devices/${Uri.encodeComponent(deviceId)}',
      token: token,
    );
    await _readResponseBody(response);
  }

  Future<LocationMigration> startLocationMigration({
    required String token,
    required String deviceId,
    required String locationId,
  }) async {
    final response = await _request(
      'POST',
      '/v1/devices/${Uri.encodeComponent(deviceId)}/location-migrations',
      token: token,
      body: {'location_id': locationId},
    );
    if (response.statusCode != HttpStatus.ok &&
        response.statusCode != HttpStatus.accepted) {
      await _readResponseBody(response);
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_migration_response',
      );
    }
    return _readLocationMigration(response, expectedDeviceId: deviceId);
  }

  Future<LocationMigration> getLocationMigration({
    required String token,
    required String deviceId,
    required String migrationId,
  }) async {
    final response = await _request(
      'GET',
      '/v1/devices/${Uri.encodeComponent(deviceId)}/location-migrations/${Uri.encodeComponent(migrationId)}',
      token: token,
    );
    if (response.statusCode != HttpStatus.ok) {
      await _readResponseBody(response);
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_migration_response',
      );
    }
    return _readLocationMigration(response, expectedDeviceId: deviceId);
  }

  Future<LocationMigration> _readLocationMigration(
    HttpClientResponse response, {
    required String expectedDeviceId,
  }) async {
    if (!_hasNoStore(response.headers.value(HttpHeaders.cacheControlHeader))) {
      await _readResponseBody(response);
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_migration_response',
      );
    }
    try {
      final decoded = jsonDecode(await _readResponseBody(response));
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException();
      }
      return LocationMigration.fromJson(
        decoded,
        expectedDeviceId: expectedDeviceId,
        retryAfterSeconds: ApiException._retryAfter(
          response.headers.value(HttpHeaders.retryAfterHeader),
          now: _retryAfterClock(),
        ),
      );
    } on FormatException {
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_migration_response',
      );
    } on TypeError {
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_migration_response',
      );
    }
  }

  Future<DeviceProfiles> deviceProfiles({
    required String token,
    required String deviceId,
  }) async {
    final response = await _request(
      'GET',
      '/v1/devices/${Uri.encodeComponent(deviceId)}/profiles',
      token: token,
    );
    final body = await _readJsonObject(response);
    return DeviceProfiles.fromJson(body);
  }

  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) => _openVpnActivation(
    path: '/v1/devices/${Uri.encodeComponent(deviceId)}/profiles/openvpn',
    token: token,
    csrPem: csrPem,
    expectedDeviceId: deviceId,
    ipFamilies: ipFamilies,
  );

  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) => _openVpnActivation(
    path: '/v1/devices/${Uri.encodeComponent(deviceId)}/profiles/openvpn/renew',
    token: token,
    csrPem: csrPem,
    expectedDeviceId: deviceId,
    ipFamilies: ipFamilies,
  );

  Future<void> revokeOpenVpnProfile({
    required String token,
    required String deviceId,
  }) async {
    final response = await _request(
      'DELETE',
      '/v1/devices/${Uri.encodeComponent(deviceId)}/profiles/openvpn',
      token: token,
    );
    await _readResponseBody(response);
  }

  Future<OpenVpnActivation> _openVpnActivation({
    required String path,
    required String token,
    required String csrPem,
    required String expectedDeviceId,
    List<IpFamily>? ipFamilies,
  }) async {
    final response = await _request(
      'POST',
      path,
      token: token,
      body: {
        'csr_pem': csrPem,
        if (ipFamilies != null)
          'ip_families': ipFamilies.map((family) => family.apiValue).toList(),
      },
    );
    if (response.statusCode != HttpStatus.created ||
        !_hasNoStore(response.headers.value(HttpHeaders.cacheControlHeader))) {
      await _readResponseBody(response);
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_activation_response',
      );
    }
    final body = await _readJsonObject(response);
    try {
      final activation = OpenVpnActivation.fromJson(
        body,
        expectedDeviceId: expectedDeviceId,
      );
      if (ipFamilies?.contains(IpFamily.ipv6) == true &&
          !activation.supportsIpv6) {
        throw const FormatException('Activation double pile absente.');
      }
      return activation;
    } on FormatException {
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_activation_response',
      );
    } on TypeError {
      throw const ApiException(
        statusCode: 502,
        errorCode: 'invalid_activation_response',
      );
    }
  }

  static bool _hasNoStore(String? cacheControl) =>
      cacheControl
          ?.toLowerCase()
          .split(',')
          .map((directive) => directive.trim())
          .contains('no-store') ??
      false;

  Future<UserProfile> me(String token) async {
    final response = await _request('GET', '/v1/me', token: token);
    final body = await _readJsonObject(response);
    return UserProfile.fromJson(body);
  }

  Future<Subscription> subscription(String token) async {
    final response = await _request(
      'GET',
      '/v1/billing/subscription',
      token: token,
    );
    try {
      return Subscription.fromJson(await _readJsonObject(response));
    } on FormatException {
      throw const ApiException(
        statusCode: HttpStatus.badGateway,
        errorCode: 'subscription_response_invalid',
      );
    } on TypeError {
      throw const ApiException(
        statusCode: HttpStatus.badGateway,
        errorCode: 'subscription_response_invalid',
      );
    }
  }

  Future<DiagnosticReceipt> submitDiagnostic({
    required String token,
    required FrozenDiagnosticReport report,
    DiagnosticRequestCancellation? cancellation,
  }) async {
    final cancel = cancellation ?? DiagnosticRequestCancellation();
    cancel.check();
    if (token.isEmpty) {
      throw const DiagnosticsFailure('diagnostic_session_required');
    }
    try {
      final response = await _request(
        'POST',
        '/v1/diagnostics',
        token: token,
        bodyBytes: report.bytes,
        cancellation: cancel,
      );
      final body = await _readJsonObject(response, cancellation: cancel);
      cancel.check();
      return DiagnosticReceipt.fromJson(
        body,
        expectedClientId: report.reportId,
        httpStatus: response.statusCode,
      );
    } catch (_) {
      cancel.check();
      rethrow;
    } finally {
      cancel._abort = null;
    }
  }

  Future<HttpClientResponse> _request(
    String method,
    String path, {
    String? token,
    Map<String, dynamic>? body,
    Uint8List? bodyBytes,
    DiagnosticRequestCancellation? cancellation,
    String cacheControl = 'no-store',
    String? ifNoneMatch,
    bool allowNotModified = false,
  }) {
    final traceId = DiagnosticLog.nextRequestId();
    final timer = Stopwatch()..start();
    // A fixed route category identifies the operation without exposing paths,
    // query parameters, device/account identifiers or authentication data.
    final category = switch (path.split('?').first) {
      '/v1/locations' => 'locations',
      '/v1/updates/windows/latest' => 'update_manifest',
      '/v1/billing/subscription' => 'subscription',
      '/v1/auth/login' => 'login',
      '/v1/me' => 'account',
      '/v1/devices' => 'devices',
      '/v1/diagnostics' => 'diagnostic_report',
      final route when route.startsWith('/v1/devices/') => 'device_operation',
      _ => 'other',
    };
    return runZoned(() async {
      DiagnosticLog.record(
        area: 'api_request',
        event: 'started',
        code: category,
        stage: 'request',
        requestId: traceId,
      );
      try {
        final response = await _requestImpl(
          method,
          path,
          token: token,
          body: body,
          bodyBytes: bodyBytes,
          cancellation: cancellation,
          cacheControl: cacheControl,
          ifNoneMatch: ifNoneMatch,
          allowNotModified: allowNotModified,
        );
        DiagnosticLog.record(
          area: 'api_request',
          event: 'headers_completed',
          stage: 'response_headers',
          requestId: traceId,
          durationMs: timer.elapsedMilliseconds,
          httpStatus: response.statusCode,
        );
        return response;
      } catch (error) {
        if (error is DiagnosticsFailure &&
            error.code == 'diagnostic_cancelled') {
          DiagnosticLog.record(
            area: 'api_request',
            event: 'cancelled',
            code: 'diagnostic_cancelled',
            stage: 'request',
            requestId: traceId,
            durationMs: timer.elapsedMilliseconds,
          );
        } else {
          DiagnosticLog.recordFailure(
            area: 'api_request',
            event: 'failed',
            error: error,
            stage: 'request',
            requestId: traceId,
            durationMs: timer.elapsedMilliseconds,
          );
        }
        rethrow;
      }
    }, zoneValues: {_apiTraceZoneKey: traceId});
  }

  Future<HttpClientResponse> _requestImpl(
    String method,
    String path, {
    String? token,
    Map<String, dynamic>? body,
    Uint8List? bodyBytes,
    DiagnosticRequestCancellation? cancellation,
    String cacheControl = 'no-store',
    String? ifNoneMatch,
    bool allowNotModified = false,
  }) async {
    assert(body == null || bodyBytes == null);
    cancellation?.check();
    HttpClientRequest? request;
    if (cancellation != null) cancellation._abort = () => request?.abort();
    final clock = Stopwatch()..start();
    Duration remaining() {
      final value = _requestTimeout - clock.elapsed;
      if (value <= Duration.zero) throw _timeoutException();
      return value;
    }

    var openingExpired = false;
    final traceId = Zone.current[_apiTraceZoneKey] as int?;
    DiagnosticLog.record(
      area: 'api_request',
      event: 'open_started',
      stage: 'open_connection',
      requestId: traceId,
    );
    try {
      final opening = _client.openUrl(method, _baseUri.resolve(path));
      // Future.timeout does not cancel openUrl. Abort a request that arrives
      // after its caller has timed out, before adding any credentials.
      unawaited(
        opening.then<void>((lateRequest) {
          if (openingExpired) lateRequest.abort();
        }, onError: (Object _, StackTrace _) {}),
      );
      final pending = opening.timeout(remaining());
      final activeRequest = await (cancellation?.wait(pending) ?? pending);
      request = activeRequest;
      cancellation?.check();
      DiagnosticLog.record(
        area: 'api_request',
        event: 'open_completed',
        stage: 'open_connection',
        requestId: traceId,
        durationMs: clock.elapsedMilliseconds,
      );
      // API responses must never redirect a request carrying a bearer token.
      // Handle redirects as errors instead of allowing dart:io to follow them
      // automatically, including to a subdomain of the API host.
      activeRequest.followRedirects = false;
      activeRequest.headers.contentType = ContentType.json;
      activeRequest.headers.set(HttpHeaders.cacheControlHeader, cacheControl);
      if (ifNoneMatch != null) {
        activeRequest.headers.set(HttpHeaders.ifNoneMatchHeader, ifNoneMatch);
      }
      if (token != null) {
        activeRequest.headers.set(
          HttpHeaders.authorizationHeader,
          'Bearer $token',
        );
      }
      if (body != null) {
        activeRequest.write(jsonEncode(body));
      }
      if (bodyBytes != null) {
        activeRequest.contentLength = bodyBytes.length;
        activeRequest.add(bodyBytes);
      }
    } on DiagnosticsFailure {
      openingExpired = true;
      request?.abort();
      rethrow;
    } on TimeoutException {
      openingExpired = true;
      request?.abort();
      throw _timeoutException();
    } on ApiException {
      openingExpired = true;
      request?.abort();
      rethrow;
    }

    late final HttpClientResponse response;
    final activeRequest = request;
    DiagnosticLog.record(
      area: 'api_request',
      event: 'send_started',
      stage: 'send_request',
      requestId: traceId,
    );
    try {
      final closing = activeRequest.close().timeout(remaining());
      response = await (cancellation?.wait(closing) ?? closing);
    } on DiagnosticsFailure {
      activeRequest.abort();
      rethrow;
    } on TimeoutException {
      activeRequest.abort();
      throw _timeoutException();
    } on ApiException {
      activeRequest.abort();
      rethrow;
    }
    _responseClocks[response] = clock;
    _responseRequestIds[response] = traceId;
    DiagnosticLog.record(
      area: 'api_request',
      event: 'response_received',
      stage: 'response_headers',
      requestId: traceId,
      durationMs: clock.elapsedMilliseconds,
      httpStatus: response.statusCode,
    );
    if ((response.statusCode < 200 || response.statusCode >= 300) &&
        !(allowNotModified && response.statusCode == HttpStatus.notModified)) {
      final reading = _readResponseBody(response, cancellation: cancellation);
      final body = await (cancellation?.wait(reading) ?? reading);
      throw ApiException.fromResponse(
        statusCode: response.statusCode,
        body: body,
        retryAfterHeader: response.headers.value(HttpHeaders.retryAfterHeader),
        now: _retryAfterClock(),
      );
    }
    return response;
  }

  Future<Map<String, dynamic>> _readJsonObject(
    HttpClientResponse response, {
    DiagnosticRequestCancellation? cancellation,
  }) async {
    final text = await _readResponseBody(response, cancellation: cancellation);
    final timer = Stopwatch()..start();
    final traceId = _responseRequestIds[response];
    DiagnosticLog.record(
      area: 'api_request',
      event: 'json_started',
      stage: 'decode_response',
      requestId: traceId,
    );
    try {
      final result = jsonDecode(text) as Map<String, dynamic>;
      DiagnosticLog.record(
        area: 'api_request',
        event: 'json_completed',
        stage: 'decode_response',
        requestId: traceId,
        durationMs: timer.elapsedMilliseconds,
      );
      return result;
    } catch (error) {
      DiagnosticLog.recordFailure(
        area: 'api_request',
        event: 'json_failed',
        error: error,
        stage: 'decode_response',
        requestId: traceId,
        durationMs: timer.elapsedMilliseconds,
      );
      rethrow;
    }
  }

  Future<String> _readResponseBody(
    HttpClientResponse response, {
    DiagnosticRequestCancellation? cancellation,
  }) async {
    final iterator = StreamIterator<List<int>>(response);
    final bytes = BytesBuilder(copy: false);
    final clock = _responseClocks[response]!;
    final traceId = _responseRequestIds[response];
    final timer = Stopwatch()..start();
    DiagnosticLog.record(
      area: 'api_request',
      event: 'body_started',
      stage: 'read_response',
      requestId: traceId,
    );
    try {
      if (response.contentLength > _maxResponseBytes) {
        throw _responseTooLargeException();
      }
      while (true) {
        final remaining = _requestTimeout - clock.elapsed;
        if (remaining <= Duration.zero) throw _timeoutException();

        late final bool hasNext;
        try {
          final next = iterator.moveNext().timeout(remaining);
          hasNext = await (cancellation?.wait(next) ?? next);
        } on TimeoutException {
          throw _timeoutException();
        }
        if (!hasNext) break;

        final chunk = iterator.current;
        if (chunk.length > _maxResponseBytes - bytes.length) {
          throw _responseTooLargeException();
        }
        bytes.add(chunk);
      }
      final length = bytes.length;
      final text = utf8.decode(bytes.takeBytes());
      DiagnosticLog.record(
        area: 'api_request',
        event: 'body_completed',
        stage: 'read_response',
        requestId: traceId,
        durationMs: timer.elapsedMilliseconds,
        bytes: length,
      );
      return text;
    } catch (error) {
      DiagnosticLog.recordFailure(
        area: 'api_request',
        event: 'body_failed',
        error: error,
        stage: 'read_response',
        requestId: traceId,
        durationMs: timer.elapsedMilliseconds,
      );
      rethrow;
    } finally {
      await iterator.cancel();
    }
  }

  static ApiException _timeoutException() => const ApiException(
    statusCode: HttpStatus.requestTimeout,
    errorCode: 'request_timeout',
  );

  static ApiException _responseTooLargeException() => const ApiException(
    statusCode: HttpStatus.badGateway,
    errorCode: 'response_too_large',
  );
}

/// A cancellable connection attempt. The factory returns its task immediately
/// so HttpClient's own deadline also covers native DNS resolution and TLS.
class _ResolvedApiConnection {
  _ResolvedApiConnection({
    required this.uri,
    required this.resolve,
    required this.context,
    required this.timeout,
    required this.onFailure,
  });

  final Uri uri;
  final Future<List<InternetAddress>> Function() resolve;
  final SecurityContext? context;
  final Duration timeout;
  final void Function() onFailure;
  bool _cancelled = false;
  ConnectionTask<RawSocket>? _task;
  RawSocket? _transport;
  Socket? _socket;

  void cancel() {
    _cancelled = true;
    _task?.cancel();
    _socket?.destroy();
    _closeTransport();
  }

  void _closeTransport() {
    final transport = _transport;
    _transport = null;
    if (transport != null) {
      unawaited(() async {
        try {
          await transport.close();
        } catch (_) {}
      }());
    }
  }

  void _checkCancelled() {
    if (_cancelled) throw const SocketException('API connection cancelled.');
  }

  Future<Socket> connect() async {
    final traceId = Zone.current[_apiTraceZoneKey] as int?;
    final timer = Stopwatch()..start();
    var stage = 'resolution';
    var attempt = 0;
    String? family;
    DiagnosticLog.record(
      area: 'api_transport',
      event: 'connection_started',
      stage: stage,
      requestId: traceId,
      connectionId: traceId,
    );
    try {
      final addresses = await resolve();
      DiagnosticLog.record(
        area: 'api_transport',
        event: 'resolution_completed',
        stage: stage,
        requestId: traceId,
        count: addresses.length,
        durationMs: timer.elapsedMilliseconds,
      );
      _checkCancelled();
      Object? lastError;
      for (final address
          in addresses.isEmpty ? <Object>[uri.host] : addresses) {
        attempt++;
        family = address is InternetAddress
            ? (address.type == InternetAddressType.IPv6 ? 'ipv6' : 'ipv4')
            : 'system';
        stage = address is InternetAddress
            ? 'tcp_connect'
            : 'system_dns_and_tcp';
        timer.reset();
        _checkCancelled();
        try {
          DiagnosticLog.record(
            area: 'api_transport',
            event: 'tcp_started',
            stage: stage,
            requestId: traceId,
            attempt: attempt,
            family: family,
          );
          _task = await RawSocket.startConnect(address, uri.port);
          _checkCancelled();
          _transport = await _task!.socket.timeout(timeout);
          DiagnosticLog.record(
            area: 'api_transport',
            event: 'tcp_completed',
            stage: stage,
            requestId: traceId,
            attempt: attempt,
            family: family,
            durationMs: timer.elapsedMilliseconds,
          );
          _checkCancelled();
          final transport = _transport!;
          stage = 'tls_handshake';
          timer.reset();
          DiagnosticLog.record(
            area: 'api_transport',
            event: 'tls_started',
            stage: stage,
            requestId: traceId,
            attempt: attempt,
            family: family,
          );
          final handshake = RawSecureSocket.secure(
            transport,
            host: uri.host,
            context: context,
          );
          // Keep the raw transport while TLS negotiates: Socket.secure would
          // detach its public TCP wrapper, making destroy() a no-op until the
          // handshake finishes. A late success must also be closed explicitly.
          unawaited(
            handshake.then<void>((secure) {
              if (_cancelled || !identical(_transport, transport)) {
                unawaited(() async {
                  try {
                    await secure.close();
                  } catch (_) {}
                }());
              }
            }, onError: (Object _, StackTrace _) {}),
          );
          final secure = await handshake.timeout(timeout);
          DiagnosticLog.record(
            area: 'api_transport',
            event: 'tls_completed',
            stage: stage,
            requestId: traceId,
            attempt: attempt,
            family: family,
            durationMs: timer.elapsedMilliseconds,
          );
          _socket = _ApiSecureSocket(secure);
          _checkCancelled();
          return _socket!;
        } catch (error) {
          DiagnosticLog.recordFailure(
            area: 'api_transport',
            event: 'attempt_failed',
            error: error,
            stage: stage,
            requestId: traceId,
            attempt: attempt,
            family: family,
            durationMs: timer.elapsedMilliseconds,
          );
          lastError = error;
          _task?.cancel();
          _socket?.destroy();
          _socket = null;
          _closeTransport();
        }
      }
      throw lastError ?? const SocketException('API connection unavailable.');
    } catch (error) {
      DiagnosticLog.recordFailure(
        area: 'api_transport',
        event: 'connection_failed',
        error: error,
        stage: stage,
        requestId: traceId,
        attempt: attempt == 0 ? null : attempt,
        family: family,
        durationMs: timer.elapsedMilliseconds,
      );
      onFailure();
      rethrow;
    }
  }
}

/// Public Socket/IOSink adapter for RawSecureSocket. Retaining the raw TCP
/// transport lets the connection task abort even a silent TLS peer. The
/// adapter observes read pauses and writes only after native write readiness.
class _ApiSecureSocket extends Stream<Uint8List> implements SecureSocket {
  _ApiSecureSocket(this._raw) {
    _incoming = StreamController<Uint8List>(
      sync: true,
      onListen: () => _raw.readEventsEnabled = true,
      onPause: () => _raw.readEventsEnabled = false,
      onResume: () => _raw.readEventsEnabled = true,
      onCancel: destroy,
    );
    _sink = IOSink(_ApiSocketConsumer(this));
    unawaited(
      _sink.done.then<void>(
        (_) {
          if (!_done.isCompleted) _done.complete();
        },
        onError: (Object error, StackTrace stack) {
          if (!_done.isCompleted) _done.completeError(error, stack);
        },
      ),
    );
    unawaited(
      _done.future.then<void>((_) {}, onError: (Object _, StackTrace _) {}),
    );
    _raw.listen(_event, onError: _error, onDone: _remoteClosed);
    _raw.readEventsEnabled = false;
    _raw.writeEventsEnabled = false;
  }

  final RawSecureSocket _raw;
  // A persistent socket can serve later requests. Its creation identifier is
  // a connection reference, never evidence of the currently active request.
  final int? _connectionTraceId = Zone.current[_apiTraceZoneKey] as int?;
  late final StreamController<Uint8List> _incoming;
  late final IOSink _sink;
  final Completer<void> _done = Completer<void>();
  StreamIterator<List<int>>? _outgoing;
  Completer<void>? _writeReady;
  bool _destroyed = false;

  void _event(RawSocketEvent event) {
    if (_destroyed) return;
    if (event == RawSocketEvent.read) {
      while (!_destroyed && !_incoming.isClosed && !_incoming.isPaused) {
        final data = _raw.read();
        if (data == null) break;
        _incoming.add(data);
      }
    } else if (event == RawSocketEvent.write) {
      _raw.writeEventsEnabled = false;
      final ready = _writeReady;
      _writeReady = null;
      ready?.complete();
    } else if (event == RawSocketEvent.readClosed) {
      _remoteClosed();
    } else if (event == RawSocketEvent.closed) {
      destroy();
    }
  }

  void _remoteClosed() {
    if (!_incoming.isClosed) unawaited(_incoming.close());
  }

  void _error(Object error, StackTrace stack) {
    DiagnosticLog.recordFailure(
      area: 'api_transport',
      event: 'socket_failed',
      error: error,
      stage: 'socket_read',
      connectionId: _connectionTraceId,
    );
    if (!_incoming.isClosed) _incoming.addError(error, stack);
    destroy();
  }

  Future<void> _write(Stream<List<int>> stream) async {
    if (_destroyed) throw const SocketException('API socket closed.');
    final iterator = StreamIterator<List<int>>(stream);
    _outgoing = iterator;
    try {
      while (await iterator.moveNext()) {
        final data = iterator.current;
        var offset = 0;
        while (offset < data.length) {
          if (_destroyed) throw const SocketException('API socket closed.');
          offset += _raw.write(data, offset, data.length - offset);
          if (offset < data.length) {
            final ready = Completer<void>();
            _writeReady = ready;
            _raw.writeEventsEnabled = true;
            await ready.future;
          }
        }
      }
      if (_destroyed) throw const SocketException('API socket closed.');
    } catch (error) {
      DiagnosticLog.recordFailure(
        area: 'api_transport',
        event: 'socket_failed',
        error: error,
        stage: 'socket_write',
        connectionId: _connectionTraceId,
      );
      rethrow;
    } finally {
      if (identical(_outgoing, iterator)) _outgoing = null;
      await iterator.cancel();
    }
  }

  @override
  void destroy() {
    if (_destroyed) return;
    _destroyed = true;
    final ready = _writeReady;
    _writeReady = null;
    ready?.completeError(const SocketException('API socket closed.'));
    final outgoing = _outgoing;
    if (outgoing != null) {
      unawaited(() async {
        try {
          await outgoing.cancel();
        } catch (_) {}
      }());
    }
    if (!_done.isCompleted) _done.complete();
    unawaited(() async {
      try {
        await _raw.close();
      } catch (_) {}
    }());
    _remoteClosed();
  }

  @override
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => _incoming.stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );

  @override
  void add(List<int> data) => _sink.add(data);
  @override
  Future<void> addStream(Stream<List<int>> stream) => _sink.addStream(stream);
  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      throw UnsupportedError('Socket sinks do not support addError.');
  @override
  void write(Object? object) => _sink.write(object);
  @override
  void writeAll(Iterable<Object?> objects, [String separator = '']) =>
      _sink.writeAll(objects, separator);
  @override
  void writeln([Object? object = '']) => _sink.writeln(object);
  @override
  void writeCharCode(int charCode) => _sink.writeCharCode(charCode);
  @override
  Future<void> flush() => _sink.flush();
  @override
  Future<void> close() {
    _sink.close();
    return done;
  }

  @override
  Future<void> get done => _done.future;
  @override
  Encoding get encoding => _sink.encoding;
  @override
  set encoding(Encoding value) => _sink.encoding = value;
  @override
  InternetAddress get address => _raw.address;
  @override
  InternetAddress get remoteAddress => _raw.remoteAddress;
  @override
  int get port => _raw.port;
  @override
  int get remotePort => _raw.remotePort;
  @override
  bool setOption(SocketOption option, bool enabled) =>
      _raw.setOption(option, enabled);
  @override
  Uint8List getRawOption(RawSocketOption option) => _raw.getRawOption(option);
  @override
  void setRawOption(RawSocketOption option) => _raw.setRawOption(option);
  @override
  X509Certificate? get peerCertificate => _raw.peerCertificate;
  @override
  String? get selectedProtocol => _raw.selectedProtocol;
  // SecureSocket documents renegotiate as an unimplemented no-op. Keep that
  // contract without invoking the deprecated RawSecureSocket stub.
  @override
  @Deprecated('Not implemented')
  void renegotiate({
    bool useSessionCache = true,
    bool requestClientCertificate = false,
    bool requireClientCertificate = false,
  }) {}

  // Socket has a dart:io-private upgrade hook. This is already a secure,
  // direct connection: proxy upgrades are rejected by the factory above.
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _ApiSocketConsumer implements StreamConsumer<List<int>> {
  _ApiSocketConsumer(this.socket);
  final _ApiSecureSocket socket;
  @override
  Future<void> addStream(Stream<List<int>> stream) => socket._write(stream);
  @override
  Future<void> close() async {
    if (!socket._destroyed) socket._raw.shutdown(SocketDirection.send);
  }
}
