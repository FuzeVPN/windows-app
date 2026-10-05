// SPDX-License-Identifier: MPL-2.0
part of 'app_controller.dart';

// Detailed update references stay local. Reports keep the versioned API's
// existing categories rather than introducing unsupported error identifiers.
String _updateReportCode(String code) => switch (code) {
  'update_application_signature_invalid' => 'update_unsigned_application',
  'update_application_open_failed' => 'update_storage_failed',
  'update_archive_extract_failed' ||
  'update_portable_target_invalid' => 'update_storage_failed',
  'update_portable_replace_failed' => 'update_install_failed',
  'update_application_architecture_mismatch' => 'update_unsupported',
  'update_download_http_error' ||
  'update_download_redirect_rejected' ||
  'update_download_network_error' ||
  'update_download_timeout' ||
  'update_download_url_invalid' ||
  'update_download_too_large' ||
  'update_download_empty' => 'update_download_failed',
  'update_network_timeout' => 'update_network_failed',
  'update_hash_mismatch' ||
  'update_signature_invalid' ||
  'update_publisher_mismatch' ||
  'update_untrusted_publisher' ||
  'update_version_mismatch' ||
  'update_package_architecture_mismatch' ||
  'update_package_mode_mismatch' ||
  'update_archive_invalid' ||
  'update_archive_unsafe' ||
  'update_archive_too_large' ||
  'update_portable_manifest_invalid' ||
  'update_package_version_mismatch' => 'update_verification_failed',
  'update_prepare_failed' => 'update_request_failed',
  'update_uac_cancelled' => 'update_cancelled',
  _ => code,
};

class DiagnosticCheckView {
  const DiagnosticCheckView(
    this.label,
    this.result,
    this.ageMs, {
    this.id = 'unknown',
    this.code,
    this.windowsError,
    this.httpStatus,
    String? tlsReason,
    // Keep a public named argument while validating its private backing field.
    // ignore: prefer_initializing_formals
  }) : _tlsReason = tlsReason;
  final String id;
  final String label;
  final String result;
  final int? ageMs;
  final String? code;
  final int? windowsError;
  final int? httpStatus;
  final String? _tlsReason;
  String? get tlsReason =>
      DiagnosticLog.tlsFailureReasons.contains(_tlsReason) ? _tlsReason : null;
}

// A local error reference is deliberately narrower than arbitrary exception
// text. These additional native references are not part of the API v1 schema.
const _localDiagnosticCodes = {
  'api_resolver_invalid_response',
  'maintenance_in_progress',
  'network_unreachable',
  'runtime_detection_failed',
  'runtime_owned_by_another_user',
};

String? _localDiagnosticCode(String? code) => code == null
    ? null
    : diagnosticCodes.contains(code) || _localDiagnosticCodes.contains(code)
    ? code
    : 'unknown_error';

String _diagnosticApiCheckLabel(String? code, int? httpStatus) {
  if (httpStatus != null) return 'Accès aux services FuzeVPN';
  return switch (code) {
    'api_bootstrap_unavailable' ||
    'api_resolution_unavailable' ||
    'api_resolver_invalid_response' ||
    'endpoint_resolution_failed' => 'Résolution réseau',
    'storage_access_denied' ||
    'storage_corrupt' ||
    'storage_decryption_failed' ||
    'storage_error' ||
    'storage_failure' ||
    'storage_io_error' ||
    'storage_unavailable' ||
    'secure_storage_corrupt' ||
    'secure_storage_read_failed' ||
    'secure_storage_write_failed' => 'Stockage protégé',
    'broker_unavailable' ||
    'broker_busy' ||
    'broker_write_failed' ||
    'broker_response_timeout' ||
    'broker_protocol_error' ||
    'runtime_detection_failed' ||
    'runtime_status_unavailable' ||
    'runtime_unavailable' ||
    'runtime_owned_by_another_user' ||
    'service_configuration_mismatch' ||
    'service_unavailable' ||
    'native_bridge_unavailable' ||
    'native_operation_failed' ||
    'maintenance_in_progress' => 'Moteur VPN',
    'permission_denied' => 'Autorisations',
    'network_unreachable' ||
    'network_error' ||
    'network_unavailable' ||
    'network_timeout' ||
    'request_timeout' ||
    'tls_handshake_failed' ||
    'api_transport_unsupported' ||
    'invalid_api_response' ||
    'invalid_response' => 'Connexion de l’application',
    _ => 'Vérification technique',
  };
}

// Native detail is for the local view only. The versioned report retains its
// existing code schema and never includes raw exception text or details.
class _LocalDiagnosticApiFailure {
  const _LocalDiagnosticApiFailure(
    this.code,
    this.windowsError,
    this.httpStatus,
    this.tlsReason,
  );
  final String code;
  final int? windowsError;
  final int? httpStatus;
  final String? tlsReason;
}

final _diagnosticApiFailures = Expando<_LocalDiagnosticApiFailure>();
final _diagnosticNativeFailures = Expando<_LocalDiagnosticApiFailure>();

class DiagnosticDeliveryView {
  const DiagnosticDeliveryView(
    this.id,
    this.status, {
    this.pending = false,
    this.retryable = false,
  });
  final String id;
  final String status;
  final bool pending;
  final bool retryable;
}

extension AppDiagnostics on AppController {
  List<DiagnosticDeliveryView> get diagnosticDeliveries => [
    for (final report in diagnostics.pendingReports)
      DiagnosticDeliveryView(
        report.reportId,
        diagnostics.sendingReportId == report.reportId
            ? 'Envoi en cours…'
            : report.pausedForAuth
            ? 'Envoi suspendu : reconnectez-vous au même compte.'
            : report.terminalCode != null
            ? 'Envoi arrêté. Consultez l’assistance.'
            : report.automaticAttempts >= 5
            ? 'Envoi suspendu : réessayez manuellement.'
            : 'Rapport en attente d’envoi.',
        pending: true,
        retryable:
            report.terminalCode == null &&
            !report.pausedForAuth &&
            profile != null &&
            !diagnostics.isSending,
      ),
    for (final receipt in diagnostics.receipts)
      DiagnosticDeliveryView(receipt.reportId, 'Rapport reçu par le serveur.'),
  ];
  bool get canRunDiagnostic =>
      !_disposed &&
      !diagnosticRunning &&
      !diagnosticRepairRunning &&
      !isConnectionBusy &&
      !_isSigningOut &&
      !_automaticReconnectInProgress &&
      !isLocationMigrationActive;

  bool get canSendPreparedDiagnostic =>
      profile != null &&
      preparedDiagnosticReport != null &&
      !diagnostics.pendingReports.any(
        (r) => r.reportId == preparedDiagnosticReport!.reportId,
      ) &&
      !diagnostics.receipts.any(
        (r) => r.clientReportId == preparedDiagnosticReport!.reportId,
      ) &&
      !diagnosticRunning &&
      !diagnosticRepairRunning &&
      !_isSigningOut;

  String? get diagnosticDeliveryError {
    final code = diagnostics.lastFailure?.code;
    if (code == null ||
        code == 'diagnostic_collection_failed' ||
        code == 'diagnostic_cancelled') {
      return null;
    }
    return 'Le rapport n’a pas pu être envoyé ou enregistré. Le VPN continue de fonctionner indépendamment.';
  }

  String? get diagnosticDeliveryCode {
    final value = diagnostics.lastFailure?.code;
    return value == null
        ? null
        : diagnosticCodes.contains(value) ||
              const {
                'invalid_diagnostic',
                'diagnostic_conflict',
                'diagnostic_too_large',
                'diagnostic_quota_exceeded',
                'diagnostics_unavailable',
                'diagnostic_content_unavailable',
                'diagnostic_session_required',
                'diagnostics_storage_failed',
                'diagnostic_delivery_unknown',
                'diagnostic_rate_limited',
                'diagnostic_queue_full',
                'diagnostic_environment_invalid',
                'diagnostic_preparation_failed',
                'diagnostic_collection_failed',
                'diagnostic_cancelled',
                'broker_unavailable',
                'runtime_detection_failed',
              }.contains(value)
        ? value
        : 'unknown_error';
  }

  int? get diagnosticDeliveryHttpStatus {
    final value = diagnostics.lastFailure?.httpStatus;
    return value != null && value >= 100 && value <= 599 ? value : null;
  }

  String? get diagnosticPreview => preparedDiagnosticReport == null
      ? null
      : const JsonEncoder.withIndent(
          '  ',
        ).convert(preparedDiagnosticReport!.json);

  /// The complete support report merges the persisted and current app trace
  /// with native evidence; this getter remains for internal compatibility.
  List<String> get diagnosticLocalTrace => DiagnosticLog.recentLines;

  String get diagnosticLocalExport =>
      diagnosticPreview ??
      const JsonEncoder.withIndent('  ').convert({
        'status': 'not_collected',
        if (_diagnosticSupport != null) 'support': _diagnosticSupport,
      });

  bool get canRunCompleteDiagnostic =>
      !_disposed &&
      !diagnosticRunning &&
      !diagnosticRepairRunning &&
      !diagnosticExportRunning &&
      !_completeDiagnosticRunning &&
      !_isSigningOut;

  Future<String> collectLocalDiagnosticExport() {
    final existing = _diagnosticExport;
    if (existing != null) return existing;
    final future = _collectCompleteDiagnosticExport();
    _diagnosticExport = future;
    return future;
  }

  Future<String> _collectCompleteDiagnosticExport() async {
    diagnosticExportRunning = true;
    _notifyDiagnosticView();
    try {
      if (canRunDiagnostic) {
        await runUserDiagnostic();
      } else {
        final generation = _diagnosticGeneration;
        final support = await _collectCompleteSupport(report: 'busy');
        if (!_disposed && generation == _diagnosticGeneration) {
          _diagnosticSupport = support;
          preparedDiagnosticReport = diagnostics.prepareManualReport(
            snapshot: {
              'protocol': _diagnosticProtocol,
              'state': _diagnosticState,
              'snapshot': {'kill_switch_requested': killSwitchEnabled},
              'windows': {'support': support},
            },
          );
        }
      }
      return diagnosticLocalExport;
    } finally {
      _diagnosticExport = null;
      diagnosticExportRunning = false;
      _notifyDiagnosticView();
    }
  }

  Future<void> runCompleteDiagnostic() async {
    if (!canRunCompleteDiagnostic) return;
    _completeDiagnosticRunning = true;
    try {
      await _runCompleteDiagnostic();
    } finally {
      _completeDiagnosticRunning = false;
      _notifyDiagnosticView();
    }
  }

  Future<void> _runCompleteDiagnostic() async {
    final account = profile?.userId;
    final sessionEpoch = _sessionEpoch;
    await collectLocalDiagnosticExport();
    if (_disposed ||
        _isSigningOut ||
        sessionEpoch != _sessionEpoch ||
        account != profile?.userId) {
      return;
    }
    final report = preparedDiagnosticReport;
    if (report == null) {
      diagnosticMessage = 'Le diagnostic est incomplet. Réessayez.';
    } else if (account == null) {
      diagnosticMessage =
          'Diagnostic complet collecté. Connectez-vous à votre compte pour l’envoyer.';
    } else {
      diagnosticExportRunning = true;
      _notifyDiagnosticView();
      try {
        final received = await diagnostics.sendPreparedReport(report);
        if (_disposed ||
            sessionEpoch != _sessionEpoch ||
            account != profile?.userId) {
          return;
        }
        diagnosticMessage = received
            ? 'Diagnostic complet transmis à l’assistance.'
            : diagnostics.pendingReports.any(
                (r) => r.reportId == report.reportId && r.terminalCode == null,
              )
            ? 'Diagnostic complet conservé, en attente d’envoi.'
            : 'Le diagnostic complet n’a pas pu être transmis. Consultez le code d’erreur.';
      } finally {
        diagnosticExportRunning = false;
      }
    }
    _notifyDiagnosticView();
  }

  Future<Map<String, Object?>> _collectCompleteSupport({
    required String report,
  }) async {
    Map<String, Object?> unavailable(String status, {int? windowsError}) => {
      'status': status,
      'truncated': false,
      'discarded_lines': 0,
      if (windowsError != null &&
          windowsError >= 0 &&
          windowsError <= 0xffffffff)
        'win32_error': windowsError,
    };
    final applicationFuture = () async {
      try {
        return await LocalDiagnosticTrace.collect(
          currentLines: DiagnosticLog.recentLines,
        ).timeout(const Duration(seconds: 3));
      } on TimeoutException {
        return {...unavailable('timeout'), 'events': <Object?>[]};
      } catch (_) {
        return {...unavailable('read_failed'), 'events': <Object?>[]};
      }
    }();
    final nativeFuture = () async {
      try {
        final value = await _diagnosticsBridge
            .collectLocalDiagnostics()
            .timeout(const Duration(seconds: 5));
        return <String, Object?>{
          'observation': value,
          'collection': unavailable('ok'),
        };
      } on TimeoutException {
        return <String, Object?>{'collection': unavailable('timeout')};
      } on PlatformException catch (error) {
        final details = error.details;
        final code = details is Map ? details['win32_error'] : null;
        return <String, Object?>{
          'collection': unavailable(
            'unavailable',
            windowsError: code is int ? code : null,
          ),
        };
      } catch (_) {
        return <String, Object?>{'collection': unavailable('unavailable')};
      }
    }();
    final application = await applicationFuture;
    final native = await nativeFuture;
    final observation =
        native['observation'] as Map<String, Object?>? ?? const {};
    final nativeLog =
        observation['native_log'] as Map<String, Object?>? ??
        unavailable('unavailable');
    final timeline =
        <Map<String, Object?>>[
          for (final event in application['events'] as List)
            {
              'source': 'application',
              ...Map<String, Object?>.from(event as Map),
            },
          for (final event in nativeLog['events'] as List? ?? const [])
            {'source': 'native', ...Map<String, Object?>.from(event as Map)},
        ]..sort((a, b) {
          final order = DateTime.parse(
            a['timestamp'] as String,
          ).compareTo(DateTime.parse(b['timestamp'] as String));
          return order != 0 ? order : jsonEncode(a).compareTo(jsonEncode(b));
        });
    Map<String, Object?> metadata(Map<String, Object?> value) =>
        Map.of(value)..remove('events');
    return DiagnosticSupport.validate({
      'schema_version': 1,
      'collected_at': _now().toUtc().toIso8601String(),
      'collection': {
        'report': report,
        'application_log': metadata(application),
        'native': native['collection'],
        'native_log': metadata(nativeLog),
      },
      if (observation['environment'] != null)
        'environment': observation['environment'],
      if (observation['service'] != null) 'service': observation['service'],
      if (observation['runtime'] != null) 'runtime': observation['runtime'],
      'timeline': timeline,
    });
  }

  List<DiagnosticCheckView> get diagnosticChecks {
    final values = diagnosticResults?['checks'];
    if (values is! List) return const [];
    return values
        .whereType<Map>()
        .map(
          (check) => DiagnosticCheck.fromMap(Map<String, Object?>.from(check)),
        )
        .map((check) {
          final failure = check.id == 'api_reachability'
              ? _diagnosticApiFailures[this]
              : check.id == 'service_availability'
              ? _diagnosticNativeFailures[this]
              : null;
          final code = _localDiagnosticCode(failure?.code ?? check.code);
          return DiagnosticCheckView(
            switch (check.id) {
              'api_reachability' =>
                check.result == 'passed'
                    ? 'Accès aux services FuzeVPN'
                    : _diagnosticApiCheckLabel(code, failure?.httpStatus),
              'service_availability' => 'Moteur VPN',
              'driver_availability' => 'Pilote VPN',
              'secure_storage' => 'Stockage protégé',
              'tunnel_configuration' => 'Configuration du tunnel',
              'tunnel_connection' => 'État du tunnel',
              'handshake' => 'Échange avec le serveur VPN',
              'routing' => 'Routes du tunnel',
              'dns' => 'Configuration DNS',
              'ipv4' => 'Configuration IPv4',
              'ipv6' => 'Configuration IPv6',
              'kill_switch' => 'Kill switch',
              'webrtc' => 'Protection WebRTC',
              'certificate' => 'Certificat VPN',
              'cleanup' => 'Nettoyage du tunnel',
              'connectivity' => 'Accès Internet',
              'permissions' => 'Autorisations',
              _ => 'Vérification technique',
            },
            check.result,
            check.ageMs,
            id: check.id,
            code: code,
            windowsError: failure?.windowsError,
            httpStatus: failure?.httpStatus,
            tlsReason: failure?.tlsReason,
          );
        })
        .toList(growable: false);
  }

  bool get canRepairDiagnosticCleanup {
    final runtime = diagnosticResults?['runtime'];
    return !isConnectionBusy &&
        !_isSigningOut &&
        !runtimeOwnedByAnotherUser &&
        !diagnosticRepairRunning &&
        runtime is Map &&
        runtime['presence'] == 'present' &&
        runtime['cleanup_eligible'] == true &&
        runtime['owned_by_another_user'] == false;
  }

  void _onDiagnosticsChanged() {
    if (!_disposed) {
      final report = preparedDiagnosticReport;
      if (report != null &&
          diagnosticMessage ==
              'Diagnostic complet conservé, en attente d’envoi.' &&
          diagnostics.receipts.any(
            (receipt) => receipt.clientReportId == report.reportId,
          )) {
        diagnosticMessage = 'Diagnostic complet transmis à l’assistance.';
      }
      _notifyDiagnosticView();
    }
  }

  void _bindDiagnosticSession() {
    final account = profile?.userId;
    if (account == null || _disposed || _isSigningOut) return;
    if (diagnostics.accountId != null && diagnostics.accountId != account) {
      _diagnosticGeneration++;
      preparedDiagnosticReport = null;
      diagnosticResults = null;
      _diagnosticSupport = null;
      diagnosticMessage = null;
    }
    final epoch = _sessionEpoch;
    unawaited(_loadDiagnosticEnvironment());
    unawaited(
      diagnostics.sessionChanged(
        accountId: account,
        tokenProvider: () async {
          if (_disposed ||
              _isSigningOut ||
              epoch != _sessionEpoch ||
              profile?.userId != account) {
            return null;
          }
          final token = await _store.token();
          return _disposed ||
                  _isSigningOut ||
                  epoch != _sessionEpoch ||
                  profile?.userId != account
              ? null
              : token;
        },
      ),
    );
  }

  Future<void> _loadDiagnosticEnvironment() async {
    try {
      final env = await const WindowsUpdateBridge().getEnvironment();
      if (_disposed) return;
      diagnostics.updateEnvironment(
        appVersion: env.version.toString(),
        environment: {
          'architecture': env.arch,
          'os_family': 'windows',
          'os_major': env.windowsBuild >= 22000 ? 11 : 10,
          'windows_build': env.windowsBuild,
          'installation_mode': env.installationMode.name,
        },
      );
    } catch (_) {
      /* The collection remains independent of startup. */
    }
  }

  void _suspendDiagnostics({required bool purge}) {
    _diagnosticGeneration++;
    preparedDiagnosticReport = null;
    diagnosticResults = null;
    _diagnosticSupport = null;
    unawaited(diagnostics.suspendSession(purge: purge));
  }

  Future<void> _resumeDiagnostics() async {
    try {
      await diagnostics.resumePending();
    } catch (_) {
      /* Best effort. */
    }
  }

  Future<bool> setDiagnosticAutomaticConsent(bool value) async {
    if (profile == null || _isSigningOut || _disposed) return false;
    final saved = await diagnostics.setAutomaticConsent(value);
    if (!_disposed) _notifyDiagnosticView();
    return saved;
  }

  String get _diagnosticProtocol =>
      (activeProtocol ?? _retainedProtectionProtocol ?? vpnProtocol) ==
          VpnProtocol.openVpn
      ? 'openvpn'
      : 'wireguard';

  String get _diagnosticState => switch (vpnStatus) {
    VpnStatus.preparing || VpnStatus.connecting => 'connecting',
    VpnStatus.blocked => 'degraded',
    _ => vpnStatus.name,
  };

  Future<Map<String, Object?>> _collectDiagnosticSnapshot() async {
    final generation = _diagnosticGeneration;
    var protocol = _diagnosticProtocol;
    final result = <String, Object?>{};
    try {
      final environment = await const WindowsUpdateBridge()
          .getEnvironment()
          .timeout(const Duration(seconds: 3));
      final fields = <String, Object?>{
        'architecture': environment.arch,
        'os_family': 'windows',
        'os_major': environment.windowsBuild >= 22000 ? 11 : 10,
        'windows_build': environment.windowsBuild,
        'installation_mode': environment.installationMode.name,
      };
      diagnostics.updateEnvironment(
        appVersion: environment.version.toString(),
        environment: fields,
      );
      result['environment'] = fields;
    } catch (error) {
      await DiagnosticLog.recordFailure(
        area: 'runtime_state',
        event: 'failed',
        stage: 'diagnostic_environment',
        error: error,
      );
      /* Environment remains unknown, never guessed from UI. */
    }
    if (_disposed || generation != _diagnosticGeneration || isConnectionBusy) {
      throw const DiagnosticsFailure('diagnostic_cancelled');
    }
    _diagnosticNativeFailures[this] = null;
    try {
      final native = await _diagnosticsBridge.collectSnapshot().timeout(
        const Duration(seconds: 8),
      );
      result.addAll(native);
      final runtime = native['runtime'];
      if (runtime is Map &&
          const {'openvpn', 'wireguard'}.contains(runtime['protocol'])) {
        protocol = runtime['protocol'] as String;
      }
    } catch (error) {
      await DiagnosticLog.recordFailure(
        area: 'runtime_state',
        event: 'failed',
        stage: 'native_snapshot',
        error: error,
      );
      final details = error is PlatformException ? error.details : null;
      final nativeCode = details is Map ? details['win32_error'] : null;
      final windowsError =
          nativeCode is int && nativeCode >= 0 && nativeCode <= 0xffffffff
          ? nativeCode
          : null;
      final code = _localDiagnosticCode(
        error is PlatformException
            ? error.code
            : error is TimeoutException
            ? 'request_timeout'
            : 'native_bridge_unavailable',
      )!;
      _diagnosticNativeFailures[this] = _LocalDiagnosticApiFailure(
        code,
        windowsError,
        null,
        null,
      );
      result['runtime'] = <String, Object?>{'presence': 'unknown'};
      result['checks'] = <Object?>[
        {
          'id': 'service_availability',
          'result': 'unknown',
          'code': diagnosticCode(code),
        },
        {'id': 'tunnel_connection', 'result': 'unknown'},
        {'id': 'kill_switch', 'result': 'unknown'},
      ];
    }
    if (_disposed || generation != _diagnosticGeneration || isConnectionBusy) {
      throw const DiagnosticsFailure('diagnostic_cancelled');
    }
    final checks = <Object?>[...?result['checks'] as List?];
    final clock = Stopwatch()..start();
    _diagnosticApiFailures[this] = null;
    try {
      await _api.locations();
      checks.add(
        DiagnosticCheck(
          id: 'api_reachability',
          result: 'passed',
          durationMs: clock.elapsedMilliseconds,
          ageMs: 0,
        ).toJson(),
      );
    } catch (error) {
      final code = _localDiagnosticCode(switch (error) {
        ApiException error => error.diagnosticErrorCode,
        PlatformException error => error.code,
        TlsException _ => 'tls_handshake_failed',
        SocketException _ => 'network_unreachable',
        TimeoutException _ => 'request_timeout',
        FormatException _ => 'invalid_api_response',
        _ => 'unexpected_error',
      })!;
      final nativeCode = switch (error) {
        ApiException error => error.windowsError,
        SocketException error => error.osError?.errorCode,
        _ => null,
      };
      final windowsError =
          nativeCode != null &&
              nativeCode >= -0x80000000 &&
              nativeCode <= 0xffffffff
          ? nativeCode
          : null;
      final observedStatus = error is ApiException
          ? error.observedHttpStatus
          : null;
      final httpStatus =
          observedStatus != null &&
              observedStatus >= 100 &&
              observedStatus <= 599
          ? observedStatus
          : null;
      // Dart's TLS osError code belongs to the TLS implementation, not Win32.
      // Only a canonical reason from its bounded allowlist reaches the UI.
      final tlsReason = error is TlsException
          ? DiagnosticLog.tlsFailureReason(error)
          : null;
      _diagnosticApiFailures[this] = _LocalDiagnosticApiFailure(
        code,
        windowsError,
        httpStatus,
        tlsReason,
      );
      final localUnavailable =
          httpStatus == null &&
          (error is PlatformException ||
              error is ApiException && error.localErrorCode != null ||
              const {
                'Moteur VPN',
                'Stockage protégé',
                'Résolution réseau',
                'Autorisations',
                'Vérification technique',
              }.contains(_diagnosticApiCheckLabel(code, null)) ||
              code == 'api_transport_unsupported' ||
              code == 'unknown_error' ||
              code == 'unexpected_error');
      checks.add(
        DiagnosticCheck(
          id: 'api_reachability',
          result: localUnavailable ? 'unknown' : 'failed',
          code: code == 'runtime_detection_failed'
              ? 'runtime_status_unavailable'
              : code,
          durationMs: clock.elapsedMilliseconds,
          ageMs: 0,
        ).toJson(),
      );
    }
    if (_disposed || generation != _diagnosticGeneration || isConnectionBusy) {
      throw const DiagnosticsFailure('diagnostic_cancelled');
    }
    // Observing API reachability is not a general Internet or leakage test.
    checks.add(DiagnosticCheck(id: 'connectivity', result: 'skipped').toJson());
    final snapshot = <String, Object?>{
      ...?result['snapshot'] as Map<String, Object?>?,
      'kill_switch_requested': killSwitchEnabled,
    };
    result.addAll({
      'checks': checks,
      'snapshot': snapshot,
      'protocol': protocol,
      'state': _diagnosticState,
    });
    return result;
  }

  Future<void> runUserDiagnostic({bool send = false}) async {
    if (!canRunDiagnostic) return;
    final generation = ++_diagnosticGeneration;
    final account = profile?.userId;
    diagnosticRunning = true;
    diagnosticMessage = null;
    diagnosticResults = null;
    preparedDiagnosticReport = null;
    _diagnosticSupport = null;
    _notifyDiagnosticView();
    try {
      final snapshot = await diagnostics.runChecks();
      if (_disposed || generation != _diagnosticGeneration) return;
      final support = await _collectCompleteSupport(
        report: snapshot == null ? 'failed' : 'ok',
      );
      if (_disposed || generation != _diagnosticGeneration) return;
      _diagnosticSupport = support;
      diagnosticResults = snapshot;
      preparedDiagnosticReport = diagnostics.prepareManualReport(
        snapshot: {
          ...?snapshot,
          if (snapshot == null) 'protocol': _diagnosticProtocol,
          if (snapshot == null) 'state': _diagnosticState,
          'windows': {
            ...?snapshot?['windows'] as Map<String, Object?>?,
            'support': support,
          },
        },
      );
      diagnosticMessage =
          'Diagnostic terminé. Consultez les résultats ci-dessous.';
      diagnosticRunning = false;
      _notifyDiagnosticView();
      if (send &&
          account != null &&
          account == profile?.userId &&
          preparedDiagnosticReport != null) {
        unawaited(diagnostics.sendPreparedReport(preparedDiagnosticReport!));
      }
    } catch (_) {
      if (!_disposed && generation == _diagnosticGeneration) {
        diagnosticMessage = 'Le diagnostic est incomplet. Réessayez.';
      }
    } finally {
      if (!_disposed) {
        diagnosticRunning = false;
        _notifyDiagnosticView();
      }
    }
  }

  Future<void> sendUserDiagnostic() async {
    if (!canSendPreparedDiagnostic) return;
    await diagnostics.sendPreparedReport(preparedDiagnosticReport!);
  }

  Future<void> retryDiagnostic(String id) => diagnostics.retry(id);
  Future<void> cancelDiagnostic(String id) => diagnostics.cancel(id);

  Future<void> repairDiagnosticCleanup() async {
    if (!canRepairDiagnosticCleanup || diagnosticRunning) return;
    final sessionEpoch = _sessionEpoch;
    final account = profile?.userId;
    diagnosticRepairRunning = true;
    final stopwatch = Stopwatch()..start();
    var confirmed = false;
    final protocol =
        activeProtocol ?? _retainedProtectionProtocol ?? vpnProtocol;
    _notifyDiagnosticView();
    try {
      await _runConnectionCommand(
        (operationId) async {
          _transitionConnection(operationId, VpnStatus.disconnecting);
          _cancelAutomaticReconnect();
          try {
            await _disconnectActiveTunnel();
            final states = await Future.wait([
              _safe<bool>(_wireguard.isConnected()),
              _safe<bool>(_openVpn.isConnected()),
              _safe<NetworkProtectionStatus>(
                _wireguard.networkProtectionStatus(),
              ),
              _safe<NetworkProtectionStatus>(
                _openVpn.networkProtectionStatus(),
              ),
            ]);
            confirmed =
                states[0] == false &&
                states[1] == false &&
                states[2] is NetworkProtectionStatus &&
                states[3] is NetworkProtectionStatus &&
                !(states[2] as NetworkProtectionStatus).active &&
                !(states[3] as NetworkProtectionStatus).active &&
                !(states[2] as NetworkProtectionStatus).ownedByAnotherUser &&
                !(states[3] as NetworkProtectionStatus).ownedByAnotherUser;
            if (!_acceptConnectionOperation(operationId)) {
              confirmed = false;
              return;
            }
            if (confirmed) {
              confirmed = _markNativeDisconnected(operationId: operationId);
            } else {
              await _restoreNetworkStateAfterFailedDisconnect(
                protocol,
                operationId: operationId,
              );
            }
          } catch (_) {
            await _restoreNetworkStateAfterFailedDisconnect(
              protocol,
              operationId: operationId,
            );
          }
        },
        initialState: vpnStatus == VpnStatus.disconnected
            ? VpnStatus.preparing
            : VpnStatus.disconnecting,
      );
    } finally {
      diagnosticRepairRunning = false;
    }
    stopwatch.stop();
    if (_disposed ||
        sessionEpoch != _sessionEpoch ||
        account != profile?.userId ||
        _isSigningOut) {
      return;
    }
    await runUserDiagnostic();
    if (_disposed ||
        sessionEpoch != _sessionEpoch ||
        account != profile?.userId ||
        _isSigningOut ||
        diagnosticResults == null) {
      return;
    }
    diagnosticResults = {
      ...diagnosticResults!,
      'repairs': [
        DiagnosticRepair(
          id: 'cleanup',
          before: 'failed',
          after: confirmed ? 'passed' : 'unknown',
          result: confirmed ? 'passed' : 'failed',
          durationMs: stopwatch.elapsedMilliseconds,
          code: confirmed ? null : 'cleanup_failed',
        ).toJson(),
      ],
    };
    preparedDiagnosticReport = diagnostics.prepareManualReport(
      snapshot: diagnosticResults,
    );
    diagnosticMessage = confirmed
        ? 'La déconnexion et le nettoyage sont confirmés.'
        : 'Le nettoyage reste non confirmé.';
    _notifyDiagnosticView();
  }

  void _observeDiagnosticEvent(String area, String event, String? code) {
    if (_disposed || (area != 'openvpn' && area != 'wireguard')) return;
    final stage = event.contains('disconnect')
        ? 'disconnect'
        : event.contains('protection')
        ? 'guard_verify'
        : event.contains('enrollment')
        ? 'enrollment'
        : event.contains('renew')
        ? 'certificate_renewal'
        : event.contains('identity')
        ? 'storage'
        : event.contains('profile')
        ? 'profile_create'
        : 'tunnel_start';
    final failed = event.endsWith('_failed');
    final cancelled = const {
      'operation_cancelled',
      'permission_denied',
      'runtime_owned_by_another_user',
      'maintenance_in_progress',
    }.contains(code);
    diagnostics.recordEvent(
      DiagnosticEvent(
        stage: stage,
        event: cancelled
            ? 'cancelled'
            : failed
            ? 'error'
            : event.endsWith('_started')
            ? 'begin'
            : event.contains('cancel')
            ? 'cancelled'
            : event.contains('pending')
            ? 'waiting'
            : 'end',
        code: code,
      ),
    );
    if (failed && !cancelled && code != null && _connectionCommand != null) {
      _diagnosticCandidate = DiagnosticError(
        code: code,
        domain: stage == 'guard_verify' ? 'protection' : 'tunnel',
        operation: _diagnosticOperation,
        stage: stage,
      );
    }
  }

  void _finishDiagnosticOperation(int operationId) {
    if (_disposed ||
        !_acceptConnectionOperation(operationId) ||
        runtimeOwnedByAnotherUser ||
        diagnosticRepairRunning) {
      return;
    }
    if (_automaticReconnectTimer != null &&
        _automaticReconnectAttempts < AppController._reconnectDelays.length) {
      return;
    }
    if (vpnStatus != VpnStatus.error &&
        vpnStatus != VpnStatus.blocked &&
        !(_diagnosticOperation == 'disconnect' &&
            _diagnosticCandidate != null)) {
      return;
    }
    final error = _diagnosticCandidate;
    if (error != null) {
      _emitDiagnosticError(error);
    } else if (_automaticReconnectAttempts >=
        AppController._reconnectDelays.length) {
      _emitDiagnosticFailure(
        'tunnel_failure',
        operation: 'restore',
        stage: 'recovery',
      );
    }
  }

  void _emitDiagnosticFailure(
    String code, {
    required String operation,
    required String stage,
    int? httpStatus,
  }) {
    if (const {
      'operation_cancelled',
      'permission_denied',
      'runtime_owned_by_another_user',
      'maintenance_in_progress',
      'update_cancelled',
      'update_busy',
      'update_portable_manual',
      'update_installer_manual',
      'update_changed',
      'update_not_prepared',
    }.contains(code)) {
      return;
    }
    _emitDiagnosticError(
      DiagnosticError(
        code: code,
        operation: operation,
        stage: stage,
        domain: operation == 'update'
            ? 'client'
            : httpStatus != null
            ? 'api'
            : 'tunnel',
        httpStatus: httpStatus,
      ),
    );
  }

  void _emitDiagnosticError(DiagnosticError error) {
    if (_disposed ||
        _isSigningOut ||
        profile == null ||
        const {
          'invalid_credentials',
          'unauthorized',
          'session_expired',
          'api_token_expired',
          'rate_limited',
          'device_limit',
          'device_exists',
          'subscription_required',
          'email_verification_required',
          'verification_email_cooldown',
          'invalid_location',
          'openvpn_operation_pending',
          'update_unavailable',
          'update_unsupported',
        }.contains(error.code)) {
      return;
    }
    diagnostics.recordTerminalError(
      error,
      protocol: _diagnosticProtocol,
      state: _diagnosticState,
    );
  }
}
