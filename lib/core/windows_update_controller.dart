// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'api_client.dart';
import 'diagnostic_log.dart';
import 'windows_update_bridge.dart';
import 'windows_update_models.dart';

export 'windows_update_models.dart';

enum WindowsUpdateStatus {
  idle,
  checking,
  available,
  noUpdate,
  downloading,
  ready,
  installing,
  launched,
  error,
  unsupported,
}

enum _UpdateOperation { check, prepare, install, discard }

class WindowsUpdateController extends ChangeNotifier {
  WindowsUpdateController({ApiClient? api, WindowsUpdateBridge? bridge})
    : _api = api ?? ApiClient(),
      _ownsApi = api == null,
      _bridge = bridge ?? const WindowsUpdateBridge();

  final ApiClient _api;
  final bool _ownsApi;
  final WindowsUpdateBridge _bridge;
  WindowsUpdateStatus _status = WindowsUpdateStatus.idle;
  WindowsUpdateStatus get status => _status;
  WindowsUpdateRelease? _release;
  WindowsUpdateRelease? get release => _release;
  WindowsUpdateEnvironment? _environment;
  WindowsUpdateEnvironment? get environment => _environment;
  bool get isPortable =>
      _environment?.installationMode == WindowsInstallationMode.portable;
  bool get canUseInstaller =>
      _environment?.installationMode == WindowsInstallationMode.installed;
  bool get canUpdate => canUseInstaller || isPortable;
  bool get canAutomaticallyUpdate =>
      canUpdate && (_release?.supportsAutomaticUpdate ?? false);
  bool get requiresManualInstallation =>
      _status == WindowsUpdateStatus.unsupported &&
      _error?.code == 'update_installer_manual';
  WindowsUpdateFailure? _error;
  WindowsUpdateFailure? get error => _error;
  ({
    String token,
    WindowsUpdateRelease release,
    WindowsUpdateEnvironment environment,
  })?
  _prepared;
  WindowsUpdateRelease? get preparedRelease => _prepared?.release;
  WindowsUpdateVersion? get preparedVersion => _prepared?.release.version;
  bool get hasPreparedUpdate => _prepared != null;
  bool get isBusy => _operation != null;
  Future<dynamic>? _operation;
  _UpdateOperation? _operationKind;
  bool _disposed = false;
  int _generation = 0;
  int? _traceRequestId;

  bool _current(int generation) => !_disposed && generation == _generation;

  void _trace(
    String event, {
    String? code,
    String? stage,
    int? durationMs,
    int? requestId,
    WindowsUpdateFailure? failure,
  }) {
    unawaited(
      DiagnosticLog.record(
        area: 'update',
        event: event,
        code: failure?.code ?? code,
        stage: failure?.stage ?? stage,
        durationMs: durationMs,
        windowsError: failure?.windowsError,
        httpStatus: failure?.statusCode,
        reason: failure?.tlsReason,
        errorKind: failure?.code == 'tls_handshake_failed' ? 'tls' : null,
        requestId: requestId ?? _traceRequestId,
      ),
    );
  }

  Future<T> _tracePhase<T>(
    String phase,
    String stage,
    Future<T> Function() action, {
    String fallback = 'update_request_failed',
    String? completedCode,
  }) async {
    final requestId = _traceRequestId;
    final timer = Stopwatch()..start();
    _trace('${phase}_started', stage: stage, requestId: requestId);
    try {
      final result = await action();
      _trace(
        '${phase}_completed',
        code: completedCode,
        stage: stage,
        durationMs: timer.elapsedMilliseconds,
        requestId: requestId,
      );
      return result;
    } catch (error) {
      _trace(
        '${phase}_failed',
        failure: _failure(error, fallback: fallback, stage: stage),
        durationMs: timer.elapsedMilliseconds,
        requestId: requestId,
      );
      rethrow;
    }
  }

  Future<T> _run<T>(
    _UpdateOperation kind,
    WindowsUpdateStatus status,
    Future<T> Function(int generation) action,
    T failureResult,
  ) {
    final stage = switch (kind) {
      _UpdateOperation.check => 'update_check',
      _UpdateOperation.prepare => 'prepare_update',
      _UpdateOperation.install => 'install_update',
      _UpdateOperation.discard => 'discard_update',
    };
    if (_disposed || _status == WindowsUpdateStatus.launched) {
      _trace(
        'operation_skipped',
        code: _disposed ? 'disposed' : 'already_launched',
        stage: stage,
      );
      return Future.value(failureResult);
    }
    final running = _operation;
    if (running != null) {
      _trace(
        _operationKind == kind ? 'operation_coalesced' : 'operation_skipped',
        code: 'operation_in_progress',
        stage: stage,
      );
      return _operationKind == kind
          ? running as Future<T>
          : Future.value(failureResult);
    }
    final generation = ++_generation;
    final requestId = DiagnosticLog.nextRequestId();
    _traceRequestId = requestId;
    final completion = Completer<T>();
    _operation = completion.future;
    _operationKind = kind;
    _status = status;
    _error = null;
    final timer = Stopwatch()..start();
    _trace(
      'operation_started',
      code: kind.name,
      stage: stage,
      requestId: requestId,
    );
    notifyListeners();
    unawaited(() async {
      var result = failureResult;
      var failed = false;
      try {
        result = await action(generation);
      } catch (error) {
        failed = true;
        final failure = _failure(
          error,
          fallback: switch (kind) {
            _UpdateOperation.check => 'update_request_failed',
            _UpdateOperation.prepare => 'update_prepare_failed',
            _UpdateOperation.install => 'update_install_failed',
            _UpdateOperation.discard => 'update_storage_failed',
          },
          stage: stage,
        );
        _trace(
          'operation_failed',
          failure: failure,
          durationMs: timer.elapsedMilliseconds,
          requestId: requestId,
        );
        if (_current(generation)) {
          _error = failure;
          _status = WindowsUpdateStatus.error;
        }
      } finally {
        final completionCode = _disposed
            ? 'disposed'
            : _status.name.toLowerCase();
        _operation = null;
        _operationKind = null;
        if (_disposed) {
          await _discardAfterDispose();
        } else {
          notifyListeners();
        }
        if (!failed) {
          _trace(
            'operation_completed',
            code: completionCode,
            stage: stage,
            durationMs: timer.elapsedMilliseconds,
            requestId: requestId,
          );
        }
        if (_traceRequestId == requestId) _traceRequestId = null;
        completion.complete(result);
      }
    }());
    return completion.future;
  }

  Future<void> _loadEnvironment(int generation, {bool refresh = false}) async {
    if (!refresh && _environment != null) {
      _trace('environment_cached', stage: 'environment', durationMs: 0);
      return;
    }
    await _tracePhase<void>('environment', 'environment', () async {
      try {
        final value = await _bridge.getEnvironment();
        _trace(
          'environment_distribution',
          code: value.installationMode.name,
          stage: 'environment',
        );
        _trace(
          'environment_architecture',
          code: const {'x64', 'arm64'}.contains(value.arch)
              ? value.arch
              : 'unsupported',
          stage: 'environment',
        );
        if (_current(generation)) _environment = value;
      } on FormatException {
        throw const WindowsUpdateFailure(
          'update_environment_invalid',
          stage: 'environment',
        );
      } on TypeError {
        throw const WindowsUpdateFailure(
          'update_environment_invalid',
          stage: 'environment',
        );
      } catch (error) {
        throw _failure(
          error,
          fallback: 'update_environment_unavailable',
          stage: 'environment',
        );
      }
    }, fallback: 'update_environment_unavailable');
  }

  void _requireUpdateDistribution() {
    final timer = Stopwatch()..start();
    _trace('distribution_started', stage: 'environment');
    switch (_environment?.installationMode) {
      case WindowsInstallationMode.installed:
      case WindowsInstallationMode.portable:
        _trace(
          'distribution_completed',
          code: _environment!.installationMode.name,
          stage: 'environment',
          durationMs: timer.elapsedMilliseconds,
        );
        return;
      case WindowsInstallationMode.unavailable:
      case null:
        _trace(
          'distribution_failed',
          code: 'update_environment_unavailable',
          stage: 'environment',
          durationMs: timer.elapsedMilliseconds,
        );
        throw const WindowsUpdateFailure('update_environment_unavailable');
    }
  }

  Future<WindowsUpdateRelease?> _latestRelease({
    bool revalidate = false,
  }) async {
    final environment = _environment!;
    final candidate = await _tracePhase<WindowsUpdateRelease?>(
      'manifest',
      'update_check',
      () => _api.latestWindowsUpdate(
        arch: environment.arch,
        package: environment.package,
        revalidate: revalidate,
      ),
      completedCode: revalidate ? 'revalidated' : 'checked',
    );
    final timer = Stopwatch()..start();
    _trace('package_comparison_started', stage: 'update_check');
    if (candidate != null && candidate.package != environment.package) {
      _trace(
        'package_comparison_failed',
        code: 'update_manifest_invalid',
        stage: 'update_check',
        durationMs: timer.elapsedMilliseconds,
      );
      throw const WindowsUpdateFailure('update_manifest_invalid');
    }
    _trace(
      'package_comparison_completed',
      code: candidate == null ? 'no_release' : 'matched',
      stage: 'update_check',
      durationMs: timer.elapsedMilliseconds,
    );
    return candidate;
  }

  bool _preparedEnvironmentMatches(WindowsUpdateEnvironment environment) {
    final timer = Stopwatch()..start();
    _trace('prepared_environment_started', stage: 'environment');
    final matches =
        _prepared?.environment.arch == environment.arch &&
        _prepared?.environment.installationMode == environment.installationMode;
    _trace(
      'prepared_environment_completed',
      code: matches ? 'matched' : 'changed',
      stage: 'environment',
      durationMs: timer.elapsedMilliseconds,
    );
    return matches;
  }

  bool _sameArtifact(
    WindowsUpdateRelease candidate,
    WindowsUpdateRelease previous,
  ) {
    final timer = Stopwatch()..start();
    _trace('artifact_comparison_started', stage: 'update_check');
    final matches = candidate.sameArtifact(previous);
    _trace(
      'artifact_comparison_completed',
      code: matches ? 'matched' : 'changed',
      stage: 'update_check',
      durationMs: timer.elapsedMilliseconds,
    );
    return matches;
  }

  bool _supported(WindowsUpdateRelease? candidate) {
    final timer = Stopwatch()..start();
    _trace('compatibility_started', stage: 'update_check');
    final environment = _environment!;
    if (!const {'x64', 'arm64'}.contains(environment.arch) ||
        (candidate?.minWindowsBuild != null &&
            environment.windowsBuild < candidate!.minWindowsBuild!)) {
      _status = WindowsUpdateStatus.unsupported;
      _error = const WindowsUpdateFailure('update_unsupported');
      _trace(
        'compatibility_completed',
        code: 'update_unsupported',
        stage: 'update_check',
        durationMs: timer.elapsedMilliseconds,
      );
      return false;
    }
    _trace(
      'compatibility_completed',
      code: 'supported',
      stage: 'update_check',
      durationMs: timer.elapsedMilliseconds,
    );
    return true;
  }

  bool _isNewer(WindowsUpdateRelease? candidate) {
    final timer = Stopwatch()..start();
    _trace('version_comparison_started', stage: 'update_check');
    final newer =
        candidate != null &&
        candidate.version.compareTo(_environment!.version) > 0;
    _trace(
      'version_comparison_completed',
      code: newer ? 'newer' : 'not_newer',
      stage: 'update_check',
      durationMs: timer.elapsedMilliseconds,
    );
    return newer;
  }

  bool _automaticPackageSupported(WindowsUpdateRelease candidate) {
    final timer = Stopwatch()..start();
    _trace('package_support_started', stage: 'update_check');
    if (candidate.supportsAutomaticUpdate) {
      _trace(
        'package_support_completed',
        code: 'automatic',
        stage: 'update_check',
        durationMs: timer.elapsedMilliseconds,
      );
      return true;
    }
    _status = WindowsUpdateStatus.unsupported;
    _error = const WindowsUpdateFailure('update_installer_manual');
    _trace(
      'package_support_completed',
      code: 'update_installer_manual',
      stage: 'update_check',
      durationMs: timer.elapsedMilliseconds,
    );
    return false;
  }

  void _traceSuccessfulCheck(String result) {
    unawaited(
      DiagnosticLog.record(
        area: 'update',
        event: 'check_succeeded',
        code: result,
      ),
    );
  }

  Future<void> _discardPrepared() async {
    final prepared = _prepared;
    if (prepared == null) {
      _trace('discard_skipped', code: 'not_prepared', stage: 'discard_update');
      return;
    }
    await _tracePhase<void>(
      'discard',
      'discard_update',
      () => _bridge.discardUpdate(prepared.token),
      fallback: 'update_storage_failed',
    );
    if (_prepared == prepared) _prepared = null;
  }

  Future<void> checkForUpdates() => _run<void>(
    _UpdateOperation.check,
    WindowsUpdateStatus.checking,
    (generation) async {
      await _loadEnvironment(generation);
      if (!_current(generation)) return;
      if (!_supported(null)) return;
      final candidate = await _latestRelease();
      if (!_current(generation)) return;
      _release = candidate;
      if (_prepared != null &&
          (candidate == null ||
              !_sameArtifact(candidate, _prepared!.release) ||
              !_preparedEnvironmentMatches(_environment!))) {
        await _discardPrepared();
        if (!_current(generation)) return;
      }
      if (!_isNewer(candidate)) {
        _status = WindowsUpdateStatus.noUpdate;
        _traceSuccessfulCheck('no_update');
        return;
      }
      if (!_supported(candidate) || !_automaticPackageSupported(candidate!)) {
        _traceSuccessfulCheck(
          requiresManualInstallation ? 'manual_installation' : 'unsupported',
        );
        return;
      }
      _status = _prepared == null
          ? WindowsUpdateStatus.available
          : WindowsUpdateStatus.ready;
      _traceSuccessfulCheck(
        _status == WindowsUpdateStatus.ready ? 'ready' : 'available',
      );
    },
    null,
  );

  Future<void> prepareUpdate() => _run<void>(
    _UpdateOperation.prepare,
    WindowsUpdateStatus.downloading,
    (generation) async {
      await _loadEnvironment(generation, refresh: true);
      if (!_current(generation)) return;
      _requireUpdateDistribution();
      if (!_supported(null)) return;
      final displayed = _release;
      final candidate = await _latestRelease(revalidate: true);
      if (!_current(generation)) return;
      _release = candidate;
      if (candidate == null || !_isNewer(candidate)) {
        await _discardPrepared();
        if (_current(generation)) _status = WindowsUpdateStatus.noUpdate;
        return;
      }
      if (!_supported(candidate) || !_automaticPackageSupported(candidate)) {
        await _discardPrepared();
        return;
      }
      if (displayed != null && !_sameArtifact(candidate, displayed)) {
        await _discardPrepared();
        if (!_current(generation)) return;
        _status = WindowsUpdateStatus.available;
        _error = const WindowsUpdateFailure('update_changed');
        return;
      }
      if (_prepared != null &&
          _sameArtifact(candidate, _prepared!.release) &&
          _preparedEnvironmentMatches(_environment!)) {
        _status = WindowsUpdateStatus.ready;
        return;
      }
      await _discardPrepared();
      if (!_current(generation)) return;
      final token = await _tracePhase<String>(
        'download_prepare',
        'prepare_update',
        () => _bridge.prepareUpdate(candidate),
        fallback: 'update_prepare_failed',
      );
      _prepared = (
        token: token,
        release: candidate,
        environment: _environment!,
      );
      if (_current(generation)) _status = WindowsUpdateStatus.ready;
      // Disposal during download is handled by _run's final cleanup, including
      // a token delivered after the window has already been closed.
    },
    null,
  );

  /// Revalidate before stopping the VPN. The caller owns user confirmation
  /// and its exclusive VPN-stop callback; no callback runs for a stale token.
  Future<bool> installPreparedUpdate({
    Future<void> Function()? beforeInstall,
  }) => _run<bool>(_UpdateOperation.install, WindowsUpdateStatus.installing, (
    generation,
  ) async {
    await _loadEnvironment(generation, refresh: true);
    if (!_current(generation)) return false;
    _requireUpdateDistribution();
    final prepared = _prepared;
    if (prepared == null) {
      if (_release != null &&
          _isNewer(_release) &&
          _release!.requiresManualInstallation) {
        if (_supported(_release)) _automaticPackageSupported(_release!);
        return false;
      }
      throw const WindowsUpdateFailure('update_not_prepared');
    }
    if (!_preparedEnvironmentMatches(_environment!)) {
      await _discardPrepared();
      throw const WindowsUpdateFailure('update_changed');
    }
    final candidate = await _latestRelease(revalidate: true);
    if (!_current(generation)) return false;
    _release = candidate;
    if (candidate == null || !_isNewer(candidate)) {
      await _discardPrepared();
      if (_current(generation)) _status = WindowsUpdateStatus.noUpdate;
      return false;
    }
    if (!_supported(candidate) ||
        !_automaticPackageSupported(candidate) ||
        !_sameArtifact(candidate, prepared.release)) {
      final supported = _status != WindowsUpdateStatus.unsupported;
      await _discardPrepared();
      if (_current(generation) && supported) {
        _status = WindowsUpdateStatus.available;
        _error = const WindowsUpdateFailure('update_changed');
      }
      return false;
    }
    // Distribution can change while the publication is being revalidated.
    // Recheck before invoking the caller's VPN-stop callback.
    await _loadEnvironment(generation, refresh: true);
    if (!_current(generation)) return false;
    _requireUpdateDistribution();
    if (!_preparedEnvironmentMatches(_environment!)) {
      await _discardPrepared();
      throw const WindowsUpdateFailure('update_changed');
    }
    try {
      if (beforeInstall == null) {
        _trace(
          'preinstall_skipped',
          code: 'no_callback',
          stage: 'install_update',
        );
      } else {
        await _tracePhase<void>(
          'preinstall',
          'install_update',
          beforeInstall,
          fallback: 'update_preinstall_failed',
        );
      }
    } catch (error) {
      throw _failure(error, fallback: 'update_preinstall_failed');
    }
    if (!_current(generation)) return false;
    await _tracePhase<void>(
      'install_launch',
      'install_update',
      () => _bridge.installUpdate(prepared.token),
      fallback: 'update_install_failed',
    );
    _prepared = null;
    if (_current(generation)) _status = WindowsUpdateStatus.launched;
    return true;
  }, false);

  Future<void> discardPreparedUpdate() => _run<void>(
    _UpdateOperation.discard,
    WindowsUpdateStatus.checking,
    (generation) async {
      await _discardPrepared();
      if (!_current(generation)) return;
      _status = _release == null || _environment == null || !_isNewer(_release)
          ? WindowsUpdateStatus.noUpdate
          : !_supported(_release) || !_automaticPackageSupported(_release!)
          ? WindowsUpdateStatus.unsupported
          : WindowsUpdateStatus.available;
    },
    null,
  );

  static WindowsUpdateFailure _failure(
    Object error, {
    String fallback = 'update_request_failed',
    String? stage,
  }) {
    if (error is WindowsUpdateFailure) return error.withStage(stage);
    if (error is ApiException) {
      final httpStatus = error.observedHttpStatus;
      if (httpStatus == null) {
        // API statusCode also represents locally synthesized failures. Only a
        // received HTTP response may be shown as HTTP in the update panel.
        const localCodes = {
          'api_bootstrap_unavailable',
          'api_resolution_unavailable',
          'api_resolver_invalid_response',
          'api_transport_unsupported',
          'broker_busy',
          'broker_protocol_error',
          'broker_response_timeout',
          'broker_unavailable',
          'broker_write_failed',
          'maintenance_in_progress',
          'native_bridge_unavailable',
          'native_operation_failed',
          'permission_denied',
          'runtime_owned_by_another_user',
          'runtime_detection_failed',
          'runtime_status_unavailable',
          'runtime_unavailable',
          'service_configuration_mismatch',
          'service_unavailable',
        };
        final localCode = error.diagnosticErrorCode;
        final code = switch (localCode) {
          'request_timeout' || 'network_timeout' => 'update_network_timeout',
          'response_too_large' => 'update_manifest_invalid',
          _ =>
            localCodes.contains(localCode)
                ? localCode
                : 'update_request_failed',
        };
        final windowsError = error.windowsError;
        return WindowsUpdateFailure(
          code,
          stage: 'update_check',
          windowsError:
              windowsError != null &&
                  windowsError > 0 &&
                  windowsError <= 0xffffffff
              ? windowsError
              : null,
        );
      }
      return WindowsUpdateFailure(
        'update_request_failed',
        statusCode: httpStatus,
        stage: 'update_check',
      );
    }
    if (error is FormatException || error is TypeError) {
      return const WindowsUpdateFailure(
        'update_manifest_invalid',
        stage: 'update_check',
      );
    }
    if (error is TimeoutException) {
      return const WindowsUpdateFailure(
        'update_network_timeout',
        stage: 'update_check',
      );
    }
    if (error is TlsException) {
      return WindowsUpdateFailure(
        'tls_handshake_failed',
        stage: 'update_check',
        tlsReason: DiagnosticLog.tlsFailureReason(error),
      );
    }
    if (error is SocketException || error is HttpException) {
      return const WindowsUpdateFailure(
        'update_network_failed',
        stage: 'update_check',
      );
    }
    if (error is MissingPluginException) {
      return WindowsUpdateFailure('update_unavailable', stage: stage);
    }
    if (error is PlatformException) {
      const allowed = {
        'invalid_argument',
        'update_unsupported',
        'update_busy',
        'update_cancelled',
        'update_unsigned_application',
        'update_application_signature_invalid',
        'update_application_open_failed',
        'update_application_architecture_mismatch',
        'update_download_failed',
        'update_download_http_error',
        'update_download_redirect_rejected',
        'update_download_network_error',
        'update_download_timeout',
        'update_download_url_invalid',
        'update_download_too_large',
        'update_download_empty',
        'update_prepare_failed',
        'update_verification_failed',
        'update_hash_mismatch',
        'update_signature_invalid',
        'update_publisher_mismatch',
        'update_untrusted_publisher',
        'update_version_mismatch',
        'update_uac_cancelled',
        'update_package_architecture_mismatch',
        'update_package_version_mismatch',
        'update_not_prepared',
        'update_install_failed',
        'update_vpn_cleanup_failed',
        'update_environment_unavailable',
        'update_package_mode_mismatch',
        'update_archive_invalid',
        'update_archive_unsafe',
        'update_archive_too_large',
        'update_archive_extract_failed',
        'update_portable_manifest_invalid',
        'update_portable_target_invalid',
        'update_portable_replace_failed',
        'update_portable_manual',
        'update_version_invalid',
        'update_storage_failed',
        'update_installation_unprotected',
        'maintenance_in_progress',
      };
      return WindowsUpdateFailure.fromNative(
        allowed.contains(error.code) ? error.code : fallback,
        error.details,
        fallbackStage: stage,
      );
    }
    return WindowsUpdateFailure(fallback, stage: stage);
  }

  Future<void> _discardAfterDispose() async {
    try {
      await _discardPrepared();
    } catch (_) {
      // Native staging is owned by the process; disposal must not report into
      // a destroyed UI or turn a late cleanup failure into an uncaught error.
    }
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _generation++;
    if (_ownsApi) _api.close();
    if (_operation == null) unawaited(_discardAfterDispose());
    super.dispose();
  }
}
