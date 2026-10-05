// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:collection';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'api_client.dart';
import 'diagnostics_models.dart';
import 'diagnostics_store.dart';

/// Optional support work. This class has no tunnel, protection, authentication
/// mutation or repair capability, and never runs inside the VPN command lock.
class DiagnosticsController extends ChangeNotifier {
  DiagnosticsController({
    ApiClient? api,
    DiagnosticsStore? store,
    this.collectSnapshot,
    String appVersion = const String.fromEnvironment(
      'FLUTTER_BUILD_NAME',
      defaultValue: '1.0.1',
    ),
    int? appBuild,
    DateTime Function()? now,
    Duration Function()? monotonic,
    double Function()? random,
  }) : _api = api ?? ApiClient(),
       _ownsApi = api == null,
       _store = store ?? const DiagnosticsStore(),
       // Preserve the public injection names; these fields stay private.
       // ignore: prefer_initializing_formals
       _appVersion = appVersion,
       // ignore: prefer_initializing_formals
       _appBuild = appBuild,
       _now = now ?? DateTime.now,
       // ignore: prefer_initializing_formals
       _monotonic = monotonic,
       _random = random ?? Random.secure().nextDouble;

  final ApiClient _api;
  final bool _ownsApi;
  final DiagnosticsStore _store;
  final Future<Map<String, Object?>> Function()? collectSnapshot;
  final DateTime Function() _now;
  final Duration Function()? _monotonic;
  final double Function() _random;
  final Stopwatch _elapsed = Stopwatch()..start();
  String _appVersion;
  final int? _appBuild;
  Map<String, Object?> _environment = const {};
  static int _nextGeneration = 0;
  int _generation = 0;
  String? _accountId;
  Future<String?> Function()? _tokenProvider;
  Future<void> _sessionReady = Future.value();
  DiagnosticsStoreState _stored = const DiagnosticsStoreState();
  bool _consent = false;
  bool _optOutPending = false;
  final _locallyRevokedAccounts = <String>{};
  int _consentRevision = 0;
  bool _authPaused = false;
  bool _disposed = false;
  bool _collecting = false;
  Future<void>? _sender;
  DiagnosticRequestCancellation? _request;
  String? _sendingId;
  Timer? _wakeTimer;
  Timer? _expiryTimer;
  Timer? _automaticTimer;
  final _manualRequests = <String>{};
  final _cancelledReports = <String>{};
  final _events = Queue<({Duration at, DiagnosticEvent value})>();
  final _automaticIncidents = <String, _Incident>{};
  final _lastAutomatic = <String, Duration>{};
  int _droppedEvents = 0;
  final _preparedOwners = Expando<String>();
  final List<DiagnosticReceipt> _receipts = [];
  Map<String, Object?>? _lastSnapshot;
  FrozenDiagnosticReport? _preparedReport;
  DiagnosticError? _lastError;
  DiagnosticsFailure? lastFailure;

  String? get accountId => _accountId;
  bool get hasSession => _accountId != null && _tokenProvider != null;
  bool get automaticConsent => _consent;
  bool get isCollecting => _collecting;
  bool get isSending => _sendingId != null;
  bool get isPausedForAuthentication => _authPaused;
  String? get sendingReportId => _sendingId;
  Map<String, Object?>? get lastSnapshot => _lastSnapshot;
  FrozenDiagnosticReport? get preparedReport => _preparedReport;
  List<QueuedDiagnosticReport> get pendingReports => List.unmodifiable(
    _stored.reports
        .where((report) => _now().toUtc().isBefore(report.expiresAt))
        .where(
          (report) => !_receipts.any(
            (receipt) => receipt.clientReportId == report.reportId,
          ),
        )
        .map((report) {
          if (!_authPaused && !_cancelledReports.contains(report.reportId)) {
            return report;
          }
          return QueuedDiagnosticReport(
            report: report.report,
            expiresAt: report.expiresAt,
            attempts: report.attempts,
            automaticAttempts: report.automaticAttempts,
            nextAttemptAt: report.nextAttemptAt,
            pausedForAuth: report.pausedForAuth || _authPaused,
            terminalCode: _cancelledReports.contains(report.reportId)
                ? 'diagnostic_cancelled'
                : report.terminalCode,
          );
        }),
  );
  List<DiagnosticReceipt> get receipts => List.unmodifiable(_receipts);
  Duration get _tick => _monotonic?.call() ?? _elapsed.elapsed;
  bool _current(int generation) => !_disposed && generation == _generation;
  void _notify() {
    if (!_disposed) notifyListeners();
  }

  void updateEnvironment({
    required String appVersion,
    required Map<String, Object?> environment,
  }) {
    try {
      // Validate version and environment without contacting the update endpoint.
      FrozenDiagnosticReport.create(
        appVersion: appVersion,
        createdAt: _now(),
        manual: true,
        full: true,
        state: 'unknown',
        fragments: {'environment': environment},
      );
      _appVersion = appVersion;
      _environment =
          DiagnosticSnapshot.fromMap({
                'environment': environment,
              }).reportFragments['environment']!
              as Map<String, Object?>;
    } catch (_) {
      lastFailure = const DiagnosticsFailure('diagnostic_environment_invalid');
      _notify();
    }
  }

  /// Call only for a session validated by the normal account flow. No token is
  /// persisted here. Generation changes synchronously, before any storage I/O.
  Future<void> sessionChanged({
    String? accountId,
    Future<String?> Function()? tokenProvider,
    bool purgePrevious = false,
  }) {
    if (_disposed) return Future.value();
    final previous = _accountId;
    _request?.cancel();
    _request = null;
    _sendingId = null;
    _sender = null;
    _wakeTimer?.cancel();
    _expiryTimer?.cancel();
    _automaticTimer?.cancel();
    _automaticTimer = null;
    _automaticIncidents.clear();
    _manualRequests.clear();
    _cancelledReports.clear();
    _consentRevision++;
    _generation = ++_nextGeneration;
    final generation = _generation;
    _accountId = accountId?.isNotEmpty == true ? accountId : null;
    _tokenProvider = _accountId == null ? null : tokenProvider;
    _stored = const DiagnosticsStoreState();
    _consent = false;
    _optOutPending = _locallyRevokedAccounts.contains(_accountId);
    _authPaused = false;
    if (previous != null && previous != _accountId) {
      _events.clear();
      _droppedEvents = 0;
      _lastError = null;
      _lastSnapshot = null;
      _preparedReport = null;
      _receipts.clear();
    }
    _sessionReady = () async {
      try {
        await _store.bindSession(
          accountId: _accountId,
          generation: generation,
          purgePrevious: purgePrevious,
        );
        if (!_current(generation) || !hasSession) return;
        await _reload(generation);
        if (!_current(generation)) return;
        // Reauthentication of this same account permits paused reports again.
        for (final report in _stored.reports.where((r) => r.pausedForAuth)) {
          await _store.updateReport(
            generation: generation,
            reportId: report.reportId,
            nextAttemptAt: report.nextAttemptAt,
            terminalCode: report.terminalCode,
          );
        }
        await _reload(generation);
      } catch (error) {
        if (_current(generation)) {
          lastFailure = _failure(error, 'diagnostics_storage_failed');
        }
      }
      _notify();
    }();
    _notify();
    unawaited(
      _sessionReady.then((_) {
        if (_current(generation)) return resumePending();
      }),
    );
    return _sessionReady;
  }

  Future<void> suspendSession({bool purge = false}) =>
      sessionChanged(purgePrevious: purge);

  Future<bool> setAutomaticConsent(bool enabled) async {
    final generation = _generation;
    final revision = ++_consentRevision;
    if (!hasSession) {
      lastFailure = const DiagnosticsFailure('diagnostic_session_required');
      _notify();
      return false;
    }
    // Revocation stops in-memory sending immediately, even if persistence fails.
    if (!enabled) {
      _locallyRevokedAccounts.add(_accountId!);
      _optOutPending = true;
      _consent = false;
      _automaticTimer?.cancel();
      _automaticTimer = null;
      _automaticIncidents.clear();
      if (_sendingId != null &&
          _stored.reports.any((r) => r.reportId == _sendingId && !r.manual)) {
        _request?.cancel();
      }
    }
    try {
      await _sessionReady;
      if (!_current(generation) || revision != _consentRevision) return false;
      await _store.setConsent(generation: generation, enabled: enabled);
      if (!_current(generation) || revision != _consentRevision) return false;
      if (!enabled) {
        for (final report in _stored.reports.where((r) => !r.manual)) {
          await _store.remove(
            generation: generation,
            reportId: report.reportId,
          );
        }
      }
      await _reload(generation);
      if (!_current(generation) || revision != _consentRevision) return false;
      _consent = enabled;
      if (enabled) _locallyRevokedAccounts.remove(_accountId);
      _optOutPending = !enabled;
      lastFailure = null;
      _notify();
      return true;
    } catch (error) {
      if (_current(generation) && revision == _consentRevision) {
        if (enabled) _consent = false;
        lastFailure = _failure(error, 'diagnostics_storage_failed');
        _notify();
      }
      return false;
    }
  }

  void recordEvent(DiagnosticEvent event) {
    if (_disposed) return;
    final now = _tick;
    _pruneEvents(now);
    if (_events.length == 2000) {
      _events.removeFirst();
      _droppedEvents++;
    }
    _events.addLast((at: now, value: event));
  }

  void _pruneEvents(Duration now) {
    while (_events.isNotEmpty &&
        now - _events.first.at > const Duration(minutes: 10)) {
      _events.removeFirst();
      _droppedEvents++;
    }
  }

  /// Feed final outcomes after the existing recovery/fallback has finished.
  /// Never feed diagnostics delivery failures into this method.
  void recordTerminalError(
    DiagnosticError error, {
    String protocol = 'unknown',
    String state = 'error',
    bool terminal = true,
  }) {
    if (_disposed) return;
    _lastError = error;
    recordEvent(
      DiagnosticEvent(
        stage: error.stage,
        event: 'error',
        code: error.code,
        httpStatus: error.httpStatus,
      ),
    );
    const excluded = {
      'rate_limited',
      'invalid_credentials',
      'device_limit',
      'device_exists',
      'email_verification_required',
      'subscription_required',
      'verification_email_cooldown',
      'login_requires_disconnect',
    };
    if (!terminal ||
        !_consent ||
        !hasSession ||
        _authPaused ||
        excluded.contains(error.code)) {
      return;
    }
    final key =
        '${error.domain}/${error.operation}/${error.stage}/${error.code}/$protocol';
    final existing = _automaticIncidents[key];
    if (existing != null) {
      if (existing.occurrences < 1000000) existing.occurrences++;
      return;
    }
    final previous = _lastAutomatic[key];
    if (previous != null && _tick - previous < const Duration(minutes: 1)) {
      return;
    }
    if (_automaticIncidents.length >= 10) return;
    _automaticIncidents[key] = _Incident(error, protocol, state);
    _automaticTimer ??= Timer(
      const Duration(seconds: 2),
      _flushAutomaticIncidents,
    );
  }

  void _flushAutomaticIncidents() {
    _automaticTimer = null;
    if (_disposed || !_consent || !hasSession || _authPaused) return;
    final generation = _generation;
    final incidents = Map.of(_automaticIncidents);
    _automaticIncidents.clear();
    for (final entry in incidents.entries) {
      _lastAutomatic[entry.key] = _tick;
      final incident = entry.value;
      try {
        final report = FrozenDiagnosticReport.create(
          appVersion: _appVersion,
          appBuild: _appBuild,
          createdAt: _now(),
          manual: false,
          full: false,
          state: incident.state,
          protocol: incident.protocol,
          error: incident.error,
          occurrences: incident.occurrences,
          fragments: _environment.isEmpty
              ? const {}
              : {'environment': _environment},
        );
        _preparedOwners[report] = _accountId!;
        unawaited(
          _enqueue(report, generation).then((ok) {
            if (ok && _current(generation)) return resumePending();
          }),
        );
      } catch (_) {
        lastFailure = const DiagnosticsFailure('diagnostic_preparation_failed');
        _notify();
      }
    }
    _lastAutomatic.removeWhere(
      (_, at) => _tick - at > const Duration(minutes: 10),
    );
  }

  Future<Map<String, Object?>?> runChecks() async {
    if (_disposed || _collecting) return _lastSnapshot;
    final generation = _generation;
    _collecting = true;
    lastFailure = null;
    _notify();
    try {
      final callback = collectSnapshot;
      if (callback == null) {
        throw const DiagnosticsFailure('diagnostic_collection_unavailable');
      }
      final raw = await callback();
      if (!_current(generation)) return null;
      final protocol = raw['protocol'] ?? 'unknown';
      final state = raw['state'] ?? 'unknown';
      if (protocol is! String ||
          state is! String ||
          !{'unknown', 'wireguard', 'openvpn'}.contains(protocol) ||
          !diagnosticStates.contains(state)) {
        throw const FormatException('Invalid diagnostic state.');
      }
      final fragments = Map<String, Object?>.of(raw)
        ..remove('protocol')
        ..remove('state');
      final snapshot = DiagnosticSnapshot.fromMap(fragments);
      _lastSnapshot = Map.unmodifiable({
        ...snapshot.reportFragments,
        'runtime': snapshot.runtime,
        'protocol': protocol,
        'state': state,
      });
      return _lastSnapshot;
    } catch (error) {
      if (_current(generation)) {
        lastFailure = _failure(error, 'diagnostic_collection_failed');
      }
      return null;
    } finally {
      _collecting = false;
      _notify();
    }
  }

  FrozenDiagnosticReport? prepareManualReport({
    Map<String, Object?>? snapshot,
  }) {
    if (_disposed) return null;
    try {
      final raw = Map<String, Object?>.of(
        snapshot ?? _lastSnapshot ?? const {},
      );
      final protocol = raw.remove('protocol') ?? 'unknown';
      final state = raw.remove('state') ?? 'unknown';
      final structured = DiagnosticSnapshot.fromMap(raw);
      final fragments = Map<String, Object?>.of(structured.reportFragments);
      if (_environment.isNotEmpty) {
        fragments['environment'] = {
          ..._environment,
          ...?fragments['environment'] as Map<String, Object?>?,
        };
      }
      final now = _tick;
      _pruneEvents(now);
      final start = now > const Duration(minutes: 10)
          ? now - const Duration(minutes: 10)
          : Duration.zero;
      final report = FrozenDiagnosticReport.create(
        appVersion: _appVersion,
        appBuild: _appBuild,
        createdAt: _now(),
        manual: true,
        full: true,
        state: state as String,
        protocol: protocol as String,
        error: _lastError,
        fragments: fragments,
        events: _events
            .map((e) => e.value.toJson(offsetMs: (e.at - start).inMilliseconds))
            .toList(),
        droppedEvents: min(_droppedEvents, 1000000),
        truncated: _droppedEvents > 0,
      );
      if (_accountId != null) _preparedOwners[report] = _accountId!;
      _preparedReport = report;
      lastFailure = null;
      _notify();
      return report;
    } catch (error) {
      lastFailure = _failure(error, 'diagnostic_preparation_failed');
      _notify();
      return null;
    }
  }

  Future<bool> sendPreparedReport(FrozenDiagnosticReport report) async {
    if (!report.manual) return false;
    // A new explicit manual action can authorize this same frozen report again.
    // Cancellation of the already-running enqueue still wins until that action.
    _cancelledReports.remove(report.reportId);
    final generation = _generation;
    if (!await _enqueue(report, generation)) return false;
    if (!_current(generation)) return false;
    _manualRequests.add(report.reportId);
    await resumePending();
    return _current(generation) &&
        _receipts.any((r) => r.clientReportId == report.reportId);
  }

  Future<bool> _enqueue(FrozenDiagnosticReport report, int generation) async {
    if (!_current(generation) || !hasSession || (!report.manual && !_consent)) {
      lastFailure = const DiagnosticsFailure('diagnostic_session_required');
      _notify();
      return false;
    }
    final owner = _preparedOwners[report];
    if (owner != null && owner != _accountId) {
      lastFailure = const DiagnosticsFailure('diagnostic_account_changed');
      _notify();
      return false;
    }
    try {
      await _sessionReady;
      if (!_current(generation)) return false;
      if (_cancelledReports.contains(report.reportId)) return false;
      if (!_now().isBefore(report.createdAt.add(const Duration(hours: 24)))) {
        throw const DiagnosticsFailure('diagnostics_expired');
      }
      _preparedOwners[report] = _accountId!;
      await _store.enqueue(generation: generation, report: report);
      if (!_current(generation)) return false;
      if (_cancelledReports.contains(report.reportId)) {
        await _store.remove(generation: generation, reportId: report.reportId);
        await _reload(generation);
        return false;
      }
      await _reload(generation);
      return _current(generation);
    } catch (error) {
      if (_current(generation)) {
        lastFailure = _failure(error, 'diagnostics_storage_failed');
        _notify();
      }
      return false;
    }
  }

  Future<bool> retry(String reportId) async {
    final generation = _generation;
    if (!hasSession || _authPaused || _disposed) return false;
    final reports = _stored.reports.where((r) => r.reportId == reportId);
    if (reports.isEmpty ||
        reports.first.terminalCode != null ||
        reports.first.pausedForAuth) {
      return false;
    }
    _manualRequests.add(reportId);
    _cancelledReports.remove(reportId);
    await resumePending();
    return _current(generation) &&
        _receipts.any((r) => r.clientReportId == reportId);
  }

  Future<void> cancel(String reportId) async {
    final generation = _generation;
    if (_sendingId == reportId) _request?.cancel();
    _manualRequests.remove(reportId);
    _cancelledReports.add(reportId);
    try {
      await _store.remove(generation: generation, reportId: reportId);
      await _reload(generation);
    } catch (error) {
      if (_current(generation)) {
        lastFailure = _failure(error, 'diagnostics_storage_failed');
      }
    }
    _notify();
  }

  Future<void> resumePending() {
    if (_disposed || !hasSession || _authPaused) return Future.value();
    final running = _sender;
    if (running != null) return running;
    final generation = _generation;
    late final Future<void> work;
    work = _drain(generation).whenComplete(() {
      if (identical(_sender, work)) _sender = null;
    });
    _sender = work;
    return work;
  }

  Future<void> _drain(int generation) async {
    _wakeTimer?.cancel();
    try {
      await _sessionReady;
      while (_current(generation) && hasSession && !_authPaused) {
        await _reload(generation);
        if (!_current(generation)) return;
        final now = _now().toUtc();
        final reports = [..._stored.reports]
          ..sort(
            (a, b) => a.manual == b.manual
                ? a.report.createdAt.compareTo(b.report.createdAt)
                : a.manual
                ? -1
                : 1,
          );
        QueuedDiagnosticReport? next;
        DateTime? wake;
        for (final report in reports) {
          if (!now.isBefore(report.expiresAt)) {
            await _store.remove(
              generation: generation,
              reportId: report.reportId,
            );
            continue;
          }
          if (report.terminalCode != null ||
              report.pausedForAuth ||
              _cancelledReports.contains(report.reportId) ||
              _receipts.any((r) => r.clientReportId == report.reportId) ||
              (!report.manual && !_consent)) {
            continue;
          }
          final explicit = _manualRequests.contains(report.reportId);
          if (!explicit && report.automaticAttempts >= 5) continue;
          var eligible = report.nextAttemptAt ?? now;
          final accountDelay = _stored.retryAfterUntil;
          if (accountDelay != null && accountDelay.isAfter(eligible)) {
            eligible = accountDelay;
          }
          final rates =
              _stored.rateAttempts
                  .where((a) => now.difference(a.at) < const Duration(hours: 1))
                  .toList()
                ..sort((a, b) => a.at.compareTo(b.at));
          if (rates.length >= 20) {
            final after = rates[rates.length - 20].at.add(
              const Duration(hours: 1),
            );
            if (after.isAfter(eligible)) eligible = after;
          }
          final autoRates = rates.where((a) => a.automatic).toList();
          if (!explicit && autoRates.length >= 10) {
            final after = autoRates[autoRates.length - 10].at.add(
              const Duration(hours: 1),
            );
            if (after.isAfter(eligible)) eligible = after;
          }
          if (!eligible.isBefore(report.expiresAt)) continue;
          if (eligible.isAfter(now)) {
            if (wake == null || eligible.isBefore(wake)) wake = eligible;
            continue;
          }
          next = report;
          break;
        }
        if (next == null) {
          if (wake != null && _current(generation)) {
            _wakeTimer = Timer(wake.difference(now), () {
              unawaited(resumePending());
            });
          }
          return;
        }
        await _send(
          next,
          generation,
          automatic: !_manualRequests.remove(next.reportId),
        );
      }
    } catch (error) {
      if (_current(generation)) {
        lastFailure = _failure(error, 'diagnostics_storage_failed');
      }
    } finally {
      if (_current(generation)) {
        _sendingId = null;
        _request = null;
        _notify();
      }
    }
  }

  Future<void> _send(
    QueuedDiagnosticReport pending,
    int generation, {
    required bool automatic,
  }) async {
    final cancellation = DiagnosticRequestCancellation();
    _request = cancellation;
    _sendingId = pending.reportId;
    _notify();
    var received = false;
    try {
      final provider = _tokenProvider;
      if (provider == null) {
        throw const DiagnosticsFailure('diagnostic_session_required');
      }
      final token = await cancellation.wait(provider());
      if (!_current(generation)) return;
      if (token == null || token.isEmpty) {
        _authPaused = true;
        await _store.updateReport(
          generation: generation,
          reportId: pending.reportId,
          pausedForAuth: true,
        );
        return;
      }
      // Persist the quota reservation BEFORE sending. A crash cannot reset the budget.
      await _store.markAttempt(
        generation: generation,
        reportId: pending.reportId,
        at: _now(),
        automatic: automatic,
      );
      if (!_current(generation)) return;
      cancellation.check();
      final receipt = await _api.submitDiagnostic(
        token: token,
        report: pending.report,
        cancellation: cancellation,
      );
      if (!_current(generation) || cancellation.isCancelled) return;
      received = true;
      _receipts.removeWhere((r) => r.clientReportId == receipt.clientReportId);
      _receipts.add(receipt);
      if (_receipts.length > 10) _receipts.removeAt(0);
      await _store.remove(generation: generation, reportId: pending.reportId);
      lastFailure = null;
    } catch (error) {
      if (!_current(generation) || cancellation.isCancelled) return;
      if (received) {
        lastFailure = const DiagnosticsFailure('diagnostics_storage_failed');
        return;
      }
      final code = error is ApiException
          ? error.errorCode
          : _failure(error, 'diagnostic_delivery_unknown').code;
      lastFailure = DiagnosticsFailure(code);
      if (error is ApiException && error.statusCode == 401) {
        _authPaused = true;
        await _store.updateReport(
          generation: generation,
          reportId: pending.reportId,
          pausedForAuth: true,
        );
      } else {
        final terminal =
            error is ApiException &&
            ((error.statusCode >= 400 &&
                    error.statusCode < 500 &&
                    error.statusCode != 408 &&
                    error.statusCode != 429) ||
                error.errorCode == 'diagnostic_content_unavailable' ||
                (error.statusCode >= 300 && error.statusCode < 400));
        final delay = error is ApiException && error.retryAfterSeconds != null
            ? Duration(seconds: error.retryAfterSeconds!)
            : Duration(
                seconds:
                    (30 *
                            pow(2, min(pending.automaticAttempts, 5)) *
                            (1 + _random() * 0.25))
                        .ceil(),
              );
        await _store.updateReport(
          generation: generation,
          reportId: pending.reportId,
          terminalCode: terminal ? code : null,
          accountRetryAfter:
              error is ApiException &&
                  (error.statusCode == 429 || error.statusCode == 503) &&
                  error.retryAfterSeconds != null
              ? _now().add(delay)
              : null,
          nextAttemptAt: terminal
              ? null
              : _now().add(
                  delay < const Duration(seconds: 1)
                      ? const Duration(seconds: 1)
                      : delay,
                ),
        );
      }
    } finally {
      if (_current(generation)) {
        _request = null;
        _sendingId = null;
        _notify();
      }
    }
  }

  Future<void> _reload(int generation) async {
    final state = await _store.readState(generation);
    if (!_current(generation)) return;
    _stored = state;
    _consent = state.automaticConsent && !_optOutPending;
    _expiryTimer?.cancel();
    final now = _now().toUtc();
    final expiries =
        state.reports
            .map((report) => report.expiresAt)
            .where((expiry) => expiry.isAfter(now))
            .toList()
          ..sort();
    if (expiries.isNotEmpty) {
      final remaining = expiries.first.difference(_now().toUtc());
      _expiryTimer = Timer(
        remaining.isNegative ? Duration.zero : remaining,
        () async {
          if (!_current(generation)) return;
          try {
            // Expiry also runs while uploads are paused for authentication.
            await _reload(generation);
          } catch (_) {
            // Native storage independently enforces TTL; never resume an upload here.
            if (_current(generation)) _notify();
          }
        },
      );
    }
    _notify();
  }

  static DiagnosticsFailure _failure(Object error, String fallback) {
    if (error is DiagnosticsFailure) return error;
    if (error is PlatformException &&
        RegExp(r'^diagnostics?_[a-z_]{1,64}$').hasMatch(error.code)) {
      return DiagnosticsFailure(error.code);
    }
    return DiagnosticsFailure(fallback);
  }

  @override
  void dispose() {
    _disposed = true;
    _request?.cancel();
    _wakeTimer?.cancel();
    _expiryTimer?.cancel();
    _automaticTimer?.cancel();
    _events.clear();
    _automaticIncidents.clear();
    if (_ownsApi) _api.close();
    super.dispose();
  }
}

class _Incident {
  _Incident(this.error, this.protocol, this.state);
  final DiagnosticError error;
  final String protocol;
  final String state;
  int occurrences = 1;
}
