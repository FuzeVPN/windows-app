// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';

import 'brand_config.dart';
import 'core/api_client.dart';
import 'core/browser_auth.dart';
import 'core/connection_state_machine.dart';
import 'core/diagnostic_log.dart';
import 'core/diagnostics_bridge.dart';
import 'core/diagnostics_controller.dart';
import 'core/diagnostics_models.dart';
import 'core/diagnostics_support.dart';
import 'core/local_diagnostic_trace.dart';
import 'core/models.dart';
import 'core/openvpn_bridge.dart';
import 'core/secure_store.dart';
import 'core/wireguard_bridge.dart';
import 'core/window_bridge.dart';
import 'core/windows_update_controller.dart';
import 'core/windows_update_bridge.dart';
import 'l10n/app_localizations.dart';

part 'diagnostic_integration.dart';

enum AppSection { connection, locations, devices, settings, help }

enum DeviceRevocationResult { revoked, revokedWithLocalCleanupWarning, failed }

enum BrowserSignInStatus {
  idle,
  openingBrowser,
  waitingForBrowser,
  completingSignIn,
}

enum LocationChangePreparation {
  selectedLocally,
  alreadyOnTarget,
  confirmationRequired,
  unavailable,
  migrationInProgress,
}

enum DeviceEnrollmentIssueKind {
  sessionExpired,
  subscriptionRequired,
  emailVerificationRequired,
  deviceLimit,
  deviceExists,
  deviceIdentityRevoked,
  openVpnProfileExists,
  openVpnProfileRevoked,
  openVpnOperationPending,
  openVpnSignerUnavailable,
  nodeUnavailable,
  serverFull,
  capacityUnavailable,
  rateLimited,
  unknown,
}

class DeviceEnrollmentIssue {
  const DeviceEnrollmentIssue({
    required this.kind,
    required this.title,
    required this.message,
    this.retryAfterSeconds,
  });

  final DeviceEnrollmentIssueKind kind;
  final String title;
  final String message;
  final int? retryAfterSeconds;
}

class AppController extends ChangeNotifier {
  AppController({
    ApiClient? api,
    SecureStore? store,
    WireGuardBridge? wireguard,
    OpenVpnBridge? openVpn,
    WindowBridge? window,
    WindowsUpdateController? updates,
    DiagnosticsController? diagnostics,
    DiagnosticsBridge? diagnosticsBridge,
    BrowserAuth? browserAuth,
    Future<bool> Function(Uri)? browserLauncher,
    DateTime Function()? now,
  }) : _api = api ?? ApiClient(),
       _store = store ?? SecureStore(),
       _wireguard = wireguard ?? WireGuardBridge(),
       _openVpn = openVpn ?? OpenVpnBridge(),
       _window = window ?? const WindowBridge(),
       _browserAuth = browserAuth ?? BrowserAuth(),
       _browserLauncher =
           browserLauncher ??
           ((url) => launchUrl(url, mode: LaunchMode.externalApplication)),
       updates = updates ?? WindowsUpdateController(),
       _now = now ?? DateTime.now {
    this.updates.addListener(_onUpdateChanged);
    _diagnosticsBridge = diagnosticsBridge ?? DiagnosticsBridge();
    this.diagnostics =
        diagnostics ??
        DiagnosticsController(
          api: _api,
          collectSnapshot: _collectDiagnosticSnapshot,
          now: _now,
        );
    this.diagnostics.addListener(_onDiagnosticsChanged);
    _stopDiagnosticObserver = DiagnosticLog.observe(_observeDiagnosticEvent);
  }

  final ApiClient _api;
  final SecureStore _store;
  final WireGuardBridge _wireguard;
  final OpenVpnBridge _openVpn;
  final WindowBridge _window;
  final BrowserAuth _browserAuth;
  final Future<bool> Function(Uri) _browserLauncher;
  BrowserAuthAttempt? _browserAuthAttempt;
  Uri? _browserAuthorizationUri;
  Completer<void>? _browserCancellation;
  String _browserAuthStage = 'browser_auth_listener';
  BrowserSignInStatus browserSignInStatus = BrowserSignInStatus.idle;
  String? browserSignInErrorMessage;
  bool get browserSignInBusy => browserSignInStatus != BrowserSignInStatus.idle;
  bool _signInInProgress = false;
  int _signInGeneration = 0;
  Future<void>? _sessionTokenWrite;
  final DateTime Function() _now;
  final WindowsUpdateController updates;
  late final DiagnosticsController diagnostics;
  late final DiagnosticsBridge _diagnosticsBridge;
  late final void Function() _stopDiagnosticObserver;
  Map<String, Object?>? diagnosticResults;
  FrozenDiagnosticReport? preparedDiagnosticReport;
  bool diagnosticRunning = false;
  bool diagnosticRepairRunning = false;
  bool diagnosticExportRunning = false;
  Map<String, Object?>? _diagnosticSupport;
  Future<String>? _diagnosticExport;
  bool _completeDiagnosticRunning = false;
  String? diagnosticMessage;
  int _diagnosticGeneration = 0;
  DiagnosticError? _diagnosticCandidate;
  String _diagnosticOperation = 'connect';
  String? _lastDiagnosticUpdateCode;

  void _notifyDiagnosticView() {
    if (!_disposed) notifyListeners();
  }

  bool _isInstallingUpdate = false;
  bool get isInstallingUpdate => _isInstallingUpdate;
  String? updateInstallationError;

  void _onUpdateChanged() {
    final failure = updates.error;
    if (failure == null) {
      _lastDiagnosticUpdateCode = null;
    } else if (_lastDiagnosticUpdateCode != failure.code) {
      _lastDiagnosticUpdateCode = failure.code;
      unawaited(
        DiagnosticLog.record(
          area: 'update',
          event: updates.requiresManualInstallation
              ? 'manual_installation_required'
              : 'failed',
          code: failure.code,
          stage: failure.stage,
          windowsError: failure.windowsError,
          httpStatus: failure.statusCode,
        ),
      );
      _emitDiagnosticFailure(
        _updateReportCode(failure.code),
        operation: 'update',
        stage: 'startup',
        httpStatus: failure.statusCode,
      );
    }
    if (!_disposed) notifyListeners();
  }

  bool get canInstallUpdate =>
      isInitialized &&
      !_disposed &&
      !_isSigningOut &&
      !isConnectionBusy &&
      !_tunnelHealthCheckInProgress &&
      !isLocationMigrationActive &&
      !runtimeOwnedByAnotherUser;

  /// The publication and signed download are checked before this callback
  /// releases the VPN. The MSI repeats its own checks for manual launches.
  Future<void> installPreparedUpdate() async {
    if (!canInstallUpdate) {
      updateInstallationError =
          'Terminez l’opération VPN en cours avant de mettre à jour.';
      if (!_disposed) notifyListeners();
      return;
    }
    _isInstallingUpdate = true;
    updateInstallationError = null;
    _cancelAutomaticReconnect();
    _migrationReconnectProtocol = null;
    notifyListeners();
    var launched = false;
    try {
      launched = await updates.installPreparedUpdate(
        beforeInstall: () async {
          var confirmed = false;
          await _runConnectionCommand(
            (operationId) async {
              try {
                await _disconnectActiveTunnel();
                final states = await Future.wait([
                  _safe<bool>(_wireguard.isConnected()),
                  _safe<bool>(_openVpn.isConnected()),
                  _nativeProtectionActive(VpnProtocol.wireGuard),
                  _nativeProtectionActive(VpnProtocol.openVpn),
                ]);
                if (_disposed ||
                    !states.every((value) => value == false) ||
                    !_markNativeDisconnected(operationId: operationId)) {
                  throw PlatformException(code: 'update_vpn_cleanup_failed');
                }
                confirmed = true;
              } catch (_) {
                await _restoreNetworkStateAfterFailedDisconnect(
                  activeProtocol ?? _retainedProtectionProtocol,
                  operationId: operationId,
                );
                throw PlatformException(code: 'update_vpn_cleanup_failed');
              }
            },
            initialState: VpnStatus.disconnecting,
            allowDuringUpdate: true,
          );
          if (!confirmed) throw PlatformException(code: 'update_busy');
        },
      );
      if (launched && !_disposed) {
        // Release the executable before either MSI or the portable helper
        // replaces it. Keep reconnect disabled while either updater is waiting.
        try {
          await _window.quit();
        } catch (_) {
          updateInstallationError = updates.isPortable
              ? 'Fermez FuzeVPN pour terminer la mise à jour.'
              : 'L’installateur est ouvert. Fermez FuzeVPN pour continuer.';
        }
      }
    } finally {
      if (!launched) _isInstallingUpdate = false;
      if (!_disposed) notifyListeners();
    }
  }

  AppSection section = AppSection.connection;
  ThemeMode themeMode = ThemeMode.light;
  AppLanguage language = AppLanguage.system;
  VpnProtocolPreference protocolPreference = VpnProtocolPreference.wireGuard;
  VpnProtocol vpnProtocol = VpnProtocol.wireGuard;
  bool killSwitchEnabled = true;
  bool dnsProtectionEnabled = true;
  bool webRtcProtectionEnabled = true;
  bool automaticReconnectEnabled = true;
  bool launchWithWindows = false;
  bool autoConnectOnLaunch = false;
  bool windowsNotificationsEnabled = true;
  bool isInitialized = false;
  Set<String> favoriteLocationIds = <String>{};
  List<String> recentLocationIds = <String>[];
  VpnProtocol? activeProtocol;
  VpnProtocol? _retainedProtectionProtocol;
  final Map<VpnProtocol, NetworkProtectionStatus?> _nativeProtectionStates = {};
  final Map<VpnProtocol, bool?> _nativeProtectionPresence = {};
  DateTime? _connectedAt;
  final Stopwatch _connectedClock = Stopwatch();
  Duration _connectedOffset = Duration.zero;
  DateTime? get connectedAt => _connectedAt;
  set connectedAt(DateTime? value) {
    _connectedAt = value;
    _connectedClock
      ..stop()
      ..reset();
    _connectedOffset = Duration.zero;
    if (value != null) {
      final elapsed = _now().difference(value);
      _connectedOffset = Duration(
        seconds: elapsed.inSeconds.clamp(0, 365 * 24 * 60 * 60),
      );
      _connectedClock.start();
    }
  }

  Duration get connectedDuration => _connectedOffset + _connectedClock.elapsed;
  final VpnConnectionStateMachine _connectionStateMachine =
      VpnConnectionStateMachine();
  Future<void>? _connectionCommand;
  Future<DeviceRevocationResult>? _deviceRevocationCommand;
  bool _isRevokingCurrentDevice = false;
  int _experiencePreferenceWritesPending = 0;
  int _securityPreferenceWritesPending = 0;
  Location? _connectionTargetLocation;
  final Map<VpnProtocol, String> _knownTunnelLocationIds = {};
  Location? get _requestedLocation =>
      _connectionCommand != null ? _connectionTargetLocation : selectedLocation;

  VpnStatus get vpnStatus => _connectionStateMachine.state;
  set vpnStatus(VpnStatus value) => _connectionStateMachine.restore(value);
  bool get isConnectionBusy =>
      _isInstallingUpdate ||
      _runtimeVerificationInProgress ||
      _connectionCommand != null ||
      _isRevokingCurrentDevice ||
      _experiencePreferenceWritesPending > 0 ||
      _securityPreferenceWritesPending > 0;
  bool get runtimeOwnedByAnotherUser => _nativeProtectionStates.values.any(
    (status) => status?.ownedByAnotherUser ?? false,
  );
  static const _otherSessionMessage =
      'Le VPN est utilisé par une autre session Windows. Fermez-le depuis cette session pour continuer.';
  bool get requiresExplicitDisconnect =>
      vpnStatus == VpnStatus.connected ||
      vpnStatus == VpnStatus.blocked ||
      _retainedProtectionProtocol != null ||
      _disconnectUnconfirmed;
  bool get runtimeVerificationPending => _runtimeVerificationPending;
  String? get runtimeVerificationErrorCode => _runtimeVerificationFailureCode;
  int? get runtimeVerificationWindowsError => _runtimeVerificationWindowsError;
  List<Location> locations = const [];
  Location? selectedLocation;
  bool _locationSelectionUnavailable = false;
  String? _unavailableLocationId;
  UserProfile? _profile;
  UserProfile? get profile => _profile;
  set profile(UserProfile? value) {
    if (_profile?.userId != value?.userId) _clearSubscriptionState();
    _profile = value;
  }

  Subscription? subscription;
  bool isLoadingSubscription = false;
  String? subscriptionErrorMessage;
  Future<void>? _subscriptionRequest;
  int _subscriptionGeneration = 0;
  List<VpnDevice> devices = const [];
  int deviceLimit = 2;
  String? _currentDeviceId;
  String? get currentDeviceId => _currentDeviceId;
  set currentDeviceId(String? value) {
    _invalidateDeviceSnapshots();
    _currentDeviceId = value;
  }

  /// Location saved as the active user choice. It only changes after ready.
  Location? realDeviceLocation;

  /// Location used by the currently connected tunnel, if any.
  String? tunnelLocationId;
  Location? get tunnelLocation =>
      locations
          .where((location) => location.id == tunnelLocationId)
          .firstOrNull ??
      (realDeviceLocation?.id == tunnelLocationId
          ? realDeviceLocation
          : null) ??
      (_currentDevice?.location?.id == tunnelLocationId
          ? _currentDevice?.location
          : null);

  /// Public destination selected for the pending migration, never active early.
  Location? pendingTargetLocation;
  LocationMigration? locationMigration;
  String? locationMigrationMessage;
  String? locationMigrationError;
  bool isPollingLocationMigration = false;
  bool isLoadingLocations = true;
  int _locationsRefreshEpoch = 0;
  bool isLoadingDevices = false;
  int _devicesRefreshEpoch = 0;
  int _devicesMutationEpoch = 0;
  bool apiReachable = true;
  bool openVpnRuntimeAvailable = false;
  bool devicesReachable = true;
  String? revokingDeviceId;
  String? errorMessage;
  String? deviceErrorMessage;
  String? securitySettingsError;
  String? experienceSettingsError;
  DeviceEnrollmentIssue? deviceEnrollmentIssue;

  String? get diagnosticLogPath => DiagnosticLog.filePath;
  bool _signInPromptPending = false;
  Timer? _migrationTimer;
  Stopwatch? _migrationPollingClock;
  VpnProtocol? _migrationReconnectProtocol;
  int _migrationEpoch = 0;
  Timer? _automaticReconnectTimer;
  bool _automaticReconnectInProgress = false;
  int _automaticReconnectAttempts = 0;
  static const _reconnectDelays = [3, 6, 12, 24, 48];
  bool _sessionValidationPending = false;
  bool _sessionStorageUnavailable = false;
  String? _savedSessionVerificationErrorMessage;
  bool _sessionRecoveryInProgress = false;
  Timer? _savedSessionVerificationTimer;
  int _savedSessionVerificationRetries = 0;
  static const _savedSessionVerificationDelays = [500, 1500, 3000];
  bool get savedSessionVerificationPending =>
      _sessionValidationPending || _sessionStorageUnavailable;
  bool get sessionStorageUnavailable => _sessionStorageUnavailable;
  bool get isVerifyingSavedSession => _sessionRecoveryInProgress;
  String? get savedSessionVerificationErrorMessage =>
      _savedSessionVerificationErrorMessage;
  bool _windowListenerStarted = false;
  Future<String>? _deviceNameFuture;
  VpnProtocol? _automaticReconnectIntent;
  DateTime _ignoreConnectivityEventsUntil = DateTime.fromMillisecondsSinceEpoch(
    0,
  );
  bool _automaticWireGuardFallbackAllowed = false;
  Future<void> _securitySettingsWriteQueue = Future.value();
  Future<void> _experienceSettingsWriteQueue = Future.value();
  bool _disposed = false;
  bool _disconnectUnconfirmed = false;
  bool _runtimeVerificationPending = false;
  bool _runtimeVerificationInProgress = false;
  bool _collectingStartupState = false;
  bool _runtimeInteractionStarted = false;
  String? _runtimeVerificationFailureCode;
  int? _runtimeVerificationWindowsError;
  Timer? _runtimeVerificationTimer;
  int _runtimeVerificationRetries = 0;
  static const _runtimeVerificationDelays = [250, 1000, 2000];
  static const _runtimeVerificationMessage =
      'FuzeVPN ne peut pas vérifier l’état du VPN. Réessayez la vérification.';
  bool _isSigningOut = false;
  int _sessionEpoch = 0;
  Timer? _tunnelHealthTimer;
  bool _tunnelHealthCheckInProgress = false;
  int _consecutiveDisconnectedChecks = 0;
  int _consecutiveHealthFailures = 0;
  bool _tunnelHealthUnconfirmed = false;
  ({int operationId, String code})? _nativeConnectionFailure;

  Future<void> _runConnectionCommand(
    Future<void> Function(int operationId) action, {
    VpnStatus? initialState,
    bool allowDuringUpdate = false,
  }) {
    if (_disposed ||
        (_isInstallingUpdate && !allowDuringUpdate) ||
        _isSigningOut ||
        _isRevokingCurrentDevice ||
        _experiencePreferenceWritesPending > 0 ||
        _securityPreferenceWritesPending > 0) {
      return Future<void>.value();
    }
    if (runtimeOwnedByAnotherUser) {
      errorMessage = _otherSessionMessage;
      notifyListeners();
      return Future<void>.value();
    }
    if (_runtimeVerificationPending) return retryRuntimeVerification();
    final running = _connectionCommand;
    if (running != null) return running;

    final firstState =
        initialState ??
        (requiresExplicitDisconnect
            ? VpnStatus.disconnecting
            : VpnStatus.preparing);
    final operationId = _connectionStateMachine.begin(firstState);
    _runtimeInteractionStarted = true;
    _diagnosticGeneration++;
    _diagnosticCandidate = null;
    _diagnosticOperation = firstState == VpnStatus.disconnecting
        ? 'disconnect'
        : 'connect';
    _connectionTargetLocation = selectedLocation;
    _nativeConnectionFailure = null;
    final completion = Completer<void>();
    _connectionCommand = completion.future;
    notifyListeners();
    unawaited(_executeConnectionCommand(operationId, action, completion));
    return completion.future;
  }

  Future<void> _executeConnectionCommand(
    int operationId,
    Future<void> Function(int operationId) action,
    Completer<void> completion,
  ) async {
    try {
      await action(operationId);
      if (!completion.isCompleted) completion.complete();
    } catch (error, stackTrace) {
      if (!completion.isCompleted) completion.completeError(error, stackTrace);
    } finally {
      _finishDiagnosticOperation(operationId);
      if (_nativeConnectionFailure?.operationId == operationId) {
        _nativeConnectionFailure = null;
      }
      _connectionStateMachine.finish(operationId);
      if (identical(_connectionCommand, completion.future)) {
        _connectionCommand = null;
        _connectionTargetLocation = null;
      }
      if (!_disposed) notifyListeners();
    }
  }

  bool _acceptConnectionOperation(int? operationId) =>
      _connectionStateMachine.owns(operationId);

  bool _transitionConnection(int? operationId, VpnStatus state) =>
      _connectionStateMachine.transition(operationId, state);

  Future<void>? _invalidateConnectionOperation({VpnStatus? state}) {
    final running = _connectionCommand;
    _nativeConnectionFailure = null;
    _connectionStateMachine.invalidate(state: state);
    return running;
  }

  void _recordNativeConnectionFailure(int? operationId, String code) {
    if (operationId != null && _acceptConnectionOperation(operationId)) {
      _nativeConnectionFailure = (operationId: operationId, code: code);
    }
  }

  bool takeSignInPrompt() {
    if (!_signInPromptPending) return false;
    _signInPromptPending = false;
    return true;
  }

  VpnDevice? get penultimateDevice {
    if (devices.length < 2) return null;
    final ordered = [...devices]
      ..sort((first, second) {
        final firstDate =
            first.createdAt ?? DateTime.fromMillisecondsSinceEpoch(0);
        final secondDate =
            second.createdAt ?? DateTime.fromMillisecondsSinceEpoch(0);
        return firstDate.compareTo(secondDate);
      });
    return ordered[ordered.length - 2];
  }

  VpnDevice? get _currentDevice =>
      devices.where((device) => device.deviceId == currentDeviceId).firstOrNull;

  bool get isLocationMigrationActive =>
      locationMigration != null &&
      locationMigration!.status != LocationMigrationStatus.blocked;

  bool isFavoriteLocation(Location location) =>
      favoriteLocationIds.contains(location.id);

  bool isRecentLocation(Location location) =>
      recentLocationIds.contains(location.id);

  List<Location> get orderedLocations {
    final result = [...locations];
    result.sort((first, second) {
      final firstFavorite = favoriteLocationIds.contains(first.id);
      final secondFavorite = favoriteLocationIds.contains(second.id);
      if (firstFavorite != secondFavorite) return firstFavorite ? -1 : 1;
      final firstRecent = recentLocationIds.indexOf(first.id);
      final secondRecent = recentLocationIds.indexOf(second.id);
      if (firstRecent != secondRecent) {
        if (firstRecent < 0) return 1;
        if (secondRecent < 0) return -1;
        return firstRecent.compareTo(secondRecent);
      }
      return first.displayName.compareTo(second.displayName);
    });
    return result;
  }

  Future<void> initialize() async {
    final clock = Stopwatch()..start();
    _traceControllerPhase('startup', 'initialize', 'begin');
    try {
      await _initialize();
      _traceControllerPhase(
        'startup',
        'initialize',
        'completed',
        code: _disposed ? 'cancelled' : 'initialized',
        durationMs: clock.elapsedMilliseconds,
      );
    } catch (error) {
      _traceControllerFailure(
        'startup',
        'initialize',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      rethrow;
    }
  }

  Future<void> _initialize() async {
    final savedTheme = await _traceOptionalLoad(
      _store.themeMode(),
      stage: 'preferences_theme',
    );
    themeMode = switch (savedTheme) {
      'dark' => ThemeMode.dark,
      'system' => ThemeMode.system,
      _ => ThemeMode.light,
    };
    final savedProtocol = await _traceOptionalLoad(
      _store.vpnProtocol(),
      stage: 'preferences_protocol',
    );
    protocolPreference = switch (savedProtocol) {
      'auto' => VpnProtocolPreference.automatic,
      'openvpn' => VpnProtocolPreference.openVpn,
      _ => VpnProtocolPreference.wireGuard,
    };
    vpnProtocol = switch (protocolPreference) {
      VpnProtocolPreference.openVpn => VpnProtocol.openVpn,
      VpnProtocolPreference.automatic ||
      VpnProtocolPreference.wireGuard => VpnProtocol.wireGuard,
    };
    final securityClock = Stopwatch()..start();
    _traceControllerPhase('startup', 'preferences_security', 'begin');
    try {
      _applySecuritySettings(await _store.securitySettings());
      _traceControllerPhase(
        'startup',
        'preferences_security',
        'completed',
        durationMs: securityClock.elapsedMilliseconds,
      );
    } catch (error) {
      _traceControllerFailure(
        'startup',
        'preferences_security',
        error,
        durationMs: securityClock.elapsedMilliseconds,
      );
      _applySecuritySettings(SecuritySettings.secureDefaults);
      _traceControllerPhase(
        'startup',
        'preferences_security',
        'fallback',
        code: 'secure_defaults',
      );
      securitySettingsError =
          'Les réglages de sécurité enregistrés sont illisibles. Les protections par défaut restent activées.';
    }
    launchWithWindows =
        await _traceOptionalLoad<bool>(
          _window.isLaunchAtStartupEnabled(),
          stage: 'windows_startup_preference',
        ) ??
        false;
    autoConnectOnLaunch =
        await _traceOptionalLoad<String?>(
          _store.autoConnectOnLaunch(),
          stage: 'preferences_auto_connect',
        ) ==
        'true';
    windowsNotificationsEnabled =
        await _traceOptionalLoad<String?>(
          _store.windowsNotifications(),
          stage: 'preferences_notifications',
        ) !=
        'false';
    favoriteLocationIds = {
      ...?await _traceOptionalLoad<List<String>>(
        _store.favoriteLocationIds(),
        stage: 'preferences_favorites',
      ),
    };
    recentLocationIds = [
      ...?await _traceOptionalLoad<List<String>>(
        _store.recentLocationIds(),
        stage: 'preferences_recent_locations',
      ),
    ];
    _traceControllerPhase('startup', 'native_preferences', 'begin');
    _configureNativeNetworkProtection();
    _traceControllerPhase('startup', 'native_preferences', 'completed');
    _traceControllerPhase('startup', 'connectivity_listener', 'begin');
    _window.startConnectivityListener(_handleWindowsConnectivityEvent);
    _windowListenerStarted = true;
    _traceControllerPhase('startup', 'connectivity_listener', 'completed');
    language = AppLanguageLocale.fromStorage(
      await _traceOptionalLoad<String?>(
        _store.appLanguage(),
        stage: 'preferences_language',
      ),
    );
    final savedLocation = await _traceOptionalLoad(
      _store.selectedLocation(),
      stage: 'preferences_selected_location',
    );
    currentDeviceId = await _traceOptionalLoad<String?>(
      _store.currentDeviceId(),
      stage: 'stored_device_binding',
    );
    final token = await _readSavedSessionToken();
    _sessionValidationPending = token != null || _sessionStorageUnavailable;
    // Resolve native protection before making GUI API requests. A retained
    // lock may outlive this window, and only the native cache can resume it.
    final runtimeClock = Stopwatch()..start();
    _traceControllerPhase('startup', 'runtime_observation', 'begin');
    await Future.wait([_loadTunnelState(), _loadOpenVpnRuntime()]);
    _traceControllerPhase(
      'startup',
      'runtime_observation',
      'completed',
      code: _runtimeVerificationPending ? 'verification_pending' : 'observed',
      durationMs: runtimeClock.elapsedMilliseconds,
    );
    if (_disposed) return;
    final retainedProtocol = _retainedProtectionProtocol;
    if (token != null &&
        automaticReconnectEnabled &&
        vpnStatus == VpnStatus.blocked &&
        retainedProtocol != null) {
      _automaticReconnectIntent = retainedProtocol;
      await _runConnectionCommand(
        (operationId) =>
            _performAutomaticReconnect(operationId, protocol: retainedProtocol),
        initialState: VpnStatus.preparing,
      );
    }
    if (vpnStatus != VpnStatus.blocked &&
        !_disconnectUnconfirmed &&
        !_runtimeVerificationPending) {
      await Future.wait([refreshLocations(savedLocation), _loadProfile(token)]);
      if (profile != null) {
        await refreshDevices();
        await _resumeStoredLocationMigration();
      }
    } else {
      // Keep the saved token for validation after protection is restored or
      // explicitly released. Do not send requests into a known/unknown lock.
      isLoadingLocations = false;
      apiReachable = false;
      devicesReachable = false;
      _traceControllerPhase(
        'startup',
        'initial_remote_data',
        'deferred',
        code: _runtimeVerificationPending
            ? 'runtime_verification_pending'
            : 'retained_protection',
      );
    }
    isInitialized = true;
    _scheduleRuntimeVerificationRetry();
    _scheduleSavedSessionVerificationRetry();
    _startTunnelHealthMonitoring();
    notifyListeners();
    // An unavailable update endpoint never blocks account or VPN startup.
    unawaited(updates.checkForUpdates());
    if (autoConnectOnLaunch &&
        profile != null &&
        vpnStatus == VpnStatus.disconnected &&
        !isLocationMigrationActive &&
        !isConnectionBusy) {
      await quickConnect();
    }
  }

  Future<void> _loadOpenVpnRuntime() async {
    final clock = Stopwatch()..start();
    _traceControllerPhase('runtime_state', 'openvpn_availability', 'begin');
    try {
      openVpnRuntimeAvailable = await _openVpn.isAvailable();
      _traceControllerPhase(
        'runtime_state',
        'openvpn_availability',
        'completed',
        code: openVpnRuntimeAvailable ? 'available' : 'unavailable',
        durationMs: clock.elapsedMilliseconds,
      );
    } catch (error) {
      _traceControllerFailure(
        'runtime_state',
        'openvpn_availability',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      openVpnRuntimeAvailable = false;
    }
    notifyListeners();
  }

  Future<T?> _safe<T>(Future<T> action) async {
    try {
      return await action;
    } catch (_) {
      return null;
    }
  }

  // Tracing is best-effort and records fixed phase names and bounded metadata.
  // It must not change the optional-load fallback or persist returned values.
  Future<T?> _traceOptionalLoad<T>(
    Future<T> action, {
    required String stage,
    String area = 'startup',
  }) async {
    final clock = Stopwatch()..start();
    _traceControllerPhase(area, stage, 'begin');
    try {
      final value = await action;
      _traceControllerPhase(
        area,
        stage,
        'completed',
        durationMs: clock.elapsedMilliseconds,
      );
      return value;
    } catch (error) {
      _traceControllerFailure(
        area,
        stage,
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      return null;
    }
  }

  void _traceControllerPhase(
    String area,
    String stage,
    String event, {
    String? code,
    int? durationMs,
  }) {
    unawaited(
      DiagnosticLog.record(
        area: area,
        event: event,
        stage: stage,
        code: code,
        durationMs: durationMs,
      ),
    );
  }

  void _traceControllerFailure(
    String area,
    String stage,
    Object error, {
    String event = 'failed',
    int? durationMs,
  }) {
    unawaited(
      DiagnosticLog.recordFailure(
        area: area,
        event: event,
        error: error,
        stage: stage,
        durationMs: durationMs,
      ),
    );
  }

  Future<void> _forgetCurrentDeviceBinding() async {
    currentDeviceId = null;
    realDeviceLocation = null;
    await _safe<void>(_store.clearCurrentDeviceId());
  }

  Future<String> _deviceName() async {
    final cached = _deviceNameFuture;
    if (cached != null) return cached;
    final future = _loadDeviceName();
    _deviceNameFuture = future;
    return future;
  }

  Future<String> _loadDeviceName() async {
    try {
      final name = (await _window.deviceName()).trim();
      if (name.isNotEmpty) return name;
    } catch (_) {
      // The native version bridge is informative; enrollment keeps a safe
      // fallback if an older runner or a test double does not expose it.
    }
    return 'FuzeVPN 1.0.1 -- Windows';
  }

  Future<VpnProtocol?> _networkProtectionOwner({String? tracePrefix}) async {
    final wireGuardActive = await _nativeProtectionActive(
      VpnProtocol.wireGuard,
      tracePrefix: tracePrefix == null
          ? null
          : '${tracePrefix}_wireguard_protection',
    );
    final openVpnActive = await _nativeProtectionActive(
      VpnProtocol.openVpn,
      tracePrefix: tracePrefix == null
          ? null
          : '${tracePrefix}_openvpn_protection',
    );
    if (wireGuardActive == true) return VpnProtocol.wireGuard;
    if (openVpnActive == true) return VpnProtocol.openVpn;

    // A transient broker query must not make a known fail-closed state appear
    // unprotected. An explicit false response still clears the remembered
    // owner once the native service confirms the filters are gone.
    if (_retainedProtectionProtocol == VpnProtocol.wireGuard &&
        wireGuardActive == null) {
      return _retainedProtectionProtocol;
    }
    if (_retainedProtectionProtocol == VpnProtocol.openVpn &&
        openVpnActive == null) {
      return _retainedProtectionProtocol;
    }
    return null;
  }

  Future<bool?> _nativeProtectionActive(
    VpnProtocol protocol, {
    String? tracePrefix,
  }) async {
    final status = await _readNativeState<NetworkProtectionStatus>(
      protocol == VpnProtocol.wireGuard
          ? _wireguard.networkProtectionStatus()
          : _openVpn.networkProtectionStatus(),
      traceStage: tracePrefix == null ? null : '${tracePrefix}_snapshot',
    );
    _nativeProtectionStates[protocol] = status;
    // An older/unavailable status endpoint may still expose filter presence.
    // That bit preserves a stop action, never a claim of full protection.
    final active =
        status?.active ??
        await _readNativeState<bool>(
          protocol == VpnProtocol.wireGuard
              ? _wireguard.isNetworkProtectionActive()
              : _openVpn.isNetworkProtectionActive(),
          traceStage: tracePrefix == null ? null : '${tracePrefix}_fallback',
        );
    _nativeProtectionPresence[protocol] = active;
    if (active == true) _runtimeInteractionStarted = true;
    return active;
  }

  // These local traces deliberately use a separate area from automatic report
  // hooks. Only fixed stages, tri-state values and platform error codes enter
  // the log; exception messages/details and native payloads never do.
  void _traceNativeState(String stage, bool? value, {int? durationMs}) {
    unawaited(
      DiagnosticLog.record(
        area: 'runtime_state',
        event: stage,
        stage: stage,
        durationMs: durationMs,
        code: value == null
            ? 'unknown'
            : value
            ? 'true'
            : 'false',
      ),
    );
  }

  void _traceNativeStateFailure(String stage, Object error, {int? durationMs}) {
    if (_collectingStartupState) {
      _runtimeVerificationFailureCode ??= switch (error) {
        PlatformException() => error.code,
        MissingPluginException() => 'missing_plugin',
        FormatException() => 'invalid_response',
        _ => 'unknown_error',
      };
      if (error is PlatformException && error.details is Map) {
        final code = (error.details as Map)['win32_error'];
        if (code is int && code >= 0 && code <= 0xffffffff) {
          _runtimeVerificationWindowsError ??= code;
        }
      }
    }
    unawaited(
      DiagnosticLog.recordFailure(
        area: 'runtime_state',
        event: '${stage}_failed',
        stage: stage,
        error: error,
        durationMs: durationMs,
      ),
    );
  }

  Future<T?> _readNativeState<T>(Future<T> action, {String? traceStage}) async {
    final clock = Stopwatch()..start();
    if (traceStage != null) {
      _traceControllerPhase('runtime_state', traceStage, 'begin');
    }
    try {
      final value = await action;
      if (traceStage != null) {
        _traceNativeState(traceStage, switch (value) {
          bool() => value,
          NetworkProtectionStatus() => value.active,
          _ => null,
        }, durationMs: clock.elapsedMilliseconds);
      }
      return value;
    } catch (error) {
      if (traceStage != null) {
        _traceNativeStateFailure(
          traceStage,
          error,
          durationMs: clock.elapsedMilliseconds,
        );
        _traceNativeState(traceStage, null);
      }
      return null;
    }
  }

  bool get _retainedProtectionBlocksTraffic =>
      _nativeProtectionStates[_retainedProtectionProtocol]?.blocksTraffic ??
      false;

  String get _partialProtectionMessage =>
      _nativeProtectionStates[_retainedProtectionProtocol] == null
      ? 'L’état complet de la protection réseau ne peut pas être confirmé. Déconnectez-vous avant de réessayer.'
      : 'Le VPN est interrompu. Des protections partielles restent actives, mais le trafic réseau n’est pas entièrement bloqué.';

  Future<bool> _restoreRetainedNetworkProtection({
    int? operationId,
    String? message,
  }) async {
    final endpointResolutionFailed =
        operationId != null &&
        _nativeConnectionFailure?.operationId == operationId &&
        _nativeConnectionFailure?.code == 'endpoint_resolution_failed';
    final owner = await _networkProtectionOwner();
    if (!_acceptConnectionOperation(operationId)) return false;
    _retainedProtectionProtocol = owner;
    if (owner == null) return false;
    final fullyBlocked = _retainedProtectionBlocksTraffic;
    if (!_transitionConnection(
      operationId,
      fullyBlocked ? VpnStatus.blocked : VpnStatus.error,
    )) {
      return false;
    }
    activeProtocol = null;
    tunnelLocationId = null;
    connectedAt = null;
    errorMessage = runtimeOwnedByAnotherUser
        ? _otherSessionMessage
        : fullyBlocked
        ? message ??
              'La connexion VPN a échoué. Le kill switch bloque toujours le trafic réseau.'
        : _partialProtectionMessage;
    if (endpointResolutionFailed && !runtimeOwnedByAnotherUser) {
      errorMessage = fullyBlocked
          ? 'Le nom du serveur WireGuard n’a pas pu être résolu. Le kill switch bloque toujours le trafic réseau. Réessayez lorsque le réseau est disponible.'
          : _nativeProtectionStates[owner] == null
          ? 'Le nom du serveur WireGuard n’a pas pu être résolu. L’état complet de la protection réseau ne peut pas être confirmé. Déconnectez-vous avant de réessayer.'
          : 'Le nom du serveur WireGuard n’a pas pu être résolu. Des protections partielles restent actives, mais le trafic réseau n’est pas entièrement bloqué.';
    }
    final failure = _nativeConnectionFailure;
    if (!runtimeOwnedByAnotherUser &&
        failure?.operationId == operationId &&
        const {
          'installation_required',
          'openvpn_driver_restart_required',
          'openvpn_cleanup_failed',
          'openvpn_dns_configuration_failed',
          'openvpn_network_configuration_failed',
        }.contains(failure?.code)) {
      errorMessage = _openVpnPlatformErrorMessage(failure!.code);
    }
    return true;
  }

  Future<void> refreshLocations([String? savedLocation]) async {
    if (_disposed) return;
    final clock = Stopwatch()..start();
    _traceControllerPhase('locations', 'catalogue_refresh', 'begin');
    final epoch = ++_locationsRefreshEpoch;
    final sessionEpoch = _sessionEpoch;
    bool current() =>
        !_disposed &&
        epoch == _locationsRefreshEpoch &&
        sessionEpoch == _sessionEpoch;
    isLoadingLocations = true;
    notifyListeners();
    try {
      final refreshed = await _api.locations();
      if (!current()) {
        _traceControllerPhase(
          'locations',
          'catalogue_refresh',
          'discarded',
          code: 'superseded',
          durationMs: clock.elapsedMilliseconds,
        );
        return;
      }
      final preferredId =
          selectedLocation?.id ?? savedLocation ?? _unavailableLocationId;
      locations = refreshed;
      selectedLocation = preferredId == null
          ? locations.firstOrNull
          : locations.where((item) => item.id == preferredId).firstOrNull;
      _locationSelectionUnavailable =
          preferredId != null && selectedLocation == null;
      _unavailableLocationId = _locationSelectionUnavailable
          ? preferredId
          : null;
      apiReachable = true;
      _traceControllerPhase(
        'locations',
        'catalogue_refresh',
        'completed',
        durationMs: clock.elapsedMilliseconds,
      );
    } catch (error) {
      _traceControllerFailure(
        'locations',
        'catalogue_refresh',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      if (current()) apiReachable = false;
    } finally {
      if (!_disposed && epoch == _locationsRefreshEpoch) {
        isLoadingLocations = false;
        notifyListeners();
      }
    }
  }

  DeviceEnrollmentIssue? _locationCapacityIssue(ApiException error) => switch ((
    error.statusCode,
    error.errorCode,
  )) {
    (409, 'server_full') => const DeviceEnrollmentIssue(
      kind: DeviceEnrollmentIssueKind.serverFull,
      title: 'Serveur complet',
      message: 'Ce serveur n’a plus de place. Choisissez un autre emplacement.',
    ),
    (503, 'capacity_unavailable') => const DeviceEnrollmentIssue(
      kind: DeviceEnrollmentIssueKind.capacityUnavailable,
      title: 'Disponibilité non confirmée',
      message:
          'La disponibilité de ce serveur ne peut pas être confirmée pour le moment. Choisissez un autre emplacement ou réessayez plus tard.',
    ),
    _ => null,
  };

  void _refreshAfterCapacityRejection(
    DeviceEnrollmentIssue issue,
    Location? rejectedLocation,
  ) {
    if (_disposed) return;
    if (issue.kind == DeviceEnrollmentIssueKind.serverFull &&
        rejectedLocation != null) {
      locations = locations
          .where((item) => item.id != rejectedLocation.id)
          .toList();
      if (selectedLocation?.id == rejectedLocation.id) {
        selectedLocation = null;
        _locationSelectionUnavailable = true;
        _unavailableLocationId = rejectedLocation.id;
      }
    }
    // Fetch a catalogue newer than the rejection. It must not delay native
    // cleanup or let an earlier, still pending GET reintroduce the full node.
    // Unknown capacity is not evidence that a server is full.
    unawaited(refreshLocations());
  }

  void _invalidateDeviceSnapshots() {
    // The same account and logical id can acquire a newer location or access
    // state. Session validation alone cannot attest an older GET snapshot.
    _devicesMutationEpoch++;
  }

  Future<void> refreshDevices() async {
    if (_disposed || _isSigningOut) return;
    final clock = Stopwatch()..start();
    _traceControllerPhase('devices', 'device_catalogue_refresh', 'begin');
    final refreshEpoch = ++_devicesRefreshEpoch;
    var mutationEpoch = _devicesMutationEpoch;
    final sessionEpoch = _sessionEpoch;
    final userId = profile?.userId;
    bool current() =>
        _isCurrentSession(sessionEpoch, userId) &&
        refreshEpoch == _devicesRefreshEpoch &&
        mutationEpoch == _devicesMutationEpoch;
    void finishLoading() {
      if (_isCurrentSession(sessionEpoch, userId) &&
          refreshEpoch == _devicesRefreshEpoch) {
        isLoadingDevices = false;
        notifyListeners();
      }
    }

    final token = await _traceOptionalLoad(
      _store.token(),
      stage: 'device_catalogue_session_storage',
      area: 'storage',
    );
    if (!current()) {
      _traceControllerPhase(
        'devices',
        'device_catalogue_refresh',
        'discarded',
        code: 'superseded',
        durationMs: clock.elapsedMilliseconds,
      );
      finishLoading();
      return;
    }
    if (token == null || profile == null) {
      _traceControllerPhase(
        'devices',
        'device_catalogue_refresh',
        'skipped',
        code: 'session_unavailable',
        durationMs: clock.elapsedMilliseconds,
      );
      devices = const [];
      deviceErrorMessage = null;
      isLoadingDevices = false;
      notifyListeners();
      return;
    }

    isLoadingDevices = true;
    deviceErrorMessage = null;
    notifyListeners();
    try {
      final deviceList = await _api.devices(token);
      if (!current()) return;
      deviceLimit = deviceList.limit;
      devices = deviceList.devices;
      if (currentDeviceId != null && _currentDevice == null) {
        // The device may have been removed from another client while this
        // application was still open. Do not keep using its revoked logical
        // id for OpenVPN enrollment or location checks.
        final forgettingBinding = _forgetCurrentDeviceBinding();
        // This accepted snapshot owns its own removal. Later mutations still
        // invalidate it while protected storage is being cleared.
        mutationEpoch = _devicesMutationEpoch;
        await forgettingBinding;
        if (!current()) return;
        _cancelLocationMigrationPolling();
        locationMigration = null;
        pendingTargetLocation = null;
        locationMigrationMessage = null;
        locationMigrationError = null;
        await _safe<void>(_store.clearLocationMigration());
        if (!current()) return;
      }
      final currentLocation = _currentDevice?.location;
      if (currentLocation != null) {
        realDeviceLocation = currentLocation;
      }
      devicesReachable = true;
      _traceControllerPhase(
        'devices',
        'device_catalogue_refresh',
        'completed',
        durationMs: clock.elapsedMilliseconds,
      );
    } catch (error) {
      _traceControllerFailure(
        'devices',
        'device_catalogue_refresh',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      if (!current()) return;
      devicesReachable = false;
      deviceErrorMessage =
          'La liste de vos appareils ne peut pas être chargée pour le moment.';
    } finally {
      finishLoading();
    }
  }

  bool _isCurrentSession(int epoch, String? userId) =>
      !_disposed &&
      !_isSigningOut &&
      epoch == _sessionEpoch &&
      userId == profile?.userId;

  void _clearSubscriptionState() {
    _subscriptionGeneration++;
    _subscriptionRequest = null;
    subscription = null;
    isLoadingSubscription = false;
    subscriptionErrorMessage = null;
  }

  bool get _subscriptionApiBlocked =>
      runtimeOwnedByAnotherUser ||
      _runtimeVerificationPending ||
      _disconnectUnconfirmed;

  String get _subscriptionApiBlockedMessage => _runtimeVerificationPending
      ? _runtimeVerificationFailureMessage
      : runtimeOwnedByAnotherUser
      ? _otherSessionMessage
      : 'L’état du VPN ne peut pas être confirmé pour le moment. Réessayez dans quelques instants.';

  /// Called by the account panel on opening or retry, never by startup.
  /// Concurrent refreshes share a request; only the owning account/session can
  /// publish its result. The previous same-account value survives a failed retry.
  Future<void> refreshSubscription() {
    if (_disposed || _isSigningOut) return Future.value();
    if (profile == null) {
      _clearSubscriptionState();
      notifyListeners();
      return Future.value();
    }
    final running = _subscriptionRequest;
    if (running != null) return running;
    if (_subscriptionApiBlocked) {
      subscriptionErrorMessage = _subscriptionApiBlockedMessage;
      notifyListeners();
      return Future.value();
    }
    final epoch = _sessionEpoch;
    final userId = profile!.userId;
    final generation = ++_subscriptionGeneration;
    // Reserve before notifying: a listener can synchronously request the same
    // refresh, and must share this request rather than start another one.
    final completion = Completer<void>();
    _subscriptionRequest = completion.future;
    isLoadingSubscription = true;
    subscriptionErrorMessage = null;
    notifyListeners();
    unawaited(
      _refreshSubscription(epoch, userId, generation).then(
        (_) => completion.complete(),
        onError: (Object error, StackTrace stack) =>
            completion.completeError(error, stack),
      ),
    );
    return completion.future;
  }

  Future<void> _refreshSubscription(
    int epoch,
    String userId,
    int generation,
  ) async {
    final clock = Stopwatch()..start();
    _traceControllerPhase('account', 'subscription_refresh', 'begin');
    bool current() =>
        _isCurrentSession(epoch, userId) &&
        generation == _subscriptionGeneration;
    try {
      final token = await _store.token();
      if (!current()) return;
      if (token == null || token.isEmpty) {
        _traceControllerPhase(
          'account',
          'subscription_refresh',
          'skipped',
          code: 'session_unavailable',
          durationMs: clock.elapsedMilliseconds,
        );
        _clearSubscriptionState();
        notifyListeners();
        return;
      }
      // The native state can change while protected storage is being read.
      if (_subscriptionApiBlocked) {
        _traceControllerPhase(
          'account',
          'subscription_refresh',
          'deferred',
          code: 'runtime_not_ready',
          durationMs: clock.elapsedMilliseconds,
        );
        subscriptionErrorMessage = _subscriptionApiBlockedMessage;
        return;
      }
      final loaded = await _api.subscription(token);
      if (!current()) return;
      subscription = loaded;
      _clearResolvedSubscriptionIssue(loaded);
      _traceControllerPhase(
        'account',
        'subscription_refresh',
        'completed',
        durationMs: clock.elapsedMilliseconds,
      );
    } on ApiException catch (error) {
      _traceControllerFailure(
        'account',
        'subscription_refresh',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      if (!current()) return;
      if (error.isUnauthorized && !_hasLocalApiCause(error)) {
        // The in-memory cache is invalidated before any protected-store work.
        // Storage failures must not escape into the account dialog's callback.
        await _safe<void>(_expireLocalSession());
        if (!_disposed) notifyListeners();
      } else {
        subscriptionErrorMessage =
            _localApiFailureMessage(error) ??
            'Les informations de votre abonnement ne peuvent pas être chargées pour le moment. Réessayez.';
      }
    } catch (error) {
      _traceControllerFailure(
        'account',
        'subscription_refresh',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      if (!current()) return;
      subscriptionErrorMessage =
          'Les informations de votre abonnement ne peuvent pas être chargées pour le moment. Réessayez.';
    } finally {
      _traceControllerPhase(
        'account',
        'subscription_refresh',
        'finished',
        code: current() ? 'current_session' : 'superseded',
        durationMs: clock.elapsedMilliseconds,
      );
      if (current()) {
        isLoadingSubscription = false;
        _subscriptionRequest = null;
        notifyListeners();
      }
    }
  }

  /// Re-read access before preparing WFP. Cached billing cannot decide a new
  /// connection: the user may have subscribed since the previous refusal.
  /// Failed or unrecognized billing responses leave enrollment authoritative.
  Future<bool> _checkSubscriptionBeforeConnection(
    String token, {
    int? operationId,
  }) async {
    final userId = profile?.userId;
    if (userId == null || !_acceptConnectionOperation(operationId)) {
      return false;
    }
    final epoch = _sessionEpoch;
    final generation = ++_subscriptionGeneration;
    final completion = Completer<void>();
    // Supersede older panel responses and let an account panel opened during
    // this check join it without issuing a competing request.
    _subscriptionRequest = completion.future;
    isLoadingSubscription = true;
    subscriptionErrorMessage = null;
    final clock = Stopwatch()..start();
    _traceControllerPhase('account', 'subscription_preflight', 'begin');
    bool current() =>
        _isCurrentSession(epoch, userId) &&
        generation == _subscriptionGeneration &&
        _acceptConnectionOperation(operationId);
    notifyListeners();
    try {
      final loaded = await _api.subscription(token);
      if (!current()) return false;
      subscription = loaded;
      _clearResolvedSubscriptionIssue(loaded);
      final denied =
          loaded.status != SubscriptionStatus.unknown && !loaded.hasAccess;
      _traceControllerPhase(
        'account',
        'subscription_preflight',
        'completed',
        code: denied
            ? 'access_denied'
            : loaded.status == SubscriptionStatus.unknown
            ? 'access_unknown'
            : 'access_allowed',
        durationMs: clock.elapsedMilliseconds,
      );
      if (!denied) return true;
      if (!_transitionConnection(operationId, VpnStatus.error)) return false;
      errorMessage = null;
      _setSubscriptionRequiredIssue();
      _diagnosticCandidate = DiagnosticError(
        code: 'subscription_required',
        domain: 'api',
        operation: _diagnosticOperation,
        stage: 'enrollment',
      );
      return false;
    } on ApiException catch (error) {
      _traceControllerFailure(
        'account',
        'subscription_preflight',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      if (!current()) return false;
      if (!_hasLocalApiCause(error) &&
          (error.isUnauthorized ||
              (error.statusCode == HttpStatus.forbidden &&
                  error.observedHttpStatus == HttpStatus.forbidden &&
                  error.errorCode == 'subscription_required'))) {
        await _handleDeviceEnrollmentError(
          error,
          identityWasReset: false,
          operationId: operationId,
        );
        return false;
      }
      subscriptionErrorMessage =
          _localApiFailureMessage(error) ??
          'Les informations de votre abonnement ne peuvent pas être chargées pour le moment. Réessayez.';
      return true;
    } catch (error) {
      _traceControllerFailure(
        'account',
        'subscription_preflight',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      if (!current()) return false;
      subscriptionErrorMessage =
          'Les informations de votre abonnement ne peuvent pas être chargées pour le moment. Réessayez.';
      return true;
    } finally {
      _traceControllerPhase(
        'account',
        'subscription_preflight',
        'finished',
        code: current() ? 'current_session' : 'superseded',
        durationMs: clock.elapsedMilliseconds,
      );
      if (_isCurrentSession(epoch, userId) &&
          generation == _subscriptionGeneration) {
        isLoadingSubscription = false;
        _subscriptionRequest = null;
        notifyListeners();
      }
      completion.complete();
    }
  }

  void _finishAbandonedSubscriptionPreflight(int? operationId) {
    if (!_acceptConnectionOperation(operationId) ||
        vpnStatus != VpnStatus.preparing) {
      return;
    }
    if (requiresExplicitDisconnect) {
      _transitionConnection(
        operationId,
        _retainedProtectionBlocksTraffic ? VpnStatus.blocked : VpnStatus.error,
      );
      return;
    }
    _transitionConnection(
      operationId,
      activeProtocol == null &&
              !_runtimeVerificationPending &&
              !runtimeOwnedByAnotherUser
          ? VpnStatus.disconnected
          : VpnStatus.error,
    );
  }

  // ApiException also carries local resolver/bridge failures. A synthesized
  // status (e.g. 503) is not proof that the server replied or caused the error.
  bool _hasLocalApiCause(ApiException error) =>
      error.observedHttpStatus == null && error.localErrorCode != null;

  String? _localApiFailureMessage(ApiException error) {
    if (!_hasLocalApiCause(error)) return null;
    final code = _localDiagnosticCode(error.diagnosticErrorCode)!;
    if (code.startsWith('storage_') || code.startsWith('secure_storage_')) {
      return 'Le stockage protégé de FuzeVPN ne peut pas être utilisé. Réessayez.';
    }
    return switch (code) {
      'api_bootstrap_unavailable' ||
      'api_resolution_unavailable' ||
      'api_resolver_invalid_response' ||
      'endpoint_resolution_failed' =>
        'FuzeVPN ne peut pas résoudre l’adresse du service de connexion.',
      'broker_unavailable' || 'service_unavailable' =>
        'Le service VPN local est indisponible. Fermez puis rouvrez FuzeVPN.',
      'broker_write_failed' ||
      'broker_response_timeout' ||
      'broker_protocol_error' => _wireGuardPlatformErrorMessage(code),
      'runtime_owned_by_another_user' => _otherSessionMessage,
      'runtime_detection_failed' =>
        'Windows n’a pas permis de vérifier l’installation de FuzeVPN.',
      'permission_denied' =>
        'Windows n’a pas autorisé l’opération WireGuard demandée.',
      'native_bridge_unavailable' ||
      'native_operation_failed' ||
      'broker_busy' ||
      'runtime_status_unavailable' ||
      'runtime_unavailable' ||
      'service_configuration_mismatch' ||
      'maintenance_in_progress' =>
        'Le composant Windows de FuzeVPN n’est pas disponible. Réessayez.',
      'network_timeout' || 'request_timeout' =>
        'La tentative de connexion réseau a échoué. Cela ne permet pas de déterminer si le service est indisponible.',
      _ =>
        'La vérification n’a pas abouti. La cause n’est pas encore identifiée.',
    };
  }

  DiagnosticError _apiFailureDiagnostic(
    ApiException error, {
    required String operation,
    required String stage,
  }) {
    final code = error.diagnosticErrorCode;
    final local = _hasLocalApiCause(error);
    final domain = error.observedHttpStatus != null
        ? 'api'
        : local &&
              (code.startsWith('storage_') ||
                  code.startsWith('secure_storage_'))
        ? 'storage'
        : local &&
              const {
                'broker_unavailable',
                'broker_write_failed',
                'broker_response_timeout',
                'broker_protocol_error',
                'broker_busy',
                'runtime_owned_by_another_user',
                'runtime_detection_failed',
                'runtime_status_unavailable',
                'runtime_unavailable',
                'native_bridge_unavailable',
                'native_operation_failed',
                'service_configuration_mismatch',
                'service_unavailable',
                'maintenance_in_progress',
                'permission_denied',
              }.contains(code)
        ? 'system'
        : 'client';
    final native = error.windowsError;
    final windowsError =
        native != null && native >= -0x80000000 && native <= 0xffffffff
        ? native
        : null;
    return DiagnosticError(
      code: code,
      domain: domain,
      operation: operation,
      stage: stage,
      httpStatus: error.observedHttpStatus,
      nativeDomain: windowsError == null ? null : 'win32',
      nativeCode: windowsError,
    );
  }

  Future<void> _loadProfile(String? token) async {
    final clock = Stopwatch()..start();
    if (token == null) {
      _traceControllerPhase(
        'account',
        'session_validation',
        'skipped',
        code: 'no_saved_session',
      );
      return;
    }
    _traceControllerPhase('account', 'session_validation', 'begin');
    final sessionEpoch = _sessionEpoch;
    try {
      final loaded = await _api.me(token);
      if (_disposed || _isSigningOut || sessionEpoch != _sessionEpoch) {
        _traceControllerPhase(
          'account',
          'session_validation',
          'discarded',
          code: 'superseded',
          durationMs: clock.elapsedMilliseconds,
        );
        return;
      }
      profile = loaded;
      _sessionValidationPending = false;
      _sessionStorageUnavailable = false;
      _savedSessionVerificationErrorMessage = null;
      _cancelSavedSessionVerificationRetry();
      _traceSavedSessionVerification(
        'saved_session_verification_succeeded',
        durationMs: clock.elapsedMilliseconds,
      );
      _bindDiagnosticSession();
      notifyListeners();
    } on ApiException catch (error) {
      if (_disposed || _isSigningOut || sessionEpoch != _sessionEpoch) return;
      if (error.isUnauthorized && !_hasLocalApiCause(error)) {
        _sessionValidationPending = false;
        _sessionStorageUnavailable = false;
        _savedSessionVerificationErrorMessage = null;
        _cancelSavedSessionVerificationRetry();
        _traceSavedSessionVerification(
          'saved_session_verification_rejected',
          error: error,
          durationMs: clock.elapsedMilliseconds,
        );
        await _safe<void>(_store.clearToken());
      } else {
        _sessionValidationPending = true;
        _savedSessionVerificationErrorMessage =
            _localApiFailureMessage(error) ??
            (error.errorCode == 'api_resolution_unavailable' ||
                    error.errorCode == 'request_timeout'
                ? 'Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.'
                : 'Le service de connexion est momentanément indisponible. Réessayez plus tard.');
        _traceSavedSessionVerification(
          'saved_session_verification_pending',
          code: error.diagnosticErrorCode,
          error: error,
          durationMs: clock.elapsedMilliseconds,
        );
      }
    } catch (error) {
      // An unavailable API does not invalidate the saved session. The profile
      // stays unverified until a later successful authentication check.
      if (!_disposed && !_isSigningOut && sessionEpoch == _sessionEpoch) {
        _sessionValidationPending = true;
        _savedSessionVerificationErrorMessage =
            error is SocketException ||
                error is HttpException ||
                error is HandshakeException ||
                error is TimeoutException
            ? 'Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.'
            : 'Le service de connexion est momentanément indisponible. Réessayez plus tard.';
        _traceSavedSessionVerification(
          'saved_session_verification_pending',
          error: error,
          durationMs: clock.elapsedMilliseconds,
        );
      }
    }
  }

  Future<String?> _readSavedSessionToken() async {
    final clock = Stopwatch()..start();
    _traceControllerPhase('storage', 'saved_session_storage', 'begin');
    final epoch = _sessionEpoch;
    try {
      final token = await _store.token();
      if (_disposed || _isSigningOut || epoch != _sessionEpoch) return null;
      _sessionStorageUnavailable = false;
      _savedSessionVerificationErrorMessage = null;
      _traceControllerPhase(
        'storage',
        'saved_session_storage',
        'completed',
        code: token == null ? 'absent' : 'present',
        durationMs: clock.elapsedMilliseconds,
      );
      return token;
    } catch (error) {
      if (!_disposed && !_isSigningOut && epoch == _sessionEpoch) {
        // A failed protected-store read cannot establish that no account was
        // saved. Keep the value on disk and offer passive verification only.
        _sessionStorageUnavailable = true;
        _sessionValidationPending = true;
        _savedSessionVerificationErrorMessage =
            'Votre session enregistrée ne peut pas être lue. Réessayez la vérification.';
        _traceSavedSessionVerification(
          'saved_session_storage_unavailable',
          error: error,
          stage: 'saved_session_storage',
          durationMs: clock.elapsedMilliseconds,
        );
      }
      return null;
    }
  }

  void _traceSavedSessionVerification(
    String event, {
    String? code,
    Object? error,
    String stage = 'session_validation',
    int? durationMs,
  }) {
    if (error != null) {
      _traceControllerFailure(
        'account',
        stage,
        error,
        event: event,
        durationMs: durationMs,
      );
      return;
    }
    _traceControllerPhase(
      'account',
      stage,
      event,
      code: code,
      durationMs: durationMs,
    );
  }

  void _cancelSavedSessionVerificationRetry() {
    _savedSessionVerificationTimer?.cancel();
    _savedSessionVerificationTimer = null;
    _savedSessionVerificationRetries = 0;
  }

  void _scheduleSavedSessionVerificationRetry() {
    if (_disposed ||
        _isSigningOut ||
        !isInitialized ||
        !savedSessionVerificationPending ||
        _sessionRecoveryInProgress ||
        _runtimeVerificationPending ||
        isConnectionBusy ||
        (requiresExplicitDisconnect && vpnStatus != VpnStatus.connected) ||
        runtimeOwnedByAnotherUser ||
        _savedSessionVerificationTimer != null ||
        _savedSessionVerificationRetries >=
            _savedSessionVerificationDelays.length) {
      return;
    }
    final epoch = _sessionEpoch;
    final delay =
        _savedSessionVerificationDelays[_savedSessionVerificationRetries++];
    _savedSessionVerificationTimer = Timer(Duration(milliseconds: delay), () {
      _savedSessionVerificationTimer = null;
      if (!_disposed && epoch == _sessionEpoch) {
        _api.invalidateBootstrapCache();
        unawaited(_recoverSavedSession(allowAutoConnect: false));
      }
    });
  }

  Future<void> _loadTunnelState({bool observationOnly = false}) async {
    final sessionEpoch = _sessionEpoch;
    _collectingStartupState = true;
    var stage = 'startup_wireguard_connected';
    final queryClock = Stopwatch()..start();
    var disconnectAttempted = false;
    try {
      _traceControllerPhase('runtime_state', stage, 'begin');
      final wireGuardConnected = await _wireguard.isConnected();
      _traceNativeState(
        stage,
        wireGuardConnected,
        durationMs: queryClock.elapsedMilliseconds,
      );
      if (_disposed || sessionEpoch != _sessionEpoch) return;
      if (wireGuardConnected) {
        _runtimeInteractionStarted = true;
        activeProtocol = VpnProtocol.wireGuard;
      }
      stage = 'startup_openvpn_connected';
      queryClock.reset();
      _traceControllerPhase('runtime_state', stage, 'begin');
      final openVpnConnected = await _openVpn.isConnected();
      _traceNativeState(
        stage,
        openVpnConnected,
        durationMs: queryClock.elapsedMilliseconds,
      );
      if (_disposed || sessionEpoch != _sessionEpoch) return;
      if (openVpnConnected) {
        _runtimeInteractionStarted = true;
        activeProtocol ??= VpnProtocol.openVpn;
      }
      if (wireGuardConnected && openVpnConnected && !observationOnly) {
        // Never leave two tunnels active after a stale or interrupted switch.
        stage = 'startup_duplicate_openvpn_disconnect';
        disconnectAttempted = true;
        await _openVpn.disconnect();
      }
      activeProtocol = wireGuardConnected
          ? VpnProtocol.wireGuard
          : openVpnConnected
          ? VpnProtocol.openVpn
          : null;
      stage = 'startup_protection_owner';
      final protectionOwner = await _networkProtectionOwner(
        tracePrefix: 'startup',
      );
      if (_disposed || sessionEpoch != _sessionEpoch) return;
      if (activeProtocol == null &&
          protectionOwner == null &&
          VpnProtocol.values.any(
            (protocol) => _nativeProtectionPresence[protocol] == null,
          )) {
        // A stopped tunnel does not prove that its persistent filters are
        // absent. Retry the snapshot and retain a stop action if still unknown.
        await _restoreNetworkStateAfterFailedDisconnect(
          null,
          expectedSessionEpoch: sessionEpoch,
          restoringStartupState: true,
        );
        if (!_disposed) notifyListeners();
        return;
      }
      stage = 'startup_state_commit';
      if (_runtimeVerificationPending) errorMessage = null;
      _clearRuntimeVerification();
      // Passive verification cannot resolve duplicate tunnels by stopping one.
      // Preserve the explicit stop-both path until the user requests it.
      _disconnectUnconfirmed =
          observationOnly && wireGuardConnected && openVpnConnected;
      _retainedProtectionProtocol = activeProtocol == null
          ? protectionOwner
          : null;
      connectedAt = null;
      vpnStatus = activeProtocol != null
          ? VpnStatus.connected
          : _retainedProtectionProtocol != null
          ? _retainedProtectionBlocksTraffic
                ? VpnStatus.blocked
                : VpnStatus.error
          : VpnStatus.disconnected;
      if (vpnStatus == VpnStatus.disconnected) {
        _runtimeInteractionStarted = false;
      }
      if (activeProtocol != null) {
        _ignoreConnectivityEvents(const Duration(seconds: 10));
      }
      tunnelLocationId = _knownTunnelLocationIds[activeProtocol];
      if (vpnStatus == VpnStatus.blocked) {
        errorMessage =
            'La connexion VPN s’est interrompue. Le kill switch bloque toujours le trafic réseau.';
      } else if (_retainedProtectionProtocol != null) {
        errorMessage = _partialProtectionMessage;
      }
      if (runtimeOwnedByAnotherUser) errorMessage = _otherSessionMessage;
      notifyListeners();
    } catch (error) {
      if (_disposed || sessionEpoch != _sessionEpoch) return;
      _traceNativeStateFailure(
        stage,
        error,
        durationMs: queryClock.elapsedMilliseconds,
      );
      // A failed observation cannot confirm absence. Initial uncertainty is
      // distinct from a previous tunnel/protection that needs to be stopped.
      await _restoreNetworkStateAfterFailedDisconnect(
        activeProtocol,
        expectedSessionEpoch: sessionEpoch,
        restoringStartupState: !disconnectAttempted,
      );
      if (!_disposed) notifyListeners();
    } finally {
      _collectingStartupState = false;
    }
  }

  String get _runtimeVerificationFailureMessage =>
      switch (_runtimeVerificationFailureCode) {
        'runtime_detection_failed' =>
          'Windows n’a pas permis de vérifier l’installation de FuzeVPN.',
        'broker_unavailable' =>
          'Le service VPN local est indisponible. Fermez puis rouvrez FuzeVPN.',
        'broker_write_failed' ||
        'broker_response_timeout' ||
        'broker_protocol_error' => _wireGuardPlatformErrorMessage(
          _runtimeVerificationFailureCode!,
        ),
        _ => _runtimeVerificationMessage,
      };

  void _clearRuntimeVerification() {
    _runtimeVerificationPending = false;
    _runtimeVerificationFailureCode = null;
    _runtimeVerificationWindowsError = null;
    _runtimeVerificationRetries = 0;
    _runtimeVerificationTimer?.cancel();
    _runtimeVerificationTimer = null;
  }

  void _scheduleRuntimeVerificationRetry() {
    if (_disposed ||
        _isSigningOut ||
        !isInitialized ||
        !_runtimeVerificationPending ||
        _runtimeVerificationTimer != null ||
        _runtimeVerificationRetries >= _runtimeVerificationDelays.length) {
      return;
    }
    final epoch = _sessionEpoch;
    final delay = _runtimeVerificationDelays[_runtimeVerificationRetries++];
    _runtimeVerificationTimer = Timer(Duration(milliseconds: delay), () {
      _runtimeVerificationTimer = null;
      if (!_disposed && epoch == _sessionEpoch) {
        unawaited(retryRuntimeVerification(automatic: true));
      }
    });
  }

  /// Repeats passive observations only. It never connects, stops a tunnel,
  /// prepares filters or resets an identity, even when automatic startup was
  /// requested before the native status became unavailable.
  Future<void> retryRuntimeVerification({bool automatic = false}) async {
    if (_disposed ||
        _isSigningOut ||
        !_runtimeVerificationPending ||
        _runtimeVerificationInProgress) {
      return;
    }
    if (!automatic) {
      _runtimeVerificationTimer?.cancel();
      _runtimeVerificationTimer = null;
      _runtimeVerificationRetries = 0;
    }
    final epoch = _sessionEpoch;
    _runtimeVerificationInProgress = true;
    notifyListeners();
    try {
      await _loadTunnelState(observationOnly: true);
    } finally {
      _runtimeVerificationInProgress = false;
      if (!_disposed && epoch == _sessionEpoch) {
        _scheduleRuntimeVerificationRetry();
        notifyListeners();
      }
    }
    if (_disposed || epoch != _sessionEpoch || _runtimeVerificationPending) {
      return;
    }
    if (_sessionValidationPending) {
      await _recoverSavedSession(allowAutoConnect: false);
    } else if (!requiresExplicitDisconnect) {
      final saved = await _safe(_store.selectedLocation());
      if (!_disposed && epoch == _sessionEpoch) await refreshLocations(saved);
    }
  }

  void selectSection(AppSection value) {
    section = value;
    notifyListeners();
  }

  Future<void> selectLocation(Location value) async {
    if (isConnectionBusy) return;
    await _selectLocation(value);
  }

  Future<bool> _selectLocation(Location value, {int? operationId}) async {
    final saved = await _persistExperiencePreference(
      () => _store.saveSelectedLocation(value.id),
      () {
        selectedLocation = value;
        _locationSelectionUnavailable = false;
        _unavailableLocationId = null;
        if (operationId != null && _acceptConnectionOperation(operationId)) {
          _connectionTargetLocation = value;
        }
      },
      'Le serveur choisi n’a pas pu être enregistré sur cet ordinateur.',
    );
    return saved;
  }

  Future<bool> _persistExperiencePreference(
    Future<void> Function() write,
    void Function() commit,
    String failureMessage,
  ) async {
    _experiencePreferenceWritesPending++;
    notifyListeners();
    var saved = false;
    final operation = _experienceSettingsWriteQueue.then((_) async {
      try {
        await write();
        if (_disposed) return;
        commit();
        experienceSettingsError = null;
        saved = true;
      } catch (_) {
        if (_disposed) return;
        experienceSettingsError = failureMessage;
      }
      notifyListeners();
    });
    _experienceSettingsWriteQueue = operation;
    try {
      await operation;
      return saved;
    } finally {
      _experiencePreferenceWritesPending--;
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> toggleFavoriteLocation(Location location) async {
    final previous = {...favoriteLocationIds};
    if (!favoriteLocationIds.add(location.id)) {
      favoriteLocationIds.remove(location.id);
    }
    experienceSettingsError = null;
    notifyListeners();
    try {
      await _store.saveFavoriteLocationIds(favoriteLocationIds);
    } catch (_) {
      favoriteLocationIds = previous;
      experienceSettingsError =
          'Ce favori n’a pas pu être enregistré sur cet ordinateur.';
      notifyListeners();
    }
  }

  Future<void> setLaunchWithWindows(bool value) async {
    final previous = launchWithWindows;
    launchWithWindows = value;
    experienceSettingsError = null;
    notifyListeners();
    try {
      await _window.setLaunchAtStartup(value);
    } catch (_) {
      launchWithWindows = previous;
      experienceSettingsError =
          'Le lancement avec Windows n’a pas pu être modifié.';
      notifyListeners();
    }
  }

  Future<void> setAutoConnectOnLaunch(bool value) async {
    final previous = autoConnectOnLaunch;
    autoConnectOnLaunch = value;
    experienceSettingsError = null;
    notifyListeners();
    try {
      await _store.saveAutoConnectOnLaunch(value);
    } catch (_) {
      autoConnectOnLaunch = previous;
      experienceSettingsError =
          'La connexion automatique n’a pas pu être enregistrée.';
      notifyListeners();
    }
  }

  Future<void> setWindowsNotifications(bool value) async {
    final previous = windowsNotificationsEnabled;
    windowsNotificationsEnabled = value;
    experienceSettingsError = null;
    notifyListeners();
    try {
      await _store.saveWindowsNotifications(value);
    } catch (_) {
      windowsNotificationsEnabled = previous;
      experienceSettingsError =
          'La préférence de notification n’a pas pu être enregistrée.';
      notifyListeners();
    }
  }

  void _recordRecentLocation(String? locationId) {
    if (locationId == null || locationId.isEmpty) return;
    recentLocationIds = [
      locationId,
      ...recentLocationIds.where((item) => item != locationId),
    ].take(5).toList(growable: false);
    unawaited(_safe<void>(_store.saveRecentLocationIds(recentLocationIds)));
  }

  void _startTunnelHealthMonitoring() {
    _tunnelHealthTimer?.cancel();
    _tunnelHealthTimer = Timer.periodic(
      const Duration(seconds: 4),
      (_) => unawaited(_checkTunnelHealth()),
    );
  }

  Future<void> _checkTunnelHealth() async {
    if (_disposed) return;
    if (runtimeOwnedByAnotherUser) {
      if (_tunnelHealthCheckInProgress || isConnectionBusy) return;
      _tunnelHealthCheckInProgress = true;
      try {
        // Ownership can be released from the other desktop. Refresh the
        // read-only snapshot so this window does not remain disabled forever.
        await _loadTunnelState();
      } finally {
        _tunnelHealthCheckInProgress = false;
      }
      return;
    }
    final protocol = activeProtocol;
    if (_tunnelHealthCheckInProgress ||
        isConnectionBusy ||
        (vpnStatus != VpnStatus.connected && !_tunnelHealthUnconfirmed) ||
        protocol == null) {
      _consecutiveDisconnectedChecks = 0;
      return;
    }
    _tunnelHealthCheckInProgress = true;
    try {
      final connected = await _isTunnelStillConnected(protocol);
      if (isConnectionBusy ||
          (vpnStatus != VpnStatus.connected && !_tunnelHealthUnconfirmed) ||
          activeProtocol != protocol) {
        _consecutiveDisconnectedChecks = 0;
        return;
      }
      if (connected) {
        _consecutiveDisconnectedChecks = 0;
        _consecutiveHealthFailures = 0;
        if (_tunnelHealthUnconfirmed) {
          _tunnelHealthUnconfirmed = false;
          _disconnectUnconfirmed = false;
          _transitionConnection(null, VpnStatus.connected);
          errorMessage = null;
          notifyListeners();
        }
        return;
      }
      _consecutiveHealthFailures = 0;
      _consecutiveDisconnectedChecks++;
      if (_consecutiveDisconnectedChecks < 2) return;
      _consecutiveDisconnectedChecks = 0;
      _tunnelHealthUnconfirmed = false;
      _disconnectUnconfirmed = false;
      if (automaticReconnectEnabled && profile != null) {
        _automaticReconnectIntent = protocol;
        _automaticReconnectAttempts = 0;
        _ignoreConnectivityEventsUntil = _now();
      }
      if (await _restoreRetainedNetworkProtection(
        message:
            'La connexion VPN s’est interrompue. Le kill switch bloque toujours le trafic réseau.',
      )) {
        notifyListeners();
        return;
      }
      if (_transitionConnection(null, VpnStatus.disconnected)) {
        activeProtocol = null;
        _retainedProtectionProtocol = null;
        tunnelLocationId = null;
        connectedAt = null;
        errorMessage = 'La connexion VPN s’est interrompue.';
        notifyListeners();
      }
    } catch (_) {
      // Failure to observe the tunnel does not prove it is down. Bound the
      // time for which the UI may retain its last verified connected status.
      if (!isConnectionBusy &&
          activeProtocol == protocol &&
          (vpnStatus == VpnStatus.connected || _tunnelHealthUnconfirmed)) {
        _consecutiveDisconnectedChecks = 0;
        _consecutiveHealthFailures++;
        if (_consecutiveHealthFailures >= 3) {
          if (_consecutiveHealthFailures == 3) {
            _emitDiagnosticFailure(
              'runtime_status_unavailable',
              operation: 'probe',
              stage: 'network_check',
            );
          }
          _tunnelHealthUnconfirmed = true;
          _disconnectUnconfirmed = true;
          _transitionConnection(null, VpnStatus.error);
          errorMessage =
              'L’état du tunnel VPN ne peut plus être confirmé. Réessayez la déconnexion ou attendez sa vérification.';
          notifyListeners();
        }
      }
    } finally {
      _tunnelHealthCheckInProgress = false;
      if (vpnStatus != VpnStatus.connected && !_tunnelHealthUnconfirmed) {
        _scheduleAutomaticReconnect();
      }
    }
  }

  @visibleForTesting
  Future<void> checkTunnelHealthNow() => _checkTunnelHealth();

  /// Resolves the real server location before the UI asks the user to confirm
  /// an asynchronous move. It never makes the target appear active early.
  Future<LocationChangePreparation> prepareLocationChange(
    Location target,
  ) async {
    if (isConnectionBusy) return LocationChangePreparation.unavailable;
    if (isLocationMigrationActive) {
      return LocationChangePreparation.migrationInProgress;
    }
    if (vpnStatus == VpnStatus.connected) {
      final activeLocationId = tunnelLocationId;
      if (activeLocationId == target.id) {
        return LocationChangePreparation.alreadyOnTarget;
      }
      pendingTargetLocation = target;
      locationMigrationError = null;
      notifyListeners();
      return LocationChangePreparation.confirmationRequired;
    }
    // WireGuard keeps its original direct-selection flow. POST /v1/devices
    // applies the selected location when the user connects; the asynchronous
    // location-migration contract is only needed for OpenVPN.
    if (vpnProtocol == VpnProtocol.wireGuard) {
      return await _selectLocation(target)
          ? LocationChangePreparation.selectedLocally
          : LocationChangePreparation.unavailable;
    }
    // While disconnected, choosing an OpenVPN location is only a local UI
    // preference. Pressing Connect is the explicit action that starts the
    // server-side drain/activation workflow.
    if (vpnStatus != VpnStatus.connected) {
      if (!await _selectLocation(target)) {
        return LocationChangePreparation.unavailable;
      }
      pendingTargetLocation = target;
      locationMigrationError = null;
      notifyListeners();
      return LocationChangePreparation.selectedLocally;
    }
    final token = await _safe(_store.token());
    if (profile == null || token == null || currentDeviceId == null) {
      await selectLocation(target);
      return LocationChangePreparation.selectedLocally;
    }
    await refreshDevices();
    if (!devicesReachable) return LocationChangePreparation.unavailable;
    final device = _currentDevice;
    if (device == null) {
      await selectLocation(target);
      return LocationChangePreparation.selectedLocally;
    }
    final deviceLocation = device.location;
    if (deviceLocation != null) {
      realDeviceLocation = deviceLocation;
    }
    if (deviceLocation?.id == target.id) {
      await selectLocation(target);
      return LocationChangePreparation.alreadyOnTarget;
    }
    pendingTargetLocation = target;
    locationMigrationError = null;
    notifyListeners();
    return LocationChangePreparation.confirmationRequired;
  }

  /// Applies the single confirmation shared by WireGuard and OpenVPN.
  Future<void> confirmPreparedLocationChange() {
    if (pendingTargetLocation == null) return Future<void>.value();
    final wasConnected = vpnStatus == VpnStatus.connected;
    return _runConnectionCommand(
      (operationId) => _confirmPreparedLocationChange(operationId),
      initialState: wasConnected
          ? VpnStatus.disconnecting
          : VpnStatus.preparing,
    );
  }

  Future<void> _confirmPreparedLocationChange(int operationId) async {
    final target = pendingTargetLocation;
    if (target == null) return;
    if (vpnProtocol == VpnProtocol.openVpn) {
      await _startPreparedLocationMigration(
        operationId: operationId,
        reconnectProtocol: activeProtocol,
      );
      return;
    }

    // WireGuard has no asynchronous certificate migration. Stop the active
    // tunnel, select the destination, then reuse the existing registration
    // flow so the same logical device reconnects on the chosen node.
    try {
      if (killSwitchEnabled) {
        if (!await _prepareConnectionNetworkProtection(
          VpnProtocol.wireGuard,
          operationId: operationId,
        )) {
          return;
        }
        await _wireguard.suspendForMigration();
      } else {
        await _disconnectActiveTunnel();
      }
      if (await _wireguard.isConnected()) {
        throw StateError('Le tunnel est toujours actif.');
      }
      if (!_transitionConnection(operationId, VpnStatus.disconnected)) return;
      activeProtocol = null;
      tunnelLocationId = null;
      connectedAt = null;
      if (!await _selectLocation(target, operationId: operationId)) {
        throw StateError('La destination n’a pas pu être enregistrée.');
      }
      pendingTargetLocation = null;
      if (!_transitionConnection(operationId, VpnStatus.preparing)) return;
      await _startDeviceConnection(
        identityWasReset: false,
        forcedProtocol: VpnProtocol.wireGuard,
        operationId: operationId,
      );
    } catch (_) {
      if (!_acceptConnectionOperation(operationId)) return;
      await _restoreNetworkStateAfterFailedDisconnect(
        VpnProtocol.wireGuard,
        operationId: operationId,
      );
      errorMessage ??= 'Le changement de serveur n’a pas pu être effectué.';
      notifyListeners();
    }
  }

  Future<void> startPreparedLocationMigration({bool connectWhenReady = false}) {
    if (pendingTargetLocation == null || isLocationMigrationActive) {
      return Future<void>.value();
    }
    final wasConnected = vpnStatus == VpnStatus.connected;
    final reconnectProtocol = wasConnected ? activeProtocol : null;
    return _runConnectionCommand(
      (operationId) => _startPreparedLocationMigration(
        connectWhenReady: connectWhenReady,
        operationId: operationId,
        reconnectProtocol: reconnectProtocol,
      ),
      initialState: wasConnected
          ? VpnStatus.disconnecting
          : VpnStatus.preparing,
    );
  }

  Future<void> _startPreparedLocationMigration({
    bool connectWhenReady = false,
    int? operationId,
    VpnProtocol? reconnectProtocol,
  }) async {
    final target = pendingTargetLocation;
    final token = await _safe(_store.token());
    final activeProfile = profile;
    final deviceId = currentDeviceId;
    if (target == null ||
        token == null ||
        activeProfile == null ||
        deviceId == null ||
        isLocationMigrationActive) {
      if (_acceptConnectionOperation(operationId)) {
        _transitionConnection(
          operationId,
          activeProtocol == null ? VpnStatus.disconnected : VpnStatus.connected,
        );
      }
      return;
    }

    locationMigrationError = null;
    locationMigrationMessage = 'Changement de serveur…';
    try {
      if (reconnectProtocol != null) {
        if (reconnectProtocol == VpnProtocol.openVpn && killSwitchEnabled) {
          // Replace the tunnel phase with a prepared phase before stopping the
          // old DCO interface. The migration API stays reachable through the
          // signed GUI permit while every other application remains blocked.
          if (!await _prepareConnectionNetworkProtection(
            VpnProtocol.openVpn,
            operationId: operationId,
          )) {
            return;
          }
          await DiagnosticLog.record(
            area: 'openvpn',
            event: 'migration_tunnel_suspend_started',
          );
          await _openVpn.suspendForMigration();
          await DiagnosticLog.record(
            area: 'openvpn',
            event: 'migration_tunnel_suspend_succeeded',
          );
        } else {
          await _disconnectActiveTunnel();
        }
        if (await _isTunnelStillConnected(reconnectProtocol)) {
          throw StateError('Le tunnel est toujours actif.');
        }
        if (!_transitionConnection(operationId, VpnStatus.disconnected)) {
          return;
        }
        activeProtocol = null;
        tunnelLocationId = null;
      }
      if (!_acceptConnectionOperation(operationId)) return;
      notifyListeners();
      _invalidateDeviceSnapshots();
      final migration = await _api.startLocationMigration(
        token: token,
        deviceId: deviceId,
        locationId: target.id,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      _migrationReconnectProtocol =
          reconnectProtocol ?? (connectWhenReady ? VpnProtocol.openVpn : null);
      _migrationPollingClock = Stopwatch()..start();
      var resumeMarkerSaved = true;
      try {
        await _store.saveLocationMigration(
          StoredLocationMigration(
            migrationId: migration.migrationId,
            deviceId: migration.deviceId,
            targetLocationId: migration.targetLocationId,
            userId: activeProfile.userId,
          ),
        );
      } catch (_) {
        // The API has already accepted the operation. Keep following it in
        // memory instead of incorrectly claiming that it never started.
        resumeMarkerSaved = false;
      }
      await _acceptLocationMigration(migration, operationId: operationId);
      if (!resumeMarkerSaved && isLocationMigrationActive) {
        locationMigrationError =
            'Le changement a bien démarré, mais sa reprise locale n’a pas pu être enregistrée. Laissez l’application ouverte jusqu’à la fin.';
        notifyListeners();
      }
    } on ApiException catch (error) {
      if (!_acceptConnectionOperation(operationId)) return;
      await _handleLocationMigrationError(error);
    } catch (_) {
      if (!_acceptConnectionOperation(operationId)) return;
      locationMigrationError =
          'Le changement de serveur n’a pas pu être démarré. Réessayez plus tard.';
      locationMigrationMessage = null;
      notifyListeners();
    }
    if (_acceptConnectionOperation(operationId) && activeProtocol == null) {
      final retained = await _restoreRetainedNetworkProtection(
        operationId: operationId,
        message:
            locationMigrationError ??
            'Le changement de serveur continue. Le kill switch bloque le trafic jusqu’à la reconnexion ou une déconnexion explicite.',
      );
      if (!retained &&
          (vpnStatus == VpnStatus.preparing ||
              vpnStatus == VpnStatus.disconnecting)) {
        _transitionConnection(operationId, VpnStatus.disconnected);
      }
      notifyListeners();
    }
  }

  Future<bool> _isTunnelStillConnected(VpnProtocol protocol) =>
      protocol == VpnProtocol.openVpn
      ? _openVpn.isConnected()
      : _wireguard.isConnected();

  Future<void> _resumeStoredLocationMigration({int? operationId}) async {
    final epoch = _migrationEpoch;
    final sessionEpoch = _sessionEpoch;
    final activeProfile = profile;
    final token = await _safe(_store.token());
    final marker = await _safe(_store.locationMigration());
    if (activeProfile == null ||
        token == null ||
        marker == null ||
        !_isCurrentSession(sessionEpoch, activeProfile.userId) ||
        epoch != _migrationEpoch ||
        marker.userId != activeProfile.userId ||
        marker.deviceId != currentDeviceId) {
      return;
    }
    final target = locations
        .where((item) => item.id == marker.targetLocationId)
        .firstOrNull;
    pendingTargetLocation = target;
    _migrationPollingClock ??= Stopwatch()..start();
    try {
      final migration = await _api.getLocationMigration(
        token: token,
        deviceId: marker.deviceId,
        migrationId: marker.migrationId,
      );
      if (!_isCurrentSession(sessionEpoch, activeProfile.userId) ||
          epoch != _migrationEpoch) {
        return;
      }
      await _acceptLocationMigration(migration, operationId: operationId);
    } on ApiException catch (error) {
      if (!_isCurrentSession(sessionEpoch, activeProfile.userId) ||
          epoch != _migrationEpoch) {
        return;
      }
      await _handleLocationMigrationError(error, keepResumeMarker: true);
    } catch (_) {
      if (!_isCurrentSession(sessionEpoch, activeProfile.userId) ||
          epoch != _migrationEpoch) {
        return;
      }
      locationMigrationError =
          'Le changement de serveur sera repris lorsque la connexion sera disponible.';
      _scheduleLocationMigrationPoll(2);
      notifyListeners();
    }
  }

  Future<void> _acceptLocationMigration(
    LocationMigration migration, {
    int? operationId,
  }) async {
    if (_disposed ||
        _isSigningOut ||
        (operationId != null && !_acceptConnectionOperation(operationId))) {
      return;
    }
    final sessionEpoch = _sessionEpoch;
    final userId = profile?.userId;
    _invalidateDeviceSnapshots();
    locationMigration = migration;
    pendingTargetLocation =
        locations
            .where((item) => item.id == migration.targetLocationId)
            .firstOrNull ??
        pendingTargetLocation;
    locationMigrationError = null;
    switch (migration.status) {
      case LocationMigrationStatus.draining:
        locationMigrationMessage =
            'Retrait de l’accès à ${_locationName(migration.sourceLocationId)}…';
        _scheduleLocationMigrationPoll(migration.retryAfterSeconds);
        break;
      case LocationMigrationStatus.activating:
        locationMigrationMessage =
            'Activation sur ${_locationName(migration.targetLocationId)}…';
        _scheduleLocationMigrationPoll(migration.retryAfterSeconds);
        break;
      case LocationMigrationStatus.ready:
        await _finishLocationMigration(migration, operationId: operationId);
        break;
      case LocationMigrationStatus.blocked:
        _cancelLocationMigrationPolling();
        locationMigrationMessage = null;
        locationMigrationError =
            'Le changement de serveur nécessite une intervention. Réessayez plus tard ou contactez l’assistance.';
        break;
    }
    if (_isCurrentSession(sessionEpoch, userId)) notifyListeners();
  }

  String _locationName(String locationId) =>
      locations
          .where((item) => item.id == locationId)
          .firstOrNull
          ?.displayName ??
      'le serveur VPN';

  void _scheduleLocationMigrationPoll(int seconds) {
    _migrationTimer?.cancel();
    if ((_migrationPollingClock?.elapsed ?? Duration.zero) >=
        const Duration(seconds: 120)) {
      isPollingLocationMigration = false;
      locationMigrationMessage =
          'Le changement de serveur continue. Ouvrez l’application plus tard pour le reprendre.';
      notifyListeners();
      return;
    }
    final delay = seconds.clamp(1, 120);
    final epoch = _migrationEpoch;
    _migrationTimer = Timer(Duration(seconds: delay), () {
      if (epoch == _migrationEpoch) {
        unawaited(
          locationMigration == null
              ? _resumeStoredLocationMigration()
              : _pollLocationMigration(),
        );
      }
    });
  }

  Future<void> _pollLocationMigration() async {
    if (isPollingLocationMigration || locationMigration == null) return;
    final epoch = _migrationEpoch;
    final sessionEpoch = _sessionEpoch;
    final userId = profile?.userId;
    isPollingLocationMigration = true;
    notifyListeners();
    try {
      final token = await _safe(_store.token());
      final migration = locationMigration;
      if (token == null ||
          migration == null ||
          epoch != _migrationEpoch ||
          !_isCurrentSession(sessionEpoch, userId)) {
        return;
      }
      if (migration.status == LocationMigrationStatus.ready) {
        await _finishLocationMigration(migration);
        return;
      }
      final update = await _api.getLocationMigration(
        token: token,
        deviceId: migration.deviceId,
        migrationId: migration.migrationId,
      );
      if (epoch != _migrationEpoch ||
          !_isCurrentSession(sessionEpoch, userId)) {
        return;
      }
      await _acceptLocationMigration(update);
    } on ApiException catch (error) {
      if (epoch != _migrationEpoch ||
          !_isCurrentSession(sessionEpoch, userId)) {
        return;
      }
      await _handleLocationMigrationError(error, keepResumeMarker: true);
    } catch (_) {
      if (epoch != _migrationEpoch ||
          !_isCurrentSession(sessionEpoch, userId)) {
        return;
      }
      locationMigrationError =
          'La progression du changement de serveur est momentanément indisponible.';
      _scheduleLocationMigrationPoll(2);
    } finally {
      if (epoch == _migrationEpoch && _isCurrentSession(sessionEpoch, userId)) {
        isPollingLocationMigration = false;
        notifyListeners();
      }
    }
  }

  Future<void> _finishLocationMigration(
    LocationMigration migration, {
    int? operationId,
  }) async {
    final sessionEpoch = _sessionEpoch;
    final userId = profile?.userId;
    final epoch = _migrationEpoch;
    if (operationId == null) {
      final running = _connectionCommand;
      if (running != null) await _safe<void>(running);
      if (!_isCurrentSession(sessionEpoch, userId) ||
          epoch != _migrationEpoch) {
        return;
      }
      if (isConnectionBusy) {
        _scheduleLocationMigrationPoll(2);
        return;
      }
      await _runConnectionCommand(
        (nextOperationId) =>
            _finishLocationMigration(migration, operationId: nextOperationId),
        initialState: vpnStatus,
      );
      return;
    }
    _migrationTimer?.cancel();
    _migrationTimer = null;
    bool stillCurrent() =>
        _acceptConnectionOperation(operationId) &&
        _isCurrentSession(sessionEpoch, userId) &&
        epoch == _migrationEpoch;
    try {
      await refreshDevices();
      if (!stillCurrent()) return;
      // A ready migration belongs to this device even if its destination has
      // since filled up and disappeared from the public discovery catalogue.
      final target =
          locations
              .where((item) => item.id == migration.targetLocationId)
              .firstOrNull ??
          (_currentDevice?.location?.id == migration.targetLocationId
              ? _currentDevice?.location
              : null) ??
          (pendingTargetLocation?.id == migration.targetLocationId
              ? pendingTargetLocation
              : null);
      if (!devicesReachable || target == null) {
        throw StateError('La destination ne peut pas être confirmée.');
      }
      // Commit durable state before clearing the visible pending migration.
      await _store.saveSelectedLocation(target.id);
      if (!stillCurrent()) return;
      await _store.clearLocationMigration();
      if (!stillCurrent()) return;
      _invalidateDeviceSnapshots();
      realDeviceLocation = target;
      selectedLocation = target;
      _connectionTargetLocation = target;
    } catch (_) {
      if (!stillCurrent()) return;
      locationMigrationMessage = null;
      locationMigrationError =
          'Le serveur est prêt, mais sa confirmation locale a échoué. La reprise sera retentée automatiquement.';
      _scheduleLocationMigrationPoll(2);
      return;
    }
    _cancelLocationMigrationPolling();
    locationMigration = null;
    pendingTargetLocation = null;
    locationMigrationError = null;
    locationMigrationMessage =
        'Serveur modifié. Vous pouvez maintenant vous connecter.';
    final reconnectProtocol = _migrationReconnectProtocol;
    _migrationReconnectProtocol = null;
    if (reconnectProtocol != null && profile != null) {
      vpnProtocol = reconnectProtocol;
      if (!_transitionConnection(operationId, VpnStatus.preparing)) return;
      await _startDeviceConnection(
        identityWasReset: false,
        skipLocationMigrationCheck: true,
        forcedProtocol: reconnectProtocol,
        operationId: operationId,
      );
    }
  }

  Future<void> _handleLocationMigrationError(
    ApiException error, {
    bool keepResumeMarker = false,
  }) async {
    final localMessage = _localApiFailureMessage(error);
    _traceControllerFailure('account', 'location_migration', error);
    if (keepResumeMarker &&
        (error.statusCode == 408 ||
            error.statusCode == 429 ||
            error.statusCode >= 500)) {
      locationMigrationError =
          localMessage ??
          'La progression du changement de serveur est momentanément indisponible.';
      _scheduleLocationMigrationPoll(error.retryAfterSeconds ?? 2);
      notifyListeners();
      return;
    }
    _cancelLocationMigrationPolling();
    _emitDiagnosticError(
      _apiFailureDiagnostic(error, operation: 'refresh', stage: 'enrollment'),
    );
    if (localMessage != null) {
      locationMigrationError = localMessage;
      notifyListeners();
      return;
    }
    final capacityIssue = _locationCapacityIssue(error);
    if (capacityIssue != null) {
      locationMigrationError = capacityIssue.message;
      _refreshAfterCapacityRejection(capacityIssue, pendingTargetLocation);
    } else if (error.isUnauthorized) {
      await _expireLocalSession();
      locationMigrationError =
          'Votre session a expiré. Connectez-vous de nouveau.';
    } else {
      switch (error.errorCode) {
        case 'location_migration_pending':
          locationMigrationError =
              'Un changement de serveur est déjà en cours pour cet appareil. Il sera repris ici dès que son identifiant est disponible.';
          break;
        case 'location_migration_blocked':
        case 'target_ca_mismatch':
          locationMigrationError =
              'Le serveur cible ne peut pas être préparé pour le moment. Réessayez plus tard ou contactez l’assistance.';
          break;
        case 'target_unavailable':
        case 'openvpn_signer_unavailable':
          locationMigrationError =
              'Le serveur cible est momentanément indisponible. Votre appareil reste sur son emplacement actuel.';
          break;
        case 'invalid_location':
        case 'not_found':
        case 'location_migration_conflict':
          locationMigrationError =
              'Le changement de serveur ne peut pas être poursuivi. Actualisez les emplacements puis réessayez.';
          break;
        default:
          locationMigrationError =
              'Le changement de serveur est momentanément indisponible. Réessayez plus tard.';
          break;
      }
    }
    locationMigrationMessage = null;
    if (!keepResumeMarker) {
      locationMigration = null;
      pendingTargetLocation = null;
    }
    notifyListeners();
  }

  void _cancelLocationMigrationPolling() {
    _migrationEpoch++;
    _migrationTimer?.cancel();
    _migrationTimer = null;
    isPollingLocationMigration = false;
  }

  void _clearLocationMigrationState() {
    _cancelLocationMigrationPolling();
    locationMigration = null;
    pendingTargetLocation = null;
    locationMigrationMessage = null;
    locationMigrationError = null;
    _migrationReconnectProtocol = null;
    _migrationPollingClock?.stop();
    _migrationPollingClock = null;
  }

  /// Used by the interface and tests to retry a persisted migration without
  /// creating a second migration request.
  Future<void> pollLocationMigrationNow() => _pollLocationMigration();

  /// Re-reads the protected resume marker for the signed-in account.
  Future<void> resumeLocationMigration() {
    _migrationPollingClock = Stopwatch()..start();
    return _resumeStoredLocationMigration();
  }

  Future<void> setTheme(ThemeMode value) async {
    await _persistExperiencePreference(
      () => _store.saveThemeMode(value.name),
      () => themeMode = value,
      'Le thème n’a pas pu être enregistré sur cet ordinateur.',
    );
  }

  Future<void> setLanguage(AppLanguage value) async {
    await _persistExperiencePreference(
      () => _store.saveAppLanguage(value.storageValue),
      () => language = value,
      'La langue n’a pas pu être enregistrée sur cet ordinateur.',
    );
  }

  Future<void> setVpnProtocol(VpnProtocol value) async {
    await setProtocolPreference(
      value == VpnProtocol.openVpn
          ? VpnProtocolPreference.openVpn
          : VpnProtocolPreference.wireGuard,
    );
  }

  Future<void> setProtocolPreference(VpnProtocolPreference value) async {
    if (requiresExplicitDisconnect || isConnectionBusy) {
      errorMessage = 'Déconnectez-vous avant de modifier le protocole VPN.';
      notifyListeners();
      return;
    }
    await _persistExperiencePreference(
      () => _store.saveVpnProtocol(switch (value) {
        VpnProtocolPreference.automatic => 'auto',
        VpnProtocolPreference.wireGuard => 'wireguard',
        VpnProtocolPreference.openVpn => 'openvpn',
      }),
      () {
        protocolPreference = value;
        vpnProtocol = value == VpnProtocolPreference.openVpn
            ? VpnProtocol.openVpn
            : VpnProtocol.wireGuard;
        errorMessage = null;
      },
      'Le protocole VPN n’a pas pu être enregistré sur cet ordinateur.',
    );
  }

  void _configureNativeNetworkProtection() {
    _wireguard.configureNetworkProtection(
      killSwitch: killSwitchEnabled,
      dnsProtection: dnsProtectionEnabled,
      webRtcProtection: webRtcProtectionEnabled,
    );
    _openVpn.configureNetworkProtection(
      killSwitch: killSwitchEnabled,
      dnsProtection: dnsProtectionEnabled,
      webRtcProtection: webRtcProtectionEnabled,
    );
  }

  Future<bool> _prepareConnectionNetworkProtection(
    VpnProtocol protocol, {
    int? operationId,
  }) async {
    if (!killSwitchEnabled) return true;
    final area = protocol == VpnProtocol.wireGuard ? 'wireguard' : 'openvpn';
    await DiagnosticLog.record(
      area: area,
      event: 'network_protection_prepare_started',
    );
    try {
      if (protocol == VpnProtocol.wireGuard) {
        await _wireguard.prepareNetworkProtection();
      } else {
        await _openVpn.prepareNetworkProtection();
      }
      if (!_acceptConnectionOperation(operationId)) return false;
      if (killSwitchEnabled) {
        _retainedProtectionProtocol = protocol;
      }
      await DiagnosticLog.record(
        area: area,
        event: 'network_protection_prepare_succeeded',
      );
      return true;
    } on PlatformException catch (error) {
      if (!_acceptConnectionOperation(operationId)) return false;
      await DiagnosticLog.recordFailure(
        area: area,
        event: 'network_protection_prepare_failed',
        stage: 'network_protection_prepare',
        error: error,
      );
      final retained = await _restoreRetainedNetworkProtection(
        operationId: operationId,
      );
      if (!retained && _transitionConnection(operationId, VpnStatus.error)) {
        errorMessage = protocol == VpnProtocol.wireGuard
            ? _wireGuardPlatformErrorMessage(error.code)
            : _openVpnPlatformErrorMessage(error.code);
      }
      notifyListeners();
      return false;
    } catch (error) {
      if (!_acceptConnectionOperation(operationId)) return false;
      await DiagnosticLog.recordFailure(
        area: area,
        event: 'network_protection_prepare_failed',
        stage: 'network_protection_prepare',
        error: error,
      );
      final retained = await _restoreRetainedNetworkProtection(
        operationId: operationId,
      );
      if (!retained && _transitionConnection(operationId, VpnStatus.error)) {
        errorMessage =
            'Windows n’a pas pu préparer le kill switch avant la connexion VPN.';
      }
      notifyListeners();
      return false;
    }
  }

  bool get canChangeNetworkProtection =>
      !requiresExplicitDisconnect && !isConnectionBusy;

  SecuritySettings get _securitySettings => SecuritySettings(
    killSwitch: killSwitchEnabled,
    dnsProtection: dnsProtectionEnabled,
    webRtcProtection: webRtcProtectionEnabled,
    automaticReconnect: automaticReconnectEnabled,
  );

  void _applySecuritySettings(SecuritySettings value) {
    killSwitchEnabled = value.killSwitch;
    dnsProtectionEnabled = value.dnsProtection;
    webRtcProtectionEnabled = value.webRtcProtection;
    automaticReconnectEnabled = value.automaticReconnect;
  }

  bool get _canSaveDisconnectedSecuritySettings =>
      !requiresExplicitDisconnect &&
      !_isInstallingUpdate &&
      !_isSigningOut &&
      _connectionCommand == null &&
      !_isRevokingCurrentDevice;

  Future<void> _persistSecuritySettingsChange({
    bool? killSwitch,
    bool? dnsProtection,
    bool? webRtcProtection,
    bool? automaticReconnect,
    bool requiresDisconnectedTunnel = false,
  }) {
    if (_disposed || _isSigningOut || _isInstallingUpdate) {
      return Future<void>.value();
    }
    // Reserve before the queue's first microtask: neither a tray action nor a
    // connection button can capture preferences that are not durable yet.
    _securityPreferenceWritesPending++;
    final operation = _securitySettingsWriteQueue.then((_) async {
      try {
        if (_disposed ||
            _isSigningOut ||
            _isInstallingUpdate ||
            (requiresDisconnectedTunnel &&
                !_canSaveDisconnectedSecuritySettings)) {
          return;
        }
        final current = _securitySettings;
        final next = SecuritySettings(
          killSwitch: killSwitch ?? current.killSwitch,
          dnsProtection: dnsProtection ?? current.dnsProtection,
          webRtcProtection: webRtcProtection ?? current.webRtcProtection,
          automaticReconnect: automaticReconnect ?? current.automaticReconnect,
        );
        securitySettingsError = null;
        notifyListeners();
        await _store.saveSecuritySettings(next);
        if (_disposed ||
            (requiresDisconnectedTunnel &&
                !_canSaveDisconnectedSecuritySettings)) {
          return;
        }
        _applySecuritySettings(next);
        _configureNativeNetworkProtection();
        if (!automaticReconnectEnabled) _cancelAutomaticReconnect();
      } catch (_) {
        if (_disposed) return;
        securitySettingsError =
            'Les réglages de sécurité n’ont pas pu être enregistrés.';
      } finally {
        _securityPreferenceWritesPending--;
        if (!_disposed) notifyListeners();
      }
    });
    _securitySettingsWriteQueue = operation;
    notifyListeners();
    return operation;
  }

  Future<void> setKillSwitch(bool value) => _persistSecuritySettingsChange(
    killSwitch: value,
    requiresDisconnectedTunnel: true,
  );

  Future<void> setDnsProtection(bool value) => _persistSecuritySettingsChange(
    dnsProtection: value,
    requiresDisconnectedTunnel: true,
  );

  Future<void> setWebRtcProtection(bool value) =>
      _persistSecuritySettingsChange(
        webRtcProtection: value,
        requiresDisconnectedTunnel: true,
      );

  Future<void> setAutomaticReconnect(bool value) =>
      _persistSecuritySettingsChange(automaticReconnect: value);

  void _ignoreConnectivityEvents(Duration duration) {
    final candidate = _now().add(duration);
    if (candidate.isAfter(_ignoreConnectivityEventsUntil)) {
      _ignoreConnectivityEventsUntil = candidate;
    }
  }

  void _cancelAutomaticReconnect() {
    _automaticReconnectTimer?.cancel();
    _automaticReconnectTimer = null;
    _automaticReconnectIntent = null;
    _automaticReconnectAttempts = 0;
  }

  void _scheduleAutomaticReconnect({Duration? delay}) {
    if (_disposed ||
        _isInstallingUpdate ||
        _isSigningOut ||
        runtimeOwnedByAnotherUser ||
        !automaticReconnectEnabled ||
        _automaticReconnectIntent == null ||
        _automaticReconnectAttempts >= _reconnectDelays.length ||
        _automaticReconnectTimer != null) {
      return;
    }
    _automaticReconnectTimer = Timer(
      delay ?? Duration(seconds: _reconnectDelays[_automaticReconnectAttempts]),
      () => unawaited(_reconnectAfterWindowsEvent()),
    );
  }

  Future<void> _recoverSavedSession({bool allowAutoConnect = true}) async {
    if (!savedSessionVerificationPending ||
        _sessionRecoveryInProgress ||
        !isInitialized ||
        _disposed ||
        _isSigningOut ||
        _signInInProgress ||
        isConnectionBusy ||
        _runtimeVerificationPending ||
        (requiresExplicitDisconnect && vpnStatus != VpnStatus.connected) ||
        runtimeOwnedByAnotherUser) {
      return;
    }
    final clock = Stopwatch()..start();
    _traceControllerPhase('account', 'saved_session_recovery', 'begin');
    final epoch = _sessionEpoch;
    _sessionRecoveryInProgress = true;
    notifyListeners();
    try {
      final token = await _readSavedSessionToken();
      if (_disposed || _isSigningOut || epoch != _sessionEpoch) return;
      if (_sessionStorageUnavailable) return;
      if (token == null) {
        _sessionValidationPending = false;
        _cancelSavedSessionVerificationRetry();
        return;
      }
      await _loadProfile(token);
      if (!_isCurrentSession(epoch, profile?.userId) ||
          profile == null ||
          savedSessionVerificationPending) {
        return;
      }
      final savedLocation = await _safe(_store.selectedLocation());
      if (!_isCurrentSession(epoch, profile?.userId)) return;
      await refreshLocations(savedLocation);
      await refreshDevices();
      if (!_isCurrentSession(epoch, profile?.userId)) return;
      if (allowAutoConnect) await _resumeStoredLocationMigration();
      if (_isCurrentSession(epoch, profile?.userId) &&
          autoConnectOnLaunch &&
          allowAutoConnect &&
          vpnStatus == VpnStatus.disconnected &&
          !isLocationMigrationActive &&
          !isConnectionBusy) {
        await quickConnect();
      }
    } catch (error) {
      _traceControllerFailure(
        'account',
        'saved_session_recovery',
        error,
        durationMs: clock.elapsedMilliseconds,
      );
      rethrow;
    } finally {
      _sessionRecoveryInProgress = false;
      _scheduleSavedSessionVerificationRetry();
      _traceControllerPhase(
        'account',
        'saved_session_recovery',
        'finished',
        code: savedSessionVerificationPending
            ? 'verification_pending'
            : 'settled',
        durationMs: clock.elapsedMilliseconds,
      );
      if (!_disposed) notifyListeners();
    }
  }

  /// Validates the saved account without login, native identity work, cached
  /// tunnel reconnection or a location migration. Only confirmed authentication
  /// rejection may remove the saved credential.
  Future<void> retrySavedSessionVerification() {
    _cancelSavedSessionVerificationRetry();
    _api.invalidateBootstrapCache();
    return _recoverSavedSession(allowAutoConnect: false);
  }

  Future<void> _handleWindowsConnectivityEvent(
    WindowsConnectivityEvent event,
  ) async {
    _api.invalidateBootstrapCache();
    unawaited(_resumeDiagnostics());
    if (_isInstallingUpdate) return;
    await _recoverSavedSession();
    if (_disposed || _isSigningOut || runtimeOwnedByAnotherUser) return;
    if (!automaticReconnectEnabled ||
        (profile == null &&
            (_automaticReconnectIntent == null ||
                _retainedProtectionProtocol == null))) {
      return;
    }
    if (_now().isBefore(_ignoreConnectivityEventsUntil)) return;
    if (vpnStatus == VpnStatus.connected && activeProtocol != null) {
      _automaticReconnectIntent = activeProtocol;
    }
    if (_automaticReconnectIntent == null ||
        _automaticReconnectInProgress ||
        isConnectionBusy) {
      return;
    }
    _automaticReconnectTimer?.cancel();
    _automaticReconnectTimer = null;
    _automaticReconnectAttempts = 0;
    final delay = event == WindowsConnectivityEvent.systemResumed
        ? const Duration(seconds: 2)
        : const Duration(seconds: 3);
    _scheduleAutomaticReconnect(delay: delay);
  }

  Future<void> _reconnectAfterWindowsEvent() async {
    _automaticReconnectTimer = null;
    final protocol = _automaticReconnectIntent;
    if (!automaticReconnectEnabled ||
        protocol == null ||
        (profile == null && _retainedProtectionProtocol == null) ||
        (selectedLocation == null &&
            _knownTunnelLocationIds[protocol] == null &&
            _retainedProtectionProtocol == null) ||
        _automaticReconnectInProgress) {
      return;
    }
    if (isConnectionBusy) {
      _scheduleAutomaticReconnect(delay: const Duration(seconds: 1));
      return;
    }
    _automaticReconnectAttempts++;
    await _runConnectionCommand(
      (operationId) =>
          _performAutomaticReconnect(operationId, protocol: protocol),
      initialState: VpnStatus.preparing,
    );
  }

  Future<void> _performAutomaticReconnect(
    int operationId, {
    required VpnProtocol protocol,
  }) async {
    _automaticReconnectInProgress = true;
    _ignoreConnectivityEvents(const Duration(seconds: 12));
    vpnProtocol = protocol;
    errorMessage = null;
    notifyListeners();
    try {
      final protectionBeforeReconnect = await _networkProtectionOwner();
      if (!_acceptConnectionOperation(operationId)) return;
      if (protectionBeforeReconnect != null) {
        _retainedProtectionProtocol = protectionBeforeReconnect;
      }
      if (!await _prepareConnectionNetworkProtection(
        protocol,
        operationId: operationId,
      )) {
        return;
      }
      // Native resume can repair a protected tunnel even while WFP prevents
      // this GUI from contacting the API. No tunnel material enters Dart.
      if (!_transitionConnection(operationId, VpnStatus.connecting)) return;
      final restored = protocol == VpnProtocol.wireGuard
          ? await _wireguard.reconnect()
          : await _openVpn.reconnect();
      if (!_acceptConnectionOperation(operationId)) return;
      if (restored) {
        _markNativeConnected(protocol, operationId: operationId, cached: true);
      } else {
        final protectionNow = await _networkProtectionOwner();
        if (!_acceptConnectionOperation(operationId)) return;
        if (protectionBeforeReconnect != null || protectionNow != null) {
          _retainedProtectionProtocol =
              protectionNow ?? protectionBeforeReconnect;
          _transitionConnection(
            operationId,
            _retainedProtectionBlocksTraffic
                ? VpnStatus.blocked
                : VpnStatus.error,
          );
          activeProtocol = null;
          tunnelLocationId = null;
          connectedAt = null;
          errorMessage = _retainedProtectionBlocksTraffic
              ? 'La configuration locale de reprise est indisponible. Le kill switch bloque toujours le trafic réseau. Déconnectez-vous avant de réessayer.'
              : _partialProtectionMessage;
          return;
        }
        // Missing/failed status reads are not permission to send API traffic.
        final protectionStates = await Future.wait([
          _safe<bool>(_wireguard.isNetworkProtectionActive()),
          _safe<bool>(_openVpn.isNetworkProtectionActive()),
        ]);
        if (!_acceptConnectionOperation(operationId)) return;
        if (protectionStates.any((active) => active != false)) {
          _disconnectUnconfirmed = true;
          _transitionConnection(operationId, VpnStatus.error);
          errorMessage =
              'L’état de la protection réseau ne peut pas être confirmé. Déconnectez-vous avant de réessayer.';
          return;
        }
        _transitionConnection(operationId, VpnStatus.disconnected);
        _transitionConnection(operationId, VpnStatus.preparing);
        await _startDeviceConnection(
          identityWasReset: false,
          forcedProtocol: protocol,
          operationId: operationId,
        );
      }
      if (vpnStatus == VpnStatus.connected && activeProtocol == protocol) {
        _automaticReconnectIntent = null;
        errorMessage = null;
        // A window reopened under a retained lock could not validate its saved
        // session yet. Once native resume succeeds, API access is safe again.
        if (profile == null && isInitialized) {
          final token = await _safe(_store.token());
          if (!_acceptConnectionOperation(operationId)) return;
          if (token != null) {
            final savedLocation = await _safe(_store.selectedLocation());
            if (!_acceptConnectionOperation(operationId)) return;
            await Future.wait([
              refreshLocations(savedLocation),
              _loadProfile(token),
            ]);
            if (!_acceptConnectionOperation(operationId)) return;
            if (profile != null) await refreshDevices();
            // Native cache restoration does not attest a server destination.
          }
        }
      } else {
        final existingTunnelConnected =
            await _safe<bool>(_isTunnelStillConnected(protocol)) ?? false;
        if (existingTunnelConnected &&
            _markNativeConnected(
              protocol,
              operationId: operationId,
              cached: true,
            )) {
          _automaticReconnectIntent = null;
        } else if (!await _restoreRetainedNetworkProtection(
          operationId: operationId,
          message:
              'La reconnexion automatique a échoué. Le kill switch bloque toujours le trafic réseau.',
        )) {
          errorMessage ??=
              'La reconnexion automatique n’a pas pu être terminée. Réessayez.';
        }
      }
    } catch (_) {
      if (!_acceptConnectionOperation(operationId)) return;
      await _restoreNetworkStateAfterFailedDisconnect(
        protocol,
        operationId: operationId,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      if (runtimeOwnedByAnotherUser) {
        _cancelAutomaticReconnect();
        errorMessage = _otherSessionMessage;
        return;
      }
      if (vpnStatus == VpnStatus.connected) {
        _automaticReconnectIntent = null;
        errorMessage = null;
      } else if (vpnStatus == VpnStatus.blocked) {
        errorMessage =
            'La reconnexion automatique a échoué. Le kill switch bloque toujours le trafic réseau.';
      } else {
        _transitionConnection(operationId, VpnStatus.error);
        errorMessage =
            'La reconnexion automatique n’a pas pu être terminée. Réessayez.';
      }
    } finally {
      _automaticReconnectInProgress = false;
      if (vpnStatus != VpnStatus.connected) {
        _ignoreConnectivityEventsUntil = _now();
        _scheduleAutomaticReconnect();
      } else {
        _automaticReconnectAttempts = 0;
      }
      if (!_disposed) notifyListeners();
    }
  }

  Future<bool> signIn({required String email, required String password}) =>
      _performSignIn(() => _api.login(email: email, password: password));

  Future<bool> signInWithBrowser() async {
    if (_signInInProgress || browserSignInBusy || _isSigningOut || _disposed) {
      return false;
    }
    browserSignInErrorMessage = null;
    final cancellation = Completer<void>();
    _browserCancellation = cancellation;
    var succeeded = false;
    try {
      succeeded = await _performSignIn(
        () => _authenticateWithBrowser(cancellation),
        browser: true,
      );
      if (!succeeded && !cancellation.isCompleted && !_disposed) {
        browserSignInErrorMessage = errorMessage;
      }
      return succeeded;
    } finally {
      if (identical(_browserCancellation, cancellation)) {
        if (!cancellation.isCompleted) cancellation.complete();
        _browserCancellation = null;
        final attempt = _browserAuthAttempt;
        _browserAuthAttempt = null;
        _browserAuthorizationUri = null;
        if (attempt != null) await attempt.dispose();
        browserSignInStatus = BrowserSignInStatus.idle;
        if (!_disposed) notifyListeners();
      }
    }
  }

  Future<T> _browserWork<T>(Future<T> work, Completer<void> cancellation) =>
      Future.any([
        work,
        cancellation.future.then<T>((_) => throw BrowserAuthException.canceled),
      ]);

  Future<AuthSession> _authenticateWithBrowser(
    Completer<void> cancellation,
  ) async {
    final clock = Stopwatch()..start();
    Future<T> beforeDeadline<T>(Future<T> work) {
      final remaining = _browserAuth.timeout - clock.elapsed;
      return _browserWork(work, cancellation)
          .timeout(
            remaining > Duration.zero ? remaining : Duration.zero,
            onTimeout: () => throw BrowserAuthException.timeout,
          )
          .then((value) {
            if (clock.elapsed >= _browserAuth.timeout) {
              throw BrowserAuthException.timeout;
            }
            return value;
          });
    }

    browserSignInStatus = BrowserSignInStatus.openingBrowser;
    errorMessage = null;
    notifyListeners();
    _browserAuthStage = 'browser_auth_listener';
    _traceControllerPhase('account', 'browser_auth_listener', 'begin');
    final creating = _browserAuth.start();
    // Binding can finish after an explicit cancellation. Close that listener
    // as well; it must never become an orphan waiting for browser traffic.
    unawaited(
      creating.then<void>((attempt) {
        if (cancellation.isCompleted) unawaited(attempt.dispose());
      }, onError: (Object _, StackTrace _) {}),
    );
    final attempt = await beforeDeadline(creating);
    _browserAuthAttempt = attempt;
    _traceControllerPhase('account', 'browser_auth_listener', 'completed');
    final url = attempt.authorizationUri(
      BrandConfig.portalWindowsConnect,
      BrandConfig.windowsBrowserClientId,
    );
    _browserAuthorizationUri = url;
    _browserAuthStage = 'browser_auth_open';
    _traceControllerPhase('account', 'browser_auth_open', 'begin');
    bool opened;
    try {
      opened = await beforeDeadline(
        _browserLauncher(url).timeout(const Duration(seconds: 10)),
      );
    } on BrowserAuthException {
      rethrow;
    } catch (_) {
      // Platform messages can contain the complete authorization URL.
      throw BrowserAuthException.launchFailed;
    }
    if (!opened) {
      throw BrowserAuthException.launchFailed;
    }
    _traceControllerPhase('account', 'browser_auth_open', 'completed');
    browserSignInStatus = BrowserSignInStatus.waitingForBrowser;
    notifyListeners();
    _browserAuthStage = 'browser_auth_callback';
    _traceControllerPhase('account', 'browser_auth_callback', 'begin');
    final code = await beforeDeadline(attempt.callback);
    _traceControllerPhase('account', 'browser_auth_callback', 'completed');
    browserSignInStatus = BrowserSignInStatus.completingSignIn;
    notifyListeners();
    _browserAuthStage = 'browser_auth_exchange';
    _traceControllerPhase('account', 'browser_auth_exchange', 'begin');
    // Do not retry this one-use code after a lost response. A fresh explicit
    // browser authorization is required instead.
    final session = await beforeDeadline(
      _api.exchangeWindowsBrowserCode(
        code: code,
        redirectUri: attempt.redirectUri,
        codeVerifier: attempt.codeVerifier,
      ),
    );
    _traceControllerPhase('account', 'browser_auth_exchange', 'completed');
    // Once the token arrives within the authorization deadline, finalize the
    // normal session. Do not interrupt protected storage with that deadline.
    await _browserWork(_window.show(), cancellation);
    return session;
  }

  Future<bool> reopenBrowserSignIn() async {
    final url = _browserAuthorizationUri;
    final cancellation = _browserCancellation;
    if (url == null ||
        cancellation == null ||
        cancellation.isCompleted ||
        browserSignInStatus != BrowserSignInStatus.waitingForBrowser) {
      return false;
    }
    bool current() =>
        !_disposed &&
        identical(_browserCancellation, cancellation) &&
        !cancellation.isCompleted &&
        browserSignInStatus == BrowserSignInStatus.waitingForBrowser;
    try {
      final opened = await _browserWork(
        _browserLauncher(url).timeout(const Duration(seconds: 10)),
        cancellation,
      );
      if (!opened) throw BrowserAuthException.launchFailed;
      if (!current()) return false;
      browserSignInErrorMessage = null;
      notifyListeners();
      return opened;
    } catch (_) {
      if (current()) {
        browserSignInErrorMessage = _browserSignInFailureMessage(
          'browser_auth_launch_failed',
        );
        _traceControllerPhase(
          'account',
          'browser_auth_open',
          'failed',
          code: 'browser_auth_launch_failed',
        );
        notifyListeners();
      }
      return false;
    }
  }

  void cancelBrowserSignIn() {
    final cancellation = _browserCancellation;
    if (cancellation == null || cancellation.isCompleted) return;
    cancellation.complete();
    _signInGeneration++;
    final attempt = _browserAuthAttempt;
    if (attempt != null) unawaited(attempt.cancel());
    browserSignInErrorMessage = null;
    errorMessage = null;
    _traceControllerPhase('account', 'account_authentication', 'cancelled');
    if (!_disposed) notifyListeners();
  }

  static String _browserSignInFailureMessage(String code) => switch (code) {
    'browser_auth_timeout' =>
      'La demande de connexion a expiré. Ouvrez à nouveau le navigateur depuis FuzeVPN.',
    'browser_auth_denied' => 'La connexion a été annulée dans le navigateur.',
    'browser_auth_launch_failed' =>
      'Le navigateur n’a pas pu être ouvert. Vérifiez votre navigateur par défaut puis réessayez.',
    'browser_auth_callback_unavailable' =>
      'FuzeVPN ne peut pas recevoir la connexion du navigateur sur cet appareil. Réessayez ou utilisez votre adresse e-mail et votre mot de passe.',
    _ =>
      'La réponse de connexion du navigateur est invalide. Recommencez depuis FuzeVPN.',
  };

  Future<bool> _performSignIn(
    Future<AuthSession> Function() authenticate, {
    bool browser = false,
  }) async {
    if (_isSigningOut || _disposed || _signInInProgress || browserSignInBusy) {
      return false;
    }
    if (runtimeOwnedByAnotherUser) {
      errorMessage = _otherSessionMessage;
      notifyListeners();
      return false;
    }
    if (_runtimeVerificationPending) {
      errorMessage = _runtimeVerificationFailureMessage;
      notifyListeners();
      return false;
    }
    if (vpnStatus == VpnStatus.blocked || _disconnectUnconfirmed) {
      errorMessage =
          'Déconnectez le VPN avant de vous connecter à votre compte.';
      notifyListeners();
      return false;
    }
    _signInInProgress = true;
    final generation = ++_signInGeneration;
    // An older saved-session validation must not overwrite this new account.
    final sessionEpoch = ++_sessionEpoch;
    _cancelSavedSessionVerificationRetry();
    bool current() =>
        !_isSigningOut &&
        !_disposed &&
        sessionEpoch == _sessionEpoch &&
        generation == _signInGeneration;
    var credentialsAccepted = false;
    var profileLoaded = false;
    var signInStage = 'account_authentication';
    try {
      final session = await authenticate();
      if (!current()) return false;
      credentialsAccepted = true;
      signInStage = 'session_validation';
      final nextProfile = await _api.me(session.accessToken);
      if (!current()) return false;
      profileLoaded = true;
      signInStage = 'local_identity';

      // A local WireGuard identity belongs to one VPN account only. The
      // native runner compares its protected account binding, removes any
      // older identity (and active tunnel), then creates a fresh pair when
      // another account signs in. No key material enters Dart here.
      await _wireguard.prepareIdentityForAccount(nextProfile.userId);
      if (!current()) return false;
      _clearSubscriptionState();
      signInStage = 'saved_session_storage';
      final writing = _store.saveToken(session.accessToken);
      _sessionTokenWrite = writing;
      try {
        await writing;
      } finally {
        if (identical(_sessionTokenWrite, writing)) _sessionTokenWrite = null;
      }
      if (!current()) return false;
      profile = nextProfile;
      _sessionValidationPending = false;
      _sessionStorageUnavailable = false;
      _savedSessionVerificationErrorMessage = null;
      _cancelSavedSessionVerificationRetry();
      _bindDiagnosticSession();
      signInStage = 'device_catalogue';
      await refreshDevices();
      if (!current()) return false;
      if (currentDeviceId != null && _currentDevice == null) {
        await _forgetCurrentDeviceBinding();
      }
      await _resumeStoredLocationMigration();
      if (!current()) return false;
      errorMessage = null;
      deviceEnrollmentIssue = null;
      notifyListeners();
      return true;
    } on BrowserAuthException catch (error) {
      if (!current()) return false;
      _traceControllerFailure('account', _browserAuthStage, error);
      errorMessage = _browserSignInFailureMessage(error.code);
      notifyListeners();
      return false;
    } on ApiException catch (error) {
      if (!current()) return false;
      _traceControllerFailure(
        'account',
        browser && !credentialsAccepted ? _browserAuthStage : signInStage,
        error,
      );
      final localMessage = _localApiFailureMessage(error);
      if (localMessage != null) {
        errorMessage = localMessage;
      } else if (browser && error.errorCode == 'desktop_auth_invalid_grant') {
        errorMessage =
            'Cette demande de connexion a expiré ou a déjà été utilisée. Recommencez depuis FuzeVPN.';
      } else if (browser && error.errorCode == 'desktop_auth_unavailable') {
        errorMessage =
            'La connexion par navigateur est momentanément indisponible. Utilisez votre adresse e-mail et votre mot de passe, ou réessayez plus tard.';
      } else if (browser &&
          !credentialsAccepted &&
          (error.errorCode == 'account_login_required' ||
              error.isUnauthorized)) {
        errorMessage =
            'Reconnectez-vous à votre compte dans le navigateur, puis réessayez depuis FuzeVPN.';
      } else if (browser &&
          const {
            'desktop_auth_invalid_request',
            'invalid_json',
            'browser_auth_invalid_response',
          }.contains(error.errorCode)) {
        errorMessage = _browserSignInFailureMessage(
          'browser_auth_invalid_response',
        );
      } else if (!credentialsAccepted &&
          error.statusCode == HttpStatus.unauthorized &&
          error.errorCode == 'invalid_credentials') {
        errorMessage =
            'La connexion au compte a échoué. Vérifiez votre adresse e-mail et votre mot de passe.';
      } else if (error.isUnauthorized) {
        errorMessage = 'Votre session a expiré. Connectez-vous de nouveau.';
      } else if (error.statusCode == HttpStatus.tooManyRequests &&
          error.errorCode == 'rate_limited') {
        errorMessage =
            'Trop de tentatives de connexion. Réessayez dans quelques instants.';
      } else {
        errorMessage = _signInFailureMessage(
          credentialsAccepted: credentialsAccepted,
          profileLoaded: profileLoaded,
          networkFailure:
              (error.statusCode == HttpStatus.requestTimeout &&
                  error.errorCode == 'request_timeout') ||
              (error.statusCode == HttpStatus.serviceUnavailable &&
                  error.errorCode == 'api_resolution_unavailable'),
        );
      }
      notifyListeners();
      return false;
    } on PlatformException catch (error) {
      if (!current()) return false;
      _traceControllerFailure(
        'account',
        browser && !credentialsAccepted ? _browserAuthStage : signInStage,
        error,
      );
      errorMessage =
          error.code.startsWith('storage_') ||
              error.code.startsWith('secure_storage_')
          ? 'Le stockage protégé de FuzeVPN ne peut pas être utilisé. Réessayez.'
          : error.code == 'runtime_owned_by_another_user'
          ? _otherSessionMessage
          : 'Impossible de préparer l’identité VPN sécurisée de cet appareil.';
      notifyListeners();
      return false;
    } catch (error) {
      if (!current()) return false;
      _traceControllerFailure(
        'account',
        browser && !credentialsAccepted ? _browserAuthStage : signInStage,
        error,
      );
      errorMessage = _signInFailureMessage(
        credentialsAccepted: credentialsAccepted,
        profileLoaded: profileLoaded,
        networkFailure:
            error is SocketException ||
            error is HttpException ||
            error is HandshakeException ||
            error is TimeoutException,
      );
      notifyListeners();
      return false;
    } finally {
      _signInInProgress = false;
      _scheduleSavedSessionVerificationRetry();
    }
  }

  static String _signInFailureMessage({
    required bool credentialsAccepted,
    required bool profileLoaded,
    required bool networkFailure,
  }) {
    if (profileLoaded) {
      return 'Impossible de finaliser la connexion à ce compte. Réessayez.';
    }
    if (credentialsAccepted) {
      return 'Votre connexion a été acceptée, mais les informations du compte ne peuvent pas être chargées pour le moment. Réessayez plus tard.';
    }
    return networkFailure
        ? 'Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.'
        : 'Le service de connexion est momentanément indisponible. Réessayez plus tard.';
  }

  Future<void> toggleConnection() {
    final disconnect = requiresExplicitDisconnect;
    return _runConnectionCommand(
      (operationId) => _toggleConnection(operationId, disconnect: disconnect),
      initialState: disconnect ? VpnStatus.disconnecting : VpnStatus.preparing,
    );
  }

  Future<void> _toggleConnection(
    int operationId, {
    required bool disconnect,
  }) async {
    _cancelAutomaticReconnect();
    _ignoreConnectivityEvents(const Duration(seconds: 12));
    if (disconnect) {
      // Releasing a prepared kill switch is an explicit cancellation of any
      // delayed OpenVPN reconnect. The remote migration may keep progressing,
      // but it must not silently re-arm the tunnel afterwards.
      _migrationReconnectProtocol = null;
      try {
        await _disconnectActiveTunnel();
        _markNativeDisconnected(operationId: operationId);
      } catch (error) {
        await _restoreNetworkStateAfterFailedDisconnect(
          activeProtocol ?? _retainedProtectionProtocol,
          operationId: operationId,
        );
        if (error is PlatformException &&
            error.code == 'openvpn_cleanup_failed' &&
            _acceptConnectionOperation(operationId) &&
            requiresExplicitDisconnect &&
            !runtimeOwnedByAnotherUser) {
          errorMessage = _openVpnPlatformErrorMessage(error.code);
        }
      }
      notifyListeners();
      return;
    }
    await _startDeviceConnection(
      identityWasReset: false,
      operationId: operationId,
    );
  }

  /// Connects with the selected compatible location. A first compatible
  /// location is chosen only when the user has never selected one; an
  /// incompatible existing selection is never replaced silently.
  Future<void> quickConnect() {
    final disconnect = requiresExplicitDisconnect;
    return _runConnectionCommand(
      (operationId) => _quickConnect(operationId, disconnect: disconnect),
      initialState: disconnect ? VpnStatus.disconnecting : VpnStatus.preparing,
    );
  }

  Future<void> _quickConnect(
    int operationId, {
    required bool disconnect,
  }) async {
    if (disconnect) {
      await _toggleConnection(operationId, disconnect: true);
      return;
    }
    if (profile == null) {
      _signInPromptPending = true;
      _transitionConnection(operationId, VpnStatus.disconnected);
      errorMessage = null;
      notifyListeners();
      return;
    }
    if (selectedLocation != null &&
        !_locationSupportsPreference(selectedLocation!)) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage =
          'Cet emplacement n’est pas compatible avec le protocole choisi. Sélectionnez un autre emplacement.';
      section = AppSection.locations;
      notifyListeners();
      return;
    }
    if (selectedLocation == null) {
      if (_locationSelectionUnavailable) {
        _transitionConnection(operationId, VpnStatus.error);
        errorMessage =
            'Le serveur choisi n’est plus disponible. Sélectionnez un autre emplacement.';
        section = AppSection.locations;
        notifyListeners();
        return;
      }
      final fallback = protocolPreference == VpnProtocolPreference.automatic
          ? locations
                    .where(
                      (location) => location.supportedProtocols.contains(
                        VpnProtocol.wireGuard,
                      ),
                    )
                    .firstOrNull ??
                locations.where(_locationSupportsPreference).firstOrNull
          : locations.where(_locationSupportsPreference).firstOrNull;
      if (fallback == null) {
        _transitionConnection(operationId, VpnStatus.error);
        errorMessage =
            'Aucun emplacement compatible n’est disponible pour ce protocole.';
        notifyListeners();
        return;
      }
      if (!await _selectLocation(fallback, operationId: operationId)) {
        _transitionConnection(operationId, VpnStatus.error);
        errorMessage = experienceSettingsError;
        return;
      }
    }
    if (!_acceptConnectionOperation(operationId)) return;
    await _toggleConnection(operationId, disconnect: false);
  }

  bool _locationSupportsPreference(Location location) =>
      switch (protocolPreference) {
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

  VpnProtocol? _protocolForConnection({VpnProtocol? forcedProtocol}) {
    if (forcedProtocol != null) return forcedProtocol;
    if (protocolPreference != VpnProtocolPreference.automatic) {
      // Keep [vpnProtocol] as the concrete source for backwards-compatible
      // callers and for an in-progress manual location change.
      return vpnProtocol;
    }
    final location = _requestedLocation;
    if (location == null) return null;
    if (location.supportedProtocols.contains(VpnProtocol.wireGuard)) {
      return VpnProtocol.wireGuard;
    }
    if (openVpnRuntimeAvailable &&
        location.supportedProtocols.contains(VpnProtocol.openVpn)) {
      return VpnProtocol.openVpn;
    }
    return null;
  }

  Future<void> _disconnectActiveTunnel() async {
    _ignoreConnectivityEvents(const Duration(seconds: 12));
    if (_disconnectUnconfirmed) {
      Object? failure;
      StackTrace? failureStack;
      for (final protocol in VpnProtocol.values) {
        try {
          await _disconnectProtocol(protocol);
        } catch (error, stackTrace) {
          failure ??= error;
          failureStack ??= stackTrace;
        }
      }
      if (failure != null) Error.throwWithStackTrace(failure, failureStack!);
      return;
    }
    final requestedProtocol =
        activeProtocol ?? _retainedProtectionProtocol ?? VpnProtocol.wireGuard;
    await _disconnectProtocol(requestedProtocol);

    // A prepared policy can atomically change the native WFP owner before the
    // UI has replaced its last connected protocol. If that operation is then
    // interrupted, stopping the cached protocol succeeds but intentionally
    // cannot remove the other protocol's filters. Resolve the authoritative
    // native owner once more so an explicit Disconnect always releases the
    // remaining FuzeVPN policy instead of requiring an application restart.
    var protectionStates = await Future.wait([
      _safe<bool>(_wireguard.isNetworkProtectionActive()),
      _safe<bool>(_openVpn.isNetworkProtectionActive()),
    ]);
    final remainingOwner = protectionStates[0] == true
        ? VpnProtocol.wireGuard
        : protectionStates[1] == true
        ? VpnProtocol.openVpn
        : null;
    if (remainingOwner != null) {
      await _disconnectProtocol(remainingOwner);
    } else {
      final otherProtocol = requestedProtocol == VpnProtocol.wireGuard
          ? VpnProtocol.openVpn
          : VpnProtocol.wireGuard;
      final otherState = requestedProtocol == VpnProtocol.wireGuard
          ? protectionStates[1]
          : protectionStates[0];
      if (otherState == null) {
        // An unavailable status read is not evidence that the other owner's
        // dynamic filters are absent. Its disconnect is idempotent and lets
        // the authenticated broker release a transferred prepared policy.
        await _disconnectProtocol(otherProtocol);
      }
    }
  }

  Future<VpnProtocol?> _protocolRequiringDisconnect() async {
    final states = await Future.wait([
      _safe<bool>(_wireguard.isConnected()),
      _safe<bool>(_openVpn.isConnected()),
      _safe<bool>(_wireguard.isNetworkProtectionActive()),
      _safe<bool>(_openVpn.isNetworkProtectionActive()),
    ]);
    _disconnectUnconfirmed =
        _disconnectUnconfirmed || states.any((state) => state == null);
    if (activeProtocol case final protocol?) return protocol;
    if (states[0] == true || states[2] == true) {
      return VpnProtocol.wireGuard;
    }
    if (states[1] == true || states[3] == true) {
      return VpnProtocol.openVpn;
    }
    if (_retainedProtectionProtocol case final protocol?) return protocol;
    if (_disconnectUnconfirmed) {
      return states[0] == null || states[2] == null
          ? VpnProtocol.wireGuard
          : VpnProtocol.openVpn;
    }
    return null;
  }

  Future<void> _disconnectProtocol(VpnProtocol protocol) async {
    final area = protocol == VpnProtocol.wireGuard ? 'wireguard' : 'openvpn';
    await DiagnosticLog.record(area: area, event: 'disconnect_started');
    try {
      switch (protocol) {
        case VpnProtocol.openVpn:
          await _openVpn.disconnect();
          break;
        case VpnProtocol.wireGuard:
          await _wireguard.disconnect();
          break;
      }
      if (_retainedProtectionProtocol == protocol) {
        _retainedProtectionProtocol = null;
      }
      await DiagnosticLog.record(area: area, event: 'disconnect_acknowledged');
    } on PlatformException catch (error) {
      // The broker publishes its status before writing the IPC response. A
      // lost response must not turn a completed disconnection into a GUI
      // error.
      if (await _recoverNativeDisconnection(protocol)) {
        await DiagnosticLog.record(
          area: area,
          event: 'disconnect_state_recovered',
        );
        return;
      }
      await DiagnosticLog.record(
        area: area,
        event: 'disconnect_failed',
        code: error.code,
      );
      rethrow;
    } catch (_) {
      if (await _recoverNativeDisconnection(protocol)) {
        await DiagnosticLog.record(
          area: area,
          event: 'disconnect_state_recovered',
        );
        return;
      }
      await DiagnosticLog.record(
        area: area,
        event: 'disconnect_failed',
        code: 'unexpected_error',
      );
      rethrow;
    }
  }

  /// Refuses to request a tunnel configuration for a location that the API has
  /// not yet confirmed for this logical device.
  Future<bool> _ensureSelectedLocationMatchesDevice({int? operationId}) async {
    final desired = _requestedLocation;
    if (desired == null || currentDeviceId == null || profile == null) {
      return false;
    }
    await refreshDevices();
    if (!_acceptConnectionOperation(operationId)) return true;
    if (!devicesReachable) {
      errorMessage = 'Impossible de vérifier l’emplacement de cet appareil.';
      notifyListeners();
      return true;
    }
    final device = _currentDevice;
    if (device == null) return false;
    final deviceLocation = device.location;
    if (deviceLocation == null) {
      // Browser extensions and other account entries can have no VPN
      // location. That is missing metadata, not a failed device request.
      final migration = locationMigration;
      if (migration != null && migration.targetLocationId == desired.id) {
        locationMigrationMessage ??= 'Changement de serveur en cours…';
        _scheduleLocationMigrationPoll(migration.retryAfterSeconds);
        errorMessage = locationMigrationMessage;
        notifyListeners();
        return true;
      }
      final marker = await _safe(_store.locationMigration());
      if (marker != null &&
          marker.userId == profile!.userId &&
          marker.deviceId == device.deviceId) {
        pendingTargetLocation =
            locations
                .where((item) => item.id == marker.targetLocationId)
                .firstOrNull ??
            desired;
        _migrationReconnectProtocol = VpnProtocol.openVpn;
        errorMessage =
            'Le changement de serveur est en cours. Réessayez dans quelques instants.';
        await _resumeStoredLocationMigration(operationId: operationId);
        notifyListeners();
        return true;
      }
      errorMessage = null;
      notifyListeners();
      return false;
    }
    realDeviceLocation = deviceLocation;
    if (deviceLocation.id == desired.id) return false;
    final migration = locationMigration;
    if (migration != null && migration.targetLocationId == desired.id) {
      locationMigrationMessage ??= 'Changement de serveur en cours…';
      _scheduleLocationMigrationPoll(migration.retryAfterSeconds);
      errorMessage = locationMigrationMessage;
    } else {
      final marker = await _safe(_store.locationMigration());
      if (marker != null &&
          marker.userId == profile!.userId &&
          marker.deviceId == device.deviceId) {
        pendingTargetLocation =
            locations
                .where((item) => item.id == marker.targetLocationId)
                .firstOrNull ??
            desired;
        _migrationReconnectProtocol = VpnProtocol.openVpn;
        errorMessage =
            'Le changement de serveur est en cours. Réessayez dans quelques instants.';
        await _resumeStoredLocationMigration(operationId: operationId);
      } else {
        // The user selected this destination while disconnected. Connecting
        // is the explicit confirmation: start the migration now and reconnect
        // OpenVPN only after the API confirms `ready`.
        pendingTargetLocation = desired;
        errorMessage = null;
        await _startPreparedLocationMigration(
          connectWhenReady: true,
          operationId: operationId,
          reconnectProtocol: VpnProtocol.openVpn,
        );
      }
    }
    notifyListeners();
    return true;
  }

  Future<void> retryAfterIdentityReset() => _runConnectionCommand(
    _retryAfterIdentityReset,
    initialState: VpnStatus.preparing,
  );

  Future<void> _retryAfterIdentityReset(int operationId) async {
    if (vpnProtocol != VpnProtocol.wireGuard) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage =
          'Sélectionnez WireGuard pour renouveler une identité WireGuard.';
      notifyListeners();
      return;
    }
    final activeProfile = profile;
    final token = await _safe(_store.token());
    if (activeProfile == null || token == null || _requestedLocation == null) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = 'Connectez-vous à votre compte avant de vous connecter.';
      notifyListeners();
      return;
    }

    errorMessage = null;
    deviceEnrollmentIssue = null;
    notifyListeners();
    if (!await _prepareConnectionNetworkProtection(
      VpnProtocol.wireGuard,
      operationId: operationId,
    )) {
      return;
    }
    await DiagnosticLog.record(
      area: 'wireguard',
      event: 'identity_reset_started',
    );
    try {
      // Stop, erase and recreate inside one privileged native request. The UI
      // never observes or attempts to use a half-reset identity.
      await _wireguard.recreateIdentityForAccount(activeProfile.userId);
      if (!_acceptConnectionOperation(operationId)) return;
      await _forgetCurrentDeviceBinding();
      await _enrollAndConnect(
        token,
        identityWasReset: true,
        operationId: operationId,
      );
      if (_acceptConnectionOperation(operationId) &&
          vpnStatus != VpnStatus.connected) {
        await _restoreRetainedNetworkProtection(operationId: operationId);
      }
    } on PlatformException catch (error) {
      if (!_transitionConnection(operationId, VpnStatus.error)) return;
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'identity_reset_failed',
        code: error.code,
      );
      errorMessage =
          'L’identité VPN de cet appareil n’a pas pu être réinitialisée.';
      await _restoreRetainedNetworkProtection(operationId: operationId);
    } catch (_) {
      if (!_transitionConnection(operationId, VpnStatus.error)) return;
      errorMessage =
          'L’identité VPN de cet appareil n’a pas pu être réinitialisée.';
      await _restoreRetainedNetworkProtection(operationId: operationId);
    } finally {
      notifyListeners();
    }
  }

  Future<void> _startDeviceConnection({
    required bool identityWasReset,
    bool skipLocationMigrationCheck = false,
    VpnProtocol? forcedProtocol,
    int? operationId,
  }) async {
    _ignoreConnectivityEvents(const Duration(seconds: 12));
    final token = await _safe(_store.token());
    if (!_acceptConnectionOperation(operationId)) return;
    // A location switch may begin by stopping the previous tunnel. Its
    // enrollment/recovery result belongs to the new connection attempt.
    if (_diagnosticOperation != 'renew') _diagnosticOperation = 'connect';
    if (profile == null || token == null) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = 'Connectez-vous à votre compte avant de vous connecter.';
      notifyListeners();
      return;
    }
    if (_requestedLocation == null) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = 'Choisissez un emplacement avant de vous connecter.';
      notifyListeners();
      return;
    }
    final automaticAttempt =
        forcedProtocol == null &&
        protocolPreference == VpnProtocolPreference.automatic;
    final resolvedProtocol = _protocolForConnection(
      forcedProtocol: forcedProtocol,
    );
    if (resolvedProtocol == null) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage =
          'Aucun protocole compatible n’est disponible sur cet emplacement.';
      notifyListeners();
      return;
    }
    vpnProtocol = resolvedProtocol;
    if (isLocationMigrationActive) {
      if (vpnProtocol == VpnProtocol.openVpn &&
          vpnStatus == VpnStatus.disconnected) {
        _migrationReconnectProtocol = VpnProtocol.openVpn;
      }
      errorMessage =
          locationMigrationMessage ?? 'Changement de serveur en cours…';
      _transitionConnection(operationId, VpnStatus.disconnected);
      notifyListeners();
      return;
    }
    if (!_requestedLocation!.supportedProtocols.contains(vpnProtocol)) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = vpnProtocol == VpnProtocol.openVpn
          ? 'OpenVPN n’est pas encore disponible sur cet emplacement.'
          : 'Ce protocole n’est pas disponible sur cet emplacement.';
      notifyListeners();
      return;
    }
    if (vpnProtocol == VpnProtocol.openVpn && !openVpnRuntimeAvailable) {
      _transitionConnection(operationId, VpnStatus.error);
      _setOpenVpnIssue(
        DeviceEnrollmentIssueKind.openVpnSignerUnavailable,
        'Le composant OpenVPN intégré n’a pas pu être préparé sur cet ordinateur. Fermez puis rouvrez FuzeVPN et acceptez la demande Windows.',
      );
      notifyListeners();
      return;
    }
    final subscriptionEpoch = _sessionEpoch;
    final subscriptionUserId = profile?.userId;
    if (!await _checkSubscriptionBeforeConnection(
      token,
      operationId: operationId,
    )) {
      _finishAbandonedSubscriptionPreflight(operationId);
      return;
    }
    if (!_isCurrentSession(subscriptionEpoch, subscriptionUserId) ||
        !_acceptConnectionOperation(operationId)) {
      _finishAbandonedSubscriptionPreflight(operationId);
      return;
    }
    if (!await _prepareConnectionNetworkProtection(
      vpnProtocol,
      operationId: operationId,
    )) {
      return;
    }
    if (vpnProtocol == VpnProtocol.openVpn &&
        !skipLocationMigrationCheck &&
        await _ensureSelectedLocationMatchesDevice(operationId: operationId)) {
      if (!_acceptConnectionOperation(operationId)) return;
      if (vpnStatus == VpnStatus.connected) {
        notifyListeners();
        return;
      }
      if (!await _restoreRetainedNetworkProtection(
            operationId: operationId,
            message:
                locationMigrationError ??
                errorMessage ??
                'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.',
          ) &&
          (vpnStatus == VpnStatus.preparing ||
              vpnStatus == VpnStatus.disconnecting)) {
        _transitionConnection(operationId, VpnStatus.disconnected);
      }
      notifyListeners();
      return;
    }
    if (!_acceptConnectionOperation(operationId)) return;
    errorMessage = null;
    deviceEnrollmentIssue = null;
    notifyListeners();
    final diagnosticArea = vpnProtocol == VpnProtocol.wireGuard
        ? 'wireguard'
        : 'openvpn';
    await DiagnosticLog.record(
      area: diagnosticArea,
      event: 'connection_started',
    );
    try {
      if (vpnProtocol == VpnProtocol.wireGuard) {
        // Stop only a tunnel that is actually active. Calling the inactive
        // OpenVPN bridge here left the next WireGuard connection waiting on
        // an unrelated native teardown after a normal disconnect.
        if (activeProtocol == VpnProtocol.openVpn) {
          await _disconnectProtocol(VpnProtocol.openVpn);
        }
        _automaticWireGuardFallbackAllowed = false;
        await _enrollAndConnect(
          token,
          identityWasReset: identityWasReset,
          operationId: operationId,
        );
        if (automaticAttempt &&
            _acceptConnectionOperation(operationId) &&
            vpnStatus != VpnStatus.connected &&
            _automaticWireGuardFallbackAllowed &&
            openVpnRuntimeAvailable &&
            _requestedLocation!.supportedProtocols.contains(
              VpnProtocol.openVpn,
            )) {
          // A native WireGuard startup failure is the only automatic fallback
          // case. API, account and device errors must remain visible as-is.
          _automaticWireGuardFallbackAllowed = false;
          if (!_acceptConnectionOperation(operationId)) return;
          vpnProtocol = VpnProtocol.openVpn;
          _transitionConnection(operationId, VpnStatus.preparing);
          errorMessage = null;
          deviceEnrollmentIssue = null;
          notifyListeners();
          await _enrollAndConnectOpenVpn(token, operationId: operationId);
        }
      } else {
        // The active tunnel was already stopped by the Disconnect action.
        // Do not send a second stop request to the other native engine on a
        // later connection attempt.
        if (activeProtocol == VpnProtocol.wireGuard) {
          await _disconnectProtocol(VpnProtocol.wireGuard);
        }
        await _enrollAndConnectOpenVpn(token, operationId: operationId);
      }
      if (_acceptConnectionOperation(operationId) &&
          vpnStatus != VpnStatus.connected) {
        await _restoreRetainedNetworkProtection(operationId: operationId);
      }
    } on PlatformException catch (error) {
      // Stopping the other native tunnel is part of every protocol switch. If
      // that privileged operation fails, never leave the UI in a permanent
      // `connecting` state: the next user attempt must start from a clean,
      // explicit error state.
      if (!_transitionConnection(operationId, VpnStatus.error)) return;
      await DiagnosticLog.recordFailure(
        area: diagnosticArea,
        event: 'connection_failed',
        error: error,
      );
      errorMessage = vpnProtocol == VpnProtocol.openVpn
          ? _openVpnPlatformErrorMessage(error.code)
          : _wireGuardPlatformErrorMessage(error.code);
      await _restoreRetainedNetworkProtection(operationId: operationId);
    } catch (_) {
      if (!_transitionConnection(operationId, VpnStatus.error)) return;
      await DiagnosticLog.record(
        area: diagnosticArea,
        event: 'connection_failed',
        code: 'unexpected_error',
      );
      errorMessage = vpnProtocol == VpnProtocol.openVpn
          ? 'Le tunnel OpenVPN n’a pas pu être démarré.'
          : _wireGuardPlatformErrorMessage('unexpected_error');
      await _restoreRetainedNetworkProtection(operationId: operationId);
    }
    notifyListeners();
  }

  Future<void> _enrollAndConnect(
    String token, {
    required bool identityWasReset,
    bool allowOpenVpnProfileRelease = true,
    int? operationId,
  }) async {
    var nativeConnectAttempted = false;
    if (!_acceptConnectionOperation(operationId)) return;
    _invalidateDeviceSnapshots();
    _nativeConnectionFailure = null;
    await DiagnosticLog.record(
      area: 'wireguard',
      event: 'device_enrollment_started',
    );
    try {
      // The native bridge creates and retains the private key. Dart receives
      // the public key only, then asks the API for a short, complete tunnel
      // configuration for the selected location.
      final publicKey = await _wireguard.getOrCreatePublicKey(
        accountId: profile!.userId,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'local_identity_ready',
      );
      final registration = await _registerDevice(
        token: token,
        publicKey: publicKey,
      );
      final configuration = registration.configuration;
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'api_configuration_received',
      );
      currentDeviceId = configuration.deviceId;
      await _store.saveCurrentDeviceId(configuration.deviceId);
      realDeviceLocation = _requestedLocation;
      nativeConnectAttempted = true;
      if (!_transitionConnection(operationId, VpnStatus.connecting)) return;
      notifyListeners();
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'native_connect_started',
      );
      // If a native attempt fails ambiguously, its cache may already contain
      // the new destination. Only a confirmed success can attest it again.
      _knownTunnelLocationIds.remove(VpnProtocol.wireGuard);
      await _wireguard.connect(configuration);
      if (!_acceptConnectionOperation(operationId)) return;
      // The native connect call returns success only after Windows reports the
      // WireGuard service running and the requested protections are active.
      // A second SCM query from the unelevated UI can briefly be denied even
      // though that confirmed tunnel is already carrying traffic.
      _markNativeConnected(VpnProtocol.wireGuard, operationId: operationId);
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'native_connect_acknowledged',
      );
    } on ApiException catch (error) {
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.recordFailure(
        area: 'wireguard',
        event: 'api_enrollment_failed',
        error: error,
        stage: 'enrollment',
      );
      if (error.statusCode == HttpStatus.conflict &&
          error.errorCode == 'device_identity_revoked' &&
          !identityWasReset &&
          await _recreateWireGuardIdentityForRecovery(
            operationId: operationId,
          )) {
        await _enrollAndConnect(
          token,
          identityWasReset: true,
          operationId: operationId,
        );
        return;
      }
      if (allowOpenVpnProfileRelease &&
          error.statusCode == HttpStatus.conflict &&
          error.errorCode == 'device_location_locked' &&
          await _releaseOpenVpnProfileForWireGuard(token)) {
        await _enrollAndConnect(
          token,
          identityWasReset: identityWasReset,
          allowOpenVpnProfileRelease: false,
          operationId: operationId,
        );
        return;
      }
      await _handleDeviceEnrollmentError(
        error,
        identityWasReset: identityWasReset,
        operationId: operationId,
      );
    } on PlatformException catch (error) {
      if (nativeConnectAttempted &&
          error.code != 'runtime_owned_by_another_user' &&
          await _recoverNativeConnection(
            VpnProtocol.wireGuard,
            operationId: operationId,
          )) {
        await DiagnosticLog.record(
          area: 'wireguard',
          event: 'native_state_recovered',
          code: error.code,
        );
        return;
      }
      if (!_acceptConnectionOperation(operationId)) return;
      _recordNativeConnectionFailure(operationId, error.code);
      await DiagnosticLog.recordFailure(
        area: 'wireguard',
        event: 'native_connect_failed',
        error: error,
      );
      _automaticWireGuardFallbackAllowed =
          error.code != 'runtime_owned_by_another_user';
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = _wireGuardPlatformErrorMessage(error.code);
    } catch (_) {
      if (nativeConnectAttempted &&
          await _recoverNativeConnection(
            VpnProtocol.wireGuard,
            operationId: operationId,
          )) {
        await DiagnosticLog.record(
          area: 'wireguard',
          event: 'native_state_recovered',
          code: 'unexpected_error',
        );
        return;
      }
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'native_connect_failed',
        code: 'unexpected_error',
      );
      _automaticWireGuardFallbackAllowed = true;
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = _wireGuardPlatformErrorMessage('unexpected_error');
    }
  }

  Future<bool> _recreateWireGuardIdentityForRecovery({int? operationId}) async {
    if (!_acceptConnectionOperation(operationId) || profile == null) {
      return false;
    }
    await DiagnosticLog.record(
      area: 'wireguard',
      event: 'identity_reset_started',
      code: 'automatic_revocation_recovery',
    );
    try {
      await _wireguard.recreateIdentityForAccount(profile!.userId);
      if (!_acceptConnectionOperation(operationId)) return false;
      await _forgetCurrentDeviceBinding();
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'identity_reset_completed',
      );
      return true;
    } on PlatformException catch (error) {
      await DiagnosticLog.recordFailure(
        area: 'wireguard',
        event: 'identity_reset_failed',
        error: error,
      );
      return false;
    } catch (_) {
      await DiagnosticLog.record(
        area: 'wireguard',
        event: 'identity_reset_failed',
        code: 'unexpected_error',
      );
      return false;
    }
  }

  /// The API keeps a logical device count of one, but an old OpenVPN
  /// credential must be revoked before WireGuard can use its fast direct node
  /// update. This never resets or exposes the WireGuard identity and retries
  /// enrollment at most once.
  Future<bool> _releaseOpenVpnProfileForWireGuard(String token) async {
    final deviceId = currentDeviceId;
    if (deviceId == null || deviceId.isEmpty) return false;
    try {
      await _disconnectProtocol(VpnProtocol.openVpn);
      await _api.revokeOpenVpnProfile(token: token, deviceId: deviceId);
      await _openVpn.deleteProfile();
      return true;
    } on ApiException catch (error) {
      if (error.isUnauthorized) {
        await _expireLocalSession();
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  Future<({DeviceConfiguration configuration, bool requestedDualStack})>
  _registerDevice({required String token, required String publicKey}) async {
    final target = _requestedLocation!;
    final requestDualStack =
        (currentDeviceId == null || currentDeviceId!.isEmpty) &&
        target.supportsIpv6;
    final requestedFamilies = requestDualStack ? dualStackIpFamilies : null;
    try {
      final configuration = await _api.registerDevice(
        token: token,
        name: await _deviceName(),
        publicKey: publicKey,
        locationId: target.id,
        ipFamilies: requestedFamilies,
      );
      return (
        configuration: configuration,
        requestedDualStack: requestDualStack,
      );
    } on ApiException catch (error) {
      if (!requestDualStack ||
          error.statusCode != HttpStatus.serviceUnavailable ||
          error.errorCode != 'ipv6_unavailable') {
        rethrow;
      }
      await DiagnosticLog.record(
        area: 'network',
        event: 'ipv6_enrollment_fallback',
        code: 'ipv6_unavailable',
      );
      final configuration = await _api.registerDevice(
        token: token,
        name: await _deviceName(),
        publicKey: publicKey,
        locationId: target.id,
      );
      return (configuration: configuration, requestedDualStack: false);
    }
  }

  Future<({String deviceId, List<IpFamily>? profileIpFamilies})>
  _ensureLogicalDevice(String token) async {
    final existingId = currentDeviceId;
    if (existingId != null && existingId.isNotEmpty) {
      return (deviceId: existingId, profileIpFamilies: null);
    }

    // The existing WireGuard registration creates the one logical device.
    // It is deliberately not connected here: OpenVPN will use its profile on
    // this exact device, preserving the global two-device limit.
    _invalidateDeviceSnapshots();
    final publicKey = await _wireguard.getOrCreatePublicKey(
      accountId: profile!.userId,
    );
    final registration = await _registerDevice(
      token: token,
      publicKey: publicKey,
    );
    final configuration = registration.configuration;
    currentDeviceId = configuration.deviceId;
    await _store.saveCurrentDeviceId(configuration.deviceId);
    realDeviceLocation = _requestedLocation;
    return (
      deviceId: configuration.deviceId,
      profileIpFamilies: registration.requestedDualStack
          ? dualStackIpFamilies
          : null,
    );
  }

  Future<void> _enrollAndConnectOpenVpn(
    String token, {
    bool identityWasReset = false,
    int? operationId,
  }) async {
    var nativeConnectAttempted = false;
    if (!_acceptConnectionOperation(operationId)) return;
    _nativeConnectionFailure = null;
    // Automatic WireGuard fallback changes the WFP owner before any OpenVPN
    // control-plane request. The native swap keeps all non-FuzeVPN traffic
    // blocked while this process obtains the replacement activation profile.
    if (killSwitchEnabled &&
        _retainedProtectionProtocol != VpnProtocol.openVpn &&
        !await _prepareConnectionNetworkProtection(
          VpnProtocol.openVpn,
          operationId: operationId,
        )) {
      return;
    }
    await DiagnosticLog.record(
      area: 'openvpn',
      event: 'profile_enrollment_started',
    );
    try {
      final logicalDevice = await _ensureLogicalDevice(token);
      final deviceId = logicalDevice.deviceId;
      if (!_acceptConnectionOperation(operationId)) return;
      final csrPem = await _openVpn.getOrCreateCsr(
        accountId: profile!.userId,
        deviceId: deviceId,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'local_identity_ready',
      );
      final activation = await _createReadyOpenVpnProfile(
        token: token,
        deviceId: deviceId,
        csrPem: csrPem,
        ipFamilies: logicalDevice.profileIpFamilies,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'api_activation_received',
      );
      nativeConnectAttempted = true;
      if (!_transitionConnection(operationId, VpnStatus.connecting)) return;
      notifyListeners();
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'native_connect_started',
      );
      _knownTunnelLocationIds.remove(VpnProtocol.openVpn);
      await _openVpn.importAndConnect(activation);
      if (!_acceptConnectionOperation(operationId)) return;
      // importAndConnect succeeds only after OpenVPN Core emitted CONNECTED,
      // installed network protection and imported the identity atomically.
      // Do not turn that confirmation into a false GUI error with an immediate
      // second IPC query while the broker is rotating its pipe instance.
      _markNativeConnected(VpnProtocol.openVpn, operationId: operationId);
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'native_connect_acknowledged',
      );
    } on ApiException catch (error) {
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.recordFailure(
        area: 'openvpn',
        event: 'api_enrollment_failed',
        error: error,
        stage: 'enrollment',
      );
      if (error.statusCode == HttpStatus.conflict &&
          error.errorCode == 'device_identity_revoked' &&
          !identityWasReset &&
          await _recreateWireGuardIdentityForRecovery(
            operationId: operationId,
          )) {
        // A remote device removal invalidates the shared logical-device
        // identity. Remove the old OpenVPN material before creating the new
        // device and CSR, then retry the same protocol once.
        await _safe<void>(_openVpn.deleteProfile());
        await _enrollAndConnectOpenVpn(
          token,
          identityWasReset: true,
          operationId: operationId,
        );
        return;
      }
      await _handleOpenVpnError(
        error,
        identityWasReset: identityWasReset,
        operationId: operationId,
      );
    } on PlatformException catch (error) {
      if (nativeConnectAttempted &&
          error.code != 'runtime_owned_by_another_user' &&
          await _recoverNativeConnection(
            VpnProtocol.openVpn,
            operationId: operationId,
          )) {
        await DiagnosticLog.record(
          area: 'openvpn',
          event: 'native_state_recovered',
          code: error.code,
        );
        return;
      }
      if (!_acceptConnectionOperation(operationId)) return;
      _recordNativeConnectionFailure(operationId, error.code);
      await DiagnosticLog.recordFailure(
        area: 'openvpn',
        event: 'native_connect_failed',
        error: error,
      );
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = _openVpnPlatformErrorMessage(error.code);
    } catch (_) {
      if (nativeConnectAttempted &&
          await _recoverNativeConnection(
            VpnProtocol.openVpn,
            operationId: operationId,
          )) {
        await DiagnosticLog.record(
          area: 'openvpn',
          event: 'native_state_recovered',
          code: 'unexpected_error',
        );
        return;
      }
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'native_connect_failed',
        code: 'unexpected_error',
      );
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = 'Le tunnel OpenVPN n’a pas pu être démarré.';
    }
  }

  /// The target OpenVPN agent polls periodically. If the API has committed the
  /// profile but has not received the target acknowledgement yet, retry the
  /// exact same CSR a bounded number of times. This is idempotent and never
  /// regenerates or exposes the native private key.
  Future<OpenVpnActivation> _createReadyOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    try {
      return await _createOpenVpnProfileWithPendingRetries(
        token: token,
        deviceId: deviceId,
        csrPem: csrPem,
        ipFamilies: ipFamilies,
      );
    } on ApiException catch (error) {
      if (ipFamilies == null ||
          error.statusCode != HttpStatus.serviceUnavailable ||
          error.errorCode != 'ipv6_unavailable') {
        rethrow;
      }
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'ipv6_profile_fallback',
        code: 'ipv6_unavailable',
      );
      return _createOpenVpnProfileWithPendingRetries(
        token: token,
        deviceId: deviceId,
        csrPem: csrPem,
      );
    }
  }

  Future<OpenVpnActivation> _createOpenVpnProfileWithPendingRetries({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    const maxAttempts = 3;
    for (var attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await _api.createOpenVpnProfile(
          token: token,
          deviceId: deviceId,
          csrPem: csrPem,
          ipFamilies: ipFamilies,
        );
      } on ApiException catch (error) {
        if (error.statusCode != HttpStatus.conflict ||
            error.errorCode != 'openvpn_operation_pending' ||
            attempt == maxAttempts) {
          rethrow;
        }
        final seconds = (error.retryAfterSeconds ?? 2).clamp(0, 10);
        await Future<void>.delayed(Duration(seconds: seconds));
      }
    }
    throw const ApiException(
      statusCode: 409,
      errorCode: 'openvpn_operation_pending',
    );
  }

  Future<void> renewOpenVpnProfile() {
    final wasConnected = vpnStatus == VpnStatus.connected;
    return _runConnectionCommand(
      _renewOpenVpnProfile,
      initialState: wasConnected
          ? VpnStatus.disconnecting
          : VpnStatus.preparing,
    );
  }

  Future<void> _renewOpenVpnProfile(int operationId) async {
    final token = await _safe(_store.token());
    if (!_acceptConnectionOperation(operationId)) return;
    _diagnosticOperation = 'renew';
    final deviceId = currentDeviceId;
    if (token == null || profile == null || deviceId == null) {
      _transitionConnection(operationId, VpnStatus.error);
      errorMessage = 'Connectez-vous avant de renouveler le profil OpenVPN.';
      notifyListeners();
      return;
    }
    final protocolToStop = activeProtocol ?? _retainedProtectionProtocol;
    var nativeConnectAttempted = false;
    try {
      // Renewal is another connection attempt: arm the OpenVPN-owned policy
      // before stopping an existing tunnel or contacting the control plane.
      // When OpenVPN already owns WFP, suspend its runtime without releasing
      // the freshly prepared filters. A WireGuard stop cannot release them
      // after the atomic owner transfer to OpenVPN.
      if (!await _prepareConnectionNetworkProtection(
        VpnProtocol.openVpn,
        operationId: operationId,
      )) {
        return;
      }
      if (killSwitchEnabled) {
        if (protocolToStop == VpnProtocol.wireGuard) {
          await _disconnectProtocol(VpnProtocol.wireGuard);
        } else if (protocolToStop == VpnProtocol.openVpn) {
          await _openVpn.suspendForMigration();
        }
      } else {
        await _disconnectActiveTunnel();
      }
      if (!_acceptConnectionOperation(operationId)) return;
      if (!_transitionConnection(operationId, VpnStatus.disconnected)) return;
      activeProtocol = null;
      tunnelLocationId = null;
      connectedAt = null;
      if (!_transitionConnection(operationId, VpnStatus.preparing)) return;
      final csrPem = await _openVpn.renewCsr(
        accountId: profile!.userId,
        deviceId: deviceId,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      final activation = await _api.renewOpenVpnProfile(
        token: token,
        deviceId: deviceId,
        csrPem: csrPem,
      );
      if (!_acceptConnectionOperation(operationId)) return;
      nativeConnectAttempted = true;
      if (!_transitionConnection(operationId, VpnStatus.connecting)) return;
      _knownTunnelLocationIds.remove(VpnProtocol.openVpn);
      await _openVpn.importAndConnect(activation);
      if (!_acceptConnectionOperation(operationId)) return;
      _markNativeConnected(VpnProtocol.openVpn, operationId: operationId);
    } on ApiException catch (error) {
      if (!_acceptConnectionOperation(operationId)) return;
      await DiagnosticLog.recordFailure(
        area: 'openvpn',
        event: 'certificate_renewal_failed',
        error: error,
        stage: 'certificate_renewal',
      );
      _diagnosticCandidate = _apiFailureDiagnostic(
        error,
        operation: 'renew',
        stage: 'certificate_renewal',
      );
      await _handleOpenVpnError(error, operationId: operationId);
    } on PlatformException catch (error) {
      if (nativeConnectAttempted &&
          error.code != 'runtime_owned_by_another_user' &&
          await _recoverNativeConnection(
            VpnProtocol.openVpn,
            operationId: operationId,
          )) {
        return;
      }
      if (!_transitionConnection(operationId, VpnStatus.error)) return;
      await DiagnosticLog.recordFailure(
        area: 'openvpn',
        event: 'certificate_renewal_failed',
        error: error,
      );
      errorMessage = error.code == 'runtime_owned_by_another_user'
          ? _otherSessionMessage
          : error.code == 'openvpn_signer_unavailable'
          ? 'Le composant OpenVPN sécurisé n’est pas disponible.'
          : 'Le profil OpenVPN n’a pas pu être renouvelé.';
    } catch (_) {
      if (nativeConnectAttempted &&
          await _recoverNativeConnection(
            VpnProtocol.openVpn,
            operationId: operationId,
          )) {
        return;
      }
      if (!_transitionConnection(operationId, VpnStatus.error)) return;
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'certificate_renewal_failed',
        code: 'unexpected_error',
      );
      errorMessage = 'Le profil OpenVPN n’a pas pu être renouvelé.';
    } finally {
      if (_acceptConnectionOperation(operationId) &&
          vpnStatus != VpnStatus.connected) {
        await _restoreRetainedNetworkProtection(
          operationId: operationId,
          message:
              'Le renouvellement OpenVPN a échoué. Le kill switch bloque toujours le trafic réseau.',
        );
      }
      notifyListeners();
    }
  }

  bool _markNativeConnected(
    VpnProtocol protocol, {
    int? operationId,
    bool cached = false,
  }) {
    if (!_transitionConnection(operationId, VpnStatus.connected)) return false;
    _runtimeInteractionStarted = true;
    _clearRuntimeVerification();
    _disconnectUnconfirmed = false;
    activeProtocol = protocol;
    _retainedProtectionProtocol = null;
    if (!cached && _requestedLocation != null) {
      _knownTunnelLocationIds[protocol] = _requestedLocation!.id;
    }
    tunnelLocationId = _knownTunnelLocationIds[protocol];
    _consecutiveHealthFailures = 0;
    _tunnelHealthUnconfirmed = false;
    connectedAt = _now();
    _recordRecentLocation(tunnelLocationId);
    errorMessage = null;
    deviceEnrollmentIssue = null;
    _ignoreConnectivityEvents(const Duration(seconds: 12));
    return true;
  }

  String _wireGuardPlatformErrorMessage(String code) => switch (code) {
    'installation_required' =>
      'Installez FuzeVPN dans un dossier protégé pour activer le VPN.',
    'runtime_owned_by_another_user' => _otherSessionMessage,
    'key_unavailable' =>
      'L’identité WireGuard locale est indisponible. Ouvrez Appareils pour renouveler uniquement cet appareil.',
    'storage_failure' =>
      'Windows n’a pas pu ouvrir le stockage protégé de WireGuard.',
    'permission_denied' =>
      'Windows n’a pas autorisé l’opération WireGuard demandée.',
    'broker_unavailable' =>
      'Le service VPN local est indisponible. Fermez puis rouvrez FuzeVPN.',
    'broker_write_failed' =>
      'La commande WireGuard n’a pas pu être transmise au service VPN local.',
    'broker_response_timeout' =>
      'Le service WireGuard local n’a pas confirmé l’opération dans le délai prévu.',
    'broker_protocol_error' =>
      'La réponse du service WireGuard local était invalide.',
    'invalid_configuration' =>
      'La configuration WireGuard reçue de l’API est invalide.',
    'endpoint_resolution_failed' =>
      'Le nom du serveur WireGuard n’a pas pu être résolu. Réessayez lorsque le réseau est disponible.',
    'network_protection_failed' =>
      'Windows n’a pas pu préparer ou finaliser la protection réseau WireGuard.',
    'tunnel_failure' || 'wireguard_start_failed' =>
      'Le service de tunnel WireGuard n’a pas atteint l’état actif.',
    _ =>
      'Une erreur WireGuard non identifiée est survenue. Consultez le journal de diagnostic local.',
  };

  String _openVpnPlatformErrorMessage(String code) => switch (code) {
    'openvpn_dns_configuration_failed' =>
      'Windows n’a pas pu configurer le DNS du tunnel OpenVPN.',
    'openvpn_network_configuration_failed' =>
      'Windows n’a pas pu finaliser la configuration réseau du tunnel OpenVPN.',
    'openvpn_cleanup_failed' =>
      'Le nettoyage du tunnel OpenVPN n’a pas pu être confirmé. Réessayez la déconnexion.',
    'openvpn_stop_timeout' =>
      'L’arrêt du tunnel OpenVPN n’a pas pu être confirmé. La protection reste active. Réessayez la déconnexion.',
    'openvpn_driver_restart_required' =>
      'La mise à niveau du pilote OpenVPN nécessite un redémarrage de Windows. Redémarrez lorsque vous serez prêt.',
    'installation_required' =>
      'Installez FuzeVPN dans un dossier protégé pour activer le VPN.',
    'runtime_owned_by_another_user' => _otherSessionMessage,
    'openvpn_profile_rejected' =>
      'Le profil OpenVPN reçu est invalide sur cet ordinateur.',
    'openvpn_certificate_validation_failed' =>
      'Le certificat du serveur OpenVPN n’a pas pu être vérifié.',
    'openvpn_tls_handshake_failed' =>
      'La négociation sécurisée avec le serveur OpenVPN a échoué.',
    'openvpn_no_server_response' =>
      'Le transport OpenVPN a démarré, mais le serveur n’a pas répondu.',
    'openvpn_dco_peer_failed' =>
      'L’adaptateur DCO est ouvert, mais le serveur n’a pas pu être configuré dans le pilote.',
    'openvpn_core_stalled' =>
      'OpenVPN Core s’est arrêté avant l’ouverture de la connexion réseau.',
    'openvpn_connection_timeout' =>
      'Le serveur OpenVPN n’a pas répondu à temps.',
    'openvpn_adapter_failed' =>
      'L’adaptateur OpenVPN DCO n’a pas pu être utilisé.',
    'openvpn_dco_profile_incompatible' =>
      'Le profil reçu n’est pas compatible avec OpenVPN DCO.',
    'openvpn_client_config_failed' =>
      'OpenVPN Core a refusé la configuration du client.',
    'openvpn_profile_crypto_failed' =>
      'Le matériel de protection du profil OpenVPN est invalide.',
    'openvpn_local_identity_mismatch' =>
      'Le certificat OpenVPN ne correspond pas à l’identité locale de cet appareil.',
    'openvpn_transport_failed' =>
      'OpenVPN n’a pas pu préparer le transport UDP sur cet ordinateur.',
    'openvpn_local_identity_failed' =>
      'L’identité OpenVPN locale n’a pas pu être lue.',
    'openvpn_signer_unavailable' =>
      'Le composant OpenVPN sécurisé n’est pas disponible.',
    'network_protection_failed' =>
      'Windows n’a pas pu préparer ou finaliser la protection réseau OpenVPN.',
    'permission_denied' =>
      'Windows n’a pas autorisé l’opération OpenVPN demandée.',
    'broker_unavailable' =>
      'Le service VPN local est indisponible. Fermez puis rouvrez FuzeVPN.',
    'broker_write_failed' =>
      'La commande OpenVPN n’a pas pu être transmise au service VPN local.',
    'broker_response_timeout' =>
      'Le service OpenVPN local n’a pas confirmé l’opération dans le délai prévu.',
    'broker_protocol_error' =>
      'La réponse du service OpenVPN local était invalide.',
    _ =>
      'Une erreur OpenVPN non identifiée est survenue. Consultez le journal de diagnostic local.',
  };

  bool _markNativeDisconnected({int? operationId}) {
    if (!_transitionConnection(operationId, VpnStatus.disconnected)) {
      return false;
    }
    _clearRuntimeVerification();
    _runtimeInteractionStarted = false;
    activeProtocol = null;
    _retainedProtectionProtocol = null;
    _disconnectUnconfirmed = false;
    _tunnelHealthUnconfirmed = false;
    _consecutiveHealthFailures = 0;
    tunnelLocationId = null;
    connectedAt = null;
    errorMessage = null;
    deviceEnrollmentIssue = null;
    return true;
  }

  /// A privileged tunnel command may complete after its IPC response is lost.
  /// The native broker publishes one non-sensitive status bit per protocol, so
  /// recover that confirmed state instead of displaying a false failure.
  Future<bool> _recoverNativeConnection(
    VpnProtocol protocol, {
    int? operationId,
  }) async {
    for (var attempt = 0; attempt < 8; attempt++) {
      if (!_acceptConnectionOperation(operationId)) return false;
      try {
        final connected = protocol == VpnProtocol.wireGuard
            ? await _wireguard.isConnected()
            : await _openVpn.isConnected();
        if (connected) {
          return _markNativeConnected(
            protocol,
            operationId: operationId,
            cached: true,
          );
        }
      } catch (_) {
        // The broker can be rotating its pipe/status handles. Retry briefly.
      }
      if (attempt < 7) {
        await Future<void>.delayed(const Duration(milliseconds: 150));
      }
    }
    return false;
  }

  Future<bool> _recoverNativeDisconnection(VpnProtocol protocol) async {
    for (var attempt = 0; attempt < 8; attempt++) {
      try {
        final connected = protocol == VpnProtocol.wireGuard
            ? await _wireguard.isConnected()
            : await _openVpn.isConnected();
        final protectionActive = protocol == VpnProtocol.wireGuard
            ? await _wireguard.isNetworkProtectionActive()
            : await _openVpn.isNetworkProtectionActive();
        if (!connected && !protectionActive) {
          if (_retainedProtectionProtocol == protocol) {
            _retainedProtectionProtocol = null;
          }
          return true;
        }
      } catch (_) {
        // The status event can be recreated while the broker is stopping.
      }
      if (attempt < 7) {
        await Future<void>.delayed(const Duration(milliseconds: 150));
      }
    }
    return false;
  }

  Future<void> _handleOpenVpnError(
    ApiException error, {
    bool identityWasReset = false,
    int? operationId,
  }) async {
    if (!_transitionConnection(operationId, VpnStatus.error)) return;
    errorMessage = null;
    switch (error.errorCode) {
      case 'openvpn_profile_exists':
        _setOpenVpnIssue(
          DeviceEnrollmentIssueKind.openVpnProfileExists,
          'Un profil OpenVPN existe déjà pour cet appareil.',
        );
        return;
      case 'openvpn_profile_revoked':
        _setOpenVpnIssue(
          DeviceEnrollmentIssueKind.openVpnProfileRevoked,
          'Le profil OpenVPN a été révoqué. Renouvelez-le pour continuer.',
        );
        return;
      case 'openvpn_operation_pending':
        _setOpenVpnIssue(
          DeviceEnrollmentIssueKind.openVpnOperationPending,
          'La création du profil OpenVPN est en cours. Réessayez dans quelques instants.',
        );
        return;
      case 'openvpn_signer_unavailable':
        _setOpenVpnIssue(
          DeviceEnrollmentIssueKind.openVpnSignerUnavailable,
          'Le service OpenVPN est momentanément indisponible. Réessayez plus tard.',
        );
        return;
      case 'node_unavailable':
        await _handleDeviceEnrollmentError(
          error,
          identityWasReset: identityWasReset,
          operationId: operationId,
        );
        return;
      default:
        await _handleDeviceEnrollmentError(
          error,
          identityWasReset: identityWasReset,
          operationId: operationId,
        );
        return;
    }
  }

  void _setOpenVpnIssue(DeviceEnrollmentIssueKind kind, String message) {
    deviceEnrollmentIssue = DeviceEnrollmentIssue(
      kind: kind,
      title: 'OpenVPN indisponible',
      message: message,
    );
  }

  void _setSubscriptionRequiredIssue() {
    deviceEnrollmentIssue = const DeviceEnrollmentIssue(
      kind: DeviceEnrollmentIssueKind.subscriptionRequired,
      title: 'Abonnement requis',
      message:
          'Le service demande un abonnement pour autoriser cette connexion VPN. Consultez « Mon compte » pour vérifier l’état de votre abonnement.',
    );
  }

  void _clearResolvedSubscriptionIssue(Subscription loaded) {
    if (loaded.status == SubscriptionStatus.unknown ||
        !loaded.hasAccess ||
        deviceEnrollmentIssue?.kind !=
            DeviceEnrollmentIssueKind.subscriptionRequired) {
      return;
    }
    deviceEnrollmentIssue = null;
    if (_diagnosticCandidate?.code == 'subscription_required') {
      _diagnosticCandidate = null;
    }
    if (vpnStatus == VpnStatus.error &&
        errorMessage == null &&
        !requiresExplicitDisconnect &&
        !isConnectionBusy) {
      _transitionConnection(null, VpnStatus.disconnected);
    }
  }

  Future<void> _handleDeviceEnrollmentError(
    ApiException error, {
    required bool identityWasReset,
    int? operationId,
  }) async {
    if (!_transitionConnection(operationId, VpnStatus.error)) return;
    _diagnosticCandidate = _apiFailureDiagnostic(
      error,
      operation: _diagnosticOperation,
      stage: _diagnosticOperation == 'renew'
          ? 'certificate_renewal'
          : 'enrollment',
    );
    errorMessage = null;
    final localMessage = _localApiFailureMessage(error);
    if (localMessage != null) {
      deviceEnrollmentIssue = null;
      errorMessage = localMessage;
      return;
    }
    final capacityIssue = _locationCapacityIssue(error);
    if (capacityIssue != null) {
      deviceEnrollmentIssue = capacityIssue;
      // Renewal addresses the existing device, not a newly selected destination.
      final rejectedLocation = _diagnosticOperation == 'renew'
          ? realDeviceLocation ?? _currentDevice?.location
          : _requestedLocation;
      _refreshAfterCapacityRejection(capacityIssue, rejectedLocation);
      return;
    }
    if (error.isUnauthorized) {
      await _expireLocalSession();
      deviceEnrollmentIssue = const DeviceEnrollmentIssue(
        kind: DeviceEnrollmentIssueKind.sessionExpired,
        title: 'Session expirée',
        message: 'Votre session a expiré. Connectez-vous de nouveau.',
      );
      return;
    }
    switch (error.errorCode) {
      case 'subscription_required'
          when error.statusCode == HttpStatus.forbidden &&
              error.observedHttpStatus == HttpStatus.forbidden:
        _setSubscriptionRequiredIssue();
        return;
      case 'email_verification_required':
        deviceEnrollmentIssue = const DeviceEnrollmentIssue(
          kind: DeviceEnrollmentIssueKind.emailVerificationRequired,
          title: 'Adresse e-mail à confirmer',
          message:
              'Confirmez votre adresse e-mail avant d’ajouter cet appareil VPN.',
        );
        return;
      case 'device_limit':
        await refreshDevices();
        deviceEnrollmentIssue = const DeviceEnrollmentIssue(
          kind: DeviceEnrollmentIssueKind.deviceLimit,
          title: 'Retirez un appareil existant',
          message: 'Retirez un appareil existant avant de vous reconnecter.',
        );
        return;
      case 'device_exists':
        deviceEnrollmentIssue = const DeviceEnrollmentIssue(
          kind: DeviceEnrollmentIssueKind.deviceExists,
          title: 'Identité VPN déjà utilisée',
          message: 'L’identité VPN de ce PC est déjà liée à un autre compte.',
        );
        return;
      case 'device_identity_revoked':
        deviceEnrollmentIssue = identityWasReset
            ? const DeviceEnrollmentIssue(
                kind: DeviceEnrollmentIssueKind.unknown,
                title: 'Connexion impossible',
                message:
                    'La nouvelle identité VPN n’a pas pu être inscrite. Réessayez plus tard.',
              )
            : const DeviceEnrollmentIssue(
                kind: DeviceEnrollmentIssueKind.deviceIdentityRevoked,
                title: 'Identité VPN à renouveler',
                message:
                    'Cette identité VPN a été retirée. Créez-en une nouvelle pour continuer.',
              );
        return;
      case 'node_unavailable':
        deviceEnrollmentIssue = const DeviceEnrollmentIssue(
          kind: DeviceEnrollmentIssueKind.nodeUnavailable,
          title: 'Emplacement indisponible',
          message:
              'Cet emplacement est momentanément indisponible. Choisissez Frankfurt 1 ou Frankfurt 2, ou réessayez plus tard.',
        );
        return;
      case 'rate_limited':
        final retryMessage = error.retryAfterSeconds == null
            ? 'Réessayez dans quelques instants.'
            : 'Réessayez dans ${error.retryAfterSeconds} secondes.';
        deviceEnrollmentIssue = DeviceEnrollmentIssue(
          kind: DeviceEnrollmentIssueKind.rateLimited,
          title: 'Trop de tentatives',
          message: retryMessage,
          retryAfterSeconds: error.retryAfterSeconds,
        );
        return;
      default:
        deviceEnrollmentIssue = const DeviceEnrollmentIssue(
          kind: DeviceEnrollmentIssueKind.unknown,
          title: 'Connexion impossible',
          message:
              'Une connexion VPN n’a pas pu être établie. Réessayez plus tard.',
        );
        return;
    }
  }

  Future<void> _expireLocalSession() async {
    _suspendDiagnostics(purge: false);
    _sessionEpoch++;
    _clearSubscriptionState();
    _sessionValidationPending = false;
    _sessionStorageUnavailable = false;
    _savedSessionVerificationErrorMessage = null;
    _cancelSavedSessionVerificationRetry();
    _cancelAutomaticReconnect();
    _clearLocationMigrationState();
    await _store.clearToken();
    await _store.clearCurrentDeviceId();
    currentDeviceId = null;
    profile = null;
    devices = const [];
    deviceErrorMessage = null;
    section = AppSection.connection;
    _signInPromptPending = true;
  }

  bool isCurrentDevice(VpnDevice device) => device.deviceId == currentDeviceId;

  Future<DeviceRevocationResult> revokeDevice(VpnDevice device) {
    final running = _deviceRevocationCommand;
    if (running != null) return running;
    if (_disposed || _isSigningOut || _isInstallingUpdate) {
      return Future.value(DeviceRevocationResult.failed);
    }
    // Reserve the native lifecycle before reading the token or issuing DELETE.
    _isRevokingCurrentDevice = isCurrentDevice(device);
    final completion = Completer<DeviceRevocationResult>();
    _deviceRevocationCommand = completion.future;
    notifyListeners();
    unawaited(() async {
      try {
        completion.complete(await _revokeDevice(device));
      } catch (error, stackTrace) {
        completion.completeError(error, stackTrace);
      } finally {
        _isRevokingCurrentDevice = false;
        _deviceRevocationCommand = null;
        revokingDeviceId = null;
        if (!_disposed) notifyListeners();
      }
    }());
    return completion.future;
  }

  Future<DeviceRevocationResult> _revokeDevice(VpnDevice device) async {
    final sessionEpoch = _sessionEpoch;
    final userId = profile?.userId;
    final token = await _safe(_store.token());
    if (!_isCurrentSession(sessionEpoch, userId)) {
      return DeviceRevocationResult.failed;
    }
    if (profile == null || token == null) {
      deviceErrorMessage =
          'Connectez-vous à votre compte pour gérer vos appareils.';
      notifyListeners();
      return DeviceRevocationResult.failed;
    }

    revokingDeviceId = device.deviceId;
    deviceErrorMessage = null;
    deviceEnrollmentIssue = null;
    _signInPromptPending = false;
    notifyListeners();
    var remoteRevoked = false;
    try {
      _invalidateDeviceSnapshots();
      await _api.revokeDevice(token: token, deviceId: device.deviceId);
      remoteRevoked = true;
      if (!_isCurrentSession(sessionEpoch, userId)) {
        return DeviceRevocationResult.revoked;
      }
      final revokingCurrentDevice = isCurrentDevice(device);
      var localCleanupFailed = false;
      _invalidateDeviceSnapshots();
      // The server's confirmed outcome cannot be undone by a disk or native
      // cleanup failure. Update the visible account list immediately.
      devices = devices
          .where((item) => item.deviceId != device.deviceId)
          .toList(growable: false);

      Future<void> cleanup(Future<void> Function() action) async {
        try {
          await action();
        } catch (_) {
          localCleanupFailed = true;
        }
      }

      if (revokingCurrentDevice) {
        _cancelAutomaticReconnect();
        final running = _invalidateConnectionOperation(
          state: VpnStatus.disconnecting,
        );
        if (running != null) await _safe<void>(running);
        if (!_isCurrentSession(sessionEpoch, userId)) {
          return DeviceRevocationResult.revoked;
        }
        await cleanup(_disconnectActiveTunnel);
        await cleanup(_wireguard.resetIdentity);
        await cleanup(_openVpn.deleteProfile);
        await _restoreNetworkStateAfterFailedDisconnect(
          activeProtocol,
          expectedSessionEpoch: sessionEpoch,
        );
        if (!_isCurrentSession(sessionEpoch, userId)) {
          return DeviceRevocationResult.revoked;
        }
        currentDeviceId = null;
        realDeviceLocation = null;
        _clearLocationMigrationState();
        await cleanup(_store.clearCurrentDeviceId);
        await cleanup(_store.clearLocationMigration);
      }
      if (localCleanupFailed) {
        deviceErrorMessage =
            'L’accès VPN a été retiré, mais le nettoyage local n’a pas pu être terminé.';
        return DeviceRevocationResult.revokedWithLocalCleanupWarning;
      }
      return DeviceRevocationResult.revoked;
    } catch (_) {
      if (remoteRevoked) {
        if (_isCurrentSession(sessionEpoch, userId)) {
          deviceErrorMessage =
              'L’accès VPN a été retiré, mais le nettoyage local n’a pas pu être terminé.';
        }
        return DeviceRevocationResult.revokedWithLocalCleanupWarning;
      }
      deviceErrorMessage =
          'Cet appareil n’a pas pu être retiré. Vérifiez votre connexion puis réessayez.';
      return DeviceRevocationResult.failed;
    } finally {
      if (_isCurrentSession(sessionEpoch, userId)) {
        revokingDeviceId = null;
        notifyListeners();
      }
    }
  }

  Future<void> signOut() async {
    if (_isSigningOut || _disposed || _isInstallingUpdate) return;
    _isSigningOut = true;
    cancelBrowserSignIn();
    _suspendDiagnostics(purge: true);
    _sessionEpoch++;
    _runtimeVerificationTimer?.cancel();
    _runtimeVerificationTimer = null;
    _clearSubscriptionState();
    _sessionValidationPending = false;
    _sessionStorageUnavailable = false;
    _savedSessionVerificationErrorMessage = null;
    _cancelSavedSessionVerificationRetry();
    _cancelAutomaticReconnect();
    _clearLocationMigrationState();
    try {
      final mayNeedDisconnect =
          requiresExplicitDisconnect ||
          activeProtocol != null ||
          _retainedProtectionProtocol != null ||
          _connectionCommand != null;
      final running = _invalidateConnectionOperation(
        state: _runtimeVerificationPending
            ? VpnStatus.error
            : mayNeedDisconnect
            ? VpnStatus.disconnecting
            : VpnStatus.disconnected,
      );
      if (running != null) await _safe<void>(running);
      final revocation = _deviceRevocationCommand;
      if (revocation != null) await _safe<DeviceRevocationResult>(revocation);
      final protocolToDisconnect = _runtimeVerificationPending
          ? null
          : await _protocolRequiringDisconnect();
      if (protocolToDisconnect != null) {
        try {
          if (_disconnectUnconfirmed) {
            await _disconnectActiveTunnel();
          } else {
            await _disconnectProtocol(protocolToDisconnect);
          }
          _markNativeDisconnected();
        } catch (_) {
          await _restoreNetworkStateAfterFailedDisconnect(protocolToDisconnect);
        }
      } else if (!_runtimeVerificationPending) {
        await _restoreNetworkStateAfterFailedDisconnect(null);
      }
      try {
        // A local sign-in write already in progress must finish before the
        // sign-out clear. Otherwise its late completion could restore a token.
        final writing = _sessionTokenWrite;
        if (writing != null) await _safe<void>(writing);
        await _store.clearToken();
      } catch (_) {
        errorMessage =
            'La session enregistrée n’a pas pu être effacée. Réessayez la déconnexion du compte.';
        return;
      }
      currentDeviceId = null;
      await _safe<void>(_store.clearCurrentDeviceId());
      profile = null;
      devices = const [];
      revokingDeviceId = null;
      isLoadingDevices = false;
      deviceErrorMessage = null;
      deviceEnrollmentIssue = null;
      _signInPromptPending = false;
      realDeviceLocation = null;
    } finally {
      _isSigningOut = false;
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> _restoreNetworkStateAfterFailedDisconnect(
    VpnProtocol? assumedProtocol, {
    int? operationId,
    int? expectedSessionEpoch,
    bool restoringStartupState = false,
  }) async {
    final states = await Future.wait([
      _readNativeState<bool>(
        _wireguard.isConnected(),
        traceStage: 'recovery_wireguard_connected',
      ),
      _readNativeState<bool>(
        _openVpn.isConnected(),
        traceStage: 'recovery_openvpn_connected',
      ),
      _nativeProtectionActive(
        VpnProtocol.wireGuard,
        tracePrefix: 'recovery_wireguard_protection',
      ),
      _nativeProtectionActive(
        VpnProtocol.openVpn,
        tracePrefix: 'recovery_openvpn_protection',
      ),
    ]);
    if (_disposed ||
        !_acceptConnectionOperation(operationId) ||
        (expectedSessionEpoch != null &&
            expectedSessionEpoch != _sessionEpoch)) {
      return;
    }
    final connected = states[0] == true
        ? VpnProtocol.wireGuard
        : states[1] == true
        ? VpnProtocol.openVpn
        : null;
    final protectionOwner = states[2] == true
        ? VpnProtocol.wireGuard
        : states[3] == true
        ? VpnProtocol.openVpn
        : null;
    if (connected != null || protectionOwner != null) {
      _runtimeInteractionStarted = true;
    }
    if (states.every((value) => value == false)) {
      _markNativeDisconnected(operationId: operationId);
      return;
    }
    _retainedProtectionProtocol = protectionOwner;
    _runtimeVerificationPending =
        restoringStartupState &&
        !_runtimeInteractionStarted &&
        connected == null &&
        protectionOwner == null;
    if (!_runtimeVerificationPending) _clearRuntimeVerification();
    _disconnectUnconfirmed =
        (states[0] == true && states[1] == true) ||
        (connected == null &&
            protectionOwner == null &&
            !_runtimeVerificationPending);
    activeProtocol =
        connected ?? (_disconnectUnconfirmed ? assumedProtocol : null);
    vpnStatus = connected != null
        ? VpnStatus.connected
        : protectionOwner != null && _retainedProtectionBlocksTraffic
        ? VpnStatus.blocked
        : VpnStatus.error;
    if (connected == null) {
      tunnelLocationId = null;
      connectedAt = null;
    }
    if (restoringStartupState) {
      errorMessage = _runtimeVerificationPending
          ? _runtimeVerificationFailureMessage
          : connected != null
          ? null
          : protectionOwner != null
          ? _retainedProtectionBlocksTraffic
                ? 'La connexion VPN s’est interrompue. Le kill switch bloque toujours le trafic réseau.'
                : _partialProtectionMessage
          : 'L’état de la protection réseau ne peut pas être confirmé. Déconnectez-vous avant de réessayer.';
    } else {
      errorMessage = connected != null
          ? 'Le tunnel VPN est toujours actif. Réessayez la déconnexion.'
          : protectionOwner != null
          ? _retainedProtectionBlocksTraffic
                ? 'Le kill switch bloque toujours le trafic réseau. Réessayez la déconnexion.'
                : _partialProtectionMessage
          : 'La déconnexion VPN n’a pas pu être confirmée. Réessayez la déconnexion.';
    }
    if (runtimeOwnedByAnotherUser) errorMessage = _otherSessionMessage;
  }

  @override
  void dispose() {
    _disposed = true;
    cancelBrowserSignIn();
    _cancelSavedSessionVerificationRetry();
    _runtimeVerificationTimer?.cancel();
    _runtimeVerificationTimer = null;
    _diagnosticGeneration++;
    _stopDiagnosticObserver();
    diagnostics.removeListener(_onDiagnosticsChanged);
    diagnostics.dispose();
    updates.removeListener(_onUpdateChanged);
    updates.dispose();
    _api.close();
    _invalidateConnectionOperation(state: VpnStatus.disconnected);
    _tunnelHealthTimer?.cancel();
    _tunnelHealthTimer = null;
    _cancelLocationMigrationPolling();
    _cancelAutomaticReconnect();
    if (_windowListenerStarted) {
      _window.stopConnectivityListener();
      _windowListenerStarted = false;
    }
    super.dispose();
  }
}

extension FirstOrNull<T> on Iterable<T> {
  T? get firstOrNull => isEmpty ? null : first;
}
