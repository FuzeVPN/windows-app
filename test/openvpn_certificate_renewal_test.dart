// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';

import 'device_enrollment_error_test.dart' as enrollment;
import 'support/backend_support_vocabulary.dart';

final _now = DateTime.utc(2026, 11, 10, 12);

// The fingerprint the client keeps of a CSR: never the CSR itself.
String _sha256(String csrPem) => sha256.convert(utf8.encode(csrPem)).toString();

const _location = Location(
  id: 'frankfurt-01',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const _user = UserProfile(
  userId: 'user-client',
  email: 'client@example.com',
  firstName: 'Client',
  emailVerified: true,
);
const _killSwitchMessage =
    'La connexion VPN a échoué. Le kill switch bloque toujours le trafic réseau.';
const _certificateNotConfirmed =
    'Le certificat VPN n’est pas confirmé. Réessayez la connexion VPN, puis contactez l’assistance si le problème persiste.';
const _lostAnswer = ApiException(statusCode: 408, errorCode: 'request_timeout');
const _signerUnavailable = ApiException(
  statusCode: 503,
  errorCode: 'openvpn_signer_unavailable',
  observedHttpStatus: 503,
);

class _Clock {
  DateTime value = _now;
  DateTime call() => value;
}

/// The control plane as the server answers it: the device's profile holds
/// the certificate issued for one CSR. Sending that exact CSR again while
/// the certificate is valid replays it for free (exact-CSR recovery); any
/// other creation or renewal counts against the server's limit.
class _RenewalApi extends enrollment.FakeApiClient {
  _RenewalApi(this.clock, {required this.storedNotAfter});

  final _Clock clock;
  String? storedCsr = 'csr-1';
  // The expiry of the stored certificate.
  DateTime storedNotAfter;
  DateTime renewedNotAfter = _now.add(const Duration(days: 365));
  int serial = 1;
  final csrBySerial = <int, String>{1: 'csr-1'};
  int countedCreates = 0;
  int countedRenewals = 0;
  int renewCalls = 0;
  final renewedCsrs = <String>[];
  // Answers given to the next counted renewals, before the server issues
  // anything.
  List<Object> renewFailures = [];
  // Answers given to the next counted creations.
  List<Object> createFailures = [];
  // Answers lost once the server issued the renewal.
  int lostRenewAnswers = 0;
  // Called with each renewal request, before any answer.
  void Function(String csrPem)? onRenew;

  bool get _storedValid => storedNotAfter.isAfter(clock());

  OpenVpnActivation activation(DateTime notAfter) => OpenVpnActivation(
    deviceId: 'device-existing',
    protocol: 'openvpn',
    certificatePem: 'certificate-not-displayed-$serial',
    caCertificatePem: 'ca-not-displayed',
    tlsCryptV2ClientKey: 'tls-key-not-displayed',
    endpoint: '198.51.100.10',
    dns: const ['1.1.1.1'],
    address: '10.20.0.2/24',
    serverName: 'frankfurt-01.openvpn.internal',
    remoteCertTlsServer: true,
    ciphers: const ['AES-256-GCM'],
    notAfter: notAfter,
  );

  String csrOf(OpenVpnActivation value) =>
      csrBySerial[int.parse(value.certificatePem.split('-').last)]!;

  OpenVpnActivation _issue(String csrPem, DateTime notAfter) {
    serial++;
    storedCsr = csrPem;
    csrBySerial[serial] = csrPem;
    storedNotAfter = notAfter;
    return activation(notAfter);
  }

  @override
  Future<UserProfile> me(String token) async => _user;

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    createOpenVpnCalls++;
    receivedCsrs.add(csrPem);
    if (csrPem == storedCsr && _storedValid) {
      return activation(storedNotAfter);
    }
    countedCreates++;
    if (createFailures.isNotEmpty) throw createFailures.removeAt(0);
    if (storedCsr != null) {
      throw const ApiException(
        statusCode: 409,
        errorCode: 'openvpn_profile_exists',
        observedHttpStatus: 409,
      );
    }
    return _issue(csrPem, renewedNotAfter);
  }

  @override
  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    renewCalls++;
    renewedCsrs.add(csrPem);
    onRenew?.call(csrPem);
    if (csrPem == storedCsr && _storedValid) {
      return activation(storedNotAfter);
    }
    countedRenewals++;
    if (renewFailures.isNotEmpty) throw renewFailures.removeAt(0);
    if (csrPem == storedCsr) {
      // The signer returns the certificate it first signed for this CSR,
      // which has expired since: the server stores nothing.
      throw const ApiException(
        statusCode: 409,
        errorCode: 'openvpn_renewal_expired',
        observedHttpStatus: 409,
      );
    }
    final renewed = _issue(csrPem, renewedNotAfter);
    if (lostRenewAnswers > 0) {
      lostRenewAnswers--;
      throw _lostAnswer;
    }
    return renewed;
  }
}

/// The native identity: one active key and at most one pending key. A
/// renewal reuses the pending key until a tunnel connects with its
/// certificate, which promotes it.
class _RenewalOpenVpn extends enrollment.FakeOpenVpnBridge {
  _RenewalOpenVpn(this.server);

  final _RenewalApi server;
  String? activeCsr = 'csr-1';
  String? pendingCsr;
  int _pendingKeys = 0;
  int renewCsrCalls = 0;
  final importedNotAfter = <DateTime>[];
  // The OpenVPN server's verdict on the imported certificate.
  String? Function(OpenVpnActivation activation)? importFailureCode;

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async {
    csrCalls++;
    return activeCsr ??= 'csr-new-${++_pendingKeys}';
  }

  /// A pending key prepared by an earlier process.
  String mintPendingKey() => pendingCsr = 'pending-csr-${++_pendingKeys}';

  @override
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async {
    renewCsrCalls++;
    return pendingCsr ??= 'pending-csr-${++_pendingKeys}';
  }

  @override
  Future<void> deleteProfile() async {
    deleteProfileCalls++;
    activeCsr = null;
    pendingCsr = null;
  }

  @override
  Future<void> suspendForMigration() async => connected = false;

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importedNotAfter.add(activation.notAfter);
    if (importFailureCode?.call(activation) case final code?) {
      importCalls++;
      connected = false;
      throw PlatformException(code: code);
    }
    await super.importAndConnect(activation);
    final csr = server.csrOf(activation);
    if (csr == pendingCsr) {
      activeCsr = csr;
      pendingCsr = null;
    }
  }
}

/// Persists the renewal marker like the protected store does.
class _MarkerStore extends enrollment.FakeSecureStore {
  String? renewalDevice;
  String? renewalCsrSha256;
  final renewalWrites = <String?>[];

  @override
  Future<String?> openVpnRenewalDeviceId() async => renewalDevice;

  @override
  Future<String?> openVpnRenewalCsrSha256() async =>
      renewalDevice == null ? null : renewalCsrSha256;

  @override
  Future<void> saveOpenVpnRenewalDeviceId(
    String deviceId, {
    String? csrSha256,
  }) async {
    renewalDevice = deviceId;
    renewalCsrSha256 = csrSha256;
    renewalWrites.add(deviceId);
  }

  @override
  Future<void> clearOpenVpnRenewalDeviceId() async {
    renewalDevice = null;
    renewalCsrSha256 = null;
    renewalWrites.add(null);
  }
}

/// Every command ends in a state the next command can begin from: checked
/// at every notification that finds no command running, so that a wedge
/// fails the test that produced it rather than a later one.
class _RestingGuard {
  _RestingGuard(this.controller) {
    controller.addListener(_check);
  }

  final AppController controller;
  final violations = <VpnStatus>[];
  static const _resting = {
    VpnStatus.disconnected,
    VpnStatus.connected,
    VpnStatus.blocked,
    VpnStatus.error,
  };

  void _check() {
    if (!controller.isConnectionBusy &&
        !_resting.contains(controller.vpnStatus)) {
      violations.add(controller.vpnStatus);
    }
  }

  void expectResting() {
    expect(violations, isEmpty);
    expect(controller.isConnectionBusy, isFalse);
    expect(_resting, contains(controller.vpnStatus));
  }
}

class _Harness {
  _Harness({
    required DateTime storedNotAfter,
    this.killSwitch = true,
    _MarkerStore? store,
  }) : store = store ?? _MarkerStore() {
    api = _RenewalApi(clock, storedNotAfter: storedNotAfter);
    openVpn = _RenewalOpenVpn(api);
    api.deviceList = const DeviceList(
      limit: 2,
      devices: [
        VpnDevice(
          deviceId: 'device-existing',
          name: 'Cet ordinateur',
          location: _location,
          createdAt: null,
        ),
      ],
    );
    controller =
        AppController(
            api: api,
            store: this.store,
            wireguard: enrollment.FakeWireGuardBridge(),
            openVpn: openVpn,
            now: clock.call,
          )
          ..profile = _user
          ..locations = const [_location]
          ..selectedLocation = _location
          ..isLoadingLocations = false
          ..currentDeviceId = 'device-existing'
          ..vpnProtocol = VpnProtocol.openVpn
          ..openVpnRuntimeAvailable = true
          ..killSwitchEnabled = killSwitch;
    guard = _RestingGuard(controller);
  }

  final clock = _Clock();
  final bool killSwitch;
  final _MarkerStore store;
  late final _RenewalApi api;
  late final _RenewalOpenVpn openVpn;
  late final AppController controller;
  late final _RestingGuard guard;

  /// A failed attempt rests with the usual kill switch semantics: blocked
  /// under the retained protection, released by nothing but Disconnect.
  void expectFailedAttempt() {
    guard.expectResting();
    expect(openVpn.disconnectCalls, 0);
    if (killSwitch) {
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(controller.errorMessage, _killSwitchMessage);
      expect(openVpn.protectionActive, isTrue);
    } else {
      expect(controller.vpnStatus, VpnStatus.error);
    }
  }

  void expectConnectedWith(DateTime notAfter) {
    guard.expectResting();
    expect(controller.vpnStatus, VpnStatus.connected);
    expect(controller.activeProtocol, VpnProtocol.openVpn);
    expect(openVpn.importedNotAfter.last, notAfter);
    expect(controller.deviceEnrollmentIssue, isNull);
  }
}

String _mode(bool killSwitch) =>
    'kill switch ${killSwitch ? 'actif' : 'inactif'}';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // recentLines is a bounded ring shared by every test: slice after a marker.
  var marks = 0;
  String markTrace() {
    final marker = 'renewal_mark_${marks++}';
    DiagnosticLog.record(area: 'trace_test', event: marker);
    return marker;
  }

  List<String> since(String marker) {
    final lines = DiagnosticLog.recentLines;
    final index = lines.lastIndexWhere(
      (line) => line.endsWith(' event=$marker'),
    );
    expect(index, isNot(-1), reason: 'trace marker $marker was evicted');
    return lines.skip(index + 1).toList();
  }

  List<String> renewalTrace(String marker, String event) => since(marker)
      .where((line) => line.split(' ').contains('event=$event'))
      .where((line) => line.contains(' area=openvpn '))
      .toList();

  void expectNoCertificateMaterial(Iterable<String> lines) {
    final text = lines.join('\n');
    for (final secret in [
      'certificate-not-displayed',
      'ca-not-displayed',
      'tls-key-not-displayed',
      'pending-csr',
      'csr-1',
      _sha256('pending-csr-1'),
    ]) {
      expect(text, isNot(contains(secret)));
    }
  }

  group('déclencheurs à la connexion', () {
    for (final killSwitch in [true, false]) {
      test('renouvelle avant tout import un certificat qui expire dans les '
          '14 jours (${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 10)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        final markerAtRenew = <String?>[];
        h.api.onRenew = (_) => markerAtRenew.add(h.store.renewalCsrSha256);
        final marker = markTrace();

        await h.controller.toggleConnection();

        // The free creation tells the date; the certificate close to
        // expiry is never handed to a tunnel.
        expect(h.api.createOpenVpnCalls, 1);
        expect(h.api.countedCreates, 0);
        expect(h.api.renewedCsrs, ['pending-csr-1']);
        expect(h.api.countedRenewals, 1);
        expect(h.openVpn.importedNotAfter, [h.api.renewedNotAfter]);
        h.expectConnectedWith(h.api.renewedNotAfter);
        // Persisted before /renew with the pending CSR's fingerprint, then
        // cleared once the renewed certificate connected.
        expect(markerAtRenew, [_sha256('pending-csr-1')]);
        expect(h.store.renewalWrites, ['device-existing', null]);
        expect(h.openVpn.activeCsr, 'pending-csr-1');
        expect(
          renewalTrace(marker, 'started').single,
          endsWith(
            'event=started code=automatic stage=certificate_renewal count=10',
          ),
        );
        expect(
          renewalTrace(marker, 'completed').single,
          endsWith(
            'event=completed code=automatic stage=certificate_renewal '
            'count=365',
          ),
        );
        // The renewal's own steps stay within the support vocabulary.
        for (final line in since(
          marker,
        ).where((line) => line.contains('stage=certificate_renewal'))) {
          expect(backendTraceLineViolations(line), isEmpty, reason: line);
        }
        expectNoCertificateMaterial(DiagnosticLog.recentLines);
      });

      test('ne renouvelle pas un certificat valide plus de 14 jours '
          '(${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 15)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);

        await h.controller.toggleConnection();

        expect(h.openVpn.renewCsrCalls, 0);
        expect(h.api.renewCalls, 0);
        expect(h.store.renewalWrites, isEmpty);
        h.expectConnectedWith(_now.add(const Duration(days: 15)));
      });

      test('un certificat connu comme expiré est renouvelé sans recréer le '
          'profil (${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 20)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        await h.controller.toggleConnection();
        await h.controller.toggleConnection();
        expect(h.controller.vpnStatus, VpnStatus.disconnected);
        final marker = markTrace();

        h.clock.value = _now.add(const Duration(days: 21));
        await h.controller.toggleConnection();

        // A creation would count before the server refused it.
        expect(h.api.createOpenVpnCalls, 1);
        expect(h.api.countedCreates, 0);
        expect(h.api.countedRenewals, 1);
        h.expectConnectedWith(h.api.renewedNotAfter);
        expect(
          renewalTrace(marker, 'started').single,
          contains(
            'code=certificate_expired stage=certificate_renewal count=0',
          ),
        );
      });

      test('une création refusée 409 openvpn_profile_exists renouvelle dans '
          'la même tentative (${_mode(killSwitch)})', () async {
        // The certificate expired while no window knew its date: the server
        // no longer recovers it and refuses the creation, after counting it.
        final h = _Harness(
          storedNotAfter: _now.subtract(const Duration(days: 2)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);

        await h.controller.toggleConnection();

        expect(h.api.createOpenVpnCalls, 1);
        expect(h.api.countedCreates, 1);
        expect(h.api.renewCalls, 1);
        expect(h.api.countedRenewals, 1);
        expect(h.openVpn.importedNotAfter, [h.api.renewedNotAfter]);
        h.expectConnectedWith(h.api.renewedNotAfter);
      });

      test('un renouvellement resté en attente passe avant toute création et '
          'rejoue le même CSR (${_mode(killSwitch)})', () async {
        // An earlier process requested it; the server issued it, but its
        // answer never arrived.
        final store = _MarkerStore()
          ..renewalDevice = 'device-existing'
          ..renewalCsrSha256 = _sha256('pending-csr-1');
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 300)),
          killSwitch: killSwitch,
          store: store,
        );
        addTearDown(h.controller.dispose);
        h.openVpn.mintPendingKey();
        h.api
          ..storedCsr = 'pending-csr-1'
          ..csrBySerial[1] = 'pending-csr-1';
        await h.controller.loadOpenVpnRenewalMarkerNow();

        await h.controller.toggleConnection();

        expect(h.api.createOpenVpnCalls, 0);
        expect(h.api.renewedCsrs, ['pending-csr-1']);
        // An exact-CSR recovery: nothing counted.
        expect(h.api.countedRenewals, 0);
        h.expectConnectedWith(_now.add(const Duration(days: 300)));
        expect(store.renewalDevice, isNull);
        expect(h.openVpn.activeCsr, 'pending-csr-1');
      });
    }

    for (final path in ['quickConnect', 'retryConnection']) {
      for (final killSwitch in [true, false]) {
        test('$path renouvelle aussi un certificat qui expire dans les 14 '
            'jours (${_mode(killSwitch)})', () async {
          final h = _Harness(
            storedNotAfter: _now.add(const Duration(days: 5)),
            killSwitch: killSwitch,
          );
          addTearDown(h.controller.dispose);

          if (path == 'quickConnect') {
            await h.controller.quickConnect();
          } else {
            await h.controller.retryConnection();
          }

          expect(h.api.countedRenewals, 1);
          expect(h.openVpn.importedNotAfter, [h.api.renewedNotAfter]);
          h.expectConnectedWith(h.api.renewedNotAfter);
        });
      }
    }
  });

  group('marqueur et rejeu', () {
    for (final killSwitch in [true, false]) {
      test('une réponse perdue garde l’identité et le CSR en attente, et la '
          'tentative suivante le rejoue sans renouvellement compté '
          '(${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 10)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        h.api.lostRenewAnswers = 1;
        // The server revoked the previous certificate when it issued the
        // renewal: the OpenVPN server refuses it from then on.
        h.openVpn.importFailureCode = (activation) =>
            h.api.csrOf(activation) == 'csr-1' && h.api.storedCsr != 'csr-1'
            ? 'openvpn_client_certificate_rejected'
            : null;

        await h.controller.toggleConnection();

        // One request, no retry loop of its own. The answer was lost without
        // a word against the current certificate, so the tunnel tries it,
        // and the server's refusal ends the attempt.
        expect(h.api.renewCalls, 1);
        expect(h.api.countedRenewals, 1);
        expect(h.openVpn.importedNotAfter, [
          _now.add(const Duration(days: 10)),
        ]);
        h.expectFailedAttempt();
        expect(h.store.renewalDevice, 'device-existing');
        expect(h.store.renewalCsrSha256, _sha256('pending-csr-1'));
        expect(h.openVpn.deleteProfileCalls, 0);
        expect(h.openVpn.activeCsr, 'csr-1');
        expect(h.openVpn.pendingCsr, 'pending-csr-1');

        expect(h.controller.canRetryConnection, isTrue);
        await h.controller.retryConnection();

        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-1']);
        expect(h.api.countedRenewals, 1);
        expect(h.api.createOpenVpnCalls, 1);
        h.expectConnectedWith(h.api.renewedNotAfter);
        expect(h.store.renewalDevice, isNull);
      });
    }

    test('un marqueur dont la clé en attente n’existe plus est oublié sans '
        'renouvellement compté', () async {
      final store = _MarkerStore()
        ..renewalDevice = 'device-existing'
        ..renewalCsrSha256 = _sha256('pending-csr-promoted-meanwhile');
      final h = _Harness(
        storedNotAfter: _now.add(const Duration(days: 60)),
        store: store,
      );
      addTearDown(h.controller.dispose);
      await h.controller.loadOpenVpnRenewalMarkerNow();

      await h.controller.toggleConnection();

      expect(h.api.renewCalls, 0);
      expect(h.api.createOpenVpnCalls, 1);
      expect(h.api.countedCreates, 0);
      h.expectConnectedWith(_now.add(const Duration(days: 60)));
      expect(store.renewalDevice, isNull);
    });

    test('un marqueur d’un autre appareil est effacé et ignoré', () async {
      final store = _MarkerStore()
        ..renewalDevice = 'device-other'
        ..renewalCsrSha256 = _sha256('pending-csr-1');
      final h = _Harness(
        storedNotAfter: _now.add(const Duration(days: 60)),
        store: store,
      );
      addTearDown(h.controller.dispose);
      await h.controller.loadOpenVpnRenewalMarkerNow();
      await pumpEventQueue();
      expect(store.renewalDevice, isNull);

      await h.controller.toggleConnection();

      expect(h.api.renewCalls, 0);
      h.expectConnectedWith(_now.add(const Duration(days: 60)));
    });

    test('un renouvellement manuel enregistre le marqueur avant /renew et '
        'l’efface une fois connecté', () async {
      final h = _Harness(storedNotAfter: _now.add(const Duration(days: 200)));
      addTearDown(h.controller.dispose);
      final markerAtRenew = <String?>[];
      h.api.onRenew = (_) => markerAtRenew.add(h.store.renewalCsrSha256);
      await h.controller.toggleConnection();
      expect(h.controller.vpnStatus, VpnStatus.connected);

      await h.controller.renewOpenVpnProfile();

      expect(markerAtRenew, [_sha256('pending-csr-1')]);
      expect(h.api.countedRenewals, 1);
      h.expectConnectedWith(h.api.renewedNotAfter);
      expect(h.store.renewalDevice, isNull);
    });
  });

  group('409 openvpn_renewal_expired', () {
    for (final killSwitch in [true, false]) {
      test('une clé en attente dont le certificat a expiré est remplacée par '
          'une nouvelle clé, renouvelée une fois de plus dans la même '
          'tentative (${_mode(killSwitch)})', () async {
        final store = _MarkerStore()
          ..renewalDevice = 'device-existing'
          ..renewalCsrSha256 = _sha256('pending-csr-1');
        final h = _Harness(
          storedNotAfter: _now.subtract(const Duration(days: 30)),
          killSwitch: killSwitch,
          store: store,
        );
        addTearDown(h.controller.dispose);
        // The server issued the pending key's certificate long ago, and
        // nothing ever connected with it.
        h.openVpn.mintPendingKey();
        h.api
          ..storedCsr = 'pending-csr-1'
          ..csrBySerial[1] = 'pending-csr-1';
        await h.controller.loadOpenVpnRenewalMarkerNow();
        final markerAtRenew = <String?>[];
        h.api.onRenew = (_) => markerAtRenew.add(store.renewalCsrSha256);
        final marker = markTrace();

        await h.controller.toggleConnection();

        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-2']);
        expect(h.openVpn.deleteProfileCalls, 1);
        expect(markerAtRenew, [
          _sha256('pending-csr-1'),
          _sha256('pending-csr-2'),
        ]);
        expect(h.api.createOpenVpnCalls, 0);
        h.expectConnectedWith(h.api.renewedNotAfter);
        expect(h.openVpn.activeCsr, 'pending-csr-2');
        expect(store.renewalDevice, isNull);
        expect(renewalTrace(marker, 'attempt_failed'), hasLength(1));
        expect(renewalTrace(marker, 'completed'), hasLength(1));
      });
    }

    test('le nouvel essai avec une nouvelle clé reste unique', () async {
      final h = _Harness(storedNotAfter: _now.add(const Duration(days: 3)));
      addTearDown(h.controller.dispose);
      const expired = ApiException(
        statusCode: 409,
        errorCode: 'openvpn_renewal_expired',
        observedHttpStatus: 409,
      );
      h.api.renewFailures = [expired, expired];

      await h.controller.toggleConnection();

      expect(h.api.renewCalls, 2);
      expect(h.openVpn.deleteProfileCalls, 1);
      h.expectFailedAttempt();
      // The second key is the pending one now, kept for the next attempt.
      expect(h.store.renewalCsrSha256, _sha256('pending-csr-2'));
    });
  });

  group('429 Retry-After', () {
    for (final killSwitch in [true, false]) {
      test('aucun renouvellement n’est envoyé avant l’instant donné par le '
          'serveur, le certificat encore valide sert en attendant, puis le '
          'suivant part (${_mode(killSwitch)})', () async {
        final current = _now.add(const Duration(days: 4));
        final h = _Harness(storedNotAfter: current, killSwitch: killSwitch);
        addTearDown(h.controller.dispose);
        h.api.renewFailures = [
          const ApiException(
            statusCode: 429,
            errorCode: 'rate_limited',
            observedHttpStatus: 429,
            retryAfterSeconds: 600,
          ),
        ];

        await h.controller.toggleConnection();

        expect(h.api.renewCalls, 1);
        h.expectConnectedWith(current);
        expect(h.store.renewalDevice, 'device-existing');
        expect(h.openVpn.pendingCsr, 'pending-csr-1');

        // Five minutes later: no renewal is sent; the current certificate,
        // replayed for free, connects again.
        await h.controller.toggleConnection();
        h.clock.value = _now.add(const Duration(minutes: 5));
        await h.controller.toggleConnection();
        expect(h.api.renewCalls, 1);
        expect(h.api.createOpenVpnCalls, 2);
        expect(h.api.countedCreates, 0);
        h.expectConnectedWith(current);

        // Past the instant, the next connection sends the same pending CSR.
        await h.controller.toggleConnection();
        h.clock.value = _now.add(const Duration(minutes: 10, seconds: 1));
        await h.controller.toggleConnection();
        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-1']);
        expect(h.api.countedRenewals, 2);
        h.expectConnectedWith(h.api.renewedNotAfter);
        expect(h.store.renewalDevice, isNull);
      });
    }

    for (final killSwitch in [true, false]) {
      test('le renouvellement 429 d’un certificat expiré finit en échec, le '
          'délai affiché décroît, et le même CSR part après l’instant '
          '(${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.subtract(const Duration(days: 1)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        h.api.renewFailures = [
          const ApiException(
            statusCode: 429,
            errorCode: 'rate_limited',
            observedHttpStatus: 429,
            retryAfterSeconds: 600,
          ),
        ];

        await h.controller.toggleConnection();

        expect(h.api.renewCalls, 1);
        h.expectFailedAttempt();
        expect(h.openVpn.importedNotAfter, isEmpty);
        expect(
          h.controller.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.rateLimited,
        );
        expect(
          h.controller.deviceEnrollmentIssue?.message,
          'Réessayez dans 600 secondes.',
        );
        expect(h.store.renewalDevice, 'device-existing');

        // Five minutes later: nothing is sent, and the delay shown has
        // decreased.
        h.clock.value = _now.add(const Duration(minutes: 5));
        await h.controller.retryConnection();
        expect(h.api.renewCalls, 1);
        expect(h.api.createOpenVpnCalls, 1);
        h.expectFailedAttempt();
        expect(h.controller.deviceEnrollmentIssue?.retryAfterSeconds, 300);

        // Past the instant, the next attempt sends the same pending CSR.
        h.clock.value = _now.add(const Duration(minutes: 10, seconds: 1));
        await h.controller.retryConnection();
        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-1']);
        h.expectConnectedWith(h.api.renewedNotAfter);
      });
    }

    test('une création refusée 429 n’est pas renvoyée avant l’instant '
        'donné', () async {
      final h = _Harness(
        storedNotAfter: _now.subtract(const Duration(days: 1)),
      );
      addTearDown(h.controller.dispose);
      h.api.createFailures = [
        const ApiException(
          statusCode: 429,
          errorCode: 'rate_limited',
          observedHttpStatus: 429,
          retryAfterSeconds: 120,
        ),
      ];

      await h.controller.toggleConnection();
      expect(h.api.createOpenVpnCalls, 1);
      h.expectFailedAttempt();

      await h.controller.retryConnection();
      expect(h.api.createOpenVpnCalls, 1);
      expect(h.api.renewCalls, 0);
      expect(
        h.controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.rateLimited,
      );
      expect(
        h.controller.deviceEnrollmentIssue?.message,
        'Réessayez dans 120 secondes.',
      );

      h.clock.value = _now.add(const Duration(minutes: 2));
      await h.controller.retryConnection();
      // Creation answers 409 for the expired certificate: renewed.
      expect(h.api.createOpenVpnCalls, 2);
      expect(h.api.countedRenewals, 1);
      h.expectConnectedWith(h.api.renewedNotAfter);
    });
  });

  group('échecs', () {
    for (final killSwitch in [true, false]) {
      test('une panne du serveur pendant un renouvellement seulement dû '
          'connecte avec le certificat encore valide et garde le CSR en '
          'attente (${_mode(killSwitch)})', () async {
        final current = _now.add(const Duration(days: 6));
        final h = _Harness(storedNotAfter: current, killSwitch: killSwitch);
        addTearDown(h.controller.dispose);
        h.api.renewFailures = [_signerUnavailable, _signerUnavailable];
        final marker = markTrace();

        await h.controller.toggleConnection();

        h.expectConnectedWith(current);
        expect(h.openVpn.deleteProfileCalls, 0);
        expect(h.openVpn.activeCsr, 'csr-1');
        expect(h.openVpn.pendingCsr, 'pending-csr-1');
        expect(h.store.renewalCsrSha256, _sha256('pending-csr-1'));
        final failed = renewalTrace(marker, 'certificate_renewal_failed');
        expect(failed.single, contains('code=openvpn_signer_unavailable '));
        expect(failed.single, endsWith('count=6'));

        // Still failing at the next connection: the pending CSR is tried
        // first, then the current certificate is replayed for free.
        await h.controller.toggleConnection();
        await h.controller.toggleConnection();
        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-1']);
        expect(h.api.createOpenVpnCalls, 2);
        expect(h.api.countedCreates, 0);
        h.expectConnectedWith(current);
        expect(h.store.renewalCsrSha256, _sha256('pending-csr-1'));

        // The server is back: the same pending CSR is renewed.
        await h.controller.toggleConnection();
        await h.controller.toggleConnection();
        expect(h.api.renewedCsrs, [
          'pending-csr-1',
          'pending-csr-1',
          'pending-csr-1',
        ]);
        h.expectConnectedWith(h.api.renewedNotAfter);
        expect(h.store.renewalDevice, isNull);
      });

      test('une panne du serveur pendant le renouvellement d’un certificat '
          'expiré finit en échec et garde l’identité et le CSR en attente '
          '(${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.subtract(const Duration(days: 1)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        h.api.renewFailures = [_signerUnavailable];

        await h.controller.toggleConnection();

        h.expectFailedAttempt();
        expect(h.openVpn.importedNotAfter, isEmpty);
        expect(
          h.controller.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.openVpnSignerUnavailable,
        );
        expect(h.openVpn.activeCsr, 'csr-1');
        expect(h.openVpn.pendingCsr, 'pending-csr-1');
        expect(h.store.renewalCsrSha256, _sha256('pending-csr-1'));

        await h.controller.retryConnection();
        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-1']);
        h.expectConnectedWith(h.api.renewedNotAfter);
      });

      test('après un renouvellement expiré qui a remplacé l’identité locale, '
          'une panne ne fait jamais repartir l’ancien certificat '
          '(${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 3)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        h.api.renewFailures = [
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_renewal_expired',
            observedHttpStatus: 409,
          ),
          _signerUnavailable,
        ];

        await h.controller.toggleConnection();

        // Both local keys were discarded: the old certificate has no key.
        expect(h.openVpn.deleteProfileCalls, 1);
        expect(h.openVpn.importedNotAfter, isEmpty);
        h.expectFailedAttempt();
        expect(h.store.renewalCsrSha256, _sha256('pending-csr-2'));
      });
    }

    test(
      'attend openvpn_operation_pending avec la même clé en attente',
      () async {
        final h = _Harness(storedNotAfter: _now.add(const Duration(days: 2)));
        addTearDown(h.controller.dispose);
        h.api.renewFailures = [
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_operation_pending',
            observedHttpStatus: 409,
            retryAfterSeconds: 0,
          ),
        ];

        await h.controller.toggleConnection();

        expect(h.openVpn.renewCsrCalls, 1);
        expect(h.api.renewedCsrs, ['pending-csr-1', 'pending-csr-1']);
        h.expectConnectedWith(h.api.renewedNotAfter);
      },
    );

    test('une attente du nœud épuisée ne repart pas avec le certificat '
        'courant, que le serveur a déjà révoqué', () async {
      final h = _Harness(storedNotAfter: _now.add(const Duration(days: 3)));
      addTearDown(h.controller.dispose);
      // The readiness wait: the server stored the pending CSR and revoked
      // the current certificate, and the node never confirms in time.
      h.api.renewFailures = [
        for (var attempt = 0; attempt < 6; attempt++)
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_operation_pending',
            observedHttpStatus: 409,
            retryAfterSeconds: 0,
          ),
      ];

      await h.controller.toggleConnection();

      // The whole bounded wait ran on the same pending CSR.
      expect(h.api.renewedCsrs, List.filled(6, 'pending-csr-1'));
      expect(h.openVpn.importedNotAfter, isEmpty);
      expect(h.api.createOpenVpnCalls, 1);
      h.expectFailedAttempt();
      expect(h.store.renewalCsrSha256, _sha256('pending-csr-1'));
    });

    test(
      'un renouvellement en attente sans Retry-After n’est pas renvoyé '
      'dans la même tentative; le certificat encore valide connecte',
      () async {
        final current = _now.add(const Duration(days: 2));
        final h = _Harness(storedNotAfter: current);
        addTearDown(h.controller.dispose);
        // Another operation of this device refused it after the server
        // counted it: only the readiness wait sends Retry-After.
        h.api.renewFailures = [
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_operation_pending',
            observedHttpStatus: 409,
          ),
        ];

        await h.controller.toggleConnection();

        expect(h.api.renewCalls, 1);
        h.expectConnectedWith(current);
        expect(h.store.renewalDevice, 'device-existing');
      },
    );

    test('un renouvellement en attente sans Retry-After d’un certificat '
        'expiré n’est pas renvoyé et affiche l’opération en attente', () async {
      final h = _Harness(
        storedNotAfter: _now.subtract(const Duration(days: 1)),
      );
      addTearDown(h.controller.dispose);
      h.api.renewFailures = [
        const ApiException(
          statusCode: 409,
          errorCode: 'openvpn_operation_pending',
          observedHttpStatus: 409,
        ),
      ];

      await h.controller.toggleConnection();

      expect(h.api.renewCalls, 1);
      h.expectFailedAttempt();
      expect(
        h.controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.openVpnOperationPending,
      );
      expect(h.store.renewalDevice, 'device-existing');
    });

    test('un profil introuvable au renouvellement laisse la tentative '
        'suivante créer le profil', () async {
      final h = _Harness(storedNotAfter: _now.add(const Duration(days: 2)));
      addTearDown(h.controller.dispose);
      h.api.renewFailures = [
        const ApiException(
          statusCode: 404,
          errorCode: 'not_found',
          observedHttpStatus: 404,
        ),
      ];

      await h.controller.toggleConnection();
      h.expectFailedAttempt();
      expect(h.store.renewalDevice, isNull);

      // The profile is gone server-side: the next attempt creates one.
      h.api.storedCsr = null;
      await h.controller.retryConnection();
      expect(h.api.createOpenVpnCalls, 2);
      expect(h.api.renewCalls, 1);
      h.expectConnectedWith(h.api.renewedNotAfter);
    });
  });

  group('refus du certificat par le serveur OpenVPN', () {
    for (final code in [
      'openvpn_certificate_expired',
      'openvpn_client_certificate_rejected',
    ]) {
      for (final killSwitch in [true, false]) {
        test('$code fait renouveler le certificat à la tentative suivante '
            '(${_mode(killSwitch)})', () async {
          final h = _Harness(
            storedNotAfter: _now.add(const Duration(days: 60)),
            killSwitch: killSwitch,
          );
          addTearDown(h.controller.dispose);
          h.openVpn.importFailureCode = (activation) =>
              h.api.csrOf(activation) == 'csr-1' ? code : null;

          await h.controller.toggleConnection();
          h.expectFailedAttempt();
          expect(h.api.renewCalls, 0);
          // No renewal was tried yet: the message asks for the retry that
          // renews, it never says a renewal failed.
          if (!killSwitch) {
            expect(h.controller.errorMessage, _certificateNotConfirmed);
          }
          final marker = markTrace();

          await h.controller.retryConnection();

          expect(h.api.createOpenVpnCalls, 1);
          expect(h.api.countedRenewals, 1);
          h.expectConnectedWith(h.api.renewedNotAfter);
          expect(
            renewalTrace(marker, 'started').single,
            contains(
              code == 'openvpn_certificate_expired'
                  ? 'code=openvpn_certificate_expired '
                  : 'code=certificate_invalid ',
            ),
          );
        });
      }
    }
  });

  group('profil révoqué', () {
    for (final killSwitch in [true, false]) {
      test('un renouvellement refusé 409 openvpn_profile_revoked affiche la '
          'carte, dont l’action remplace l’identité locale '
          '(${_mode(killSwitch)})', () async {
        final h = _Harness(
          storedNotAfter: _now.add(const Duration(days: 3)),
          killSwitch: killSwitch,
        );
        addTearDown(h.controller.dispose);
        // The profile was revoked since the creation replayed its
        // certificate: the renewal is refused.
        h.api.renewFailures = [
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_profile_revoked',
            observedHttpStatus: 409,
          ),
        ];

        await h.controller.toggleConnection();

        h.expectFailedAttempt();
        expect(
          h.controller.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.openVpnProfileRevoked,
        );
        expect(h.controller.canRenewOpenVpnProfile, isTrue);

        // The server finished the revocation and removed the profile.
        h.api.storedCsr = null;
        await h.controller.replaceRevokedOpenVpnProfile();

        expect(h.openVpn.deleteProfileCalls, 1);
        expect(h.store.renewalDevice, isNull);
        expect(h.api.receivedCsrs.last, 'csr-new-2');
        h.expectConnectedWith(h.api.renewedNotAfter);
      });
    }
  });

  test('aucun journal ne contient de matériel de certificat', () async {
    final h = _Harness(storedNotAfter: _now.add(const Duration(days: 1)));
    addTearDown(h.controller.dispose);
    h.api.lostRenewAnswers = 1;
    // The renewal revoked the previous certificate.
    h.openVpn.importFailureCode = (activation) =>
        h.api.csrOf(activation) == 'csr-1' && h.api.storedCsr != 'csr-1'
        ? 'openvpn_client_certificate_rejected'
        : null;
    final marker = markTrace();

    await h.controller.toggleConnection();
    await h.controller.retryConnection();

    h.expectConnectedWith(h.api.renewedNotAfter);
    expectNoCertificateMaterial(since(marker));
  });
}
