// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixtures;

const _location = Location(
  id: 'source',
  city: 'Source',
  countryCode: 'DE',
  displayName: 'Source',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);

const _allowed = Subscription(
  status: SubscriptionStatus.active,
  hasAccess: true,
  renewsAutomatically: false,
  cancelAtPeriodEnd: false,
);
const _denied = Subscription(
  status: SubscriptionStatus.inactive,
  hasAccess: false,
  renewsAutomatically: false,
  cancelAtPeriodEnd: false,
);
const _subscriptionRejection = ApiException(
  statusCode: HttpStatus.forbidden,
  observedHttpStatus: HttpStatus.forbidden,
  errorCode: 'subscription_required',
);

class _Api extends fixtures.ProbeApi {
  Subscription billing = _allowed;
  Object? billingFailure;
  ApiException? enrollmentFailure;
  final billingReplies = <Future<Subscription>>[];
  int billingCalls = 0;
  int registrationCalls = 0;
  int activationCalls = 0;

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async => const AuthSession(accessToken: 'new-synthetic-token');

  @override
  Future<Subscription> subscription(String token) async {
    billingCalls++;
    if (billingReplies.isNotEmpty) return billingReplies.removeAt(0);
    if (billingFailure case final failure?) throw failure;
    return billing;
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registrationCalls++;
    if (enrollmentFailure case final failure?) throw failure;
    return super.registerDevice(
      token: token,
      name: name,
      publicKey: publicKey,
      locationId: locationId,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    activationCalls++;
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }
}

class _Store extends fixtures.ProbeStore {
  String? savedToken = 'audit-synthetic-token';
  int tokenClears = 0;
  int bindingClears = 0;

  @override
  Future<String?> token() async => savedToken;
  @override
  Future<void> saveToken(String value) async => savedToken = value;
  @override
  Future<void> clearToken() async {
    tokenClears++;
    savedToken = null;
  }

  @override
  Future<void> clearCurrentDeviceId() async {
    bindingClears++;
  }
}

class _WireGuard extends fixtures.ProbeWireGuard {
  int publicKeyCalls = 0;

  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}

  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async {
    publicKeyCalls++;
    return super.getOrCreatePublicKey(accountId: accountId);
  }
}

class _OpenVpn extends fixtures.ProbeOpenVpn {
  int prepareCalls = 0;
  int csrCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    protectionActive = true;
  }

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async {
    csrCalls++;
    return super.getOrCreateCsr(accountId: accountId, deviceId: deviceId);
  }
}

class _QuietUpdates extends WindowsUpdateController {
  _QuietUpdates() : super(api: fixtures.ProbeApi());
  @override
  Future<void> checkForUpdates() async {}
}

class _Harness {
  _Harness(VpnProtocol protocol) {
    app =
        AppController(
            api: api,
            store: store,
            wireguard: wg,
            openVpn: ovpn,
            window: fixtures.ProbeWindow(),
            updates: updates,
          )
          ..profile = fixtures.account
          ..locations = [_location]
          ..selectedLocation = _location
          ..currentDeviceId = null
          ..vpnProtocol = protocol
          ..protocolPreference = protocol == VpnProtocol.wireGuard
              ? VpnProtocolPreference.wireGuard
              : VpnProtocolPreference.openVpn
          ..openVpnRuntimeAvailable = true
          ..killSwitchEnabled = true
          ..isInitialized = true
          ..isLoadingLocations = false;
    addTearDown(updates.dispose);
    addTearDown(app.dispose);
  }

  final api = _Api();
  final store = _Store();
  final wg = _WireGuard();
  final ovpn = _OpenVpn();
  final updates = _QuietUpdates();
  late final AppController app;

  void expectNoVpnPreparation() {
    expect(wg.prepareCalls, 0);
    expect(ovpn.prepareCalls, 0);
    expect(wg.publicKeyCalls, 0);
    expect(ovpn.csrCalls, 0);
    expect(api.registrationCalls, 0);
    expect(api.activationCalls, 0);
    expect(wg.connectCalls, 0);
    expect(ovpn.importCalls, 0);
    expect(wg.protectionActive, isFalse);
    expect(ovpn.protectionActive, isFalse);
  }

  void expectSessionPreserved() {
    expect(app.profile, fixtures.account);
    expect(store.savedToken, 'audit-synthetic-token');
    expect(store.tokenClears, 0);
    expect(store.bindingClears, 0);
    expect(app.takeSignInPrompt(), isFalse);
  }
}

Future<void> _waitFor(bool Function() predicate) async {
  for (var i = 0; i < 100 && !predicate(); i++) {
    await Future<void>.delayed(Duration.zero);
  }
  expect(predicate(), isTrue);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final protocol in VpnProtocol.values) {
    test('${protocol.name} rejects absent access before preparing WFP', () async {
      final h = _Harness(protocol);
      h.api.billing = _denied;

      await h.app.quickConnect();

      expect(h.api.billingCalls, 1);
      expect(h.app.subscription, same(_denied));
      expect(h.app.vpnStatus, VpnStatus.error);
      expect(h.app.requiresExplicitDisconnect, isFalse);
      expect(
        h.app.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.subscriptionRequired,
      );
      h.expectNoVpnPreparation();
      h.expectSessionPreserved();

      // A purchase is checked afresh. Merely checking it never starts a tunnel.
      h.api.billing = _allowed;
      await h.app.refreshSubscription();
      expect(h.app.deviceEnrollmentIssue, isNull);
      expect(h.app.vpnStatus, VpnStatus.disconnected);
      h.expectNoVpnPreparation();
      await h.app.quickConnect();
      expect(h.api.billingCalls, 3);
      expect(h.app.vpnStatus, VpnStatus.connected);
    });

    test(
      '${protocol.name} preserves session and WFP on authoritative HTTP403',
      () async {
        final h = _Harness(protocol);
        h.api.enrollmentFailure = _subscriptionRejection;
        final firstLine = DiagnosticLog.recentLines.length;

        await h.app.quickConnect();

        expect(h.api.billingCalls, 1);
        expect(h.api.registrationCalls, 1);
        expect(h.api.activationCalls, 0);
        expect(h.app.subscription, same(_allowed));
        expect(h.app.vpnStatus, VpnStatus.blocked);
        expect(h.app.requiresExplicitDisconnect, isTrue);
        expect(
          h.app.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.subscriptionRequired,
        );
        expect(h.wg.protectionActive, protocol == VpnProtocol.wireGuard);
        expect(h.ovpn.protectionActive, protocol == VpnProtocol.openVpn);
        expect(h.wg.connectCalls, 0);
        expect(h.ovpn.csrCalls, 0);
        expect(h.ovpn.importCalls, 0);
        expect(h.wg.disconnectCalls, 0);
        expect(h.ovpn.disconnectCalls, 0);
        h.expectSessionPreserved();
        final lines = DiagnosticLog.recentLines.skip(firstLine).join('\n');
        expect(
          lines,
          contains('event=api_enrollment_failed code=subscription_required'),
        );
        expect(lines, isNot(contains('audit-synthetic-token')));

        // Control-plane billing remains readable while protection is retained.
        // Resolving the issue must neither clear WFP nor connect the tunnel.
        await h.app.refreshSubscription();
        expect(h.api.billingCalls, 2);
        expect(h.app.subscriptionErrorMessage, isNull);
        expect(h.app.deviceEnrollmentIssue, isNull);
        expect(h.app.vpnStatus, VpnStatus.blocked);
        expect(h.app.requiresExplicitDisconnect, isTrue);
        expect(h.wg.protectionActive, protocol == VpnProtocol.wireGuard);
        expect(h.ovpn.protectionActive, protocol == VpnProtocol.openVpn);
        expect(h.wg.connectCalls, 0);
        expect(h.ovpn.importCalls, 0);
        expect(h.wg.disconnectCalls, 0);
        expect(h.ovpn.disconnectCalls, 0);
      },
    );

    test(
      '${protocol.name} honors canceled access independently of status',
      () async {
        final h = _Harness(protocol);
        h.api.billing = const Subscription(
          status: SubscriptionStatus.canceled,
          hasAccess: true,
          renewsAutomatically: false,
          cancelAtPeriodEnd: true,
        );
        await h.app.quickConnect();
        expect(h.api.billingCalls, 1);
        expect(h.api.registrationCalls, 1);
        expect(h.app.vpnStatus, VpnStatus.connected);
        expect(h.app.deviceEnrollmentIssue, isNull);
        h.expectSessionPreserved();
      },
    );

    for (final failure in <Object>[
      const SocketException('private-network-failure'),
      const FormatException('private-billing-body'),
      const ApiException(statusCode: 503, errorCode: 'server_error'),
      const ApiException(statusCode: 401, errorCode: 'api_error'),
    ]) {
      test(
        '${protocol.name} lets enrollment decide when billing ${failure is ApiException ? '${failure.statusCode}/${failure.errorCode}' : failure.runtimeType} fails',
        () async {
          final h = _Harness(protocol);
          h.app.subscription = _denied;
          h.api.billingFailure = failure;
          await h.app.quickConnect();
          expect(h.api.billingCalls, 1);
          expect(h.api.registrationCalls, 1);
          expect(h.app.vpnStatus, VpnStatus.connected);
          expect(h.app.deviceEnrollmentIssue, isNull);
          h.expectSessionPreserved();
        },
      );
    }

    test(
      '${protocol.name} leaves unknown billing status to enrollment',
      () async {
        final h = _Harness(protocol);
        h.api.billing = const Subscription(
          status: SubscriptionStatus.unknown,
          hasAccess: false,
          renewsAutomatically: false,
          cancelAtPeriodEnd: false,
        );
        await h.app.quickConnect();
        expect(h.api.registrationCalls, 1);
        expect(h.app.vpnStatus, VpnStatus.connected);
        expect(h.app.deviceEnrollmentIssue, isNull);
      },
    );

    test(
      '${protocol.name} expires only a confirmed unauthorized session before WFP',
      () async {
        final h = _Harness(protocol);
        h.api.billingFailure = const ApiException(
          statusCode: HttpStatus.unauthorized,
          observedHttpStatus: HttpStatus.unauthorized,
          errorCode: 'unauthorized',
        );
        await h.app.quickConnect();
        expect(h.app.profile, isNull);
        expect(h.store.tokenClears, 1);
        expect(h.store.bindingClears, 1);
        expect(
          h.app.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.sessionExpired,
        );
        h.expectNoVpnPreparation();
      },
    );
  }

  test(
    'an obsolete panel response cannot replace fresher connection billing',
    () async {
      final h = _Harness(VpnProtocol.wireGuard);
      final oldReply = Completer<Subscription>();
      h.api.billingReplies.add(oldReply.future);
      final oldRefresh = h.app.refreshSubscription();
      await _waitFor(() => h.api.billingCalls == 1);
      await h.app.quickConnect();
      expect(h.app.subscription, same(_allowed));
      oldReply.complete(_denied);
      await oldRefresh;
      expect(h.api.billingCalls, 2);
      expect(h.app.subscription, same(_allowed));
      expect(h.app.vpnStatus, VpnStatus.connected);
      expect(h.app.deviceEnrollmentIssue, isNull);
    },
  );

  test('the account panel joins an in-flight connection preflight', () async {
    final h = _Harness(VpnProtocol.wireGuard);
    final reply = Completer<Subscription>();
    h.api.billingReplies.add(reply.future);
    final connecting = h.app.quickConnect();
    await _waitFor(() => h.api.billingCalls == 1);
    final refresh = h.app.refreshSubscription();
    expect(h.api.billingCalls, 1);
    reply.complete(_allowed);
    await Future.wait([connecting, refresh]);
    expect(h.api.billingCalls, 1);
    expect(h.app.vpnStatus, VpnStatus.connected);
    expect(h.app.subscription, same(_allowed));
    expect(h.app.isLoadingSubscription, isFalse);
  });

  test('an HTTP500 body cannot masquerade as a subscription refusal', () async {
    final h = _Harness(VpnProtocol.wireGuard);
    h.api.enrollmentFailure = const ApiException(
      statusCode: HttpStatus.internalServerError,
      observedHttpStatus: HttpStatus.internalServerError,
      errorCode: 'subscription_required',
    );
    await h.app.quickConnect();
    expect(
      h.app.deviceEnrollmentIssue?.kind,
      DeviceEnrollmentIssueKind.unknown,
    );
    expect(h.app.vpnStatus, VpnStatus.blocked);
    h.expectSessionPreserved();
  });

  test(
    'preflight result after an account switch cannot publish or prepare WFP',
    () async {
      final h = _Harness(VpnProtocol.wireGuard);
      final reply = Completer<Subscription>();
      h.api.billingReplies.add(reply.future);
      final connecting = h.app.quickConnect();
      await _waitFor(() => h.api.billingCalls == 1);
      h.app.profile = const UserProfile(
        userId: 'new-synthetic-user',
        email: 'new@example.invalid',
        firstName: 'New',
        emailVerified: true,
      );
      reply.complete(_denied);
      await connecting;
      expect(h.app.profile?.userId, 'new-synthetic-user');
      expect(h.app.subscription, isNull);
      expect(h.app.deviceEnrollmentIssue, isNull);
      expect(h.store.tokenClears, 0);
      h.expectNoVpnPreparation();
      expect(h.app.vpnStatus, VpnStatus.disconnected);
      expect(h.app.isConnectionBusy, isFalse);
      expect(h.app.requiresExplicitDisconnect, isFalse);
    },
  );

  test(
    'old preflight unauthorized response cannot expire a replacement token',
    () async {
      final h = _Harness(VpnProtocol.wireGuard);
      final reply = Completer<Subscription>();
      h.api.billingReplies.add(reply.future);
      final connecting = h.app.quickConnect();
      await _waitFor(() => h.api.billingCalls == 1);
      expect(
        await h.app.signIn(
          email: 'synthetic@example.invalid',
          password: 'synthetic',
        ),
        isTrue,
      );
      reply.completeError(
        const ApiException(
          statusCode: HttpStatus.unauthorized,
          observedHttpStatus: HttpStatus.unauthorized,
          errorCode: 'unauthorized',
        ),
      );
      await connecting;
      expect(h.app.profile, fixtures.account);
      expect(h.store.savedToken, 'new-synthetic-token');
      expect(h.store.tokenClears, 0);
      expect(h.app.subscription, isNull);
      expect(h.app.deviceEnrollmentIssue, isNull);
      h.expectNoVpnPreparation();
    },
  );

  test(
    'a session changed by the preflight completion listener cannot prepare WFP',
    () async {
      final h = _Harness(VpnProtocol.wireGuard);
      var switched = false;
      h.app.addListener(() {
        if (!switched &&
            h.app.subscription != null &&
            !h.app.isLoadingSubscription) {
          switched = true;
          h.app.profile = null;
        }
      });
      await h.app.quickConnect();
      expect(switched, isTrue);
      expect(h.app.profile, isNull);
      h.expectNoVpnPreparation();
      expect(h.app.vpnStatus, VpnStatus.disconnected);
      expect(h.app.isConnectionBusy, isFalse);
      expect(h.app.requiresExplicitDisconnect, isFalse);
    },
  );
}
