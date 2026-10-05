// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  String source(String relativePath) => File(
    '${Directory.current.path}${Platform.pathSeparator}$relativePath',
  ).readAsStringSync();

  test('the VPN service exposes only a local authenticated pipe', () {
    final broker = source('windows/runner/privileged_broker.cpp');

    expect(broker, contains(r'--fuzevpn-vpn-service'));
    expect(broker, contains('PIPE_REJECT_REMOTE_CLIENTS'));
    expect(broker, contains('GetNamedPipeClientProcessId'));
    expect(broker, contains('IsTrustedUiProcess'));
    expect(broker, contains('ScopedProtectedStoreUser'));
    expect(broker, isNot(contains('access_token')));
    expect(broker, isNot(contains('"Authorization"')));
    expect(broker, isNot(contains("'Authorization'")));
  });

  test('the privileged service is separated from the Flutter executable', () {
    final cmake = source('windows/runner/CMakeLists.txt');
    final uiMain = source('windows/runner/main.cpp');
    final serviceMain = source('windows/runner/service_main.cpp');
    final signing = source('tools/sign-windows-release.ps1');

    expect(cmake, contains('OUTPUT_NAME "fuzevpn-service"'));
    expect(cmake, contains('FUZEVPN_SERVICE_PROCESS'));
    expect(cmake, contains('fuzevpn_service_codec STATIC'));
    expect(uiMain, isNot(contains('RunPrivilegedBrokerIfRequested')));
    expect(uiMain, isNot(contains('RunWireGuardServiceCommandIfRequested')));
    expect(serviceMain, contains('RunPrivilegedBrokerIfRequested'));
    expect(serviceMain, contains('RunWireGuardServiceCommandIfRequested'));
    expect(signing, contains("'fuzevpn-service.exe'"));
  });

  test('le client graphique Windows est limité à une seule instance', () {
    final main = source('windows/runner/main.cpp');
    final window = source('windows/runner/flutter_window.cpp');
    final singleInstance = source('windows/runner/single_instance.h');

    expect(singleInstance, contains(r'Local\\FuzeVPN.Windows.SingleInstance'));
    expect(main, contains('CreateMutexW'));
    expect(main, contains('ERROR_ALREADY_EXISTS'));
    expect(main, contains('ActivateExistingInstance'));
    expect(main, contains('FindWindowExW'));
    expect(main, contains('QueryFullProcessImageNameW'));
    expect(main, contains('PostMessageW'));
    expect(window, contains('FuzeVpnSingleInstanceMessage'));
    expect(window, contains('ActivateFuzeVpnWindow'));
    expect(singleInstance, contains('FlashWindowEx'));
    expect(main, isNot(contains('TerminateProcess')));
    expect(main, isNot(contains('fuzevpn-service')));
  });

  test(
    'le nom d’appareil Windows expose les versions sans numéro de build',
    () {
      final bridge = source('lib/core/window_bridge.dart');
      final window = source('windows/runner/flutter_window.cpp');
      final cmake = source('windows/runner/CMakeLists.txt');

      expect(bridge, contains("'getDeviceName'"));
      expect(window, contains('getDeviceName'));
      expect(window, contains('FLUTTER_VERSION'));
      expect(window, contains("version.find('+')"));
      expect(window, contains('RtlGetVersion'));
      expect(window, contains('version.dwBuildNumber >= 22000'));
      expect(window, contains('Windows 11'));
      expect(window, contains('Windows 10'));
      expect(window, contains('return "Windows";'));
      expect(cmake, contains('FLUTTER_VERSION='));
    },
  );

  test('service installation requires a valid Authenticode signature', () {
    final broker = source('windows/runner/privileged_broker.cpp');
    final signing = source('tools/sign-windows-release.ps1');

    expect(broker, contains('WinVerifyTrust'));
    expect(broker, contains('!IsCurrentExecutableTrusted()'));
    expect(signing, contains("'/fd', 'SHA256'"));
    expect(signing, contains("'/td', 'SHA256'"));
    expect(signing, contains(r"'/tr', $policy.TimestampUrl"));
    expect(signing, contains('signtool verification failed'));
  });

  test('service DPAPI impersonation is scoped to protected-store calls', () {
    final header = source('windows/runner/protected_store.h');
    final store = source('windows/runner/secure_store_channel.cpp');

    expect(header, contains('class ScopedProtectedStoreUser final'));
    expect(store, contains('class ScopedStoreImpersonation final'));
    expect(store, contains('ImpersonateLoggedOnUser'));
    expect(store, contains('RevertToSelf'));
  });

  test('la lecture reste locale et la recréation passe par le service', () {
    final wireGuard = source('windows/runner/wireguard_tunnel.cpp');
    final openVpn = source('windows/runner/openvpn_tunnel.cpp');

    final wireGuardChannel = wireGuard.indexOf('void RegisterWireGuardChannel');
    final wireGuardIdentity = wireGuard.substring(
      wireGuard.indexOf(
        'if (call.method_name() == "getOrCreatePublicKey")',
        wireGuardChannel,
      ),
      wireGuard.indexOf(
        'if (call.method_name() == "prepareIdentityForAccount")',
        wireGuardChannel,
      ),
    );
    expect(wireGuardIdentity, contains('ReadStoredPublicKeyForAccount'));
    expect(wireGuardIdentity, contains('ForwardPrivilegedCall'));
    expect(
      wireGuardIdentity.indexOf('ReadStoredPublicKeyForAccount'),
      lessThan(wireGuardIdentity.indexOf('ForwardPrivilegedCall')),
    );

    final openVpnIdentity = openVpn.substring(
      openVpn.indexOf(
        'if (call.method_name() == "getOrCreateCsr" ||',
        openVpn.indexOf('void RegisterOpenVpnChannel'),
      ),
      openVpn.indexOf(
        'if (call.method_name() == "prepareConnection" ||',
        openVpn.indexOf('void RegisterOpenVpnChannel'),
      ),
    );
    expect(openVpnIdentity, isNot(contains('ForwardPrivilegedCall')));
  });

  test('la recréation WireGuard est une seule opération native sérialisée', () {
    final wireGuard = source('windows/runner/wireguard_tunnel.cpp');
    final bridge = source('lib/core/wireguard_bridge.dart');
    final controller = source('lib/app_controller.dart');

    expect(wireGuard, contains('bool RecreateIdentityForAccount('));
    expect(wireGuard, contains('if (!ResetIdentity(failure, false))'));
    expect(wireGuard, contains('bool release_network_protection = true'));
    expect(wireGuard, contains('CreateIdentityForAccount('));
    expect(
      wireGuard,
      contains('call.method_name() == "recreateIdentityForAccount"'),
    );
    expect(bridge, contains(".invokeMethod('recreateIdentityForAccount'"));
    expect(controller, contains('_wireguard.recreateIdentityForAccount('));
  });

  test('le diagnostic natif ne conserve que des opérations non sensibles', () {
    final broker = source('windows/runner/privileged_broker.cpp');
    final diagnostic = source('lib/core/diagnostic_log.dart');

    expect(broker, contains('native_last_operation.txt'));
    expect(broker, contains('native_diagnostic.log'));
    expect(broker, contains('operation == "wireguard.connect"'));
    expect(
      broker,
      contains('operation == "wireguard.recreateIdentityForAccount"'),
    );
    expect(broker, contains('operation == "openvpn.importAndConnect"'));
    expect(diagnostic, contains('diagnostic.log'));
    expect(diagnostic, contains("'redacted'"));
    expect(diagnostic, isNot(contains('access_token')));
    expect(diagnostic, isNot(contains('csr_pem')));
    expect(diagnostic, isNot(contains('private_key')));
    expect(broker, isNot(contains('native_request.txt')));
    expect(broker, isNot(contains('native_response.txt')));
  });

  test('le broker attend la lecture complète de sa réponse', () {
    final broker = source('windows/runner/privileged_broker.cpp');

    expect(broker, contains('kResponseAckMagic'));
    expect(broker, contains('response_acknowledged'));
    expect(broker, contains('ReadExactOverlapped'));
    expect(
      broker,
      contains(
        'WriteExactOverlapped(pipe, client_cancel_event, &kResponseAckMagic',
      ),
    );
  });

  test('the kill switch is owned by the privileged VPN runtime', () {
    final protection = source('windows/runner/network_protection.cpp');
    final runtime = source('windows/runner/privileged_runtime.cpp');
    final main = source('windows/runner/main.cpp');

    expect(protection, contains('CanManageNetworkProtection()'));
    expect(runtime, contains('PrivilegedRuntimeKind::vpn_service'));
    expect(runtime, contains('PrivilegedRuntimeKind::elevated_broker'));
    expect(main, contains('if (!IsPersistentVpnServiceRunning())'));
  });

  test('pre-connect UI access stays bound to authenticated runtimes', () {
    final protection = source('windows/runner/network_protection.cpp');
    final broker = source('windows/runner/privileged_broker.cpp');

    expect(
      protection,
      contains('kUiExecutableName[] = L"fuzevpn_windows.exe"'),
    );
    expect(
      protection,
      contains('kServiceExecutableName[] = L"fuzevpn-service.exe"'),
    );
    expect(protection, contains('if (IsVpnServiceRuntime())'));
    expect(protection, contains('!IsFileTrusted(candidate_text)'));
    expect(protection, contains('current.filename().wstring()'));
    expect(
      protection,
      isNot(
        contains(
          '_wcsicmp(candidate_text.c_str(), current_executable.c_str())',
        ),
      ),
    );
    expect(
      broker,
      contains('IsExpectedProcessImage(parent, kUiExecutableName)'),
    );
    expect(broker, contains('IsUnsignedDevelopmentPair()'));
    expect(
      broker,
      contains(
        'SetPrivilegedRuntimeKind(PrivilegedRuntimeKind::elevated_broker)',
      ),
    );
  });

  test('service recovery removes an unprotected stale tunnel', () {
    final broker = source('windows/runner/privileged_broker.cpp');

    expect(broker, contains('SERVICE_CONFIG_FAILURE_ACTIONS'));
    final cleanup = broker.indexOf('if (!StopBrokerTunnels())');
    final status = broker.indexOf('PublishTunnelStatus', cleanup);
    expect(cleanup, greaterThanOrEqualTo(0));
    expect(status, greaterThan(cleanup));
    expect(broker, contains('RemoveWireGuardTunnelService();'));
    expect(broker, contains('runtime_lock.AcquireMachineRuntime()'));
    expect(broker, contains('OpenVpnCoreRecoverNetworkState()'));
  });

  test('a service configuration mismatch is diagnosed by the parent', () {
    final broker = source('windows/runner/privileged_broker.cpp');
    expect(broker, contains('SetLastError(ERROR_BAD_CONFIGURATION)'));
    expect(broker, contains('static_cast<int>(ERROR_BAD_CONFIGURATION)'));
    expect(broker, contains('GetExitCodeProcess(installer, &exit_code)'));
    expect(broker, contains('RecordServiceInstallerResult(installer)'));
    expect(broker, contains('"service_configuration_mismatch"'));
    expect(broker, contains('"broker.installService="'));
  });
}
