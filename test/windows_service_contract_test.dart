// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  String source(String relativePath) => File(
    '${Directory.current.path}${Platform.pathSeparator}$relativePath',
  ).readAsStringSync();

  test('the VPN service exposes only a local authenticated pipe', () {
    final broker = source('windows/runner/privileged_broker.cpp');
    final endpoint = source('windows/runner/service_pipe_endpoint.h');

    expect(broker, contains(r'--fuzevpn-vpn-service'));
    expect(broker, contains('fuzevpn_ipc::ServicePipeEndpoint endpoint'));
    expect(endpoint, contains('PIPE_REJECT_REMOTE_CLIENTS'));
    expect(endpoint, contains('FILE_FLAG_FIRST_PIPE_INSTANCE'));
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
    expect(main, contains('FuzeVpnDecideSingleInstanceStartup('));
    expect(singleInstance, contains('ERROR_ALREADY_EXISTS'));
    expect(
      main,
      contains('instance_decision != FuzeVpnSingleInstanceDecision::primary'),
    );
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

  test(
    'runtime recovery restores protection before cleanup and availability',
    () {
      final broker = source('windows/runner/privileged_broker.cpp');

      expect(broker, contains('SERVICE_CONFIG_FAILURE_ACTIONS'));
      final recoveryPaths = RegExp(
        r'if \(!RestoreNetworkProtection\(&recovered_user\)',
      ).allMatches(broker);
      expect(recoveryPaths, hasLength(2));
      for (final recovery in recoveryPaths) {
        final ownership = broker.indexOf(
          'runtime_ownership.AuthorizeMutation(recovered_user, true)',
          recovery.start,
        );
        final cleanup = broker.indexOf('!StopBrokerTunnels()', recovery.start);
        final status = broker.indexOf('PublishTunnelStatus', cleanup);
        expect(ownership, greaterThan(recovery.start));
        expect(cleanup, greaterThan(ownership));
        expect(status, greaterThan(cleanup));
      }
      expect(broker, contains('RemoveWireGuardTunnelService();'));
      expect(broker, contains('runtime_lock.AcquireMachineRuntime()'));
      expect(broker, contains('OpenVpnCoreRecoverNetworkState()'));
    },
  );

  test('a service configuration mismatch is diagnosed by the parent', () {
    final broker = source('windows/runner/privileged_broker.cpp');
    expect(broker, contains('SetLastError(ERROR_BAD_CONFIGURATION)'));
    expect(broker, contains('static_cast<int>(ERROR_BAD_CONFIGURATION)'));
    expect(broker, contains('GetExitCodeProcess(installer, &exit_code)'));
    expect(broker, contains('RecordServiceInstallerResult(installer)'));
    expect(broker, contains('"service_configuration_mismatch"'));
    expect(broker, contains('"broker.installService="'));
  });

  test('WireGuard keeps its pinned runtime and per-candidate wiring', () {
    final tunnel = source('windows/runner/wireguard_tunnel.cpp');

    // tunnel.dll stays pinned in the tunnel-service process and never maps
    // its Go runtime elsewhere: keys come from the OpenSSL implementation.
    expect(tunnel, contains('GET_MODULE_HANDLE_EX_FLAG_PIN'));
    expect(tunnel, contains('fuzevpn::GenerateWireGuardKeypair('));
    expect(tunnel, isNot(contains('WireGuardGenerateKeypair')));
    expect(tunnel, isNot(contains('FreeLibrary(module_)')));
    expect(tunnel, isNot(contains('FreeLibrary(loaded)')));
    // The last or only candidate gets the long handshake window.
    expect(
      tunnel,
      contains(
        'WireGuardHandshakeWindow(candidate_index, numeric_endpoints.size())',
      ),
    );
    expect(tunnel, isNot(contains('8000, connection_deadline')));
    // A stuck adapter lookup is reported as adapter_open, not starting.
    final adapterStage = tunnel.indexOf(
      'snapshot.stage = Stage::adapter_open;',
    );
    final adapterLookup = tunnel.indexOf(
      'TunnelRuntime::AdapterLuid(&interface_luid, attempt_deadline)',
    );
    expect(adapterStage, isNot(-1));
    expect(adapterLookup, greaterThan(adapterStage));
    // Every exit of a candidate attempt writes its snapshot.
    final attempt = tunnel.substring(
      tunnel.indexOf('[&](const std::string& endpoint'),
      tunnel.indexOf('SecureErase(&private_key)', adapterLookup),
    );
    expect('return finish('.allMatches(attempt), hasLength(5));
    expect(attempt, isNot(contains('return Outcome::')));
  });
}
