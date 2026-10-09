// SPDX-License-Identifier: MPL-2.0
import 'dart:io';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/browser_auth.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';

import 'complete_diagnostic_test.dart' show nativeEvidence;
import 'support/audit_fixtures.dart' as fixtures;

class _Bridge extends DiagnosticsBridge {
  @override
  Future<Map<String, Object?>> collectLocalDiagnostics() async =>
      nativeEvidence();
}

class _Delivery extends DiagnosticsController {
  FrozenDiagnosticReport? sent;
  @override
  Future<Map<String, Object?>?> runChecks() async => {
    'protocol': 'wireguard',
    'state': 'disconnected',
    'checks': [
      {'id': 'api_reachability', 'result': 'passed'},
    ],
  };
  @override
  Future<bool> sendPreparedReport(FrozenDiagnosticReport report) async {
    sent = FrozenDiagnosticReport.fromBytes(report.bytes);
    return true;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'complete diagnostic preserves fixed browser steps and failures',
    () async {
      final delivery = _Delivery();
      final controller = AppController(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        window: fixtures.ProbeWindow(),
        diagnosticsBridge: _Bridge(),
        diagnostics: delivery,
      )..profile = fixtures.account;
      addTearDown(controller.dispose);
      for (final phase in ['listener', 'open', 'callback', 'exchange']) {
        await DiagnosticLog.record(
          area: 'account',
          event: 'begin',
          stage: 'browser_auth_$phase',
        );
        await DiagnosticLog.record(
          area: 'account',
          event: 'completed',
          stage: 'browser_auth_$phase',
        );
      }
      for (final failure in [
        BrowserAuthException.canceled,
        BrowserAuthException.timeout,
        BrowserAuthException.denied,
        BrowserAuthException.callbackUnavailable,
        BrowserAuthException.launchFailed,
        BrowserAuthException.invalidResponse,
      ]) {
        await DiagnosticLog.recordFailure(
          area: 'account',
          event: 'failed',
          stage: 'browser_auth_callback',
          error: failure,
        );
      }
      for (final code in [
        'desktop_auth_invalid_request',
        'desktop_auth_invalid_grant',
        'desktop_auth_unavailable',
        'account_login_required',
      ]) {
        await DiagnosticLog.recordFailure(
          area: 'account',
          event: 'failed',
          stage: 'browser_auth_exchange',
          error: ApiException(
            statusCode: 400,
            observedHttpStatus: 400,
            errorCode: code,
          ),
        );
      }
      await DiagnosticLog.record(
        area: 'api_request',
        event: 'started',
        code: 'browser_auth_token',
        stage: 'request',
      );
      await controller.runCompleteDiagnostic();
      final report = delivery.sent!;
      final support = (report.json['windows'] as Map)['support'] as Map;
      final timeline = support['timeline'] as List;
      for (final code in browserAuthTraceCodes) {
        expect(
          timeline.any(
            (e) => e['source'] == 'application' && e['code'] == code,
          ),
          isTrue,
        );
      }
      for (final phase in ['listener', 'open', 'callback', 'exchange']) {
        expect(
          timeline.any(
            (e) =>
                e['source'] == 'application' &&
                e['stage'] == 'browser_auth_$phase',
          ),
          isTrue,
        );
      }
      expect(
        timeline.any(
          (e) =>
              e['source'] == 'application' && e['code'] == 'browser_auth_token',
        ),
        isTrue,
      );
      expect(jsonDecode(controller.diagnosticLocalExport), report.json);
      const output = String.fromEnvironment(
        'BROWSER_DIAGNOSTIC_FIXTURE_OUTPUT',
      );
      if (output.isNotEmpty) {
        await File(output).writeAsBytes(report.bytes, flush: true);
      }
    },
  );
}
