// Manually invoked by windows/tests/startup_bridge_test.cpp. Only passive
// native methods are called; this entrypoint never initializes the application.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

const _wireguard = MethodChannel('com.fuzevpn/windows_wireguard');
const _openvpn = MethodChannel('com.fuzevpn/windows_openvpn');
const _update = MethodChannel('fuzevpn/update');

Object? _jsonValue(Object? value) {
  if (value == null || value is String || value is num || value is bool) {
    return value;
  }
  if (value is List) return value.map(_jsonValue).toList(growable: false);
  if (value is Map) {
    if (value.keys.any((key) => key is! String)) {
      throw const FormatException('Invalid native map key.');
    }
    final keys = value.keys.cast<String>().toList()..sort();
    return {for (final key in keys) key: _jsonValue(value[key])};
  }
  throw const FormatException('Invalid native value.');
}

Future<Map<String, Object?>> _observe(
  MethodChannel channel,
  String method,
) async {
  try {
    final value = await channel
        .invokeMethod<Object?>(method)
        .timeout(const Duration(seconds: 5));
    return {'ok': true, 'value': _jsonValue(value)};
  } on PlatformException catch (error) {
    return {'ok': false, 'error_code': error.code};
  } on MissingPluginException {
    return {'ok': false, 'error_code': 'missing_native_channel'};
  } on TimeoutException {
    return {'ok': false, 'error_code': 'passive_query_timeout'};
  } on FormatException {
    return {'ok': false, 'error_code': 'invalid_native_value'};
  } catch (_) {
    return {'ok': false, 'error_code': 'passive_query_failed'};
  }
}

bool _inactive(Map<String, Object?> observation) {
  final value = observation['value'];
  return observation['ok'] == true &&
      value is Map &&
      value['active'] == false &&
      value['phase'] == 'inactive';
}

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1 || arguments.single.isEmpty) exit(64);
  WidgetsFlutterBinding.ensureInitialized();

  final environment = await _observe(_update, 'getEnvironment');
  final wireguardConnected = await _observe(_wireguard, 'isConnected');
  final wireguardProtection = await _observe(
    _wireguard,
    'networkProtectionStatus',
  );
  final openvpnConnected = await _observe(_openvpn, 'isConnected');
  final openvpnProtection = await _observe(_openvpn, 'networkProtectionStatus');
  final observations = [
    environment,
    wireguardConnected,
    wireguardProtection,
    openvpnConnected,
    openvpnProtection,
  ];
  final environmentValue = environment['value'];
  final report = <String, Object?>{
    'schema_version': 1,
    'passive': true,
    'environment': environment,
    'wireguard': {
      'connected': wireguardConnected,
      'protection': wireguardProtection,
    },
    'openvpn': {'connected': openvpnConnected, 'protection': openvpnProtection},
    'checks': {
      'all_native_queries_succeeded': observations.every(
        (observation) => observation['ok'] == true,
      ),
      'portable_mode':
          environment['ok'] == true &&
          environmentValue is Map &&
          environmentValue['installation_mode'] == 'portable',
      'confirmed_clean':
          wireguardConnected['ok'] == true &&
          wireguardConnected['value'] == false &&
          openvpnConnected['ok'] == true &&
          openvpnConnected['value'] == false &&
          _inactive(wireguardProtection) &&
          _inactive(openvpnProtection),
    },
  };
  try {
    await File(arguments.single).writeAsString(
      '${const JsonEncoder.withIndent('  ').convert(report)}\n',
      flush: true,
    );
  } catch (_) {
    exit(74);
  }
  // This isolated process has only observed native state. No application or
  // VPN runtime was initialized, so no application exit workflow is required.
  exit(0);
}
