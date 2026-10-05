// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';

import 'diagnostic_log.dart';

/// Public MSI-compatible version, independent of the Flutter build revision.
class WindowsUpdateVersion implements Comparable<WindowsUpdateVersion> {
  WindowsUpdateVersion._(List<int> parts)
    : components = List.unmodifiable(parts);

  factory WindowsUpdateVersion.parse(String value) {
    final parts = value.split('.');
    if (parts.length != 3) {
      throw const FormatException('Invalid Windows update version.');
    }
    final numbers = <int>[];
    for (final part in parts) {
      if (part.isEmpty ||
          part.length > 5 ||
          part.codeUnits.any((unit) => unit < 48 || unit > 57)) {
        throw const FormatException('Invalid Windows update version.');
      }
      final number = int.parse(part);
      final maximum = numbers.length < 2 ? 255 : 65535;
      if (number > maximum) {
        throw const FormatException('Invalid Windows update version.');
      }
      numbers.add(number);
    }
    return WindowsUpdateVersion._(numbers);
  }

  final List<int> components;
  @override
  int compareTo(WindowsUpdateVersion other) {
    for (var index = 0; index < 3; index++) {
      final result = components[index].compareTo(other.components[index]);
      if (result != 0) return result;
    }
    return 0;
  }

  @override
  bool operator ==(Object other) =>
      other is WindowsUpdateVersion && compareTo(other) == 0;
  @override
  int get hashCode => Object.hashAll(components);
  @override
  String toString() => components.join('.');
}

enum WindowsUpdatePackage { installer, portable }

class WindowsUpdateRelease {
  const WindowsUpdateRelease({
    required this.version,
    required this.downloadUrl,
    required this.sha256,
    required this.releaseNotes,
    this.minWindowsBuild,
    this.package = WindowsUpdatePackage.installer,
  });

  factory WindowsUpdateRelease.fromJson(
    Map<String, dynamic> json, {
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
  }) {
    final version = json['version'];
    final url = json['download_url'];
    final hash = json['sha256'];
    final notes = json['release_notes'];
    final minBuild = json['min_windows_build'];
    if (version is! String ||
        url is! String ||
        url.length > 8192 ||
        url.codeUnits.any((unit) => unit <= 32 || unit == 127) ||
        RegExp(r'^https://[^/?#]*@', caseSensitive: false).hasMatch(url) ||
        hash is! String ||
        hash.length != 64 ||
        !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(hash) ||
        notes is! String ||
        notes.contains('\u0000') ||
        utf8.encode(notes).length > 16384 ||
        (json.containsKey('min_windows_build') &&
            (minBuild is! int || minBuild <= 0 || minBuild > 0x7fffffff))) {
      throw const FormatException('Invalid Windows update manifest.');
    }
    final uri = Uri.tryParse(url);
    if (uri == null ||
        uri.scheme != 'https' ||
        !uri.hasAuthority ||
        uri.host.isEmpty ||
        uri.authority.contains('@') ||
        uri.hasFragment ||
        uri.port < 1 ||
        uri.port > 65535 ||
        !(package == WindowsUpdatePackage.portable
            ? uri.path.toLowerCase().endsWith('.zip')
            : uri.path.toLowerCase().endsWith('.exe') ||
                  uri.path.toLowerCase().endsWith('.msi'))) {
      throw const FormatException('Invalid Windows update URL.');
    }
    return WindowsUpdateRelease(
      version: WindowsUpdateVersion.parse(version),
      downloadUrl: uri,
      sha256: hash.toLowerCase(),
      releaseNotes: notes,
      minWindowsBuild: minBuild as int?,
      package: package,
    );
  }

  final WindowsUpdateVersion version;
  final Uri downloadUrl;
  final String sha256;
  final String releaseNotes;
  final int? minWindowsBuild;
  final WindowsUpdatePackage package;

  /// MSI publications are valid discovery metadata, but the native installer
  /// updater accepts the signed EXE bundle only. Portable updates use ZIP.
  bool get supportsAutomaticUpdate => package == WindowsUpdatePackage.portable
      ? downloadUrl.path.toLowerCase().endsWith('.zip')
      : downloadUrl.path.toLowerCase().endsWith('.exe');
  bool get requiresManualInstallation =>
      package == WindowsUpdatePackage.installer &&
      downloadUrl.path.toLowerCase().endsWith('.msi');

  /// Notes may change without changing the verified installation artifact.
  bool sameArtifact(WindowsUpdateRelease other) =>
      version == other.version &&
      downloadUrl == other.downloadUrl &&
      sha256 == other.sha256 &&
      package == other.package &&
      minWindowsBuild == other.minWindowsBuild;
}

enum WindowsInstallationMode { installed, portable, unavailable }

class WindowsUpdateEnvironment {
  const WindowsUpdateEnvironment({
    required this.version,
    required this.windowsBuild,
    required this.arch,
    required this.installationMode,
  });

  factory WindowsUpdateEnvironment.fromMap(Map<Object?, Object?> value) {
    final version = value['version'];
    final build = value['windows_build'];
    final arch = value['arch'];
    final mode = value['installation_mode'];
    if (version is! String ||
        build is! int ||
        build <= 0 ||
        build > 0x7fffffff ||
        arch is! String ||
        !const {'x64', 'x86', 'arm64'}.contains(arch) ||
        mode is! String ||
        !WindowsInstallationMode.values.any((item) => item.name == mode)) {
      throw const FormatException('Invalid Windows update environment.');
    }
    return WindowsUpdateEnvironment(
      version: WindowsUpdateVersion.parse(version),
      windowsBuild: build,
      arch: arch,
      installationMode: WindowsInstallationMode.values.byName(mode),
    );
  }
  final WindowsUpdateVersion version;
  final int windowsBuild;
  final String arch;
  final WindowsInstallationMode installationMode;
  WindowsUpdatePackage get package =>
      installationMode == WindowsInstallationMode.portable
      ? WindowsUpdatePackage.portable
      : WindowsUpdatePackage.installer;
}

class WindowsUpdateFailure implements Exception {
  const WindowsUpdateFailure(
    this.code, {
    this.statusCode,
    this.stage,
    this.windowsError,
    this.trustStatus,
    String? tlsReason,
    // Keep a public named argument while validating its private backing field.
    // ignore: prefer_initializing_formals
  }) : _tlsReason = tlsReason;

  /// Retain only documented native diagnostics. Native messages and arbitrary
  /// detail values can contain file paths, download credentials or user data.
  factory WindowsUpdateFailure.fromNative(
    String code,
    Object? details, {
    String? fallbackStage,
  }) {
    final values = details is Map ? details : const <Object?, Object?>{};
    final nativeStage = values['stage'];
    final httpStatus = values['http_status'];
    final windowsError = values['windows_error'];
    final trustStatus = values['trust_status'];
    return WindowsUpdateFailure(
      code,
      stage: nativeStage is String && diagnosticStages.contains(nativeStage)
          ? nativeStage
          : fallbackStage,
      statusCode: httpStatus is int && httpStatus >= 100 && httpStatus <= 599
          ? httpStatus
          : null,
      windowsError:
          windowsError is int && windowsError > 0 && windowsError <= 0xffffffff
          ? windowsError
          : null,
      trustStatus:
          trustStatus is int &&
              trustStatus >= -0x80000000 &&
              trustStatus <= 0xffffffff &&
              trustStatus != 0
          ? trustStatus & 0xffffffff
          : null,
    );
  }

  static const diagnosticStages = {
    'update_check',
    'prepare_update',
    'install_update',
    'discard_update',
    'environment',
    'application_open',
    'application_architecture',
    'application_signature',
    'application_version',
    'target_version',
    'staging_create',
    'download_url',
    'download_session',
    'download_connect',
    'download_request',
    'download_options',
    'download_send',
    'download_receive',
    'download_headers',
    'download_http',
    'download_create_file',
    'download_read',
    'download_size',
    'download_write',
    'download_deadline',
    'download_empty',
    'download_flush',
    'package_open',
    'package_architecture',
    'package_hash',
    'package_signature',
    'package_publisher',
    'package_version',
    'token_create',
    'installation_security',
    'helper_open',
    'helper_architecture',
    'helper_signature',
    'helper_publisher',
    'install_launch',
    'install_wait',
    'install_exit',
    'prepare_exception',
    'install_exception',
    'portable_hash',
    'portable_archive',
    'portable_extract',
    'portable_bundle',
    'portable_manifest',
    'portable_target',
    'portable_helper_copy',
    'portable_helper_signature',
    'portable_launch',
    'portable_ready',
    'portable_wait',
    'portable_replace',
    'portable_rollback',
    'portable_restart',
  };

  final String code;
  final int? statusCode;
  final String? stage;
  final int? windowsError;
  final int? trustStatus;
  final String? _tlsReason;

  /// Only bounded TLS classifications may reach UI, logs or error text.
  String? get tlsReason =>
      DiagnosticLog.tlsFailureReasons.contains(_tlsReason) ? _tlsReason : null;

  WindowsUpdateFailure withStage(String? fallbackStage) => stage != null
      ? this
      : WindowsUpdateFailure(
          code,
          statusCode: statusCode,
          stage: fallbackStage,
          windowsError: windowsError,
          trustStatus: trustStatus,
          tlsReason: tlsReason,
        );

  @override
  String toString() =>
      'WindowsUpdateFailure($code'
      '${stage == null ? '' : ', stage: $stage'}'
      '${statusCode == null ? '' : ', HTTP: $statusCode'}'
      '${windowsError == null ? '' : ', Windows: $windowsError'}'
      '${tlsReason == null ? '' : ', TLS: $tlsReason'}'
      '${trustStatus == null ? '' : ', trust: $trustStatus'})';
}
