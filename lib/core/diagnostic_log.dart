// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:collection';
import 'dart:io';

/// Writes a small, local, secret-free execution trace for VPN operations.
///
/// Callers may provide only stable identifiers. Messages, API bodies, tunnel
/// configurations, addresses, keys, tokens and exception details are never
/// accepted by this API.
class DiagnosticLog {
  DiagnosticLog._();

  static const _maxBytes = 256 * 1024;
  static final RegExp _safeIdentifier = RegExp(r'^[a-z0-9_.-]{1,80}$');
  static const _maxPendingLines = 256;
  static final _pending = Queue<String>();
  static Future<void>? _writer;
  static final _observers = <void Function(String, String, String?)>{};

  /// Observers receive identifiers only. They must not perform synchronous I/O;
  /// a collector failure must never affect a VPN operation.
  static void Function() observe(
    void Function(String area, String event, String? code) observer,
  ) {
    _observers.add(observer);
    return () => _observers.remove(observer);
  }

  static String? get filePath {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    if (localAppData == null || localAppData.isEmpty) return null;
    return '$localAppData${Platform.pathSeparator}FuzeVPN'
        '${Platform.pathSeparator}diagnostic.log';
  }

  static Future<void> record({
    required String area,
    required String event,
    String? code,
  }) {
    final safeArea = _sanitize(area);
    final safeEvent = _sanitize(event);
    final safeCode = code == null ? null : _sanitize(code);
    for (final observer in _observers.toList(growable: false)) {
      try {
        observer(safeArea, safeEvent, safeCode);
      } catch (_) {
        // Diagnostics are strictly best-effort and outside the VPN lifecycle.
      }
    }
    final line = <String>[
      DateTime.now().toUtc().toIso8601String(),
      'area=$safeArea',
      'event=$safeEvent',
      if (safeCode != null) 'code=$safeCode',
    ].join(' ');

    // Bound memory during slow disk/antivirus operations. Keep the most
    // recent diagnostics and serialize rotation with appends.
    if (_pending.length == _maxPendingLines) _pending.removeFirst();
    _pending.addLast(line);
    unawaited(_writer ??= _drain());
    // Existing callers may await record; disk latency must never become a
    // dependency of the VPN command itself.
    return Future<void>.value();
  }

  /// Waits for diagnostics when explicitly needed, e.g. a local export/test.
  static Future<void> flush() => _writer ?? Future<void>.value();

  static String _sanitize(String value) =>
      _safeIdentifier.hasMatch(value) ? value : 'redacted';

  static Future<void> _drain() async {
    try {
      while (_pending.isNotEmpty) {
        final batch = <String>[];
        while (_pending.isNotEmpty) {
          batch.add(_pending.removeFirst());
        }
        try {
          await _append(batch.join('\r\n'));
        } on FileSystemException {
          // Logging failure must not change the result of a VPN operation.
        }
      }
    } finally {
      _writer = null;
    }
  }

  static Future<void> _append(String line) async {
    final path = filePath;
    if (path == null) return;
    final file = File(path);
    await file.parent.create(recursive: true);
    if (await file.exists() && await file.length() >= _maxBytes) {
      final previous = File('$path.previous');
      if (await previous.exists()) await previous.delete();
      await file.rename(previous.path);
    }
    await file.writeAsString('$line\r\n', mode: FileMode.append, flush: true);
  }
}
