// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_theme.dart';

import 'package:fuzevpn_windows/core/diagnostic_log.dart';

void main() {
  test(
    'diagnostics serialize asynchronous writes and redact unsafe fields',
    () async {
      final path = DiagnosticLog.filePath;
      expect(path, isNotNull, reason: 'Use the isolated project test runner.');
      final file = File(path!);
      final writes = <Future<void>>[];
      for (var i = 0; i < 30; i++) {
        writes.add(
          DiagnosticLog.record(
            area: 'audit_test',
            event: 'event_$i',
            code: 'secret with spaces',
          ),
        );
      }
      await Future.wait(writes);
      await DiagnosticLog.flush();
      final content = await file.readAsString();
      for (var i = 0; i < 30; i++) {
        expect(content, contains('event=event_$i code=redacted'));
      }
      expect(content, isNot(contains('secret with spaces')));
    },
  );

  testWidgets('semantic text colors remain readable in both themes', (
    tester,
  ) async {
    for (final theme in [AppTheme.light(), AppTheme.dark()]) {
      late BuildContext context;
      await tester.pumpWidget(
        MaterialApp(
          theme: theme,
          home: Builder(
            builder: (value) {
              context = value;
              return const SizedBox.shrink();
            },
          ),
        ),
      );
      await tester.pumpAndSettle();
      final colors = [
        AppTheme.successFor(context),
        AppTheme.warningFor(context),
        theme.colorScheme.error,
      ];
      for (final background in [
        theme.colorScheme.surface,
        theme.colorScheme.surfaceContainerHighest,
        theme.scaffoldBackgroundColor,
      ]) {
        for (final color in colors) {
          final a = color.computeLuminance();
          final b = background.computeLuminance();
          final ratio =
              (a > b ? a + .05 : b + .05) / (a > b ? b + .05 : a + .05);
          expect(
            ratio,
            greaterThanOrEqualTo(4.5),
            reason: '${theme.brightness} $color / $background',
          );
        }
      }
    }
  });
}
