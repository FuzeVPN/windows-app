// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app_controller.dart';
import 'app_theme.dart';
import 'core/window_bridge.dart';
import 'l10n/app_localizations.dart';

final _pendingExitDialogs = <AppController>{};

/// Shared by the account panel and the Windows notification-area menu.
Future<void> requestAppExit(
  BuildContext context,
  AppController controller,
) async {
  if (!_pendingExitDialogs.add(controller)) return;
  try {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AnimatedBuilder(
        animation: controller,
        builder: (context, _) => AlertDialog(
          scrollable: true,
          icon: Align(
            alignment: AlignmentDirectional.centerStart,
            child: Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: AppTheme.signal.withValues(alpha: 0.18),
                borderRadius: BorderRadius.circular(14),
              ),
              child: const Icon(Icons.power_settings_new_outlined, size: 24),
            ),
          ),
          titleTextStyle: Theme.of(context).textTheme.headlineSmall,
          title: Text(context.tr('Quitter FuzeVPN ?')),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Divider(height: 1),
              const SizedBox(height: 20),
              Text(
                context.tr(
                  controller.isConnectionBusy
                      ? 'Veuillez patienter pendant l’opération VPN en cours.'
                      : controller.updates.isPortable
                      ? 'FuzeVPN va se fermer. En version portable, le VPN sera arrêté et ses protections seront retirées si le nettoyage réussit.'
                      : 'FuzeVPN va se fermer. Le VPN peut rester actif si le service Windows est installé.',
                ),
                style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              if (controller.isConnectionBusy) ...[
                const SizedBox(height: 20),
                const LinearProgressIndicator(),
              ],
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, false),
              child: Text(context.tr('Annuler')),
            ),
            FilledButton(
              onPressed: controller.isConnectionBusy
                  ? null
                  : () => Navigator.pop(dialogContext, true),
              child: Text(context.tr('Quitter FuzeVPN')),
            ),
          ],
        ),
      ),
    );
    if (confirmed != true || controller.isConnectionBusy) return;
    try {
      await const WindowBridge().quit();
    } on PlatformException {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            context.tr('Impossible de quitter FuzeVPN. Réessayez.'),
          ),
        ),
      );
    }
  } finally {
    _pendingExitDialogs.remove(controller);
  }
}
