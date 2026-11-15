// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app_controller.dart';
import 'app_theme.dart';
import 'core/models.dart';
import 'core/window_bridge.dart';
import 'l10n/app_localizations.dart';

final _pendingExitDialogs = <AppController>{};

/// Shared by the account panel, the sign-in dialog, the Windows
/// notification-area menu and a close request that no notification-area icon
/// can absorb.
///
/// Quitting is never refused. In an installed copy, it closes the interface
/// only: the Windows service keeps the tunnel, the kill switch and an
/// operation it already received, and the dialog offers Disconnect beside it
/// while something is engaged. In a portable copy, Quit first performs the
/// explicit stop, which is what releases the protections, and closes once
/// that stop is confirmed; pressing Quit again closes at once.
Future<void> requestAppExit(
  BuildContext context,
  AppController controller,
) async {
  if (!_pendingExitDialogs.add(controller)) return;
  // Normally loaded by the startup update check, which may have failed.
  unawaited(controller.updates.ensureInstallationMode());
  try {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => _ExitDialog(controller: controller),
    );
    if (confirmed != true) return;
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

/// Pops `true` when the application must close now, `false` or nothing when
/// it stays open. It never calls the native exit itself.
class _ExitDialog extends StatefulWidget {
  const _ExitDialog({required this.controller});

  final AppController controller;

  @override
  State<_ExitDialog> createState() => _ExitDialogState();
}

class _ExitDialogState extends State<_ExitDialog> {
  // A stop requested from this dialog has not settled yet.
  bool _stopRequested = false;
  // Portable: that stop was requested by Quit, which closes once it is
  // confirmed. Pressing Quit again meanwhile closes at once.
  bool _quitWhenStopped = false;
  // The last stop requested from this dialog left a tunnel, a protection or
  // an unknown state behind.
  bool _stopFailed = false;
  VoidCallback? _settleListener;
  Completer<void>? _settled;

  AppController get _controller => widget.controller;

  // An explicit stop runs, started here or anywhere else, or another flow
  // (sign-out, update, device removal) is stopping the VPN.
  bool get _stopping =>
      _controller.isStoppingVpn ||
      (_controller.vpnStatus == VpnStatus.disconnecting &&
          !_controller.canCancelConnection);

  bool get _idle =>
      _controller.vpnStatus == VpnStatus.disconnected &&
      !_controller.requiresExplicitDisconnect &&
      !_controller.runtimeVerificationPending;

  @override
  void dispose() {
    _releaseSettleListener();
    super.dispose();
  }

  void _releaseSettleListener() {
    final listener = _settleListener;
    if (listener != null) _controller.removeListener(listener);
    _settleListener = null;
    final settled = _settled;
    if (settled != null && !settled.isCompleted) settled.complete();
    _settled = null;
  }

  // A stop this dialog could only join (a sign-out or a device removal
  // performs its own) may outlast the request it answered.
  Future<void> _stopSettled() {
    if (!_stopping) return Future<void>.value();
    _releaseSettleListener();
    final settled = Completer<void>();
    void listener() {
      if (!_stopping) _releaseSettleListener();
    }

    _settled = settled;
    _settleListener = listener;
    _controller.addListener(listener);
    return settled.future;
  }

  /// Returns whether the disconnected state was confirmed.
  Future<bool> _stop() async {
    setState(() {
      _stopRequested = true;
      _stopFailed = false;
    });
    try {
      await _controller.disconnectVpn();
    } catch (_) {
      // The controller's state tells the outcome.
    }
    if (!mounted) return false;
    await _stopSettled();
    if (!mounted) return false;
    final confirmed = _idle;
    setState(() {
      _stopRequested = false;
      _stopFailed = !confirmed;
    });
    return confirmed;
  }

  Future<void> _stopThenQuit() async {
    setState(() => _quitWhenStopped = true);
    final confirmed = await _stop();
    // Dismissed meanwhile: the stop still completes, the application stays.
    if (!mounted) return;
    setState(() => _quitWhenStopped = false);
    if (confirmed) Navigator.pop(context, true);
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: Listenable.merge([_controller, _controller.updates]),
    builder: (context, _) {
      final theme = Theme.of(context);
      final controller = _controller;
      // Anything not known to be installed (portable, unknown or unreadable)
      // is treated as portable: quitting it without the stop would leave the
      // kill switch with nothing to release it.
      final portable = !controller.updates.canUseInstaller;
      final stopping = _stopping;
      // Something a Disconnect would stop or release right now. A healthy
      // tunnel counts only in a portable copy, whose Quit stops it, and there
      // even while another operation briefly holds the stop back:
      // disconnectVpn() waits for it.
      final engaged = portable
          ? controller.canCancelConnection ||
                controller.requiresExplicitDisconnect ||
                controller.retainsBlockingProtection ||
                controller.runtimeVerificationPending
          : controller.canDisconnectVpn &&
                (controller.canCancelConnection ||
                    controller.retainsBlockingProtection ||
                    controller.runtimeVerificationPending);
      // Busy with something a stop cannot interrupt.
      final otherBusy =
          controller.isConnectionBusy &&
          !controller.canCancelConnection &&
          !stopping;
      final failed = _stopFailed && !stopping && !_idle;
      final String message;
      if (stopping) {
        message = 'Nous arrêtons le tunnel VPN en toute sécurité.';
      } else if (failed) {
        message =
            controller.errorMessage ??
            'La déconnexion VPN n’a pas pu être confirmée. Réessayez la déconnexion.';
      } else if (otherBusy) {
        message = 'Veuillez patienter pendant l’opération VPN en cours.';
      } else if (portable) {
        message =
            'FuzeVPN va se fermer. En version portable, le VPN sera arrêté et ses protections seront retirées si le nettoyage réussit.';
      } else if (engaged && controller.retainsBlockingProtection) {
        message =
            'Le kill switch empêche toute fuite. Déconnecter rétablit votre accès Internet.';
      } else {
        message =
            'FuzeVPN va se fermer. Le VPN peut rester actif si le service Windows est installé.';
      }
      // Installed: offered beside Quit while something is engaged. Portable:
      // only as the retry of a stop that failed, since Quit stops by itself.
      // It stays in place, disabled, while the stop it started runs, so that
      // no other button slides under the pointer.
      final offersDisconnect =
          (failed && controller.canDisconnectVpn) ||
          (!portable && engaged) ||
          (_stopRequested && !_quitWhenStopped);
      // Installed: the service outlives this window with whatever it holds.
      final interfaceOnly =
          !portable && (engaged || stopping || otherBusy || failed);
      // Portable: the first press stops, then closes once that is confirmed.
      // A press while that stop runs, or after it failed, closes at once.
      final stopsBeforeQuit =
          portable && !_quitWhenStopped && !failed && (engaged || stopping);
      return AlertDialog(
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
        titleTextStyle: theme.textTheme.headlineSmall,
        title: Text(context.tr('Quitter FuzeVPN ?')),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Divider(height: 1),
            const SizedBox(height: 20),
            Text(
              context.tr(message),
              style: theme.textTheme.bodyLarge?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (stopping || otherBusy) ...[
              const SizedBox(height: 20),
              const LinearProgressIndicator(),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(context.tr('Annuler')),
          ),
          if (offersDisconnect)
            OutlinedButton(
              key: const ValueKey('exit-disconnect'),
              onPressed: stopping || !controller.canDisconnectVpn
                  ? null
                  : _stop,
              child: Text(context.tr('Déconnecter')),
            ),
          // Never disabled: an operation in progress, an update that could
          // not close the window or a kill switch cannot keep the user here.
          FilledButton(
            key: const ValueKey('exit-quit'),
            onPressed: stopsBeforeQuit
                ? _stopThenQuit
                : () => Navigator.pop(context, true),
            child: Text(
              context.tr(
                interfaceOnly
                    ? 'Quitter l’interface FuzeVPN'
                    : 'Quitter FuzeVPN',
              ),
            ),
          ),
        ],
      );
    },
  );
}
