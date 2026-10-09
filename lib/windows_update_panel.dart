// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import 'app_theme.dart';
import 'brand_config.dart';
import 'core/windows_update_controller.dart';
import 'l10n/app_localizations.dart';

/// The same controls remain available from Settings and the sign-in dialog.
class WindowsUpdatePanel extends StatelessWidget {
  const WindowsUpdatePanel({
    super.key,
    required this.controller,
    required this.onInstall,
    this.canInstall = true,
    this.installationError,
  });

  final WindowsUpdateController controller;
  final Future<void> Function() onInstall;
  final bool canInstall;
  final String? installationError;

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: controller,
    builder: (context, _) {
      final state = controller.status;
      final release = controller.release;
      final manualInstallation = controller.requiresManualInstallation;
      final failure = installationError == null ? controller.error : null;
      final error =
          installationError ??
          (failure == null || manualInstallation
              ? null
              : _updateError(failure.code));
      return Card(
        clipBehavior: Clip.antiAlias,
        child: Padding(
          padding: const EdgeInsets.all(22),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            mainAxisSize: MainAxisSize.min,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    width: 40,
                    height: 40,
                    decoration: BoxDecoration(
                      color: AppTheme.signal.withValues(alpha: 0.18),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Icon(Icons.system_update_alt, size: 20),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          context.tr('Mises à jour'),
                          style: Theme.of(context).textTheme.titleLarge,
                        ),
                        if (controller.environment case final environment?) ...[
                          const SizedBox(height: 6),
                          Text(
                            context
                                .tr('Version actuelle : {version}')
                                .replaceAll(
                                  '{version}',
                                  environment.version.toString(),
                                ),
                            style: Theme.of(context).textTheme.bodyMedium
                                ?.copyWith(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onSurfaceVariant,
                                ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 22),
              const Divider(height: 1),
              const SizedBox(height: 22),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    manualInstallation
                        ? Icons.info_outline
                        : _statusIcon(state),
                    size: 22,
                    color: manualInstallation
                        ? Theme.of(context).colorScheme.onSurfaceVariant
                        : switch (state) {
                            WindowsUpdateStatus.noUpdate ||
                            WindowsUpdateStatus.ready => AppTheme.successFor(
                              context,
                            ),
                            WindowsUpdateStatus.error ||
                            WindowsUpdateStatus.unsupported => Theme.of(
                              context,
                            ).colorScheme.error,
                            _ => Theme.of(context).colorScheme.onSurfaceVariant,
                          },
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Semantics(
                      liveRegion: true,
                      child: Text(
                        context.tr(
                          manualInstallation
                              ? 'Une nouvelle version est disponible.'
                              : _statusText(
                                  state,
                                  portable: controller.isPortable,
                                ),
                        ),
                        style: Theme.of(context).textTheme.titleSmall,
                      ),
                    ),
                  ),
                ],
              ),
              if (controller.environment?.installationMode ==
                  WindowsInstallationMode.unavailable) ...[
                const SizedBox(height: 8),
                Text(
                  context.tr(_distributionUnavailableMessage),
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
              if (manualInstallation) ...[
                const SizedBox(height: 12),
                Text(
                  context.tr(
                    'Cette mise à jour nécessite une installation manuelle depuis le site FuzeVPN.',
                  ),
                ),
              ],
              if (controller.isBusy) ...[
                const SizedBox(height: 12),
                const LinearProgressIndicator(),
              ],
              if (release != null && state != WindowsUpdateStatus.noUpdate) ...[
                const SizedBox(height: 20),
                Text(
                  context
                      .tr('Version disponible : {version}')
                      .replaceAll('{version}', release.version.toString()),
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                if (release.releaseNotes.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Theme.of(context)
                          .colorScheme
                          .surfaceContainerHighest
                          .withValues(alpha: 0.5),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: Theme.of(context).colorScheme.outlineVariant,
                      ),
                    ),
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(maxHeight: 160),
                      child: SingleChildScrollView(
                        child: SelectableText(
                          release.releaseNotes,
                          style: Theme.of(context).textTheme.bodyMedium,
                        ),
                      ),
                    ),
                  ),
                ],
              ],
              if (error != null) ...[
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Theme.of(
                      context,
                    ).colorScheme.error.withValues(alpha: 0.07),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: Theme.of(
                        context,
                      ).colorScheme.error.withValues(alpha: 0.25),
                    ),
                  ),
                  child: Semantics(
                    liveRegion: true,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          context.tr(error),
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                          ),
                        ),
                        if (failure != null) ...[
                          const SizedBox(height: 10),
                          SelectableText(
                            _updateDiagnostics(context, failure),
                            textDirection: TextDirection.ltr,
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              ],
              if (state != WindowsUpdateStatus.disabledForTesting) ...[
                const SizedBox(height: 22),
                const Divider(height: 1),
                const SizedBox(height: 20),
                Wrap(
                  spacing: 12,
                  runSpacing: 10,
                  children: [
                    OutlinedButton.icon(
                      onPressed:
                          controller.isBusy ||
                              state == WindowsUpdateStatus.launched
                          ? null
                          : controller.checkForUpdates,
                      icon: const Icon(Icons.refresh),
                      label: Text(context.tr('Rechercher une mise à jour')),
                    ),
                    if (manualInstallation)
                      OutlinedButton.icon(
                        onPressed: controller.isBusy
                            ? null
                            : () => _openOfficialWebsite(context),
                        icon: const Icon(Icons.open_in_new),
                        label: Text(context.tr('Ouvrir le site FuzeVPN')),
                      ),
                    if (controller.canAutomaticallyUpdate &&
                        (state == WindowsUpdateStatus.available ||
                            (state == WindowsUpdateStatus.error &&
                                release != null)))
                      FilledButton.icon(
                        onPressed: controller.prepareUpdate,
                        icon: const Icon(Icons.download_outlined),
                        label: Text(context.tr('Télécharger la mise à jour')),
                      ),
                    if (controller.canAutomaticallyUpdate &&
                        state == WindowsUpdateStatus.ready)
                      FilledButton.icon(
                        onPressed: canInstall
                            ? () => _confirmInstall(context)
                            : null,
                        icon: const Icon(Icons.system_update_alt),
                        label: Text(context.tr('Installer maintenant')),
                      ),
                  ],
                ),
              ],
              if (controller.canUpdate &&
                  state == WindowsUpdateStatus.ready &&
                  !canInstall) ...[
                const SizedBox(height: 8),
                Text(
                  context.tr(
                    'Terminez l’opération VPN en cours avant de mettre à jour.',
                  ),
                ),
              ],
            ],
          ),
        ),
      );
    },
  );

  Future<void> _confirmInstall(BuildContext context) async {
    if (!controller.canAutomaticallyUpdate) return;
    final accepted = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        scrollable: true,
        icon: const Icon(Icons.system_update_alt),
        titleTextStyle: Theme.of(dialogContext).textTheme.headlineSmall,
        title: Text(dialogContext.tr('Installer la mise à jour ?')),
        content: Text(
          dialogContext.tr(
            'Le VPN sera déconnecté et FuzeVPN se fermera pendant l’installation. Vos préférences seront conservées.',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: Text(dialogContext.tr('Plus tard')),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: Text(dialogContext.tr('Installer maintenant')),
          ),
        ],
      ),
    );
    if (accepted == true && context.mounted) await onInstall();
  }

  Future<void> _openOfficialWebsite(BuildContext context) async {
    var opened = false;
    try {
      opened = await launchUrl(
        BrandConfig.website(Localizations.localeOf(context).languageCode),
        mode: LaunchMode.externalApplication,
      );
    } catch (_) {
      // Browser failures remain inside the visible action's feedback.
    }
    if (!opened && context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(context.tr('Le navigateur n’a pas pu être ouvert.')),
        ),
      );
    }
  }
}

IconData _statusIcon(WindowsUpdateStatus state) => switch (state) {
  WindowsUpdateStatus.idle => Icons.update_outlined,
  WindowsUpdateStatus.disabledForTesting => Icons.info_outline,
  WindowsUpdateStatus.checking => Icons.search_outlined,
  WindowsUpdateStatus.available => Icons.new_releases_outlined,
  WindowsUpdateStatus.noUpdate ||
  WindowsUpdateStatus.ready => Icons.check_circle_outline,
  WindowsUpdateStatus.downloading => Icons.download_outlined,
  WindowsUpdateStatus.installing ||
  WindowsUpdateStatus.launched => Icons.system_update_alt,
  WindowsUpdateStatus.unsupported ||
  WindowsUpdateStatus.error => Icons.error_outline,
};

const _portableUpdateMessage =
    'Version portable : pour mettre à jour, fermez FuzeVPN et remplacez son dossier par celui de la nouvelle archive portable.';
const _distributionUnavailableMessage =
    'Le type d’installation ne peut pas être vérifié. Le téléchargement et l’installation des mises à jour sont désactivés.';

String _statusText(WindowsUpdateStatus state, {bool portable = false}) =>
    switch (state) {
      WindowsUpdateStatus.idle => 'Recherchez une nouvelle version de FuzeVPN.',
      WindowsUpdateStatus.disabledForTesting =>
        'Mises à jour désactivées dans cette version de test.',
      WindowsUpdateStatus.checking => 'Recherche de mises à jour…',
      WindowsUpdateStatus.available => 'Une nouvelle version est disponible.',
      WindowsUpdateStatus.noUpdate => 'Aucune mise à jour disponible.',
      WindowsUpdateStatus.downloading => 'Téléchargement et vérification…',
      WindowsUpdateStatus.ready => 'La mise à jour est prête.',
      WindowsUpdateStatus.installing => 'Préparation de l’installation…',
      WindowsUpdateStatus.launched =>
        portable
            ? 'Fermez FuzeVPN pour terminer la mise à jour.'
            : 'L’installateur est ouvert. Fermez FuzeVPN pour continuer.',
      WindowsUpdateStatus.unsupported =>
        'Cette mise à jour n’est pas compatible avec cet ordinateur.',
      WindowsUpdateStatus.error => 'Échec de la mise à jour',
    };

String _updateError(String code) => switch (code) {
  'update_unsupported' =>
    'Cette mise à jour n’est pas compatible avec cet ordinateur.',
  'update_portable_manual' => _portableUpdateMessage,
  'update_environment_unavailable' => _distributionUnavailableMessage,
  'maintenance_in_progress' =>
    'Une installation est déjà en cours. Réessayez une fois terminée.',
  'update_installation_unprotected' =>
    'Installez FuzeVPN avec l’installateur officiel signé pour activer les mises à jour.',
  'update_busy' => 'Terminez l’opération VPN en cours avant de mettre à jour.',
  'update_vpn_cleanup_failed' =>
    'L’arrêt du VPN n’a pas pu être confirmé. La mise à jour est interrompue.',
  'update_changed' =>
    'La publication a changé. Recherchez de nouveau une mise à jour.',
  'update_package_mode_mismatch' =>
    'La publication a changé. Recherchez de nouveau une mise à jour.',
  'update_cancelled' ||
  'update_uac_cancelled' => 'L’installation a été annulée.',
  'update_unsigned_application' =>
    'Cette version de FuzeVPN n’est pas signée. Installez manuellement la version officielle signée pour activer les mises à jour.',
  'update_application_signature_invalid' =>
    'La signature de la version installée de FuzeVPN n’est pas valide. Installez manuellement la version officielle signée.',
  'update_application_open_failed' =>
    'Windows n’a pas pu ouvrir la version installée de FuzeVPN.',
  'update_application_architecture_mismatch' =>
    'La version installée de FuzeVPN n’est pas compatible avec l’architecture de cet ordinateur.',
  'update_download_http_error' =>
    'Le serveur de téléchargement a refusé la demande.',
  'update_download_network_error' =>
    'Le téléchargement a été interrompu par une erreur réseau.',
  'update_network_failed' =>
    'Le service de mises à jour est inaccessible. Vérifiez votre connexion Internet.',
  'tls_handshake_failed' =>
    'La connexion sécurisée au service n’a pas pu être vérifiée.',
  'api_bootstrap_unavailable' || 'api_resolution_unavailable' =>
    'FuzeVPN ne peut pas utiliser la configuration réseau de cet ordinateur pour joindre le service.',
  'update_download_timeout' =>
    'Le délai de téléchargement a été dépassé. Réessayez.',
  'update_network_timeout' =>
    'Le délai de réponse du service de mises à jour a été dépassé. Réessayez.',
  'update_download_redirect_rejected' =>
    'Le téléchargement a été redirigé vers une adresse non autorisée.',
  'update_download_url_invalid' =>
    'L’adresse de téléchargement de la mise à jour est invalide.',
  'update_download_empty' => 'Le serveur a renvoyé un fichier vide.',
  'update_download_too_large' || 'update_archive_too_large' =>
    'Le fichier de mise à jour dépasse la taille autorisée.',
  'update_storage_failed' ||
  'update_archive_extract_failed' ||
  'update_portable_replace_failed' =>
    'Windows n’a pas pu enregistrer la mise à jour. Vérifiez l’espace disque et les autorisations.',
  'update_hash_mismatch' =>
    'Le SHA-256 du fichier reçu diffère de celui annoncé.',
  'update_publisher_mismatch' || 'update_untrusted_publisher' =>
    'L’éditeur du fichier reçu ne correspond pas à FuzeVPN.',
  'update_package_architecture_mismatch' =>
    'Le fichier reçu n’est pas compatible avec l’architecture de cet ordinateur.',
  'update_package_version_mismatch' || 'update_version_mismatch' =>
    'La version du fichier reçu diffère de celle annoncée.',
  'invalid_argument' || 'update_manifest_invalid' =>
    'La réponse du service de mises à jour est invalide.',
  'update_environment_invalid' => _distributionUnavailableMessage,
  'update_portable_target_invalid' =>
    'Le dossier portable ne peut pas être mis à jour. Déplacez FuzeVPN dans un dossier accessible en écriture et réessayez.',
  'update_request_failed' ||
  'api_resolver_invalid_response' ||
  'api_transport_unsupported' ||
  'broker_busy' ||
  'broker_protocol_error' ||
  'broker_response_timeout' ||
  'broker_unavailable' ||
  'broker_write_failed' ||
  'native_bridge_unavailable' ||
  'native_operation_failed' ||
  'permission_denied' ||
  'runtime_owned_by_another_user' ||
  'runtime_detection_failed' ||
  'runtime_status_unavailable' ||
  'runtime_unavailable' ||
  'service_configuration_mismatch' ||
  'service_unavailable' => 'La recherche de mise à jour a échoué.',
  'update_download_failed' => 'Le téléchargement de la mise à jour a échoué.',
  'update_prepare_failed' => 'Windows n’a pas pu préparer la mise à jour.',
  'update_not_prepared' => 'Téléchargez la mise à jour avant de l’installer.',
  'update_install_failed' => 'L’installation de la mise à jour a échoué.',
  'update_unavailable' =>
    'Les mises à jour Windows ne sont pas disponibles dans cette application.',
  'update_signature_invalid' =>
    'La signature de cette mise à jour n’a pas pu être vérifiée.',
  'update_verification_failed' ||
  'update_version_invalid' ||
  'update_archive_invalid' ||
  'update_archive_unsafe' ||
  'update_portable_manifest_invalid' =>
    'Le fichier reçu ne correspond pas à la mise à jour annoncée.',
  _ => 'La mise à jour n’a pas pu être préparée. Réessayez.',
};

String _updateDiagnostics(BuildContext context, WindowsUpdateFailure failure) {
  final lines = ['${context.tr('Code d’erreur')} : ${failure.code}'];
  final stage = failure.stage;
  if (stage != null && WindowsUpdateFailure.diagnosticStages.contains(stage)) {
    lines.add(
      '${context.tr('Étape')} : ${context.tr(_updateStageText(stage))} ($stage)',
    );
  }
  if (failure.statusCode case final status?) lines.add('HTTP : $status');
  if (failure.tlsReason case final reason?) lines.add('TLS : $reason');
  if (failure.windowsError case final code?) {
    lines.add(
      context.tr('Code Windows : {code}').replaceAll('{code}', '$code'),
    );
  }
  if (failure.trustStatus case final code?) {
    final hexadecimal =
        '0x${code.toRadixString(16).padLeft(8, '0').toUpperCase()}';
    lines.add(
      context
          .tr('Code de confiance : {code}')
          .replaceAll('{code}', hexadecimal),
    );
  }
  return lines.join('\n');
}

String _updateStageText(String stage) => switch (stage) {
  'update_check' => 'Service de mises à jour',
  'environment' ||
  'application_open' ||
  'application_architecture' ||
  'application_signature' ||
  'application_version' ||
  'installation_security' => 'Vérification de l’application',
  'staging_create' ||
  'download_create_file' ||
  'download_write' ||
  'download_flush' => 'Enregistrement du fichier',
  'portable_hash' ||
  'portable_archive' ||
  'portable_bundle' ||
  'portable_manifest' ||
  'target_version' ||
  'package_open' ||
  'package_architecture' ||
  'package_hash' ||
  'package_signature' ||
  'package_publisher' ||
  'package_version' ||
  'token_create' => 'Vérification du fichier',
  'portable_target' ||
  'portable_helper_signature' ||
  'portable_launch' ||
  'portable_ready' ||
  'portable_wait' ||
  'portable_replace' ||
  'portable_rollback' ||
  'portable_restart' ||
  'install_update' ||
  'helper_open' ||
  'helper_architecture' ||
  'helper_signature' ||
  'helper_publisher' ||
  'install_launch' ||
  'install_wait' ||
  'install_exit' ||
  'install_exception' => 'Installation',
  'portable_extract' ||
  'portable_helper_copy' ||
  'discard_update' => 'Enregistrement du fichier',
  _ => 'Téléchargement',
};
