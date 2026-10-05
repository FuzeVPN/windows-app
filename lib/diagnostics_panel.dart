// SPDX-License-Identifier: MPL-2.0
part of 'app_shell.dart';

class _DiagnosticsPage extends StatelessWidget {
  const _DiagnosticsPage({super.key, required this.controller});
  final AppController controller;

  @override
  Widget build(BuildContext context) => _PageLayout(
    title: 'Diagnostic',
    subtitle: 'Vérifiez le VPN et choisissez les informations à transmettre.',
    maxWidth: 920,
    action: _diagnosticSupportButton(context),
    child: _DiagnosticsPanel(controller: controller),
  );
}

Widget _diagnosticSupportButton(BuildContext context) => TextButton.icon(
  onPressed: () => _openWebsite(
    context,
    BrandConfig.support(Localizations.localeOf(context).languageCode),
  ),
  icon: const Icon(Icons.open_in_new, size: 18),
  label: Text(context.tr('Ouvrir l’assistance Web')),
);

Future<void> _showDiagnosticsDialog(
  BuildContext context,
  AppController controller,
) => showDialog<void>(
  context: context,
  builder: (dialogContext) => AnimatedBuilder(
    animation: controller,
    builder: (context, _) => AlertDialog(
      scrollable: true,
      icon: const Icon(Icons.fact_check_outlined),
      titleTextStyle: Theme.of(context).textTheme.headlineSmall,
      title: Text(context.tr('Diagnostic local')),
      content: SizedBox(
        width: 720,
        child: _DiagnosticsPanel(controller: controller),
      ),
      actions: [
        _diagnosticSupportButton(context),
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(),
          child: Text(context.tr('Fermer')),
        ),
      ],
    ),
  ),
);

class _DiagnosticsPanel extends StatefulWidget {
  const _DiagnosticsPanel({required this.controller});
  final AppController controller;

  @override
  State<_DiagnosticsPanel> createState() => _DiagnosticsPanelState();
}

class _DiagnosticsPanelState extends State<_DiagnosticsPanel> {
  bool _send = false;
  String? _sendAccount;
  String? _authorizedReportId;
  AppController get controller => widget.controller;

  Future<void> _run() async {
    final account = controller.profile?.userId;
    final send = account != null && _send;
    await controller.runUserDiagnostic(send: send);
    if (!mounted || account != controller.profile?.userId) return;
    if (send) {
      _authorizedReportId = controller.preparedDiagnosticReport?.reportId;
    }
  }

  void _changeSend(bool? value) {
    final send = value ?? false;
    final reportId = _authorizedReportId;
    setState(() => _send = send);
    if (!send && reportId != null) {
      _authorizedReportId = null;
      if (!controller.diagnostics.receipts.any(
        (r) => r.clientReportId == reportId,
      )) {
        unawaited(controller.cancelDiagnostic(reportId));
      }
    }
  }

  Future<void> _repair() async {
    final accepted = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        scrollable: true,
        icon: const Icon(Icons.build_outlined),
        titleTextStyle: Theme.of(context).textTheme.headlineSmall,
        title: Text(context.tr('Terminer la déconnexion ?')),
        content: Text(
          context.tr(
            'Cette action réessaie l’arrêt du VPN et son nettoyage. Si elle réussit, le tunnel et ses protections sont retirés. Votre connexion Internet habituelle peut reprendre.',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(context.tr('Annuler')),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(context.tr('Terminer la déconnexion')),
          ),
        ],
      ),
    );
    if (accepted == true && mounted) {
      await controller.repairDiagnosticCleanup();
    }
  }

  Future<void> _preview() => showDialog<void>(
    context: context,
    builder: (context) => AlertDialog(
      scrollable: true,
      icon: const Icon(Icons.description_outlined),
      titleTextStyle: Theme.of(context).textTheme.headlineSmall,
      title: Text(context.tr('Contenu du rapport')),
      content: SizedBox(
        width: 720,
        child: SingleChildScrollView(
          child: SelectableText(controller.diagnosticPreview ?? '{}'),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(context.tr('Fermer')),
        ),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) {
    final account = controller.profile?.userId;
    if (account != _sendAccount) {
      _send = false;
      _sendAccount = account;
      _authorizedReportId = null;
    }
    final busy =
        controller.diagnosticRunning || controller.diagnosticRepairRunning;
    final loggedIn = controller.profile != null;
    final checks = controller.diagnosticChecks;
    final passedChecks = checks
        .where((check) => check.result == 'passed')
        .toList();
    final skippedChecks = checks
        .where((check) => check.result == 'skipped')
        .toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _DiagnosticSurface(
          icon: Icons.fact_check_outlined,
          title: 'Diagnostic local',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                context.tr(
                  'Le diagnostic vérifie l’état actuel sans modifier la connexion. Les mesures indisponibles restent indéterminées.',
                ),
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 20),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  FilledButton.icon(
                    onPressed: controller.canRunDiagnostic ? _run : null,
                    icon: const Icon(Icons.fact_check_outlined),
                    label: Text(
                      context.tr(
                        busy ? 'Diagnostic en cours…' : 'Diagnostiquer',
                      ),
                    ),
                  ),
                  if (controller.diagnosticPreview != null)
                    OutlinedButton.icon(
                      onPressed: _preview,
                      icon: const Icon(Icons.description_outlined),
                      label: Text(context.tr('Consulter le rapport')),
                    ),
                  if (controller.canSendPreparedDiagnostic)
                    OutlinedButton.icon(
                      onPressed: controller.sendUserDiagnostic,
                      icon: const Icon(Icons.send_outlined),
                      label: Text(context.tr('Envoyer ce rapport')),
                    ),
                ],
              ),
              if (busy) ...[
                const SizedBox(height: 20),
                const LinearProgressIndicator(),
              ],
              if (controller.isConnectionBusy && !busy) ...[
                const SizedBox(height: 16),
                _DiagnosticNotice(
                  text: 'Attendez la fin de l’opération VPN en cours.',
                ),
              ],
              if (controller.diagnosticMessage case final message?) ...[
                const SizedBox(height: 16),
                Semantics(
                  liveRegion: true,
                  child: _DiagnosticNotice(text: message),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 20),
        _DiagnosticSurface(
          icon: Icons.privacy_tip_outlined,
          title: 'Confidentialité',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                controlAffinity: ListTileControlAffinity.leading,
                title: Text(
                  context.tr('Envoyer le rapport de ce diagnostic'),
                  style: Theme.of(context).textTheme.titleSmall,
                ),
                value: loggedIn && _send,
                onChanged: loggedIn && !busy ? _changeSend : null,
              ),
              Text(
                context.tr(
                  loggedIn
                      ? 'Résultats, versions et chronologie technique liés à votre compte. Conservation sur le serveur : 30 jours. Aucun journal brut, secret ou historique de navigation.'
                      : 'Diagnostic local uniquement. Connectez-vous à votre compte pour autoriser un envoi.',
                ),
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              if (loggedIn) ...[
                const SizedBox(height: 8),
                Text(
                  context.tr(
                    'En cas d’échec d’envoi, le rapport reste chiffré en attente pendant 24 heures au maximum. Vous pouvez annuler les tentatives restantes.',
                  ),
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
        if (checks.isNotEmpty) ...[
          const SizedBox(height: 20),
          Text(
            context.tr('Résultats du diagnostic'),
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 12),
          for (final check in checks)
            if (check.result != 'passed' && check.result != 'skipped')
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Card(child: _DiagnosticCheckTile(check: check)),
              ),
          if (controller.canRepairDiagnosticCleanup) ...[
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: busy ? null : _repair,
              icon: const Icon(Icons.build_outlined),
              label: Text(context.tr('Terminer la déconnexion')),
            ),
          ],
          if (passedChecks.isNotEmpty)
            _DiagnosticCheckGroup(
              group: 'passed',
              title: 'Vérifications réussies ({count})',
              checks: passedChecks,
            ),
          if (skippedChecks.isNotEmpty)
            _DiagnosticCheckGroup(
              group: 'skipped',
              title: 'Vérifications non exécutées ({count})',
              checks: skippedChecks,
            ),
          const SizedBox(height: 8),
          _DiagnosticNotice(
            text:
                'Un paramètre DNS correct ne prouve pas que la résolution fonctionne. L’accès à l’API ne prouve pas l’accès à tous les sites Internet.',
          ),
        ],
        if (controller.diagnosticDeliveryError case final message?) ...[
          const SizedBox(height: 12),
          Semantics(
            liveRegion: true,
            child: _DiagnosticNotice(text: message, isError: true),
          ),
        ],
        if (controller.diagnosticDeliveries.isNotEmpty) ...[
          const SizedBox(height: 20),
          Text(
            context.tr('Envoi des rapports'),
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 12),
          for (final item in controller.diagnosticDeliveries)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Icon(Icons.description_outlined, size: 20),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            context.tr(item.status),
                            style: Theme.of(context).textTheme.titleSmall,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    SelectableText(
                      item.id,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                    if (item.pending)
                      Padding(
                        padding: const EdgeInsets.only(top: 12),
                        child: Wrap(
                          spacing: 12,
                          children: [
                            TextButton(
                              onPressed: item.retryable
                                  ? () => controller.retryDiagnostic(item.id)
                                  : null,
                              child: Text(context.tr('Réessayer')),
                            ),
                            TextButton(
                              onPressed: () =>
                                  controller.cancelDiagnostic(item.id),
                              child: Text(context.tr('Annuler l’envoi')),
                            ),
                          ],
                        ),
                      ),
                  ],
                ),
              ),
            ),
        ],
      ],
    );
  }
}

class _DiagnosticSurface extends StatelessWidget {
  const _DiagnosticSurface({
    required this.icon,
    required this.title,
    required this.child,
  });

  final IconData icon;
  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) => Card(
    clipBehavior: Clip.antiAlias,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.all(22),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: AppTheme.signal.withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(icon, size: 20),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Text(
                  context.tr(title),
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Padding(padding: const EdgeInsets.all(22), child: child),
      ],
    ),
  );
}

class _DiagnosticNotice extends StatelessWidget {
  const _DiagnosticNotice({required this.text, this.isError = false});

  final String text;
  final bool isError;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = isError ? scheme.error : scheme.onSurfaceVariant;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: isError
            ? scheme.error.withValues(alpha: 0.07)
            : scheme.surfaceContainerHighest.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isError
              ? scheme.error.withValues(alpha: 0.25)
              : scheme.outlineVariant,
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            isError ? Icons.error_outline : Icons.info_outline,
            color: color,
            size: 20,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              context.tr(text),
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: color),
            ),
          ),
        ],
      ),
    );
  }
}

class _DiagnosticCheckGroup extends StatelessWidget {
  const _DiagnosticCheckGroup({
    required this.group,
    required this.title,
    required this.checks,
  });

  final String group;
  final String title;
  final List<DiagnosticCheckView> checks;

  @override
  Widget build(BuildContext context) => Card(
    clipBehavior: Clip.antiAlias,
    child: ExpansionTile(
      key: PageStorageKey('diagnostic-checks-$group'),
      tilePadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
      shape: const Border(),
      collapsedShape: const Border(),
      leading: Icon(
        group == 'passed'
            ? Icons.check_circle_outline
            : Icons.do_not_disturb_on_outlined,
        color: group == 'passed'
            ? AppTheme.successFor(context)
            : Theme.of(context).colorScheme.onSurfaceVariant,
      ),
      title: Text(context.tr(title).replaceAll('{count}', '${checks.length}')),
      children: [
        for (final check in checks) ...[
          const Divider(height: 1),
          _DiagnosticCheckTile(check: check),
        ],
      ],
    ),
  );
}

class _DiagnosticCheckTile extends StatelessWidget {
  const _DiagnosticCheckTile({required this.check});
  final DiagnosticCheckView check;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = switch (check.result) {
      'passed' => AppTheme.successFor(context),
      'failed' => scheme.error,
      _ => scheme.onSurfaceVariant,
    };
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 2),
            child: Icon(
              switch (check.result) {
                'passed' => Icons.check_circle_outline,
                'failed' => Icons.error_outline,
                'skipped' => Icons.do_not_disturb_on_outlined,
                _ => Icons.help_outline,
              },
              color: color,
              size: 22,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  context.tr(check.label),
                  style: Theme.of(context).textTheme.titleSmall,
                ),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 5,
                      ),
                      decoration: BoxDecoration(
                        color: color.withValues(alpha: 0.08),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: color.withValues(alpha: 0.2)),
                      ),
                      child: Text(
                        context.tr(switch (check.result) {
                          'passed' => 'Vérifié',
                          'failed' => 'Problème détecté',
                          'skipped' => 'Non exécuté',
                          _ => 'Indéterminé',
                        }),
                        style: Theme.of(
                          context,
                        ).textTheme.labelMedium?.copyWith(color: color),
                      ),
                    ),
                    if (check.ageMs != null)
                      Tooltip(
                        message: context.tr('Ancienneté de la mesure'),
                        child: Text(
                          '${context.tr('Ancienneté de la mesure')} : ${(check.ageMs! / 1000).ceil()} s',
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(color: scheme.onSurfaceVariant),
                        ),
                      ),
                  ],
                ),
                if (_diagnosticGuidance(check) case final guidance?) ...[
                  const SizedBox(height: 12),
                  Text(
                    context.tr(guidance),
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: scheme.onSurfaceVariant,
                    ),
                  ),
                ],
                if (check.windowsError case final windowsError?) ...[
                  const SizedBox(height: 8),
                  Text(
                    context
                        .tr('Code Windows : {code}')
                        .replaceAll('{code}', '$windowsError'),
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

String? _diagnosticGuidance(DiagnosticCheckView check) {
  if (check.result != 'failed' && check.result != 'unknown') return null;
  if (check.label == 'Accès aux services FuzeVPN') {
    return switch (check.code) {
      'api_bootstrap_unavailable' || 'api_resolution_unavailable' =>
        'FuzeVPN ne peut pas résoudre l’adresse du service de connexion.',
      'runtime_detection_failed' || 'service_configuration_mismatch' =>
        'Windows n’a pas permis de vérifier l’installation de FuzeVPN.',
      'runtime_status_unavailable' =>
        'FuzeVPN ne peut pas vérifier l’état du VPN. Réessayez la vérification.',
      'runtime_owned_by_another_user' =>
        'Le VPN est utilisé par une autre session Windows. Fermez-le depuis cette session pour continuer.',
      'broker_unavailable' ||
      'broker_busy' ||
      'service_unavailable' ||
      'runtime_unavailable' ||
      'broker_write_failed' ||
      'broker_response_timeout' ||
      'broker_protocol_error' =>
        'Le service VPN local est indisponible. Fermez puis rouvrez FuzeVPN.',
      'permission_denied' =>
        'Windows n’a pas confirmé les autorisations nécessaires. Contactez l’assistance pour vérifier les permissions.',
      'maintenance_in_progress' =>
        'Une installation est déjà en cours. Réessayez une fois terminée.',
      'api_transport_unsupported' =>
        'FuzeVPN ne peut pas utiliser la configuration réseau de cet ordinateur pour joindre le service.',
      'tls_handshake_failed' =>
        'La connexion sécurisée au service n’a pas pu être vérifiée.',
      'storage_access_denied' || 'storage_failure' =>
        'L’accès au stockage protégé a échoué. Relancez l’application, puis contactez l’assistance si le problème persiste.',
      'network_unreachable' || 'request_timeout' || 'network_timeout' =>
        'Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.',
      _ =>
        'Le service de connexion est momentanément indisponible. Réessayez plus tard.',
    };
  }
  if (check.label == 'Kill switch' || check.label == 'Protection WebRTC') {
    return 'Cette protection n’est pas confirmée. Ne supposez pas que le trafic est bloqué. Vérifiez les réglages et contactez l’assistance si le problème persiste.';
  }
  if (check.result == 'unknown') {
    return 'Cette mesure est indisponible. Relancez le diagnostic. Si elle reste indéterminée, contactez l’assistance.';
  }
  return switch (check.label) {
    'Accès à l’API' =>
      'Vérifiez votre connexion Internet, puis relancez le diagnostic. Le tunnel peut fonctionner même si l’API ne répond pas.',
    'Configuration du tunnel' ||
    'État du tunnel' ||
    'Échange avec le serveur VPN' ||
    'Routes du tunnel' ||
    'Configuration DNS' ||
    'Configuration IPv4' ||
    'Configuration IPv6' =>
      'Déconnectez puis reconnectez manuellement le VPN, puis relancez le diagnostic. Si le problème persiste, contactez l’assistance.',
    'Pilote VPN' =>
      'Le pilote VPN doit être vérifié. Contactez l’assistance avant de le modifier.',
    'Moteur VPN' =>
      'Le moteur VPN n’est pas disponible. Relancez l’application. Si le problème persiste, contactez l’assistance.',
    'Stockage protégé' =>
      'L’accès au stockage protégé a échoué. Relancez l’application, puis contactez l’assistance si le problème persiste.',
    'Certificat VPN' =>
      'Le certificat VPN n’est pas confirmé. Réessayez la connexion VPN, puis contactez l’assistance si le problème persiste.',
    'Autorisations' =>
      'Windows n’a pas confirmé les autorisations nécessaires. Contactez l’assistance pour vérifier les permissions.',
    'Nettoyage du tunnel' =>
      'La déconnexion n’est pas confirmée. Utilisez « Terminer la déconnexion » si cette action est proposée. Sinon, contactez l’assistance.',
    _ =>
      'Cette vérification a échoué. Relancez le diagnostic. Si le problème persiste, contactez l’assistance.',
  };
}
