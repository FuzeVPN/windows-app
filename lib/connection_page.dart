// SPDX-License-Identifier: MPL-2.0
part of 'app_shell.dart';

class _ConnectionPage extends StatelessWidget {
  const _ConnectionPage({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final state = controller.runtimeVerificationPending
        ? _ConnectionState(
            label: context.tr('État VPN inconnu'),
            description: context.tr(
              'FuzeVPN ne peut pas vérifier l’état du VPN. Réessayez la vérification.',
            ),
            icon: Icons.help_outline,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          )
        : controller.isInitialized
        ? _connectionState(controller.vpnStatus, context)
        : _ConnectionState(
            label: context.tr('Vérification de la protection…'),
            description: context.tr(
              'FuzeVPN vérifie le tunnel et le kill switch avant d’afficher votre état réseau.',
            ),
            icon: Icons.shield_outlined,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          );
    return _PageLayout(
      title: 'Connexion VPN',
      subtitle:
          controller.isInitialized &&
              controller.vpnStatus == VpnStatus.disconnected
          ? 'Choisissez un emplacement et activez le VPN.'
          : null,
      maxWidth: 1040,
      centerContent: true,
      child: Column(
        children: [
          _ConnectionHero(
            controller: controller,
            state: state,
            enabled:
                controller.isInitialized &&
                !controller.runtimeOwnedByAnotherUser,
          ),
          if (controller.isLocationMigrationActive ||
              controller.locationMigrationError != null) ...[
            const SizedBox(height: 12),
            _NoticeCard(
              icon: controller.isLocationMigrationActive
                  ? Icons.sync_outlined
                  : Icons.info_outline,
              title: controller.isLocationMigrationActive
                  ? 'Changement de serveur…'
                  : 'Changement de serveur',
              message:
                  controller.locationMigrationMessage ??
                  controller.locationMigrationError ??
                  'Le changement de serveur est en cours.',
              actionLabel:
                  controller.locationMigration != null &&
                      controller.locationMigrationError != null
                  ? 'Actualiser le suivi'
                  : null,
              onAction:
                  controller.locationMigration != null &&
                      controller.locationMigrationError != null &&
                      !controller.isConnectionBusy
                  ? controller.pollLocationMigrationNow
                  : null,
            ),
          ],
          if (controller.deviceEnrollmentIssue != null) ...[
            const SizedBox(height: 12),
            _DeviceEnrollmentIssueCard(
              controller: controller,
              issue: controller.deviceEnrollmentIssue!,
            ),
          ] else if (controller.errorMessage != null &&
              controller.errorMessage != controller.locationMigrationMessage &&
              controller.errorMessage != controller.locationMigrationError) ...[
            const SizedBox(height: 12),
            _NoticeCard(
              icon: _isConnectionProgressMessage(controller)
                  ? Icons.info_outline
                  : Icons.error_outline,
              title: _isConnectionProgressMessage(controller)
                  ? 'Information'
                  : 'À vérifier',
              message:
                  _isConnectionProgressMessage(controller) &&
                      controller.vpnStatus == VpnStatus.blocked
                  ? 'La préparation continue. Internet reste bloqué jusqu’à la connexion ou à l’arrêt des protections.'
                  : controller.runtimeVerificationPending &&
                        controller.runtimeVerificationWindowsError != null
                  ? '${context.tr(controller.errorMessage!)}\n${context.tr('Code Windows : {code}').replaceAll('{code}', controller.runtimeVerificationWindowsError.toString())}'
                  : controller.errorMessage!,
              actionLabel: _isConnectionProgressMessage(controller)
                  ? null
                  : 'Diagnostic',
              onAction: _isConnectionProgressMessage(controller)
                  ? null
                  : () => controller.selectSection(AppSection.help),
            ),
          ],
        ],
      ),
    );
  }
}

// These legacy controller messages describe pending work, not a failed action.
// Do not infer this from `blocked`: an actual failure can also retain protection.
bool _isConnectionProgressMessage(AppController controller) => const {
  'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.',
  'Le changement de serveur continue. Le kill switch bloque le trafic jusqu’à la reconnexion ou une déconnexion explicite.',
  'Changement de serveur en cours…',
}.contains(controller.errorMessage);

class _ConnectionHero extends StatelessWidget {
  const _ConnectionHero({
    required this.controller,
    required this.state,
    required this.enabled,
  });

  final AppController controller;
  final _ConnectionState state;
  final bool enabled;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final theme = Theme.of(context);
      final textScale = MediaQuery.textScalerOf(context).scale(14) / 14;
      final wide = constraints.maxWidth >= 700 * math.max(1, textScale);
      final hasNotice =
          controller.isLocationMigrationActive ||
          controller.locationMigrationError != null ||
          controller.deviceEnrollmentIssue != null ||
          controller.errorMessage != null;
      final panelPadding = wide && !hasNotice ? 28.0 : 20.0;
      // This panel has a fixed dark surface in both themes. Its status colors
      // therefore follow the dark palette independently of the app theme.
      final statusColor = !controller.isInitialized
          ? const Color(0xFFB8C4CC)
          : switch (controller.vpnStatus) {
              VpnStatus.connected => const Color(0xFF66D9AA),
              VpnStatus.blocked => const Color(0xFFFFBE70),
              VpnStatus.error => const Color(0xFFFF8C85),
              _ => AppTheme.ivory,
            };
      final status = Semantics(
        liveRegion: true,
        excludeSemantics: true,
        label: context
            .tr('État VPN : {status}')
            .replaceAll('{status}', state.label),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(state.icon, color: statusColor, size: 18),
                const SizedBox(width: 9),
                Expanded(
                  child: Text(
                    context.tr('État du tunnel'),
                    style: theme.textTheme.labelMedium?.copyWith(
                      color: AppTheme.ivory.withValues(alpha: 0.76),
                      letterSpacing: AppTheme.tracking(context, 0.5),
                    ),
                  ),
                ),
              ],
            ),
            SizedBox(height: hasNotice ? 10 : 16),
            Text(
              state.label,
              style: theme.textTheme.headlineLarge?.copyWith(
                color: statusColor,
                fontSize: hasNotice ? 30 : (wide ? 38 : 32),
                fontWeight: FontWeight.w800,
                height: AppTheme.headingHeight(context, 1.08),
                letterSpacing: AppTheme.tracking(context, -1.1),
              ),
            ),
            SizedBox(height: hasNotice ? 8 : 12),
            Text(
              state.description,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: AppTheme.ivory.withValues(alpha: 0.8),
                height: 1.5,
              ),
            ),
          ],
        ),
      );
      final action = FilledButton.icon(
        key: const ValueKey('connection-primary-action'),
        style: FilledButton.styleFrom(
          backgroundColor: AppTheme.signal,
          foregroundColor: AppTheme.brand,
          disabledBackgroundColor: AppTheme.signal.withValues(alpha: 0.22),
          disabledForegroundColor: AppTheme.ivory.withValues(alpha: 0.58),
          minimumSize: const Size(0, 48),
          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 15),
          textStyle: theme.textTheme.labelLarge?.copyWith(
            fontWeight: FontWeight.w700,
          ),
        ),
        onPressed: !enabled || controller.isConnectionBusy
            ? null
            : () => _requestConnection(context, controller),
        icon: Icon(
          controller.runtimeVerificationPending
              ? Icons.refresh
              : controller.requiresExplicitDisconnect
              ? Icons.lock_open_outlined
              : controller.savedSessionVerificationPending
              ? Icons.refresh
              : Icons.power_settings_new,
        ),
        label: Text(
          context.tr(
            controller.runtimeVerificationPending
                ? 'Réessayer'
                : controller.requiresExplicitDisconnect
                ? 'Déconnecter'
                : controller.savedSessionVerificationPending
                ? 'Réessayer'
                : 'Connexion rapide',
          ),
          textAlign: TextAlign.center,
        ),
      );
      return Container(
        key: const ValueKey('connection-control-panel'),
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          border: Border.all(color: theme.dividerColor),
          borderRadius: BorderRadius.circular(10),
        ),
        clipBehavior: Clip.antiAlias,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              color: AppTheme.network,
              padding: EdgeInsets.all(panelPadding),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: hasNotice && wide
                        ? status
                        : Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              status,
                              const SizedBox(height: 24),
                              Align(
                                alignment: AlignmentDirectional.centerStart,
                                child: action,
                              ),
                            ],
                          ),
                  ),
                  if (hasNotice && wide) ...[
                    const SizedBox(width: 24),
                    SizedBox(width: 194, child: action),
                  ] else if (wide) ...[
                    const SizedBox(width: 28),
                    _TunnelIllustration(
                      icon: state.icon,
                      statusColor: statusColor,
                    ),
                  ],
                ],
              ),
            ),
            _ConnectionSummary(controller: controller, enabled: enabled),
          ],
        ),
      );
    },
  );
}

// Abstract network geometry, never a map or a claim about a live endpoint.
// Keeping it static also respects reduced motion and widget-test settling.
class _TunnelIllustration extends StatelessWidget {
  const _TunnelIllustration({required this.icon, required this.statusColor});

  final IconData icon;
  final Color statusColor;

  @override
  Widget build(BuildContext context) => ExcludeSemantics(
    child: SizedBox(
      width: 240,
      height: 220,
      child: Stack(
        alignment: Alignment.center,
        children: [
          const Positioned.fill(
            child: CustomPaint(painter: _TunnelNetworkPainter()),
          ),
          Container(
            width: 96,
            height: 112,
            decoration: BoxDecoration(
              color: AppTheme.network,
              border: Border.all(color: AppTheme.ivory.withValues(alpha: 0.2)),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, color: statusColor, size: 48),
          ),
        ],
      ),
    ),
  );
}

class _TunnelNetworkPainter extends CustomPainter {
  const _TunnelNetworkPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final line = Paint()
      ..color = AppTheme.ivory.withValues(alpha: 0.11)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;
    final orbit = Rect.fromCenter(
      center: center,
      width: size.width * 0.89,
      height: size.height * 0.86,
    );
    canvas.drawOval(orbit, line);
    canvas.drawOval(orbit.deflate(25), line);
    final nodes = [
      Offset(size.width * 0.12, size.height * 0.27),
      Offset(size.width * 0.84, size.height * 0.18),
      Offset(size.width * 0.91, size.height * 0.69),
      Offset(size.width * 0.19, size.height * 0.83),
    ];
    for (final node in nodes) {
      canvas.drawLine(node, center, line);
      canvas.drawCircle(node, 9, Paint()..color = AppTheme.network);
      canvas.drawCircle(node, 9, line);
      canvas.drawCircle(
        node,
        3,
        Paint()..color = AppTheme.signal.withValues(alpha: 0.78),
      );
    }
    final crosshair = Paint()
      ..color = AppTheme.ivory.withValues(alpha: 0.2)
      ..strokeWidth = 1;
    for (final point in [
      Offset(size.width * 0.5, 8),
      Offset(size.width * 0.5, size.height - 8),
    ]) {
      canvas.drawLine(point.translate(-4, 0), point.translate(4, 0), crosshair);
      canvas.drawLine(point.translate(0, -4), point.translate(0, 4), crosshair);
    }
  }

  @override
  bool shouldRepaint(_TunnelNetworkPainter oldDelegate) => false;
}

class _ConnectionSummary extends StatefulWidget {
  const _ConnectionSummary({required this.controller, required this.enabled});

  final AppController controller;
  final bool enabled;

  @override
  State<_ConnectionSummary> createState() => _ConnectionSummaryState();
}

class _ConnectionSummaryState extends State<_ConnectionSummary> {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted && widget.controller.connectedAt != null) setState(() {});
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final connected = controller.vpnStatus == VpnStatus.connected;
    final location = connected
        ? controller.tunnelLocation
        : controller.selectedLocation;
    final protocol = connected
        ? controller.activeProtocol ?? controller.vpnProtocol
        : controller.vpnProtocol;
    final locationInfo = Row(
      children: [
        Container(
          width: 52,
          height: 52,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: colors.surfaceContainerHighest.withValues(alpha: 0.42),
            border: Border.all(color: theme.dividerColor),
            borderRadius: BorderRadius.circular(8),
          ),
          child: location != null
              ? _CountryFlag(
                  countryCode: location.countryCode,
                  width: 34,
                  height: 23,
                )
              : Icon(
                  Icons.location_on_outlined,
                  color: colors.onSurfaceVariant,
                ),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                context.tr('Emplacement sélectionné'),
                style: theme.textTheme.labelMedium?.copyWith(
                  color: colors.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 5),
              Text(
                location?.displayName ??
                    context.tr(
                      connected
                          ? 'Emplacement du tunnel non confirmé'
                          : 'Aucun emplacement disponible',
                    ),
                style: theme.textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.w700,
                  fontSize: 19,
                  letterSpacing: AppTheme.tracking(context, -0.25),
                ),
              ),
            ],
          ),
        ),
      ],
    );
    final chooseLocation = OutlinedButton.icon(
      key: const ValueKey('connection-location-action'),
      onPressed: widget.enabled
          ? () => controller.selectSection(AppSection.locations)
          : null,
      icon: const Icon(Icons.swap_horiz, size: 19),
      label: Text(
        context.tr('Choisir un emplacement'),
        textAlign: TextAlign.center,
      ),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
          child: LayoutBuilder(
            builder: (context, constraints) {
              final textScale = MediaQuery.textScalerOf(context).scale(14) / 14;
              final wide = constraints.maxWidth >= 620 * math.max(1, textScale);
              return wide
                  ? Row(
                      children: [
                        Expanded(child: locationInfo),
                        const SizedBox(width: 24),
                        SizedBox(width: 236, child: chooseLocation),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        locationInfo,
                        const SizedBox(height: 16),
                        chooseLocation,
                      ],
                    );
            },
          ),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          decoration: BoxDecoration(
            color: colors.surfaceContainerHighest.withValues(alpha: 0.22),
            border: Border(top: BorderSide(color: theme.dividerColor)),
          ),
          child: Wrap(
            spacing: 28,
            runSpacing: 10,
            children: [
              _ConnectionDetail(
                icon: Icons.vpn_key_outlined,
                label: context.tr('Protocole VPN'),
                value: protocol == VpnProtocol.openVpn
                    ? 'OpenVPN'
                    : 'WireGuard',
              ),
              if (connected && controller.connectedAt != null)
                _ConnectionDetail(
                  icon: Icons.schedule_outlined,
                  label: context.tr('Durée de connexion'),
                  value: _formatDuration(controller.connectedDuration),
                ),
            ],
          ),
        ),
      ],
    );
  }
}

class _ConnectionDetail extends StatelessWidget {
  const _ConnectionDetail({
    required this.icon,
    required this.label,
    required this.value,
  });

  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Icon(
        icon,
        size: 17,
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      ),
      const SizedBox(width: 8),
      Flexible(
        child: Text(
          '$label : $value',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ),
    ],
  );
}
