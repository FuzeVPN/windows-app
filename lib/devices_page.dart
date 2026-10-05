// SPDX-License-Identifier: MPL-2.0
part of 'app_shell.dart';

class DevicesPage extends StatelessWidget {
  const DevicesPage({super.key, required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final signedIn = controller.profile != null;
    return _PageLayout(
      title: 'Appareils',
      subtitle: 'Gérez les appareils associés à votre compte.',
      maxWidth: 920,
      action: signedIn
          ? IconButton(
              tooltip: context.tr('Actualiser les appareils'),
              onPressed: controller.isLoadingDevices
                  ? null
                  : controller.refreshDevices,
              icon: const Icon(Icons.refresh),
            )
          : null,
      child: !signedIn
          ? _NoticeCard(
              icon: Icons.lock_outline,
              title: 'Connectez-vous pour gérer vos appareils',
              message:
                  'Vous pourrez voir les appareils associés à votre compte et retirer un accès perdu.',
              actionLabel: 'Se connecter',
              onAction: () {
                _showSignInDialog(context, controller);
              },
            )
          : controller.isLoadingDevices
          ? const Center(
              child: Padding(
                padding: EdgeInsets.all(72),
                child: CircularProgressIndicator(),
              ),
            )
          : !controller.devicesReachable
          ? _NoticeCard(
              icon: Icons.cloud_off_outlined,
              title: 'Service indisponible',
              message:
                  controller.deviceErrorMessage ??
                  'La liste de vos appareils ne peut pas être chargée pour le moment.',
              actionLabel: 'Réessayer',
              onAction: controller.refreshDevices,
            )
          : _DeviceList(controller: controller),
    );
  }
}

class _DeviceList extends StatelessWidget {
  const _DeviceList({required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) {
    final count = controller.devices.length;
    final limit = controller.deviceLimit;
    final remaining = limit > count ? limit - count : 0;
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final quotaDescription = remaining == 0
        ? context.tr(
            'Limite atteinte. Retirez un appareil avant d’en ajouter un autre.',
          )
        : context
              .tr('Places disponibles : {count}')
              .replaceAll('{count}', '$remaining');
    final progress = ClipRRect(
      borderRadius: BorderRadius.circular(6),
      child: LinearProgressIndicator(
        value: limit > 0 ? (count / limit).clamp(0.0, 1.0) : 0,
        minHeight: 6,
        backgroundColor: scheme.outlineVariant,
        color: remaining == 0 ? AppTheme.signal : scheme.primary,
        semanticsLabel: context
            .tr('Appareils : {count} / {limit}')
            .replaceAll('{count}', '$count')
            .replaceAll('{limit}', '$limit'),
      ),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (controller.deviceErrorMessage != null) ...[
          _NoticeCard(
            icon: Icons.info_outline,
            title: 'Information',
            message: controller.deviceErrorMessage!,
          ),
          const SizedBox(height: 12),
        ],
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: scheme.surface,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: LayoutBuilder(
            builder: (context, constraints) {
              final inline =
                  constraints.maxWidth >= 600 &&
                  MediaQuery.textScalerOf(context).scale(14) <= 18;
              final summary = Row(
                children: [
                  Container(
                    width: 36,
                    height: 36,
                    decoration: BoxDecoration(
                      color: scheme.primaryContainer,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Icon(
                      Icons.devices_other_outlined,
                      size: 20,
                      color: scheme.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          context
                              .tr('Appareils : {count} / {limit}')
                              .replaceAll('{count}', '$count')
                              .replaceAll('{limit}', '$limit'),
                          style: theme.textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          quotaDescription,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: scheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (inline) ...[
                    const SizedBox(width: 24),
                    SizedBox(width: 128, child: progress),
                  ],
                ],
              );
              return inline
                  ? summary
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [summary, const SizedBox(height: 12), progress],
                    );
            },
          ),
        ),
        if (controller.devices.isNotEmpty) ...[
          const SizedBox(height: 12),
          Container(
            decoration: BoxDecoration(
              color: scheme.surface,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: scheme.outlineVariant),
            ),
            clipBehavior: Clip.antiAlias,
            child: Column(
              children: [
                for (
                  var index = 0;
                  index < controller.devices.length;
                  index++
                ) ...[
                  if (index > 0)
                    Divider(height: 1, color: scheme.outlineVariant),
                  _DeviceRow(
                    controller: controller,
                    device: controller.devices[index],
                  ),
                ],
              ],
            ),
          ),
        ],
        if (controller.devices.isEmpty) ...[
          const SizedBox(height: 12),
          const _NoticeCard(
            icon: Icons.devices_other_outlined,
            title: 'Aucun appareil VPN',
            message: 'Activez le VPN pour ajouter cet appareil à votre compte.',
          ),
        ],
      ],
    );
  }
}

class _DeviceRow extends StatelessWidget {
  const _DeviceRow({required this.controller, required this.device});

  final AppController controller;
  final VpnDevice device;

  @override
  Widget build(BuildContext context) {
    final isCurrentDevice = controller.isCurrentDevice(device);
    final isRevoking = controller.revokingDeviceId == device.deviceId;
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final identity = Row(
      children: [
        Container(
          width: 36,
          height: 36,
          decoration: BoxDecoration(
            color: scheme.primaryContainer,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(
            isCurrentDevice
                ? Icons.computer_outlined
                : Icons.devices_other_outlined,
            size: 20,
            color: scheme.onPrimaryContainer,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                _localizedDeviceName(context, device),
                style: theme.textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
              ),
              if (device.createdAt != null) ...[
                const SizedBox(height: 3),
                Text(
                  context
                      .tr('Ajouté le {date}')
                      .replaceAll(
                        '{date}',
                        MaterialLocalizations.of(
                          context,
                        ).formatMediumDate(device.createdAt!.toLocal()),
                      ),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: scheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
      ],
    );
    final badge = Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: scheme.primaryContainer,
        border: Border.all(color: scheme.outlineVariant),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        context.tr('Cet appareil'),
        style: theme.textTheme.labelSmall?.copyWith(
          color: scheme.onPrimaryContainer,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
    final action = TextButton.icon(
      key: ValueKey('device-remove-${device.deviceId}'),
      style: TextButton.styleFrom(
        foregroundColor: scheme.error,
        minimumSize: const Size(44, 44),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      ),
      onPressed: controller.revokingDeviceId == null
          ? () => _confirmRevocation(context, controller, device)
          : null,
      icon: isRevoking
          ? const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.delete_outline, size: 18),
      label: Text(context.tr(isRevoking ? 'Retrait…' : 'Retirer l’appareil')),
    );
    return Container(
      key: ValueKey('device-row-${device.deviceId}'),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      decoration: BoxDecoration(
        color: isCurrentDevice
            ? scheme.primaryContainer.withValues(alpha: .45)
            : Colors.transparent,
        border: BorderDirectional(
          start: BorderSide(
            color: isCurrentDevice ? AppTheme.signal : Colors.transparent,
            width: 3,
          ),
        ),
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final stacked =
              constraints.maxWidth < 640 ||
              MediaQuery.textScalerOf(context).scale(14) > 18;
          if (stacked) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                identity,
                const SizedBox(height: 8),
                Wrap(
                  alignment: WrapAlignment.end,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  spacing: 12,
                  runSpacing: 4,
                  children: [if (isCurrentDevice) badge, action],
                ),
              ],
            );
          }
          return Row(
            children: [
              Expanded(child: identity),
              if (isCurrentDevice) ...[
                const SizedBox(width: 16),
                ConstrainedBox(
                  constraints: BoxConstraints(
                    maxWidth: constraints.maxWidth * .22,
                  ),
                  child: badge,
                ),
              ],
              const SizedBox(width: 16),
              ConstrainedBox(
                constraints: BoxConstraints(
                  maxWidth: constraints.maxWidth * .3,
                ),
                child: action,
              ),
            ],
          );
        },
      ),
    );
  }
}

String _localizedDeviceName(BuildContext context, VpnDevice device) =>
    device.name == 'Appareil sans nom'
    ? context.tr('Appareil sans nom')
    : device.name;

Future<void> _confirmRevocation(
  BuildContext context,
  AppController controller,
  VpnDevice device,
) async {
  final isCurrentDevice = controller.isCurrentDevice(device);
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      scrollable: true,
      title: Text(context.tr('Retirer cet appareil ?')),
      content: Text(
        isCurrentDevice
            ? context.tr(
                'Cet appareil est utilisé ici. FuzeVPN va se déconnecter et supprimer son identité VPN locale. Vous devrez le reconnecter pour l’ajouter de nouveau.',
              )
            : context
                  .tr(
                    'L’accès VPN de « {device} » sera retiré. La révocation peut prendre quelques instants à être appliquée par le serveur VPN.',
                  )
                  .replaceAll(
                    '{device}',
                    _localizedDeviceName(context, device),
                  ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: Text(context.tr('Annuler')),
        ),
        FilledButton.icon(
          style: FilledButton.styleFrom(
            backgroundColor: Theme.of(context).colorScheme.error,
            foregroundColor: Theme.of(context).colorScheme.onError,
          ),
          onPressed: () => Navigator.of(dialogContext).pop(true),
          icon: const Icon(Icons.delete_outline),
          label: Text(context.tr('Retirer')),
        ),
      ],
    ),
  );
  if (confirmed != true || !context.mounted) return;

  final result = await controller.revokeDevice(device);
  if (!context.mounted) return;
  final message = switch (result) {
    DeviceRevocationResult.revoked when isCurrentDevice =>
      'Appareil retiré et identité VPN locale supprimée.',
    DeviceRevocationResult.revoked =>
      'Appareil retiré. La révocation est en cours de propagation.',
    DeviceRevocationResult.revokedWithLocalCleanupWarning =>
      controller.deviceErrorMessage ?? 'Appareil retiré.',
    DeviceRevocationResult.failed =>
      controller.deviceErrorMessage ?? 'Cet appareil n’a pas pu être retiré.',
  };
  ScaffoldMessenger.of(
    context,
  ).showSnackBar(SnackBar(content: Text(context.tr(message))));
}
