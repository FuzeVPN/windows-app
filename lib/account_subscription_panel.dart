// SPDX-License-Identifier: MPL-2.0
part of 'app_shell.dart';

class _AccountSubscriptionPanel extends StatelessWidget {
  const _AccountSubscriptionPanel({
    required this.controller,
    required this.accountIsCurrent,
  });

  final AppController controller;
  final bool accountIsCurrent;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final subscription = accountIsCurrent ? controller.subscription : null;
    final loading = accountIsCurrent && controller.isLoadingSubscription;
    final failed =
        !accountIsCurrent || controller.subscriptionErrorMessage != null;
    return Semantics(
      liveRegion: true,
      child: Container(
        key: const ValueKey('account-subscription-panel'),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: theme.colorScheme.surface,
          border: Border.all(color: theme.dividerColor),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _SubscriptionHeading(
              status: !loading && !failed ? subscription?.status : null,
            ),
            const SizedBox(height: 16),
            if (loading)
              _SubscriptionNotice(
                icon: Icons.hourglass_top_outlined,
                message: context.tr('Chargement de l’abonnement…'),
              )
            else if (failed || subscription == null) ...[
              _SubscriptionNotice(
                icon: Icons.info_outline,
                message: context.tr(
                  accountIsCurrent
                      ? controller.subscriptionErrorMessage ??
                            'Les informations d’abonnement sont indisponibles.'
                      : 'Les informations d’abonnement sont indisponibles.',
                ),
              ),
              if (accountIsCurrent) ...[
                const SizedBox(height: 8),
                Align(
                  alignment: AlignmentDirectional.centerStart,
                  child: TextButton.icon(
                    key: const ValueKey('account-subscription-retry'),
                    onPressed: controller.refreshSubscription,
                    icon: const Icon(Icons.refresh, size: 18),
                    label: Text(context.tr('Réessayer')),
                  ),
                ),
              ],
            ] else ...[
              _SubscriptionDetails(subscription: subscription),
            ],
          ],
        ),
      ),
    );
  }
}

class _SubscriptionHeading extends StatelessWidget {
  const _SubscriptionHeading({this.status});

  final SubscriptionStatus? status;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final heading = Row(
        children: [
          Icon(
            Icons.workspace_premium_outlined,
            color: Theme.of(context).colorScheme.onSurface,
            size: 20,
          ),
          const SizedBox(width: 9),
          Expanded(
            child: Text(
              context.tr('Abonnement'),
              style: Theme.of(
                context,
              ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
            ),
          ),
        ],
      );
      if (status == null) return heading;
      final scale = MediaQuery.textScalerOf(context).scale(14) / 14;
      if (constraints.maxWidth < 360 * math.max(1, scale)) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            heading,
            const SizedBox(height: 12),
            _SubscriptionStatusBadge(status: status!),
          ],
        );
      }
      return Row(
        children: [
          Expanded(child: heading),
          const SizedBox(width: 12),
          Flexible(child: _SubscriptionStatusBadge(status: status!)),
        ],
      );
    },
  );
}

class _SubscriptionDetails extends StatelessWidget {
  const _SubscriptionDetails({required this.subscription});

  final Subscription subscription;

  @override
  Widget build(BuildContext context) {
    final facts = [
      _SubscriptionFact(
        icon: subscription.status == SubscriptionStatus.unknown
            ? Icons.help_outline
            : subscription.hasAccess
            ? Icons.check_circle_outline
            : Icons.do_not_disturb_on_outlined,
        label: context.tr('Accès VPN'),
        value: context.tr(
          subscription.status == SubscriptionStatus.unknown
              ? 'Indisponible'
              : subscription.hasAccess
              ? 'Autorisé'
              : 'Non autorisé',
        ),
        valueColor: subscription.hasAccess
            ? AppTheme.successFor(context)
            : Theme.of(context).colorScheme.onSurfaceVariant,
      ),
      _SubscriptionFact(
        icon: Icons.event_outlined,
        label: context.tr('Expiration'),
        value: _subscriptionDate(context, subscription.expiresAt),
        semanticValue: _subscriptionDate(
          context,
          subscription.expiresAt,
          accessible: true,
        ),
      ),
      _SubscriptionFact(
        icon: Icons.autorenew,
        label: context.tr('Renouvellement'),
        value: context.tr(
          subscription.cancelAtPeriodEnd
              ? 'Annulé à la fin de la période'
              : subscription.renewsAutomatically
              ? 'Automatique'
              : 'Désactivé',
        ),
      ),
      if (subscription.renewsAutomatically && !subscription.cancelAtPeriodEnd)
        _SubscriptionFact(
          icon: Icons.calendar_month_outlined,
          label: context.tr('Prochaine échéance'),
          value: _subscriptionDate(context, subscription.nextChargeAt),
          semanticValue: _subscriptionDate(
            context,
            subscription.nextChargeAt,
            accessible: true,
          ),
        ),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        final scale = MediaQuery.textScalerOf(context).scale(14) / 14;
        if (constraints.maxWidth < 360 * math.max(1, scale)) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              for (var i = 0; i < facts.length; i++) ...[
                if (i != 0) const SizedBox(height: 14),
                facts[i],
              ],
            ],
          );
        }
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: facts[0]),
                const SizedBox(width: 16),
                Expanded(child: facts[1]),
              ],
            ),
            const SizedBox(height: 14),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: facts[2]),
                if (facts.length == 4) ...[
                  const SizedBox(width: 16),
                  Expanded(child: facts[3]),
                ],
              ],
            ),
          ],
        );
      },
    );
  }
}

String _subscriptionDate(
  BuildContext context,
  DateTime? date, {
  bool accessible = false,
}) {
  if (date == null) return context.tr('Indisponible');
  final locale = Localizations.localeOf(context).toString();
  final format = accessible
      ? DateFormat.yMMMMEEEEd(locale).add_Hm()
      : DateFormat.yMMMMd(locale).add_Hm();
  return format.format(date.toLocal());
}

class _SubscriptionStatusBadge extends StatelessWidget {
  const _SubscriptionStatusBadge({required this.status});

  final SubscriptionStatus status;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final (label, color, icon) = switch (status) {
      SubscriptionStatus.active => (
        'Actif',
        AppTheme.successFor(context),
        Icons.check_circle_outline,
      ),
      SubscriptionStatus.pastDue => (
        'Paiement en retard',
        AppTheme.warningFor(context),
        Icons.schedule_outlined,
      ),
      SubscriptionStatus.expired => (
        'Expiré',
        theme.colorScheme.onSurfaceVariant,
        Icons.event_busy_outlined,
      ),
      SubscriptionStatus.canceled => (
        'Annulé',
        theme.colorScheme.onSurfaceVariant,
        Icons.cancel_outlined,
      ),
      SubscriptionStatus.withdrawn => (
        'Rétracté',
        theme.colorScheme.onSurfaceVariant,
        Icons.undo_outlined,
      ),
      SubscriptionStatus.inactive => (
        'Inactif',
        theme.colorScheme.onSurfaceVariant,
        Icons.pause_circle_outline,
      ),
      SubscriptionStatus.unknown => (
        'Statut indisponible',
        theme.colorScheme.onSurfaceVariant,
        Icons.help_outline,
      ),
    };
    return Align(
      alignment: AlignmentDirectional.centerStart,
      child: Container(
        key: const ValueKey('account-subscription-status'),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.09),
          border: Border.all(color: color.withValues(alpha: 0.25)),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: 17),
            const SizedBox(width: 7),
            Flexible(
              child: Text(
                context.tr(label),
                style: theme.textTheme.labelLarge?.copyWith(color: color),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _SubscriptionFact extends StatelessWidget {
  const _SubscriptionFact({
    required this.icon,
    required this.label,
    required this.value,
    this.semanticValue,
    this.valueColor,
  });

  final IconData icon;
  final String label;
  final String value;
  final String? semanticValue;
  final Color? valueColor;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Semantics(
      excludeSemantics: true,
      label: '$label : ${semanticValue ?? value}',
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 2),
            child: Icon(
              icon,
              size: 19,
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  value,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: valueColor,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _SubscriptionNotice extends StatelessWidget {
  const _SubscriptionNotice({required this.icon, required this.message});

  final IconData icon;
  final String message;

  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Icon(
        icon,
        size: 19,
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      ),
      const SizedBox(width: 10),
      Expanded(child: Text(message)),
    ],
  );
}
