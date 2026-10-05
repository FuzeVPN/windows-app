// SPDX-License-Identifier: MPL-2.0
part of 'app_shell.dart';

enum _SettingsCategory { general, connection, privacy, updates }

class _SettingsPage extends StatefulWidget {
  const _SettingsPage({super.key, required this.controller});

  final AppController controller;

  @override
  State<_SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<_SettingsPage> {
  _SettingsCategory _category = _SettingsCategory.general;
  final _languageFieldKey = GlobalKey<FormFieldState<AppLanguage>>();
  bool _restoringLanguageSelection = false;
  AppController get controller => widget.controller;

  Future<void> _selectLanguage(AppLanguage? value) async {
    if (value == null || _restoringLanguageSelection) return;
    await controller.setLanguage(value);
    if (!mounted) return;
    final field = _languageFieldKey.currentState;
    if (field != null && field.value != controller.language) {
      // A failed save leaves the controller's persisted language unchanged.
      // didChange also invokes onChanged; restoring must not enqueue a retry.
      _restoringLanguageSelection = true;
      try {
        field.didChange(controller.language);
      } finally {
        _restoringLanguageSelection = false;
      }
    }
  }

  @override
  Widget build(BuildContext context) => SafeArea(
    child: LayoutBuilder(
      builder: (context, constraints) {
        final general = <Widget>[
          _SettingsPanel(
            icon: Icons.palette_outlined,
            title: 'Général',
            subtitle: 'Apparence, langue et intégration à Windows.',
            children: [
              Text(
                context.tr('Apparence'),
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 12),
              _SettingsSegmentedControl<ThemeMode>(
                segments: [
                  ButtonSegment(
                    value: ThemeMode.light,
                    icon: const Icon(Icons.light_mode_outlined),
                    label: Text(context.tr('Clair')),
                  ),
                  ButtonSegment(
                    value: ThemeMode.dark,
                    icon: const Icon(Icons.dark_mode_outlined),
                    label: Text(context.tr('Sombre')),
                  ),
                  ButtonSegment(
                    value: ThemeMode.system,
                    icon: const Icon(Icons.settings_brightness_outlined),
                    label: Text(context.tr('Système')),
                  ),
                ],
                selected: {controller.themeMode},
                onSelectionChanged: (value) => controller.setTheme(value.first),
              ),
              const SizedBox(height: 20),
              DropdownButtonFormField<AppLanguage>(
                key: _languageFieldKey,
                initialValue: controller.language,
                isExpanded: true,
                itemHeight: null,
                menuMaxHeight: 440,
                decoration: InputDecoration(
                  labelText: context.tr('Langue'),
                  prefixIcon: const Icon(Icons.language_outlined),
                ),
                items: AppLanguage.sortedValues
                    .map(
                      (value) => DropdownMenuItem(
                        value: value,
                        child: Row(
                          children: [
                            if (value == AppLanguage.system)
                              const Icon(Icons.language_outlined, size: 24)
                            else
                              _CountryFlag(
                                countryCode: value.flagCountryCode!,
                                width: 24,
                                height: 16,
                              ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Text(
                                AppLocalizations.of(
                                  context,
                                ).strings.languageName(value),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                textDirection: value == AppLanguage.system
                                    ? Directionality.of(context)
                                    : value.isRightToLeft
                                    ? TextDirection.rtl
                                    : TextDirection.ltr,
                              ),
                            ),
                          ],
                        ),
                      ),
                    )
                    .toList(growable: false),
                onChanged: _selectLanguage,
              ),
            ],
          ),
          _SettingsPanel(
            icon: Icons.window_outlined,
            title: 'Windows',
            subtitle: 'Démarrage et notifications.',
            edgeToEdge: true,
            children: [
              SwitchListTile(
                secondary: const Icon(Icons.power_settings_new_outlined),
                title: Text(context.tr('Lancer avec Windows')),
                subtitle: Text(
                  context.tr(
                    'Démarre discrètement près de l’horloge, sans ouvrir la fenêtre.',
                  ),
                ),
                value: controller.launchWithWindows,
                onChanged: controller.setLaunchWithWindows,
              ),
              const Divider(height: 1),
              SwitchListTile(
                secondary: const Icon(Icons.notifications_none_outlined),
                title: Text(context.tr('Notifications Windows')),
                subtitle: Text(
                  context.tr(
                    'Affiche uniquement les connexions, interruptions inattendues et erreurs importantes.',
                  ),
                ),
                value: controller.windowsNotificationsEnabled,
                onChanged: controller.setWindowsNotifications,
              ),
              if (controller.experienceSettingsError case final error?)
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(
                    context.tr(error),
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
            ],
          ),
        ];

        final privacy = <Widget>[
          _SettingsPanel(
            icon: Icons.shield_outlined,
            title: 'Sécurité',
            subtitle: 'Protections appliquées à WireGuard et OpenVPN.',
            edgeToEdge: true,
            children: [
              SwitchListTile(
                secondary: const Icon(Icons.shield_outlined),
                title: Text(context.tr('Kill switch')),
                subtitle: Text(
                  context.tr(
                    'Bloque le trafic qui tenterait de sortir en dehors du tunnel VPN.',
                  ),
                ),
                value: controller.killSwitchEnabled,
                onChanged: controller.canChangeNetworkProtection
                    ? controller.setKillSwitch
                    : null,
              ),
              const Divider(height: 1),
              SwitchListTile(
                secondary: const Icon(Icons.dns_outlined),
                title: Text(context.tr('Protection DNS')),
                subtitle: Text(
                  context.tr(
                    'Force les requêtes DNS à passer par l’interface VPN.',
                  ),
                ),
                value: controller.dnsProtectionEnabled,
                onChanged: controller.canChangeNetworkProtection
                    ? controller.setDnsProtection
                    : null,
              ),
              const Divider(height: 1),
              SwitchListTile(
                secondary: const Icon(Icons.public_outlined),
                title: Text(context.tr('Protection WebRTC')),
                subtitle: Text(
                  context.tr(
                    'Bloque les communications WebRTC qui tentent de sortir en dehors du tunnel VPN.',
                  ),
                ),
                value: controller.webRtcProtectionEnabled,
                onChanged: controller.canChangeNetworkProtection
                    ? controller.setWebRtcProtection
                    : null,
              ),
              if (!controller.canChangeNetworkProtection)
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(
                    context.tr(
                      'Déconnectez le VPN pour modifier ces protections.',
                    ),
                  ),
                ),
              if (controller.securitySettingsError case final error?)
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(
                    context.tr(error),
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
            ],
          ),
          _SettingsPanel(
            icon: Icons.fact_check_outlined,
            title: 'Diagnostic',
            subtitle: 'Rapports techniques facultatifs.',
            edgeToEdge: true,
            children: [_DiagnosticsConsentControl(controller: controller)],
          ),
        ];

        final connection = <Widget>[
          _SettingsPanel(
            icon: Icons.sync_outlined,
            title: 'Connexion',
            subtitle: 'Connexion et reconnexion automatiques.',
            edgeToEdge: true,
            children: [
              SwitchListTile(
                secondary: const Icon(Icons.login_outlined),
                title: Text(context.tr('Connexion au démarrage')),
                subtitle: Text(
                  context.tr(
                    'Se connecte automatiquement au dernier emplacement utilisé.',
                  ),
                ),
                value: controller.autoConnectOnLaunch,
                onChanged: controller.setAutoConnectOnLaunch,
              ),
              const Divider(height: 1),
              SwitchListTile(
                secondary: const Icon(Icons.sync_outlined),
                title: Text(context.tr('Reconnexion automatique')),
                subtitle: Text(
                  context.tr(
                    'Rétablit le même protocole après une sortie de veille ou un changement de réseau.',
                  ),
                ),
                value: controller.automaticReconnectEnabled,
                onChanged: controller.setAutomaticReconnect,
              ),
              if (controller.experienceSettingsError case final error?)
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(
                    context.tr(error),
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
              if (controller.securitySettingsError case final error?)
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Text(
                    context.tr(error),
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
            ],
          ),
          _SettingsPanel(
            icon: Icons.tune_outlined,
            title: 'Protocole VPN',
            subtitle: 'Choisissez le moteur VPN utilisé.',
            children: [
              _SettingsSegmentedControl<VpnProtocolPreference>(
                segments: [
                  ButtonSegment(
                    value: VpnProtocolPreference.automatic,
                    label: Text(context.tr('Automatique')),
                  ),
                  const ButtonSegment(
                    value: VpnProtocolPreference.wireGuard,
                    label: Text('WireGuard'),
                  ),
                  const ButtonSegment(
                    value: VpnProtocolPreference.openVpn,
                    label: Text('OpenVPN'),
                  ),
                ],
                selected: {controller.protocolPreference},
                onSelectionChanged:
                    controller.requiresExplicitDisconnect ||
                        controller.isConnectionBusy
                    ? null
                    : (value) => controller.setProtocolPreference(value.first),
              ),
              if (controller.protocolPreference ==
                  VpnProtocolPreference.automatic) ...[
                const SizedBox(height: 16),
                Text(
                  context.tr(
                    'WireGuard est prioritaire. OpenVPN est essayé une seule fois si WireGuard ne peut pas démarrer.',
                  ),
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ];

        final panels = switch (_category) {
          _SettingsCategory.general => general,
          _SettingsCategory.connection => connection,
          _SettingsCategory.privacy => privacy,
          _SettingsCategory.updates => <Widget>[
            WindowsUpdatePanel(
              controller: controller.updates,
              canInstall: controller.canInstallUpdate,
              installationError: controller.updateInstallationError,
              onInstall: controller.installPreparedUpdate,
            ),
          ],
        };
        final wide =
            constraints.maxWidth >= 960 &&
            MediaQuery.textScalerOf(context).scale(14) <= 18;
        final compactCategories =
            constraints.maxWidth < 620 ||
            MediaQuery.textScalerOf(context).scale(14) > 18;
        String categoryLabel(_SettingsCategory category) =>
            context.tr(switch (category) {
              _SettingsCategory.general => 'Général',
              _SettingsCategory.connection => 'Connexion',
              _SettingsCategory.privacy => 'Confidentialité',
              _SettingsCategory.updates => 'Mises à jour',
            });
        IconData categoryIcon(_SettingsCategory category) => switch (category) {
          _SettingsCategory.general => Icons.palette_outlined,
          _SettingsCategory.connection => Icons.sync_outlined,
          _SettingsCategory.privacy => Icons.shield_outlined,
          _SettingsCategory.updates => Icons.system_update_alt,
        };
        final panelList = Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            for (var index = 0; index < panels.length; index++) ...[
              if (index > 0) const SizedBox(height: 20),
              panels[index],
            ],
          ],
        );
        final scrollingPanels = SingleChildScrollView(
          key: ValueKey('settings-content-${_category.name}'),
          padding: const EdgeInsets.only(bottom: 24),
          child: panelList,
        );
        return Padding(
          padding: EdgeInsets.fromLTRB(
            constraints.maxWidth >= 760 ? 24 : 16,
            constraints.maxWidth >= 760 ? 24 : 16,
            constraints.maxWidth >= 760 ? 24 : 16,
            0,
          ),
          child: Align(
            alignment: Alignment.topCenter,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1040),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      Expanded(
                        child: Text(
                          context.tr('Réglages'),
                          style: Theme.of(context).textTheme.headlineMedium,
                        ),
                      ),
                      if (constraints.maxWidth >= 760)
                        Icon(
                          Icons.tune_outlined,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                          size: 24,
                        ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  const Divider(height: 1),
                  const SizedBox(height: 20),
                  if (wide)
                    Expanded(
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          SizedBox(
                            width: 208,
                            child: SingleChildScrollView(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                children: [
                                  for (final category
                                      in _SettingsCategory.values)
                                    Padding(
                                      padding: const EdgeInsets.only(bottom: 4),
                                      child: ChoiceChip(
                                        key: ValueKey(
                                          'settings-category-${category.name}',
                                        ),
                                        avatar: Icon(
                                          categoryIcon(category),
                                          size: 18,
                                          color: _category == category
                                              ? Theme.of(context)
                                                    .colorScheme
                                                    .onSecondaryContainer
                                              : Theme.of(
                                                  context,
                                                ).colorScheme.primary,
                                        ),
                                        label: SizedBox(
                                          width: 116,
                                          child: Text(categoryLabel(category)),
                                        ),
                                        showCheckmark: false,
                                        side: BorderSide(
                                          color: _category == category
                                              ? Theme.of(
                                                  context,
                                                ).colorScheme.outlineVariant
                                              : Colors.transparent,
                                        ),
                                        shape: RoundedRectangleBorder(
                                          borderRadius: BorderRadius.circular(
                                            12,
                                          ),
                                        ),
                                        padding: const EdgeInsets.symmetric(
                                          horizontal: 12,
                                          vertical: 10,
                                        ),
                                        backgroundColor: Colors.transparent,
                                        selectedColor: Theme.of(
                                          context,
                                        ).colorScheme.surface,
                                        selected: _category == category,
                                        onSelected: (selected) {
                                          if (selected) {
                                            setState(
                                              () => _category = category,
                                            );
                                          }
                                        },
                                      ),
                                    ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(width: 32),
                          Expanded(child: scrollingPanels),
                        ],
                      ),
                    )
                  else ...[
                    if (compactCategories)
                      Semantics(
                        label: context.tr('Réglages'),
                        child: DropdownButtonFormField<_SettingsCategory>(
                          key: const ValueKey('settings-category-selector'),
                          initialValue: _category,
                          isExpanded: true,
                          itemHeight: null,
                          decoration: const InputDecoration(
                            prefixIcon: Icon(Icons.tune_outlined),
                          ),
                          items: [
                            for (final category in _SettingsCategory.values)
                              DropdownMenuItem(
                                value: category,
                                child: Text(categoryLabel(category)),
                              ),
                          ],
                          onChanged: (category) {
                            if (category != null) {
                              setState(() => _category = category);
                            }
                          },
                        ),
                      )
                    else
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          for (final category in _SettingsCategory.values)
                            ChoiceChip(
                              key: ValueKey(
                                'settings-category-${category.name}',
                              ),
                              // A category keeps its emblem when selected.
                              // Material 3 otherwise paints an animated check
                              // and selection scrim over this avatar.
                              showCheckmark: false,
                              avatar: Icon(
                                categoryIcon(category),
                                size: 18,
                                color: _category == category
                                    ? Theme.of(
                                        context,
                                      ).colorScheme.onSecondaryContainer
                                    : Theme.of(context).colorScheme.primary,
                              ),
                              label: Text(categoryLabel(category)),
                              selected: _category == category,
                              onSelected: (selected) {
                                if (selected) {
                                  setState(() => _category = category);
                                }
                              },
                            ),
                        ],
                      ),
                    const SizedBox(height: 16),
                    Expanded(child: scrollingPanels),
                  ],
                ],
              ),
            ),
          ),
        );
      },
    ),
  );
}

class _DiagnosticsConsentControl extends StatefulWidget {
  const _DiagnosticsConsentControl({required this.controller});
  final AppController controller;
  @override
  State<_DiagnosticsConsentControl> createState() =>
      _DiagnosticsConsentControlState();
}

class _DiagnosticsConsentControlState
    extends State<_DiagnosticsConsentControl> {
  bool _saving = false;
  bool _saveFailed = false;
  String? _account;
  int _revision = 0;

  Future<void> _change(bool value) async {
    final account = widget.controller.profile?.userId;
    final revision = ++_revision;
    setState(() {
      _saving = true;
      _saveFailed = false;
    });
    final saved = await widget.controller.setDiagnosticAutomaticConsent(value);
    if (!mounted ||
        revision != _revision ||
        account != widget.controller.profile?.userId) {
      return;
    }
    setState(() {
      _saving = false;
      _saveFailed = !saved;
    });
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final account = controller.profile?.userId;
    if (account != _account) {
      _revision++;
      _account = account;
      _saving = false;
      _saveFailed = false;
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SwitchListTile(
          secondary: const Icon(Icons.description_outlined),
          title: Text(
            context.tr(
              'Envoyer automatiquement les rapports d’erreurs importants',
            ),
          ),
          subtitle: Text(
            context.tr(
              'Codes d’erreur et contexte technique liés à votre compte. Conservation sur le serveur : 30 jours. Aucun journal brut ni historique de navigation.',
            ),
          ),
          value: controller.diagnostics.automaticConsent,
          onChanged:
              account == null || !controller.diagnostics.hasSession || _saving
              ? null
              : _change,
        ),
        if (_saveFailed)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Semantics(
              liveRegion: true,
              child: Text(
                context.tr(
                  'Ce choix n’a pas pu être enregistré. Il pourrait être perdu au redémarrage. Réessayez.',
                ),
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ),
          ),
      ],
    );
  }
}

class _SettingsPanel extends StatelessWidget {
  const _SettingsPanel({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.children,
    this.edgeToEdge = false,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final List<Widget> children;
  final bool edgeToEdge;

  @override
  Widget build(BuildContext context) => Card(
    clipBehavior: Clip.antiAlias,
    child: ListTileTheme(
      data: ListTileTheme.of(context).copyWith(
        contentPadding: const EdgeInsets.symmetric(horizontal: 22, vertical: 8),
        minVerticalPadding: 10,
        iconColor: Theme.of(context).colorScheme.onSurfaceVariant,
        titleTextStyle: Theme.of(context).textTheme.titleSmall,
        subtitleTextStyle: Theme.of(context).textTheme.bodyMedium?.copyWith(
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.all(22),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
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
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        context.tr(title),
                        style: Theme.of(context).textTheme.titleLarge,
                      ),
                      const SizedBox(height: 6),
                      Text(
                        context.tr(subtitle),
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                          height: 1.4,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          if (edgeToEdge)
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: children,
              ),
            )
          else
            Padding(
              padding: const EdgeInsets.all(22),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: children,
              ),
            ),
        ],
      ),
    ),
  );
}

class _SettingsSegmentedControl<T> extends StatelessWidget {
  const _SettingsSegmentedControl({
    required this.segments,
    required this.selected,
    required this.onSelectionChanged,
  });

  final List<ButtonSegment<T>> segments;
  final Set<T> selected;
  final ValueChanged<Set<T>>? onSelectionChanged;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final painter = TextPainter(
        textDirection: Directionality.of(context),
        textScaler: MediaQuery.textScalerOf(context),
        maxLines: 1,
      );
      var segmentWidth = 0.0;
      for (final segment in segments) {
        final label = segment.label;
        painter.text = TextSpan(
          text: label is Text ? label.data ?? '' : '',
          style: Theme.of(context).textTheme.labelLarge,
        );
        painter.layout();
        segmentWidth = math.max(
          segmentWidth,
          painter.width + (segment.icon == null ? 0 : 32) + 40,
        );
      }
      painter.dispose();
      final vertical = constraints.maxWidth < segmentWidth * segments.length;
      return SegmentedButton<T>(
        showSelectedIcon: false,
        direction: vertical ? Axis.vertical : Axis.horizontal,
        expandedInsets: vertical ? null : EdgeInsets.zero,
        segments: segments,
        selected: selected,
        onSelectionChanged: onSelectionChanged,
      );
    },
  );
}
