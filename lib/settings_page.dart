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
            subtitle: 'Protections appliquées à votre ordinateur.',
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
                    'Bloque le DNS hors du tunnel sur les ports 53 et 853. Pour couvrir aussi le DNS via HTTPS, activez le kill switch.',
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
                    'Bloque l’UDP hors du tunnel VPN. Pour couvrir aussi WebRTC via TCP/TLS, activez le kill switch.',
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
              const Divider(height: 1),
              _AdBlockerSwitch(controller: controller),
            ],
          ),
          _SplitTunnelPanel(controller: controller),
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
              _SettingsCategory.privacy => 'Sécurité',
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
                  const _PageHeading(title: 'Réglages'),
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
    this.showSelectedIcon = false,
  });

  final List<ButtonSegment<T>> segments;
  final Set<T> selected;
  final ValueChanged<Set<T>>? onSelectionChanged;

  /// Replaces the selected segment's icon with a check mark.
  final bool showSelectedIcon;

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
        showSelectedIcon: showSelectedIcon,
        direction: vertical ? Axis.vertical : Axis.horizontal,
        expandedInsets: vertical ? null : EdgeInsets.zero,
        segments: segments,
        selected: selected,
        onSelectionChanged: onSelectionChanged,
      );
    },
  );
}

/// The account's DNS ad blocker. Unlike the protections above it, the
/// servers apply it within seconds, so it stays editable while connected.
class _AdBlockerSwitch extends StatefulWidget {
  const _AdBlockerSwitch({required this.controller});

  final AppController controller;

  @override
  State<_AdBlockerSwitch> createState() => _AdBlockerSwitchState();
}

class _AdBlockerSwitchState extends State<_AdBlockerSwitch> {
  @override
  void initState() {
    super.initState();
    // Another device may have changed the choice: read it each time the
    // switch appears, once the current frame is built.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) unawaited(widget.controller.refreshDnsFilter());
    });
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final settings = controller.dnsFilter;
    final busy = controller.isLoadingDnsFilter || controller.isSavingDnsFilter;
    final error = controller.dnsFilterErrorMessage;
    final muted = Theme.of(context).textTheme.bodyMedium?.copyWith(
      color: Theme.of(context).colorScheme.onSurfaceVariant,
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SwitchListTile(
          key: const ValueKey('ad-blocker-enabled'),
          secondary: const Icon(Icons.block_outlined),
          title: Text(context.tr('Bloquer la pub et le pistage')),
          subtitle: Text(
            context.tr(
              'Bloque les domaines de publicité et de pistage connus.',
            ),
          ),
          value: controller.adBlockingShown,
          onChanged: settings == null || busy ? null : controller.setAdBlocking,
        ),
        if (settings != null && !settings.available)
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 4, 20, 16),
            child: Text(
              context.tr(
                'Le bloqueur de pub est momentanément indisponible. Votre choix est conservé.',
              ),
              style: muted,
            ),
          ),
        if (error != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 4, 12, 12),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    context.tr(error),
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                TextButton(
                  key: const ValueKey('ad-blocker-retry'),
                  onPressed: busy ? null : controller.refreshDnsFilter,
                  child: Text(context.tr('Réessayer')),
                ),
              ],
            ),
          ),
      ],
    );
  }
}

class _SplitTunnelPanel extends StatefulWidget {
  const _SplitTunnelPanel({required this.controller});

  final AppController controller;

  @override
  State<_SplitTunnelPanel> createState() => _SplitTunnelPanelState();
}

class _SplitTunnelPanelState extends State<_SplitTunnelPanel> {
  final _rangeController = TextEditingController();
  String? _rangeError;

  AppController get _controller => widget.controller;

  @override
  void dispose() {
    _rangeController.dispose();
    super.dispose();
  }

  void _addRange() {
    String? error;
    final next = _controller.splitTunnel.withAddedRange(
      _rangeController.text,
      error: (value) => error = value,
    );
    setState(() => _rangeError = error);
    if (next == null) return;
    _rangeController.clear();
    _controller.setSplitTunnel(next);
  }

  @override
  Widget build(BuildContext context) {
    final settings = _controller.splitTunnel;
    final editable = _controller.canChangeNetworkProtection;
    final exclude = settings.mode == SplitTunnelMode.exclude;
    final muted = Theme.of(context).textTheme.bodyMedium?.copyWith(
      color: Theme.of(context).colorScheme.onSurfaceVariant,
      height: 1.4,
    );
    void save(SplitTunnelSettings next) => _controller.setSplitTunnel(next);
    return _SettingsPanel(
      icon: Icons.call_split_outlined,
      title: 'Tunnel fractionné',
      subtitle: 'Choisissez les adresses qui passent par le VPN ou en dehors.',
      edgeToEdge: true,
      children: [
        SwitchListTile(
          key: const ValueKey('split-tunnel-enabled'),
          secondary: const Icon(Icons.call_split_outlined),
          title: Text(context.tr('Activer le tunnel fractionné')),
          subtitle: settings.enabled
              ? null
              : Text(context.tr('Désactivé, tout le trafic passe par le VPN.')),
          value: settings.enabled,
          onChanged: editable
              ? (value) => save(settings.copyWith(enabled: value))
              : null,
        ),
        if (settings.enabled) ...[
          const Divider(height: 1),
          Padding(
            padding: const EdgeInsets.fromLTRB(22, 16, 22, 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _SettingsSegmentedControl<SplitTunnelMode>(
                  segments: [
                    ButtonSegment(
                      value: SplitTunnelMode.exclude,
                      label: Text(context.tr('Exclure du VPN')),
                    ),
                    ButtonSegment(
                      value: SplitTunnelMode.include,
                      label: Text(context.tr('Seulement via le VPN')),
                    ),
                  ],
                  selected: {settings.mode},
                  onSelectionChanged: editable
                      ? (value) => save(settings.copyWith(mode: value.first))
                      : null,
                ),
                const SizedBox(height: 12),
                Text(
                  context.tr(
                    exclude
                        ? 'Tout passe par le VPN, sauf les adresses de la liste.'
                        : 'Seules les adresses de la liste passent par le VPN. Le reste utilise votre connexion habituelle.',
                  ),
                  style: muted,
                ),
              ],
            ),
          ),
          if (exclude) ...[
            const Divider(height: 1),
            SwitchListTile(
              key: const ValueKey('split-tunnel-lan'),
              secondary: const Icon(Icons.lan_outlined),
              title: Text(context.tr('Accès au réseau local')),
              subtitle: Text(
                context.tr(
                  'Imprimantes, NAS et appareils de la maison restent joignables hors du VPN.',
                ),
              ),
              value: settings.allowLocalNetwork,
              onChanged: editable
                  ? (value) => save(settings.copyWith(allowLocalNetwork: value))
                  : null,
            ),
          ],
          const Divider(height: 1),
          if (settings.ranges.isEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(22, 16, 22, 4),
              child: Text(
                context.tr(
                  exclude
                      ? 'Aucune adresse exclue pour l’instant.'
                      : 'Ajoutez au moins une adresse : sinon, tout le trafic passe par le VPN.',
                ),
                style: muted,
              ),
            )
          else
            for (final range in settings.ranges)
              ListTile(
                key: ValueKey('split-tunnel-range-${range.cidr}'),
                leading: const Icon(Icons.router_outlined),
                title: Text(range.toString(), textDirection: TextDirection.ltr),
                // While locked, the list is shown without any edit control.
                trailing: editable
                    ? IconButton(
                        tooltip: context.tr('Retirer'),
                        icon: const Icon(Icons.close),
                        onPressed: () => save(settings.withoutRange(range)),
                      )
                    : null,
              ),
          if (editable)
            Padding(
              padding: const EdgeInsets.fromLTRB(22, 12, 22, 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: TextField(
                      key: const ValueKey('split-tunnel-range-field'),
                      controller: _rangeController,
                      textDirection: TextDirection.ltr,
                      decoration: InputDecoration(
                        labelText: context.tr('Adresse IP ou plage CIDR'),
                        hintText: '192.168.1.0/24',
                        errorText: _rangeError == null
                            ? null
                            : context.tr(_rangeError!),
                        errorMaxLines: 3,
                      ),
                      onSubmitted: (_) => _addRange(),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Padding(
                    padding: const EdgeInsets.only(top: 6),
                    child: FilledButton.tonal(
                      key: const ValueKey('split-tunnel-add'),
                      onPressed: _addRange,
                      child: Text(context.tr('Ajouter')),
                    ),
                  ),
                ],
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(22, 8, 22, 16),
            child: Text(
              context.tr(
                exclude
                    ? 'Le DNS passe toujours par le VPN. Avec le kill switch, ces exceptions restent actives si le VPN se coupe.'
                    : 'Le DNS passe toujours par le VPN. Avec le kill switch, les adresses de la liste restent bloquées si le VPN se coupe.',
              ),
              style: muted,
            ),
          ),
        ],
        if (!editable)
          Padding(
            padding: const EdgeInsets.all(20),
            child: Text(
              context.tr(
                'Déconnectez le VPN pour modifier le tunnel fractionné.',
              ),
            ),
          ),
        if (_controller.splitTunnelSettingsError case final error?)
          Padding(
            padding: const EdgeInsets.all(20),
            child: Text(
              context.tr(error),
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
      ],
    );
  }
}
