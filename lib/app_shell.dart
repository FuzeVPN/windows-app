// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart' show DateFormat;
import 'package:url_launcher/url_launcher.dart';

import 'app_controller.dart';
import 'app_exit.dart';
import 'app_theme.dart';
import 'brand_config.dart';
import 'core/location_directory.dart';
import 'core/models.dart';
import 'core/windows_update_controller.dart';
import 'fuze_emblem.dart';
import 'l10n/app_localizations.dart';
import 'windows_update_panel.dart';

part 'settings_page.dart';
part 'connection_page.dart';
part 'devices_page.dart';
part 'locations_page.dart';
part 'diagnostics_panel.dart';
part 'account_subscription_panel.dart';

class AppShell extends StatefulWidget {
  const AppShell({super.key, required this.controller});

  final AppController controller;

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  _SignInRequest? get _signInRequest => _activeSignInRequests[controller];
  bool _authenticationGateScheduled = false;
  bool _resumeConnectionAfterSignIn = false;
  String? _dismissedUpdateVersion;

  AppController get controller => widget.controller;

  @override
  void initState() {
    super.initState();
    controller.addListener(_handleControllerChanged);
    _scheduleAuthenticationGate();
  }

  @override
  void didUpdateWidget(covariant AppShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != controller) {
      oldWidget.controller.removeListener(_handleControllerChanged);
      controller.addListener(_handleControllerChanged);
    }
    _scheduleAuthenticationGate();
  }

  @override
  void dispose() {
    controller.removeListener(_handleControllerChanged);
    super.dispose();
  }

  void _handleControllerChanged() => _scheduleAuthenticationGate();

  bool get _needsAuthenticationGate =>
      mounted &&
      controller.isInitialized &&
      controller.profile == null &&
      !controller.savedSessionVerificationPending &&
      !controller.runtimeVerificationPending &&
      !controller.requiresExplicitDisconnect &&
      !controller.runtimeOwnedByAnotherUser &&
      !controller.isConnectionBusy;

  void _scheduleAuthenticationGate() {
    if (!_needsAuthenticationGate) return;
    _resumeConnectionAfterSignIn |= controller.takeSignInPrompt();
    if (_signInRequest case final request?) {
      request.merge(
        resumeConnection: _resumeConnectionAfterSignIn,
        authenticationRequired: true,
      );
      _resumeConnectionAfterSignIn = false;
      return;
    }
    if (_authenticationGateScheduled) return;
    _authenticationGateScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      _authenticationGateScheduled = false;
      if (!_needsAuthenticationGate) {
        if (_signInRequest == null) _resumeConnectionAfterSignIn = false;
        return;
      }
      await _openSignInDialog(authenticationRequired: true);
    });
  }

  Future<void> _openSignInDialog({
    bool resumeConnection = false,
    bool authenticationRequired = false,
  }) {
    if (!mounted) return Future.value();
    resumeConnection |= _resumeConnectionAfterSignIn;
    _resumeConnectionAfterSignIn = false;
    return _showSignInDialog(
      context,
      controller,
      resumeConnection: resumeConnection,
      authenticationRequired: authenticationRequired,
    ).whenComplete(() {
      if (mounted) _scheduleAuthenticationGate();
    });
  }

  @override
  Widget build(BuildContext context) {
    Widget shell = LayoutBuilder(
      builder: (context, constraints) {
        final textScale = MediaQuery.textScalerOf(context).scale(14) / 14;
        final desktop = constraints.maxWidth >= 1040 && textScale <= 1.35;
        if (!desktop) {
          return Scaffold(
            appBar: AppBar(
              toolbarHeight: 64,
              title: const _FuzeBrand(),
              actions: [
                IconButton(
                  tooltip: context.tr('Ouvrir l’aide'),
                  onPressed: () => controller.selectSection(AppSection.help),
                  icon: const Icon(Icons.help_outline),
                ),
                _AccountBlock(controller: controller, compact: true),
                const SizedBox(width: 8),
              ],
            ),
            drawer: Drawer(
              backgroundColor: AppTheme.brand,
              child: _Sidebar(
                controller: controller,
                compact: false,
                closeOnSelect: true,
              ),
            ),
            body: Column(
              children: [
                _updateNotice(),
                _savedSessionNotice(),
                Expanded(child: _Content(controller: controller)),
              ],
            ),
          );
        }
        return Scaffold(
          body: SafeArea(
            child: Row(
              children: [
                _Sidebar(controller: controller, compact: false),
                Expanded(
                  child: Column(
                    children: [
                      _updateNotice(),
                      _savedSessionNotice(),
                      Expanded(child: _Content(controller: controller)),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
    shell = CallbackShortcuts(
      bindings: <ShortcutActivator, VoidCallback>{
        const SingleActivator(LogicalKeyboardKey.digit1, control: true): () =>
            controller.selectSection(AppSection.connection),
        const SingleActivator(LogicalKeyboardKey.digit2, control: true): () =>
            controller.selectSection(AppSection.locations),
        const SingleActivator(LogicalKeyboardKey.comma, control: true): () =>
            controller.selectSection(AppSection.settings),
        const SingleActivator(LogicalKeyboardKey.keyF, control: true): () =>
            controller.selectSection(AppSection.locations),
      },
      child: FocusTraversalGroup(child: shell),
    );

    if (!MediaQuery.highContrastOf(context)) return shell;

    final theme = Theme.of(context);
    final highContrastBorder = theme.colorScheme.onSurface;
    return Theme(
      data: theme.copyWith(
        colorScheme: theme.colorScheme.copyWith(
          outline: highContrastBorder,
          outlineVariant: highContrastBorder,
        ),
        dividerColor: highContrastBorder,
        focusColor: theme.colorScheme.primary.withValues(alpha: 0.24),
        cardTheme: theme.cardTheme.copyWith(
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(6),
            side: BorderSide(color: highContrastBorder, width: 1.5),
          ),
        ),
      ),
      child: shell,
    );
  }

  Widget _savedSessionNotice() {
    if (!controller.savedSessionVerificationPending) {
      return const SizedBox.shrink();
    }
    return Padding(
      key: const ValueKey('saved-session-verification-notice'),
      padding: const EdgeInsets.all(16),
      child: _NoticeCard(
        icon: Icons.account_circle_outlined,
        title: 'Vérification du compte',
        message: [
          context.tr('Votre session est conservée. Réessayez sa vérification.'),
          if (controller.savedSessionVerificationErrorMessage
              case final message?)
            context.tr(message),
        ].join('\n'),
        actionLabel: 'Réessayer',
        onAction:
            controller.isVerifyingSavedSession ||
                controller.runtimeVerificationPending ||
                controller.requiresExplicitDisconnect ||
                controller.isConnectionBusy
            ? null
            : controller.retrySavedSessionVerification,
      ),
    );
  }

  Widget _updateNotice() {
    final update = controller.updates;
    final version = update.release?.version.toString();
    if (version == null ||
        version == _dismissedUpdateVersion ||
        (update.status != WindowsUpdateStatus.available &&
            update.status != WindowsUpdateStatus.ready)) {
      return const SizedBox.shrink();
    }
    return Material(
      color: Theme.of(context).colorScheme.secondaryContainer,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
        child: Row(
          children: [
            Expanded(
              child: Text(context.tr('Une nouvelle version est disponible.')),
            ),
            TextButton(
              onPressed: () => _showUpdatesDialog(context, controller),
              child: Text(context.tr('Mises à jour')),
            ),
            IconButton(
              tooltip: context.tr('Plus tard'),
              onPressed: () =>
                  setState(() => _dismissedUpdateVersion = version),
              icon: const Icon(Icons.close),
            ),
          ],
        ),
      ),
    );
  }
}

class _FuzeBrand extends StatelessWidget {
  const _FuzeBrand({this.compact = false, this.onDark = false});

  final bool compact;
  final bool onDark;

  @override
  Widget build(BuildContext context) {
    final color = onDark
        ? AppTheme.ivory
        : Theme.of(context).colorScheme.onSurface;
    return Semantics(
      label: 'FuzeVPN',
      container: true,
      image: true,
      excludeSemantics: true,
      child: FittedBox(
        fit: BoxFit.scaleDown,
        alignment: AlignmentDirectional.centerStart,
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            FuzeEmblem(color: color),
            if (!compact) ...[
              const SizedBox(width: 8),
              Text(
                'FuzeVPN',
                textScaler: TextScaler.noScaling,
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                  color: color,
                  fontSize: 25,
                  letterSpacing: -0.9,
                  fontWeight: FontWeight.w800,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({
    required this.controller,
    required this.compact,
    this.closeOnSelect = false,
  });

  final AppController controller;
  final bool compact;
  final bool closeOnSelect;

  void _select(BuildContext context, AppSection section) {
    controller.selectSection(section);
    if (closeOnSelect) Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) => SizedBox(
    width: compact
        ? 80
        : closeOnSelect
        ? 280
        : 220,
    child: Material(
      color: AppTheme.brand,
      child: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: EdgeInsets.fromLTRB(compact ? 20 : 22, 26, 18, 20),
              child: _FuzeBrand(compact: compact, onDark: true),
            ),
            if (!compact)
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
                child: Row(
                  children: [
                    Container(width: 20, height: 2, color: AppTheme.signal),
                    const SizedBox(width: 9),
                    Text(
                      'WINDOWS',
                      style: Theme.of(context).textTheme.labelSmall?.copyWith(
                        color: AppTheme.ivory.withValues(alpha: 0.6),
                        fontSize: 10,
                        letterSpacing: 1.5,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                children: [
                  _NavItem(
                    section: AppSection.connection,
                    label: 'Connexion',
                    icon: Icons.shield_outlined,
                    controller: controller,
                    compact: compact,
                    onSelected: () => _select(context, AppSection.connection),
                  ),
                  _NavItem(
                    section: AppSection.locations,
                    label: 'Emplacements',
                    icon: Icons.public_outlined,
                    controller: controller,
                    compact: compact,
                    onSelected: () => _select(context, AppSection.locations),
                  ),
                  _NavItem(
                    section: AppSection.devices,
                    label: 'Appareils',
                    icon: Icons.devices_other_outlined,
                    controller: controller,
                    compact: compact,
                    onSelected: () => _select(context, AppSection.devices),
                  ),
                  Padding(
                    padding: const EdgeInsets.symmetric(
                      vertical: 16,
                      horizontal: 12,
                    ),
                    child: Divider(
                      color: AppTheme.ivory.withValues(alpha: 0.12),
                    ),
                  ),
                  _NavItem(
                    section: AppSection.settings,
                    label: 'Réglages',
                    icon: Icons.tune_outlined,
                    controller: controller,
                    compact: compact,
                    onSelected: () => _select(context, AppSection.settings),
                  ),
                  _NavItem(
                    section: AppSection.help,
                    label: 'Diagnostic',
                    icon: Icons.help_outline,
                    controller: controller,
                    compact: compact,
                    onSelected: () => _select(context, AppSection.help),
                  ),
                ],
              ),
            ),
            Divider(color: AppTheme.ivory.withValues(alpha: 0.12)),
            _AccountBlock(
              controller: controller,
              compact: compact,
              onDark: true,
            ),
          ],
        ),
      ),
    ),
  );
}

class _NavItem extends StatefulWidget {
  const _NavItem({
    required this.section,
    required this.label,
    required this.icon,
    required this.controller,
    required this.compact,
    this.onSelected,
  });

  final AppSection section;
  final String label;
  final IconData icon;
  final AppController controller;
  final bool compact;
  final VoidCallback? onSelected;

  @override
  State<_NavItem> createState() => _NavItemState();
}

class _NavItemState extends State<_NavItem> {
  bool _focused = false;
  AppSection get section => widget.section;
  String get label => widget.label;
  IconData get icon => widget.icon;
  AppController get controller => widget.controller;
  bool get compact => widget.compact;
  VoidCallback? get onSelected => widget.onSelected;

  @override
  Widget build(BuildContext context) {
    final displayLabel = context.tr(label);
    final selected = controller.section == section;
    final color = selected
        ? AppTheme.signal
        : AppTheme.ivory.withValues(alpha: 0.68);
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Tooltip(
        message: displayLabel,
        child: Semantics(
          selected: selected,
          child: Material(
            color: selected
                ? AppTheme.signal.withValues(alpha: 0.1)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(6),
            child: InkWell(
              onTap: onSelected ?? () => controller.selectSection(section),
              onFocusChange: (focused) => setState(() => _focused = focused),
              focusColor: Colors.transparent,
              hoverColor: AppTheme.ivory.withValues(alpha: 0.05),
              borderRadius: BorderRadius.circular(6),
              child: Container(
                constraints: const BoxConstraints(minHeight: 46),
                padding: EdgeInsets.symmetric(
                  horizontal: compact ? 16 : 14,
                  vertical: 13,
                ),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    width: 2,
                    color: _focused
                        ? AppTheme.signal
                        : selected
                        ? AppTheme.signal.withValues(alpha: 0.22)
                        : Colors.transparent,
                  ),
                ),
                child: Row(
                  mainAxisAlignment: compact
                      ? MainAxisAlignment.center
                      : MainAxisAlignment.start,
                  children: [
                    Icon(icon, color: color, size: 21),
                    if (!compact) ...[
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          displayLabel,
                          style: Theme.of(context).textTheme.labelLarge
                              ?.copyWith(
                                color: color,
                                fontWeight: selected
                                    ? FontWeight.w700
                                    : FontWeight.w500,
                              ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _AccountBlock extends StatefulWidget {
  const _AccountBlock({
    required this.controller,
    required this.compact,
    this.onDark = false,
  });

  final AppController controller;
  final bool compact;
  final bool onDark;

  @override
  State<_AccountBlock> createState() => _AccountBlockState();
}

class _AccountBlockState extends State<_AccountBlock> {
  bool _focused = false;
  AppController get controller => widget.controller;
  bool get compact => widget.compact;
  bool get onDark => widget.onDark;

  @override
  Widget build(BuildContext context) {
    final signedIn = controller.profile != null;
    final theme = Theme.of(context);
    final foreground = onDark ? AppTheme.ivory : theme.colorScheme.onSurface;
    final sessionPending = controller.savedSessionVerificationPending;
    final label = signedIn
        ? (controller.profile!.firstName.isNotEmpty
              ? controller.profile!.firstName
              : controller.profile!.email)
        : context.tr(
            sessionPending ? 'Vérification du compte' : 'Compte non connecté',
          );
    final avatar = Container(
      width: 36,
      height: 36,
      decoration: BoxDecoration(
        color: onDark
            ? AppTheme.signal.withValues(alpha: 0.12)
            : theme.colorScheme.primaryContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(
        signedIn || sessionPending ? Icons.person_outline : Icons.login,
        color: onDark ? AppTheme.signal : theme.colorScheme.onPrimaryContainer,
        size: 20,
      ),
    );
    if (compact) {
      return IconButton(
        tooltip: context.tr('Mon compte'),
        onPressed: () => _openAccountDestination(context, controller),
        icon: avatar,
      );
    }
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Tooltip(
        message: context.tr('Mon compte'),
        child: Material(
          color: onDark
              ? AppTheme.ivory.withValues(alpha: 0.04)
              : theme.colorScheme.surface,
          borderRadius: BorderRadius.circular(6),
          child: InkWell(
            borderRadius: BorderRadius.circular(6),
            onFocusChange: (focused) => setState(() => _focused = focused),
            focusColor: Colors.transparent,
            hoverColor: onDark ? AppTheme.ivory.withValues(alpha: 0.05) : null,
            onTap: () => _openAccountDestination(context, controller),
            child: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(6),
                border: Border.all(
                  width: 2,
                  color: _focused
                      ? (onDark ? AppTheme.signal : theme.colorScheme.primary)
                      : Colors.transparent,
                ),
              ),
              child: Row(
                children: [
                  avatar,
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          label,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.labelLarge?.copyWith(
                            color: foreground,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          context.tr(
                            signedIn
                                ? 'Mon compte'
                                : sessionPending
                                ? 'Réessayer'
                                : 'Se connecter',
                          ),
                          style: theme.textTheme.labelSmall?.copyWith(
                            color: foreground.withValues(alpha: 0.58),
                          ),
                        ),
                      ],
                    ),
                  ),
                  Icon(
                    Icons.chevron_right,
                    size: 16,
                    color: foreground.withValues(alpha: 0.45),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _Content extends StatelessWidget {
  const _Content({required this.controller});

  final AppController controller;

  @override
  Widget build(BuildContext context) => AnimatedSwitcher(
    duration: MediaQuery.disableAnimationsOf(context)
        ? Duration.zero
        : const Duration(milliseconds: 180),
    child: switch (controller.section) {
      AppSection.connection => _ConnectionPage(
        key: const ValueKey('connection'),
        controller: controller,
      ),
      AppSection.locations => _LocationsPage(
        key: const ValueKey('locations'),
        controller: controller,
      ),
      AppSection.devices => DevicesPage(
        key: const ValueKey('devices'),
        controller: controller,
      ),
      AppSection.settings => _SettingsPage(
        key: const ValueKey('settings'),
        controller: controller,
      ),
      AppSection.help => _DiagnosticsPage(
        key: const ValueKey('help'),
        controller: controller,
      ),
    },
  );
}

class _PageLayout extends StatelessWidget {
  const _PageLayout({
    required this.title,
    required this.subtitle,
    required this.child,
    this.action,
    this.scrollController,
    this.maxWidth = 1040,
    this.centerContent = false,
  });

  final String title;
  final String? subtitle;
  final Widget child;
  final Widget? action;
  final ScrollController? scrollController;
  final double maxWidth;
  final bool centerContent;

  @override
  Widget build(BuildContext context) => SafeArea(
    child: LayoutBuilder(
      builder: (context, constraints) => SingleChildScrollView(
        controller: scrollController,
        padding: EdgeInsets.all(constraints.maxWidth >= 760 ? 24 : 16),
        child: Center(
          child: ConstrainedBox(
            constraints: BoxConstraints(
              maxWidth: maxWidth,
              minHeight: math.max(
                0,
                constraints.maxHeight - (constraints.maxWidth >= 760 ? 48 : 32),
              ),
            ),
            child: Column(
              mainAxisAlignment: centerContent
                  ? MainAxisAlignment.center
                  : MainAxisAlignment.start,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                LayoutBuilder(
                  builder: (context, headerConstraints) {
                    final heading = Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Container(
                          width: 3,
                          height: 36,
                          margin: const EdgeInsetsDirectional.only(
                            end: 16,
                            top: 2,
                          ),
                          color: AppTheme.signal,
                        ),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                context.tr(title),
                                style: Theme.of(context)
                                    .textTheme
                                    .headlineMedium
                                    ?.copyWith(
                                      fontWeight: FontWeight.w700,
                                      letterSpacing: AppTheme.tracking(
                                        context,
                                        -0.8,
                                      ),
                                    ),
                              ),
                              if (subtitle != null) ...[
                                const SizedBox(height: 4),
                                Text(
                                  context.tr(subtitle!),
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
                    );
                    if (action == null) return heading;
                    final inline =
                        headerConstraints.maxWidth >=
                        (action is IconButton ? 360 : 640) *
                            math.max(
                              1,
                              MediaQuery.textScalerOf(context).scale(14) / 14,
                            );
                    return inline
                        ? Row(
                            crossAxisAlignment: CrossAxisAlignment.center,
                            children: [
                              Expanded(child: heading),
                              const SizedBox(width: 24),
                              action!,
                            ],
                          )
                        : Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              heading,
                              const SizedBox(height: 12),
                              action!,
                            ],
                          );
                  },
                ),
                const SizedBox(height: 20),
                child,
              ],
            ),
          ),
        ),
      ),
    ),
  );
}

class _LocationRow extends StatelessWidget {
  const _LocationRow({
    super.key,
    required this.location,
    this.title,
    this.unavailableReason,
    required this.selected,
    required this.favorite,
    required this.recent,
    required this.onTap,
    required this.onToggleFavorite,
  });

  final Location location;
  final String? title;
  final String? unavailableReason;
  final bool selected;
  final bool favorite;
  final bool recent;
  final VoidCallback? onTap;
  final VoidCallback onToggleFavorite;

  @override
  Widget build(BuildContext context) => Semantics(
    button: true,
    enabled: onTap != null,
    selected: selected,
    label:
        '${location.displayName}, ${location.city}, ${_countryName(context, location.countryCode)}${favorite ? ', ${context.tr('Favori')}' : ''}${recent ? ', ${context.tr('Récent')}' : ''}${selected ? ', ${context.tr('Sélectionné')}' : ''}',
    child: LayoutBuilder(
      builder: (context, constraints) {
        final showRecent =
            recent &&
            constraints.maxWidth >=
                520 *
                    math.max(
                      1,
                      MediaQuery.textScalerOf(context).scale(14) / 14,
                    );
        return Material(
          color: selected
              ? Theme.of(context).colorScheme.primaryContainer
              : Colors.transparent,
          child: InkWell(
            onTap: onTap,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 15),
              child: Row(
                children: [
                  ExcludeSemantics(
                    child: _CountryFlag(
                      countryCode: location.countryCode,
                      width: 36,
                      height: 24,
                    ),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          title ?? location.displayName,
                          style: Theme.of(context).textTheme.titleMedium
                              ?.copyWith(
                                fontWeight: FontWeight.w700,
                                fontSize: 15,
                                color: unavailableReason == null
                                    ? null
                                    : Theme.of(
                                        context,
                                      ).colorScheme.onSurfaceVariant,
                              ),
                        ),
                        const SizedBox(height: 3),
                        Text(
                          unavailableReason ??
                              (title == null
                                  ? '${location.city} · ${_countryName(context, location.countryCode)}'
                                  : location.displayName),
                          style: TextStyle(
                            color: Theme.of(
                              context,
                            ).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (showRecent)
                    Padding(
                      padding: const EdgeInsetsDirectional.only(end: 8),
                      child: _LocationTag(
                        icon: Icons.history,
                        label: context.tr('Récent'),
                      ),
                    ),
                  IconButton(
                    tooltip: context.tr(
                      favorite ? 'Retirer des favoris' : 'Ajouter aux favoris',
                    ),
                    onPressed: onToggleFavorite,
                    icon: Icon(
                      favorite ? Icons.star : Icons.star_border,
                      color: favorite
                          ? AppTheme.warningFor(context)
                          : Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (selected) ...[
                    const SizedBox(width: 4),
                    Icon(
                      Icons.check_circle,
                      color: AppTheme.successFor(context),
                    ),
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

class _LocationTag extends StatelessWidget {
  const _LocationTag({required this.icon, required this.label});

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Icon(icon, size: 14, color: Theme.of(context).colorScheme.primary),
      const SizedBox(width: 4),
      Text(
        label,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.w600,
        ),
      ),
    ],
  );
}

Future<void> _requestLocationChange(
  BuildContext context,
  AppController controller,
  Location target,
) async {
  if (controller.isConnectionBusy) return;
  final preparation = await controller.prepareLocationChange(target);
  if (!context.mounted) return;
  switch (preparation) {
    case LocationChangePreparation.selectedLocally:
    case LocationChangePreparation.alreadyOnTarget:
      return;
    case LocationChangePreparation.unavailable:
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            context.tr('Impossible de vérifier cet appareil pour le moment.'),
          ),
        ),
      );
      return;
    case LocationChangePreparation.migrationInProgress:
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            context.tr('Un changement de serveur est déjà en cours.'),
          ),
        ),
      );
      return;
    case LocationChangePreparation.confirmationRequired:
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (dialogContext) => AlertDialog(
          title: Text(context.tr('Changer de serveur ?')),
          content: Text(
            context.tr(
              'Souhaitez-vous vraiment changer de serveur ? Votre connexion VPN sera interrompue pendant le changement, puis rétablie automatiquement.',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: Text(context.tr('Annuler')),
            ),
            FilledButton(
              onPressed: () => Navigator.of(dialogContext).pop(true),
              child: Text(context.tr('Changer de serveur')),
            ),
          ],
        ),
      );
      if (confirmed == true && context.mounted) {
        await controller.confirmPreparedLocationChange();
      }
      return;
  }
}

Future<void> _showUpdatesDialog(
  BuildContext context,
  AppController controller,
) => showDialog<void>(
  context: context,
  builder: (dialogContext) => AnimatedBuilder(
    animation: controller,
    builder: (context, _) => AlertDialog(
      scrollable: true,
      contentPadding: const EdgeInsets.all(8),
      content: SizedBox(
        width: 500,
        child: WindowsUpdatePanel(
          controller: controller.updates,
          canInstall: controller.canInstallUpdate,
          installationError: controller.updateInstallationError,
          onInstall: controller.installPreparedUpdate,
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(dialogContext),
          child: Text(context.tr('Fermer')),
        ),
      ],
    ),
  ),
);

class _NoticeCard extends StatelessWidget {
  const _NoticeCard({
    required this.icon,
    required this.title,
    required this.message,
    this.actionLabel,
    this.onAction,
  });

  final IconData icon;
  final String title;
  final String message;
  final String? actionLabel;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) => Semantics(
    liveRegion: true,
    child: Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: LayoutBuilder(
          builder: (context, constraints) {
            final inlineAction =
                constraints.maxWidth >=
                660 *
                    math.max(
                      1,
                      MediaQuery.textScalerOf(context).scale(14) / 14,
                    );
            final action = onAction == null
                ? null
                : OutlinedButton(
                    onPressed: onAction,
                    child: Text(context.tr(actionLabel!)),
                  );
            return Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  icon,
                  size: 22,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        context.tr(title),
                        style: const TextStyle(fontWeight: FontWeight.w700),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        context.tr(message),
                        style: TextStyle(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                      if (action != null && !inlineAction) ...[
                        const SizedBox(height: 8),
                        action,
                      ],
                    ],
                  ),
                ),
                if (action != null && inlineAction) ...[
                  const SizedBox(width: 16),
                  action,
                ],
              ],
            );
          },
        ),
      ),
    ),
  );
}

class _DeviceEnrollmentIssueCard extends StatelessWidget {
  const _DeviceEnrollmentIssueCard({
    required this.controller,
    required this.issue,
  });

  final AppController controller;
  final DeviceEnrollmentIssue issue;

  @override
  Widget build(BuildContext context) {
    final action = switch (issue.kind) {
      DeviceEnrollmentIssueKind.sessionExpired => (
        'Se connecter',
        () => _showSignInDialog(context, controller),
      ),
      DeviceEnrollmentIssueKind.emailVerificationRequired => (
        'Confirmer mon e-mail',
        () => _openWebsite(context, BrandConfig.portalVerifyEmail),
      ),
      DeviceEnrollmentIssueKind.subscriptionRequired => (
        'Mon compte',
        () => _openAccountDestination(context, controller),
      ),
      DeviceEnrollmentIssueKind.deviceLimit => (
        'Gérer mes appareils',
        () => controller.selectSection(AppSection.devices),
      ),
      DeviceEnrollmentIssueKind.deviceExists => (
        'Gérer sur le Web',
        () => _openWebsite(context, BrandConfig.portalDashboard),
      ),
      DeviceEnrollmentIssueKind.deviceIdentityRevoked => (
        'Créer une nouvelle identité',
        () => _confirmIdentityReset(context, controller),
      ),
      DeviceEnrollmentIssueKind.openVpnProfileExists => (
        'Réessayer',
        controller.toggleConnection,
      ),
      DeviceEnrollmentIssueKind.openVpnProfileRevoked => (
        'Renouveler le profil',
        controller.renewOpenVpnProfile,
      ),
      DeviceEnrollmentIssueKind.openVpnOperationPending => (
        'Réessayer',
        controller.toggleConnection,
      ),
      DeviceEnrollmentIssueKind.openVpnSignerUnavailable => (
        'Voir les réglages',
        () => controller.selectSection(AppSection.settings),
      ),
      DeviceEnrollmentIssueKind.nodeUnavailable => (
        'Voir les options',
        () => _showNodeUnavailableDialog(context, controller),
      ),
      DeviceEnrollmentIssueKind.serverFull ||
      DeviceEnrollmentIssueKind.capacityUnavailable => (
        'Choisir un emplacement',
        () => controller.selectSection(AppSection.locations),
      ),
      DeviceEnrollmentIssueKind.rateLimited => (
        'Réessayer',
        controller.toggleConnection,
      ),
      DeviceEnrollmentIssueKind.unknown => (
        'Réessayer',
        controller.toggleConnection,
      ),
    };
    return _NoticeCard(
      icon: Icons.info_outline,
      title: issue.title,
      message: issue.message,
      actionLabel: action.$1,
      onAction: action.$2,
    );
  }
}

class _ConnectionState {
  const _ConnectionState({
    required this.label,
    required this.description,
    required this.icon,
    required this.color,
  });

  final String label;
  final String description;
  final IconData icon;
  final Color color;
}

_ConnectionState _connectionState(
  VpnStatus value,
  BuildContext context,
) => switch (value) {
  VpnStatus.connected => _ConnectionState(
    label: context.tr('Protégé'),
    description: context.tr('Votre connexion est protégée par FuzeVPN.'),
    icon: Icons.lock_outline,
    color: AppTheme.successFor(context),
  ),
  VpnStatus.connecting => _ConnectionState(
    label: context.tr('Connexion en cours'),
    description: context.tr('Nous établissons une connexion sécurisée.'),
    icon: Icons.sync,
    color: Theme.of(context).colorScheme.onSurface,
  ),
  VpnStatus.preparing => _ConnectionState(
    label: context.tr('Préparation de la connexion'),
    description: context.tr('Nous préparons votre connexion sécurisée.'),
    icon: Icons.sync,
    color: Theme.of(context).colorScheme.onSurface,
  ),
  VpnStatus.disconnecting => _ConnectionState(
    label: context.tr('Déconnexion en cours'),
    description: context.tr('Nous arrêtons le tunnel VPN en toute sécurité.'),
    icon: Icons.sync,
    color: Theme.of(context).colorScheme.onSurface,
  ),
  VpnStatus.blocked => _ConnectionState(
    label: context.tr('Trafic bloqué'),
    description: context.tr('Internet est bloqué par les protections du VPN.'),
    icon: Icons.gpp_maybe_outlined,
    color: AppTheme.warningFor(context),
  ),
  VpnStatus.error => _ConnectionState(
    label: context.tr('Connexion impossible'),
    description: context.tr(
      'La connexion nécessite votre attention. Consultez le diagnostic.',
    ),
    icon: Icons.error_outline,
    color: Theme.of(context).colorScheme.error,
  ),
  VpnStatus.disconnected => _ConnectionState(
    label: context.tr('Non protégé'),
    description: context.tr(
      'Votre trafic utilise actuellement votre connexion Internet normale.',
    ),
    icon: Icons.shield_outlined,
    color: Theme.of(context).colorScheme.onSurface,
  ),
};

String _formatDuration(Duration value) {
  final hours = value.inHours;
  final minutes = value.inMinutes.remainder(60).toString().padLeft(2, '0');
  final seconds = value.inSeconds.remainder(60).toString().padLeft(2, '0');
  return hours > 0 ? '$hours:$minutes:$seconds' : '$minutes:$seconds';
}

class _CountryFlag extends StatelessWidget {
  const _CountryFlag({
    required this.countryCode,
    required this.width,
    required this.height,
  });

  final String countryCode;
  final double width;
  final double height;

  @override
  Widget build(BuildContext context) {
    final normalizedCode = countryCode.trim().toUpperCase();
    final isIsoCode = _isIsoCountryCode(normalizedCode);

    return Semantics(
      key: ValueKey('country-flag-$normalizedCode'),
      label: _CountryFlagPainter.drawnCountries.contains(normalizedCode)
          ? context
                .tr('Drapeau : {country}')
                .replaceAll('{country}', _countryName(context, normalizedCode))
          : _countryName(context, normalizedCode),
      child: Container(
        width: width,
        height: height,
        clipBehavior: Clip.antiAlias,
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: Theme.of(context).dividerColor),
        ),
        child: !isIsoCode
            ? Icon(
                Icons.flag_outlined,
                size: height * 0.75,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              )
            : CustomPaint(
                painter: _CountryFlagPainter(normalizedCode),
                child: const SizedBox.expand(),
              ),
      ),
    );
  }
}

bool _isIsoCountryCode(String code) {
  if (code.length != 2) return false;
  final units = code.codeUnits;
  return !units.any((unit) => unit < 0x41 || unit > 0x5A);
}

class _CountryFlagPainter extends CustomPainter {
  const _CountryFlagPainter(this.countryCode);

  static const drawnCountries = {
    'AT',
    'AU',
    'BE',
    'CA',
    'CH',
    'DE',
    'DK',
    'ES',
    'FI',
    'FR',
    'GB',
    'IE',
    'IT',
    'JP',
    'NL',
    'NO',
    'PL',
    'PT',
    'SE',
    'SG',
    'US',
  };

  final String countryCode;

  @override
  void paint(Canvas canvas, Size size) {
    switch (countryCode) {
      case 'AT':
        _horizontalStripes(canvas, size, const [
          Colors.red,
          Colors.white,
          Colors.red,
        ]);
      case 'AU':
        _australia(canvas, size);
      case 'BE':
        _verticalStripes(canvas, size, const [
          Color(0xff171717),
          Colors.amber,
          Colors.red,
        ]);
      case 'CA':
        _canada(canvas, size);
      case 'CH':
        _switzerland(canvas, size);
      case 'DE':
        _horizontalStripes(canvas, size, const [
          Colors.black,
          Colors.red,
          Colors.amber,
        ]);
      case 'DK':
        _nordic(
          canvas,
          size,
          background: const Color(0xffc8102e),
          cross: Colors.white,
        );
      case 'ES':
        _horizontalStripes(
          canvas,
          size,
          const [Colors.red, Colors.amber, Colors.red],
          proportions: [1, 2, 1],
        );
      case 'FI':
        _nordic(
          canvas,
          size,
          background: Colors.white,
          cross: const Color(0xff003580),
        );
      case 'FR':
        _verticalStripes(canvas, size, const [
          Color(0xff0055a4),
          Colors.white,
          Color(0xffef4135),
        ]);
      case 'GB':
        _unitedKingdom(canvas, size);
      case 'IE':
        _verticalStripes(canvas, size, const [
          Color(0xff169b62),
          Colors.white,
          Color(0xffff883e),
        ]);
      case 'IT':
        _verticalStripes(canvas, size, const [
          Color(0xff009246),
          Colors.white,
          Color(0xffce2b37),
        ]);
      case 'JP':
        _japan(canvas, size);
      case 'NL':
        _horizontalStripes(canvas, size, const [
          Color(0xffae1c28),
          Colors.white,
          Color(0xff21468b),
        ]);
      case 'NO':
        _nordic(
          canvas,
          size,
          background: const Color(0xffba0c2f),
          cross: Colors.white,
          innerCross: const Color(0xff00205b),
        );
      case 'PL':
        _horizontalStripes(canvas, size, const [Colors.white, Colors.red]);
      case 'PT':
        _portugal(canvas, size);
      case 'SE':
        _nordic(
          canvas,
          size,
          background: const Color(0xff006aa7),
          cross: const Color(0xfffecc00),
        );
      case 'SG':
        _singapore(canvas, size);
      case 'US':
        _unitedStates(canvas, size);
      default:
        _genericFlag(canvas, size, countryCode);
    }
  }

  @override
  bool shouldRepaint(covariant _CountryFlagPainter oldDelegate) =>
      oldDelegate.countryCode != countryCode;
}

void _drawFlagRect(Canvas canvas, Size size, Color color) {
  canvas.drawRect(Offset.zero & size, Paint()..color = color);
}

void _horizontalStripes(
  Canvas canvas,
  Size size,
  List<Color> colors, {
  List<double>? proportions,
}) {
  final weights = proportions ?? List<double>.filled(colors.length, 1);
  final total = weights.fold<double>(0, (sum, value) => sum + value);
  var top = 0.0;
  for (var index = 0; index < colors.length; index++) {
    final height = size.height * weights[index] / total;
    canvas.drawRect(
      Rect.fromLTWH(0, top, size.width, height),
      Paint()..color = colors[index],
    );
    top += height;
  }
}

void _verticalStripes(Canvas canvas, Size size, List<Color> colors) {
  final width = size.width / colors.length;
  for (var index = 0; index < colors.length; index++) {
    canvas.drawRect(
      Rect.fromLTWH(width * index, 0, width, size.height),
      Paint()..color = colors[index],
    );
  }
}

void _nordic(
  Canvas canvas,
  Size size, {
  required Color background,
  required Color cross,
  Color? innerCross,
}) {
  _drawFlagRect(canvas, size, background);
  final horizontal = Rect.fromLTWH(
    0,
    size.height * .40,
    size.width,
    size.height * .20,
  );
  final vertical = Rect.fromLTWH(
    size.width * .32,
    0,
    size.width * .20,
    size.height,
  );
  canvas.drawRect(horizontal, Paint()..color = cross);
  canvas.drawRect(vertical, Paint()..color = cross);
  if (innerCross != null) {
    final innerHorizontal = Rect.fromLTWH(
      0,
      size.height * .445,
      size.width,
      size.height * .11,
    );
    final innerVertical = Rect.fromLTWH(
      size.width * .365,
      0,
      size.width * .11,
      size.height,
    );
    canvas.drawRect(innerHorizontal, Paint()..color = innerCross);
    canvas.drawRect(innerVertical, Paint()..color = innerCross);
  }
}

void _australia(Canvas canvas, Size size) {
  _drawFlagRect(canvas, size, const Color(0xff012169));
  _unitedKingdom(
    canvas,
    size,
    rect: Rect.fromLTWH(0, 0, size.width * .48, size.height * .58),
  );
  _drawStar(
    canvas,
    Offset(size.width * .75, size.height * .68),
    size.height * .18,
    Colors.white,
  );
  _drawStar(
    canvas,
    Offset(size.width * .88, size.height * .36),
    size.height * .09,
    Colors.white,
  );
  _drawStar(
    canvas,
    Offset(size.width * .66, size.height * .34),
    size.height * .08,
    Colors.white,
  );
}

void _canada(Canvas canvas, Size size) {
  _verticalStripes(canvas, size, const [Colors.red, Colors.white, Colors.red]);
  final center = Offset(size.width * .5, size.height * .5);
  final paint = Paint()..color = Colors.red;
  final path = Path()
    ..moveTo(center.dx, size.height * .16)
    ..lineTo(center.dx + size.width * .07, size.height * .35)
    ..lineTo(center.dx + size.width * .17, size.height * .27)
    ..lineTo(center.dx + size.width * .11, size.height * .47)
    ..lineTo(center.dx + size.width * .19, size.height * .47)
    ..lineTo(center.dx + size.width * .06, size.height * .62)
    ..lineTo(center.dx + size.width * .09, size.height * .82)
    ..lineTo(center.dx, size.height * .70)
    ..lineTo(center.dx - size.width * .09, size.height * .82)
    ..lineTo(center.dx - size.width * .06, size.height * .62)
    ..lineTo(center.dx - size.width * .19, size.height * .47)
    ..lineTo(center.dx - size.width * .11, size.height * .47)
    ..lineTo(center.dx - size.width * .17, size.height * .27)
    ..lineTo(center.dx - size.width * .07, size.height * .35)
    ..close();
  canvas.drawPath(path, paint);
}

void _switzerland(Canvas canvas, Size size) {
  _drawFlagRect(canvas, size, const Color(0xffd52b1e));
  final paint = Paint()..color = Colors.white;
  canvas.drawRect(
    Rect.fromLTWH(
      size.width * .39,
      size.height * .18,
      size.width * .22,
      size.height * .64,
    ),
    paint,
  );
  canvas.drawRect(
    Rect.fromLTWH(
      size.width * .22,
      size.height * .39,
      size.width * .56,
      size.height * .22,
    ),
    paint,
  );
}

void _japan(Canvas canvas, Size size) {
  _drawFlagRect(canvas, size, Colors.white);
  canvas.drawCircle(
    Offset(size.width * .5, size.height * .5),
    size.height * .28,
    Paint()..color = const Color(0xffbc002d),
  );
}

void _portugal(Canvas canvas, Size size) {
  _verticalStripes(canvas, size, const [Color(0xff046a38), Color(0xffda291c)]);
  canvas.drawCircle(
    Offset(size.width * .43, size.height * .5),
    size.height * .23,
    Paint()..color = const Color(0xffffcd00),
  );
  canvas.drawCircle(
    Offset(size.width * .43, size.height * .5),
    size.height * .14,
    Paint()..color = Colors.white,
  );
}

void _singapore(Canvas canvas, Size size) {
  _horizontalStripes(canvas, size, const [Color(0xffed2939), Colors.white]);
  final center = Offset(size.width * .23, size.height * .30);
  canvas.drawCircle(center, size.height * .18, Paint()..color = Colors.white);
  canvas.drawCircle(
    Offset(center.dx + size.width * .06, center.dy),
    size.height * .15,
    Paint()..color = const Color(0xffed2939),
  );
  for (var index = 0; index < 5; index++) {
    _drawStar(
      canvas,
      Offset(
        center.dx + size.width * .12 + size.width * .07 * index,
        center.dy + size.height * .16,
      ),
      size.height * .035,
      Colors.white,
    );
  }
}

void _unitedStates(Canvas canvas, Size size) {
  final stripeHeight = size.height / 13;
  for (var index = 0; index < 13; index++) {
    canvas.drawRect(
      Rect.fromLTWH(0, stripeHeight * index, size.width, stripeHeight),
      Paint()..color = index.isEven ? const Color(0xffb22234) : Colors.white,
    );
  }
  canvas.drawRect(
    Rect.fromLTWH(0, 0, size.width * .42, stripeHeight * 7),
    Paint()..color = const Color(0xff3c3b6e),
  );
  for (var row = 0; row < 3; row++) {
    for (var column = 0; column < 4; column++) {
      canvas.drawCircle(
        Offset(
          size.width * (.08 + column * .09),
          size.height * (.10 + row * .16),
        ),
        size.height * .025,
        Paint()..color = Colors.white,
      );
    }
  }
}

void _unitedKingdom(Canvas canvas, Size size, {Rect? rect}) {
  final target = rect ?? (Offset.zero & size);
  canvas.drawRect(target, Paint()..color = const Color(0xff012169));
  final center = target.center;
  final diagonal = Paint()
    ..color = Colors.white
    ..strokeWidth = target.height * .22
    ..strokeCap = StrokeCap.square;
  canvas.drawLine(
    Offset(target.left, target.top),
    Offset(target.right, target.bottom),
    diagonal,
  );
  canvas.drawLine(
    Offset(target.right, target.top),
    Offset(target.left, target.bottom),
    diagonal,
  );
  final redDiagonal = Paint()
    ..color = const Color(0xffc8102e)
    ..strokeWidth = target.height * .09
    ..strokeCap = StrokeCap.square;
  canvas.drawLine(
    Offset(target.left, target.top),
    Offset(target.right, target.bottom),
    redDiagonal,
  );
  canvas.drawLine(
    Offset(target.right, target.top),
    Offset(target.left, target.bottom),
    redDiagonal,
  );
  canvas.drawRect(
    Rect.fromLTWH(
      target.left,
      center.dy - target.height * .13,
      target.width,
      target.height * .26,
    ),
    Paint()..color = Colors.white,
  );
  canvas.drawRect(
    Rect.fromLTWH(
      center.dx - target.width * .13,
      target.top,
      target.width * .26,
      target.height,
    ),
    Paint()..color = Colors.white,
  );
  canvas.drawRect(
    Rect.fromLTWH(
      target.left,
      center.dy - target.height * .07,
      target.width,
      target.height * .14,
    ),
    Paint()..color = const Color(0xffc8102e),
  );
  canvas.drawRect(
    Rect.fromLTWH(
      center.dx - target.width * .07,
      target.top,
      target.width * .14,
      target.height,
    ),
    Paint()..color = const Color(0xffc8102e),
  );
}

void _drawStar(Canvas canvas, Offset center, double radius, Color color) {
  final path = Path();
  for (var index = 0; index < 10; index++) {
    final angle = -math.pi / 2 + index * math.pi / 5;
    final currentRadius = index.isEven ? radius : radius * .42;
    final point = Offset(
      center.dx + math.cos(angle) * currentRadius,
      center.dy + math.sin(angle) * currentRadius,
    );
    if (index == 0) {
      path.moveTo(point.dx, point.dy);
    } else {
      path.lineTo(point.dx, point.dy);
    }
  }
  path.close();
  canvas.drawPath(path, Paint()..color = color);
}

void _genericFlag(Canvas canvas, Size size, String code) {
  // An ISO badge is honest when no flag artwork is bundled. Never invent a
  // national flag from hashed colors (new language options exposed this path).
  _drawFlagRect(canvas, size, const Color(0xffe4e7ea));
  final painter = TextPainter(
    text: TextSpan(
      text: code,
      style: TextStyle(
        color: const Color(0xff101820),
        fontSize: size.height * .60,
        fontFamily: 'Segoe UI',
        fontWeight: FontWeight.w700,
      ),
    ),
    textDirection: TextDirection.ltr,
    maxLines: 1,
  )..layout(maxWidth: size.width);
  painter.paint(
    canvas,
    Offset(
      (size.width - painter.width) / 2,
      (size.height - painter.height) / 2,
    ),
  );
  painter.dispose();
}

String _countryName(BuildContext context, String code) =>
    AppLocalizations.of(context).strings.countryName(code);

Future<void> _requestConnection(
  BuildContext context,
  AppController controller,
) async {
  if (controller.runtimeVerificationPending) {
    await controller.retryRuntimeVerification();
    return;
  }
  if (controller.requiresExplicitDisconnect) {
    await controller.quickConnect();
    return;
  }
  if (controller.savedSessionVerificationPending) {
    await controller.retrySavedSessionVerification();
    return;
  }
  if (controller.profile == null) {
    await _showSignInDialog(context, controller, resumeConnection: true);
    return;
  }
  await controller.quickConnect();
}

Future<void> _openAccountDestination(
  BuildContext context,
  AppController controller,
) async {
  final profile = controller.profile;
  if (controller.savedSessionVerificationPending) {
    await controller.retrySavedSessionVerification();
    return;
  }
  if (profile == null) {
    await _showSignInDialog(context, controller);
    return;
  }
  final action = await showDialog<String>(
    context: context,
    builder: (dialogContext) => _AccountDialog(
      controller: controller,
      userId: profile.userId,
      email: profile.email,
    ),
  );
  if (!context.mounted) return;
  if (action == 'quit') {
    await requestAppExit(context, controller);
  } else if (action == 'signOut') {
    if (controller.profile?.userId != profile.userId) return;
    if (controller.requiresExplicitDisconnect || controller.isConnectionBusy) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (dialogContext) => AlertDialog(
          scrollable: true,
          title: Text(context.tr('Se déconnecter du compte ?')),
          content: Text(
            context.tr(
              'Cette action ferme votre session et demande l’arrêt du VPN.',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, false),
              child: Text(context.tr('Annuler')),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(dialogContext, true),
              child: Text(context.tr('Se déconnecter du compte')),
            ),
          ],
        ),
      );
      if (confirmed != true) return;
    }
    if (controller.profile?.userId != profile.userId) return;
    await controller.signOut();
    if (context.mounted &&
        controller.profile != null &&
        controller.errorMessage != null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(context.tr(controller.errorMessage!))),
      );
    }
  }
}

class _AccountDialog extends StatefulWidget {
  const _AccountDialog({
    required this.controller,
    required this.userId,
    required this.email,
  });

  final AppController controller;
  final String userId;
  final String email;

  @override
  State<_AccountDialog> createState() => _AccountDialogState();
}

class _AccountDialogState extends State<_AccountDialog> {
  final accountScrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && widget.controller.profile?.userId == widget.userId) {
        unawaited(widget.controller.refreshSubscription());
      }
    });
  }

  @override
  void dispose() {
    accountScrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final dialogContext = context;
    return AnimatedBuilder(
      animation: widget.controller,
      builder: (context, _) => AlertDialog(
        title: Row(
          children: [
            const Icon(Icons.account_circle_outlined, size: 25),
            const SizedBox(width: 12),
            Expanded(child: Text(context.tr('Mon compte'))),
          ],
        ),
        content: SizedBox(
          width: 440,
          child: Scrollbar(
            controller: accountScrollController,
            thumbVisibility: true,
            child: SingleChildScrollView(
              controller: accountScrollController,
              padding: const EdgeInsetsDirectional.only(end: 12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Theme.of(
                        dialogContext,
                      ).colorScheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: SelectableText(
                      widget.email,
                      style: Theme.of(dialogContext).textTheme.bodyLarge
                          ?.copyWith(fontWeight: FontWeight.w600),
                    ),
                  ),
                  const SizedBox(height: 16),
                  _AccountSubscriptionPanel(
                    controller: widget.controller,
                    accountIsCurrent:
                        widget.controller.profile?.userId == widget.userId,
                  ),
                  const SizedBox(height: 10),
                  OutlinedButton.icon(
                    onPressed: () =>
                        _openWebsite(context, BrandConfig.portalDashboard),
                    icon: const Icon(Icons.open_in_new),
                    label: Text(context.tr('Gérer mon abonnement sur le Web')),
                  ),
                  const SizedBox(height: 12),
                  const Divider(),
                  const SizedBox(height: 8),
                  FilledButton.icon(
                    style: FilledButton.styleFrom(
                      backgroundColor: Theme.of(
                        dialogContext,
                      ).colorScheme.error,
                      foregroundColor: Theme.of(
                        dialogContext,
                      ).colorScheme.onError,
                    ),
                    onPressed: () => Navigator.pop(dialogContext, 'signOut'),
                    icon: const Icon(Icons.logout),
                    label: Text(context.tr('Se déconnecter du compte')),
                  ),
                  const SizedBox(height: 4),
                  TextButton.icon(
                    onPressed: () => Navigator.pop(dialogContext, 'quit'),
                    icon: const Icon(Icons.power_settings_new),
                    label: Text(context.tr('Quitter FuzeVPN')),
                  ),
                ],
              ),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text(context.tr('Fermer')),
          ),
        ],
      ),
    );
  }
}

Future<void> _confirmIdentityReset(
  BuildContext context,
  AppController controller,
) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      title: Text(context.tr('Créer une nouvelle identité VPN ?')),
      content: Text(
        context.tr(
          'Le tunnel VPN sera déconnecté et l’identité VPN locale actuelle sera supprimée. Une nouvelle identité sera créée pour ce compte uniquement.',
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(false),
          child: Text(context.tr('Annuler')),
        ),
        FilledButton(
          onPressed: () => Navigator.of(dialogContext).pop(true),
          child: Text(context.tr('Continuer')),
        ),
      ],
    ),
  );
  if (confirmed == true && context.mounted) {
    await controller.retryAfterIdentityReset();
  }
}

Future<void> _showNodeUnavailableDialog(
  BuildContext context,
  AppController controller,
) async {
  final action = await showDialog<String>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      title: Text(context.tr('Emplacement indisponible')),
      content: Text(
        context.tr('Réessayez maintenant ou choisissez un autre emplacement.'),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop(),
          child: Text(context.tr('Annuler')),
        ),
        TextButton(
          onPressed: () => Navigator.of(dialogContext).pop('location'),
          child: Text(context.tr('Choisir un emplacement')),
        ),
        FilledButton(
          onPressed: () => Navigator.of(dialogContext).pop('retry'),
          child: Text(context.tr('Réessayer')),
        ),
      ],
    ),
  );
  if (!context.mounted) return;
  if (action == 'location') {
    controller.selectSection(AppSection.locations);
  } else if (action == 'retry') {
    await controller.toggleConnection();
  }
}

final _activeSignInRequests = Expando<_SignInRequest>();

Future<void> _showSignInDialog(
  BuildContext context,
  AppController controller, {
  bool resumeConnection = false,
  bool authenticationRequired = false,
}) {
  if (controller.savedSessionVerificationPending) {
    return controller.retrySavedSessionVerification();
  }
  authenticationRequired |=
      controller.isInitialized &&
      controller.profile == null &&
      !controller.runtimeVerificationPending &&
      !controller.requiresExplicitDisconnect &&
      !controller.runtimeOwnedByAnotherUser &&
      !controller.isConnectionBusy;
  if (_activeSignInRequests[controller] case final request?) {
    request.merge(
      resumeConnection: resumeConnection,
      authenticationRequired: authenticationRequired,
    );
    return request.completion;
  }
  final request = _SignInRequest(
    resumeConnection: resumeConnection,
    authenticationRequired: authenticationRequired,
  );
  _activeSignInRequests[controller] = request;
  return request.completion = _presentSignInDialog(
    context,
    controller,
    request,
  );
}

Future<void> _presentSignInDialog(
  BuildContext context,
  AppController controller,
  _SignInRequest request,
) async {
  try {
    final navigator = Navigator.of(context, rootNavigator: true);
    final signedIn = await navigator.push<bool>(
      _SignInRoute(
        context: context,
        controller: controller,
        request: request,
        themes: InheritedTheme.capture(from: context, to: navigator.context),
      ),
    );
    if (identical(_activeSignInRequests[controller], request)) {
      _activeSignInRequests[controller] = null;
    }
    if (signedIn == true && navigator.mounted) {
      ScaffoldMessenger.of(navigator.context).showSnackBar(
        SnackBar(
          content: Text(navigator.context.tr('Vous êtes connecté à FuzeVPN.')),
        ),
      );
      if (request.resumeConnection) await controller.quickConnect();
    }
  } finally {
    if (identical(_activeSignInRequests[controller], request)) {
      _activeSignInRequests[controller] = null;
    }
  }
}

class _SignInRequest extends ChangeNotifier {
  _SignInRequest({
    required this.resumeConnection,
    required this.authenticationRequired,
  });

  bool resumeConnection;
  bool authenticationRequired;
  late Future<void> completion;

  void merge({
    required bool resumeConnection,
    required bool authenticationRequired,
  }) {
    this.resumeConnection |= resumeConnection;
    if (authenticationRequired && !this.authenticationRequired) {
      this.authenticationRequired = true;
      notifyListeners();
    }
  }
}

class _SignInRoute extends DialogRoute<bool> {
  _SignInRoute({
    required super.context,
    required AppController controller,
    required this.request,
    required super.themes,
  }) : appController = controller,
       super(
         builder: (_) => ListenableBuilder(
           listenable: request,
           builder: (_, _) => _SignInDialog(
             controller: controller,
             authenticationRequired: request.authenticationRequired,
           ),
         ),
       ) {
    request.addListener(changedInternalState);
    appController.addListener(changedInternalState);
  }

  final _SignInRequest request;
  final AppController appController;

  @override
  bool get barrierDismissible =>
      !request.authenticationRequired && !appController.browserSignInBusy;

  @override
  void dispose() {
    request.removeListener(changedInternalState);
    appController.removeListener(changedInternalState);
    request.dispose();
    super.dispose();
  }
}

class _SignInDialog extends StatefulWidget {
  const _SignInDialog({
    required this.controller,
    required this.authenticationRequired,
  });

  final AppController controller;
  final bool authenticationRequired;

  @override
  State<_SignInDialog> createState() => _SignInDialogState();
}

class _SignInDialogState extends State<_SignInDialog> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  bool _isSubmitting = false;
  bool _isBrowserSubmitting = false;
  bool _isReopeningBrowser = false;
  int _browserAttempt = 0;
  String? _submissionErrorMessage;

  bool get _browserActive =>
      _isBrowserSubmitting || widget.controller.browserSignInBusy;
  bool get _browserCommitting =>
      widget.controller.browserSignInStatus ==
      BrowserSignInStatus.completingSignIn;

  @override
  void dispose() {
    _browserAttempt++;
    if (_isBrowserSubmitting) widget.controller.cancelBrowserSignIn();
    _emailController.clear();
    _passwordController.clear();
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_isSubmitting || _browserActive) return;
    setState(() {
      _isSubmitting = true;
      _submissionErrorMessage = null;
    });
    final success = await widget.controller.signIn(
      email: _emailController.text.trim(),
      password: _passwordController.text,
    );
    if (!mounted) return;
    if (success) {
      Navigator.of(context).pop(true);
    } else {
      setState(() {
        _isSubmitting = false;
        _submissionErrorMessage = widget.controller.errorMessage;
      });
    }
  }

  Future<void> _signInWithBrowser() async {
    if (_isSubmitting || _browserActive) return;
    final attempt = ++_browserAttempt;
    FocusManager.instance.primaryFocus?.unfocus();
    setState(() {
      _isBrowserSubmitting = true;
      _submissionErrorMessage = null;
    });
    var success = false;
    String? failure;
    try {
      success = await widget.controller.signInWithBrowser();
      failure = widget.controller.browserSignInErrorMessage;
    } catch (_) {
      failure =
          'La connexion par navigateur n’a pas pu être terminée. Réessayez.';
    }
    if (!mounted || attempt != _browserAttempt) return;
    if (success) {
      _isBrowserSubmitting = false;
      Navigator.of(context).pop(true);
    } else {
      setState(() {
        _isBrowserSubmitting = false;
        _submissionErrorMessage = failure;
      });
    }
  }

  Future<void> _reopenBrowser() async {
    if (!_browserActive || _browserCommitting || _isReopeningBrowser) return;
    final attempt = _browserAttempt;
    setState(() => _isReopeningBrowser = true);
    try {
      await widget.controller.reopenBrowserSignIn();
    } catch (_) {
      if (mounted && attempt == _browserAttempt) {
        setState(() {
          _submissionErrorMessage = 'Le navigateur n’a pas pu être ouvert.';
        });
      }
    } finally {
      if (mounted && attempt == _browserAttempt) {
        setState(() => _isReopeningBrowser = false);
      }
    }
  }

  void _cancelBrowserSignIn() {
    if (_browserCommitting) return;
    _browserAttempt++;
    widget.controller.cancelBrowserSignIn();
    setState(() {
      _isBrowserSubmitting = false;
      _isReopeningBrowser = false;
      _submissionErrorMessage = null;
    });
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: widget.controller,
    builder: (context, _) => _buildDialog(context),
  );

  Widget _buildDialog(BuildContext context) {
    final busy = _isSubmitting || _browserActive;
    final compact = MediaQuery.sizeOf(context).height < 700;
    final sectionGap = compact ? 12.0 : 18.0;
    return PopScope(
      canPop: !widget.authenticationRequired && !busy,
      child: AlertDialog(
        scrollable: true,
        titlePadding: compact ? const EdgeInsets.fromLTRB(24, 20, 24, 0) : null,
        contentPadding: compact
            ? const EdgeInsets.fromLTRB(24, 12, 24, 12)
            : null,
        actionsPadding: compact
            ? const EdgeInsets.fromLTRB(24, 0, 24, 16)
            : null,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(9),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(
                Icons.login,
                size: 22,
                color: Theme.of(context).colorScheme.onPrimaryContainer,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Text(
                context.tr('Se connecter'),
                style: Theme.of(context).textTheme.titleLarge,
              ),
            ),
          ],
        ),
        content: SizedBox(
          width: 420,
          child: SingleChildScrollView(
            child: AutofillGroup(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Align(
                    alignment: AlignmentDirectional.centerStart,
                    child: Text(
                      context.tr(
                        'Utilisez votre compte FuzeVPN. La création de compte se fait sur le Web.',
                      ),
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                  SizedBox(height: compact ? 12 : 20),
                  if (_browserActive)
                    _browserWaitingCard(context)
                  else ...[
                    SizedBox(
                      width: double.infinity,
                      child: OutlinedButton.icon(
                        key: const ValueKey('sign-in-browser'),
                        onPressed: busy ? null : _signInWithBrowser,
                        icon: const Icon(Icons.open_in_browser_outlined),
                        label: Text(context.tr('Continuer dans le navigateur')),
                      ),
                    ),
                    SizedBox(height: sectionGap),
                    Row(
                      children: [
                        const Expanded(child: Divider()),
                        const SizedBox(width: 12),
                        Flexible(
                          flex: 2,
                          fit: FlexFit.tight,
                          child: Text(
                            context.tr('ou par e-mail'),
                            textAlign: TextAlign.center,
                            style: Theme.of(context).textTheme.bodySmall
                                ?.copyWith(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onSurfaceVariant,
                                ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        const Expanded(child: Divider()),
                      ],
                    ),
                    SizedBox(height: sectionGap),
                    TextField(
                      controller: _emailController,
                      enabled: !busy,
                      textDirection: TextDirection.ltr,
                      keyboardType: TextInputType.emailAddress,
                      autofillHints: const [AutofillHints.email],
                      textInputAction: TextInputAction.next,
                      autofocus: true,
                      decoration: InputDecoration(
                        labelText: context.tr('Adresse e-mail'),
                        prefixIcon: const Icon(Icons.alternate_email),
                      ),
                    ),
                    SizedBox(height: compact ? 12 : 14),
                    TextField(
                      controller: _passwordController,
                      enabled: !busy,
                      obscureText: true,
                      enableSuggestions: false,
                      autocorrect: false,
                      autofillHints: const [AutofillHints.password],
                      onSubmitted: (_) => _submit(),
                      decoration: InputDecoration(
                        labelText: context.tr('Mot de passe'),
                        prefixIcon: const Icon(Icons.lock_outline),
                      ),
                    ),
                  ],
                  if (!_browserActive && _submissionErrorMessage != null) ...[
                    const SizedBox(height: 12),
                    Align(
                      alignment: AlignmentDirectional.centerStart,
                      child: Text(
                        context.tr(_submissionErrorMessage!),
                        style: TextStyle(
                          color: Theme.of(context).colorScheme.error,
                        ),
                      ),
                    ),
                  ],
                  SizedBox(height: sectionGap),
                  const Divider(),
                  SizedBox(height: compact ? 2 : 6),
                  Column(
                    children: [
                      TextButton(
                        onPressed: busy
                            ? null
                            : () => _openWebsite(
                                context,
                                BrandConfig.portalRegister,
                              ),
                        child: Text(context.tr('Créer un compte sur le Web')),
                      ),
                      Row(
                        children: [
                          Expanded(
                            child: TextButton(
                              onPressed: busy
                                  ? null
                                  : () => _showUpdatesDialog(
                                      context,
                                      widget.controller,
                                    ),
                              child: Text(
                                context.tr('Mises à jour'),
                                textAlign: TextAlign.center,
                              ),
                            ),
                          ),
                          Expanded(
                            child: TextButton(
                              onPressed: busy
                                  ? null
                                  : () => _showDiagnosticsDialog(
                                      context,
                                      widget.controller,
                                    ),
                              child: Text(
                                context.tr('Diagnostic local'),
                                textAlign: TextAlign.center,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: busy
                ? null
                : () => requestAppExit(context, widget.controller),
            child: Text(context.tr('Quitter FuzeVPN')),
          ),
          if (!widget.authenticationRequired && !_browserActive)
            TextButton(
              onPressed: _isSubmitting
                  ? null
                  : () => Navigator.of(context).pop(),
              child: Text(context.tr('Annuler')),
            ),
          if (!_browserActive)
            FilledButton(
              onPressed: _isSubmitting ? null : _submit,
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_isSubmitting) ...[
                    const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 10),
                  ],
                  Flexible(
                    child: Text(
                      context.tr(_isSubmitting ? 'Connexion…' : 'Se connecter'),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget _browserWaitingCard(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final status = widget.controller.browserSignInStatus;
    final message =
        widget.controller.browserSignInErrorMessage ?? _submissionErrorMessage;
    final title = status == BrowserSignInStatus.openingBrowser
        ? 'Ouverture du navigateur…'
        : _browserCommitting
        ? 'Finalisation de la connexion…'
        : 'Connexion dans le navigateur';
    return Container(
      key: const ValueKey('sign-in-browser-waiting'),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: scheme.primaryContainer.withValues(alpha: 0.55),
        border: Border.all(color: scheme.outlineVariant),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Semantics(
                  liveRegion: true,
                  child: Text(
                    context.tr(title),
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            context.tr(
              _browserCommitting
                  ? 'Votre compte est en cours de vérification.'
                  : 'Terminez la connexion dans votre navigateur. FuzeVPN vous connectera automatiquement.',
            ),
            style: Theme.of(
              context,
            ).textTheme.bodyMedium?.copyWith(color: scheme.onSurfaceVariant),
          ),
          if (message != null) ...[
            const SizedBox(height: 12),
            Semantics(
              liveRegion: true,
              child: Text(
                context.tr(message),
                style: TextStyle(color: scheme.error),
              ),
            ),
          ],
          if (!_browserCommitting) ...[
            const SizedBox(height: 16),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton.icon(
                  key: const ValueKey('sign-in-browser-reopen'),
                  onPressed:
                      status == BrowserSignInStatus.openingBrowser ||
                          _isReopeningBrowser
                      ? null
                      : _reopenBrowser,
                  icon: const Icon(Icons.open_in_new, size: 18),
                  label: Text(context.tr('Ouvrir à nouveau le navigateur')),
                ),
                TextButton(
                  key: const ValueKey('sign-in-browser-cancel'),
                  onPressed: _cancelBrowserSignIn,
                  child: Text(context.tr('Annuler la connexion')),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

Future<void> _openWebsite(BuildContext context, Uri url) async {
  var opened = false;
  try {
    opened = await launchUrl(url, mode: LaunchMode.externalApplication);
  } on PlatformException {
    // ShellExecute can report a policy/access error instead of returning false.
  }
  if (!opened && context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(context.tr('Le navigateur n’a pas pu être ouvert.')),
      ),
    );
  }
}
