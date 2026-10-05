// SPDX-License-Identifier: MPL-2.0
part of 'app_shell.dart';

class _LocationsPage extends StatefulWidget {
  const _LocationsPage({super.key, required this.controller});

  final AppController controller;

  @override
  State<_LocationsPage> createState() => _LocationsPageState();
}

class _LocationsPageState extends State<_LocationsPage> {
  final _searchController = TextEditingController();
  final _scrollController = ScrollController();
  String _query = '';
  bool _favoritesOnly = false;
  String? _countryCode;
  String? _city;

  @override
  void didUpdateWidget(covariant _LocationsPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    // A refreshed catalogue may remove the last available server in a city
    // or country. Return to the closest remaining level, never a stale row.
    final country = buildLocationDirectory(
      widget.controller.locations,
    ).where((group) => group.countryCode == _countryCode).firstOrNull;
    if (country == null) {
      _countryCode = null;
      _city = null;
    } else if (!country.cities.any((group) => _cityKey(group) == _city)) {
      _city = null;
    }
  }

  @override
  void dispose() {
    _searchController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  String _cityKey(CityLocationGroup city) => city.city.toLowerCase();

  void _navigate({String? countryCode, String? city}) {
    setState(() {
      _countryCode = countryCode;
      _city = city;
    });
    _scrollToTop();
  }

  void _scrollToTop() {
    if (_scrollController.hasClients) _scrollController.jumpTo(0);
  }

  Location? _candidate(List<Location> locations) => preferredLocationForGroup(
    locations,
    selectedLocationId: widget.controller.selectedLocation?.id,
    protocolPreference: widget.controller.protocolPreference,
    openVpnRuntimeAvailable: widget.controller.openVpnRuntimeAvailable,
  );

  VoidCallback? _select(Location? location) =>
      location == null || widget.controller.isConnectionBusy
      ? null
      : () => _requestLocationChange(context, widget.controller, location);

  String _count(int count, String singular, String plural) => count == 1
      ? context.tr(singular)
      : context.tr(plural).replaceAll('{count}', '$count');

  Widget _server(Location location, {String? cityTitle, Key? key}) {
    final controller = widget.controller;
    final candidate = _candidate([location]);
    return _LocationRow(
      key: key ?? ValueKey('location-server-${location.id}'),
      location: location,
      title: cityTitle,
      unavailableReason: candidate == null
          ? context.tr('Aucun serveur compatible avec le protocole choisi.')
          : null,
      selected: location.id == controller.selectedLocation?.id,
      favorite: controller.isFavoriteLocation(location),
      recent: controller.isRecentLocation(location),
      onTap: _select(candidate),
      onToggleFavorite: () => controller.toggleFavoriteLocation(location),
    );
  }

  Widget _group({
    required String keySuffix,
    required String name,
    required String countryCode,
    required List<Location> locations,
    required String count,
    required String openLabel,
    required String openTooltip,
    required VoidCallback onOpen,
  }) {
    final candidate = _candidate(locations);
    final selected =
        candidate != null &&
        candidate.id == widget.controller.selectedLocation?.id;
    return _LocationGroupRow(
      selectionKey: ValueKey('location-select-$keySuffix'),
      expansionKey: ValueKey('location-open-$keySuffix'),
      countryCode: countryCode,
      name: name,
      count: count,
      candidateLabel: candidate == null
          ? context.tr('Aucun serveur compatible avec le protocole choisi.')
          : context
                .tr(selected ? 'Sélectionné : {server}' : 'Choisir : {server}')
                .replaceAll('{server}', candidate.displayName),
      selected: selected,
      onSelect: _select(candidate),
      selectionLabel: context
          .tr('Sélectionner {name}')
          .replaceAll('{name}', name),
      openLabel: context.tr(openLabel),
      openTooltip: openTooltip,
      onOpen: onOpen,
    );
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final ordered = controller.orderedLocations;
    final countries = [...buildLocationDirectory(ordered)]
      ..sort(
        (a, b) => _countryName(
          context,
          a.countryCode,
        ).compareTo(_countryName(context, b.countryCode)),
      );
    final country = countries
        .where((group) => group.countryCode == _countryCode)
        .firstOrNull;
    final city = country?.cities
        .where((group) => _cityKey(group) == _city)
        .firstOrNull;
    final query = _query.trim().toLowerCase();
    final searching = query.isNotEmpty;
    final filtering = searching || _favoritesOnly;
    final favoriteCount = ordered.where(controller.isFavoriteLocation).length;
    final matches = filtering
        ? ordered
              .where(
                (location) =>
                    (!_favoritesOnly ||
                        controller.isFavoriteLocation(location)) &&
                    (location.displayName.toLowerCase().contains(query) ||
                        location.city.toLowerCase().contains(query) ||
                        location.countryCode.toLowerCase().contains(query) ||
                        AppLocalizations.of(
                          context,
                        ).strings.countryMatches(location.countryCode, query)),
              )
              .toList(growable: false)
        : const <Location>[];
    final cities = [...?country?.cities]
      ..sort((a, b) => a.city.compareTo(b.city));
    final rows = filtering
        ? matches.map((location) => _server(location)).toList()
        : city != null
        ? city.locations.map((location) => _server(location)).toList()
        : country != null
        ? cities.map((group) {
            final keySuffix = 'city-${country.countryCode}-${_cityKey(group)}';
            if (group.locations.length == 1) {
              return _server(
                group.locations.single,
                cityTitle: group.city,
                key: ValueKey('location-select-$keySuffix'),
              );
            }
            return _group(
              keySuffix: keySuffix,
              name: group.city,
              countryCode: country.countryCode,
              locations: group.locations,
              count: _count(
                group.locations.length,
                '1 serveur',
                '{count} serveurs',
              ),
              openLabel: 'Serveurs',
              openTooltip: context
                  .tr('Serveurs à {name}')
                  .replaceAll('{name}', group.city),
              onOpen: () => _navigate(
                countryCode: country.countryCode,
                city: _cityKey(group),
              ),
            );
          }).toList()
        : countries.map((group) {
            final name = _countryName(context, group.countryCode);
            return _group(
              keySuffix: 'country-${group.countryCode}',
              name: name,
              countryCode: group.countryCode,
              locations: group.locations,
              count:
                  '${_count(group.cities.length, '1 ville', '{count} villes')} · ${_count(group.locations.length, '1 serveur', '{count} serveurs')}',
              openLabel: 'Villes',
              openTooltip: context
                  .tr('Villes de {name}')
                  .replaceAll('{name}', name),
              onOpen: () => _navigate(countryCode: group.countryCode),
            );
          }).toList();

    final visibleLocations = filtering
        ? matches
        : city?.locations ?? country?.locations ?? ordered;
    final listTitle = filtering
        ? context.tr('Serveurs')
        : city != null
        ? context.tr('Serveurs à {name}').replaceAll('{name}', city.city)
        : country != null
        ? context.tr('Villes')
        : context.tr('Tous les pays');
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return _PageLayout(
      scrollController: _scrollController,
      title: 'Emplacements',
      subtitle: controller.isLocationMigrationActive
          ? (controller.locationMigrationMessage ??
                'Changement de serveur en cours…')
          : controller.requiresExplicitDisconnect
          ? 'Changer d’emplacement interrompra le VPN pendant la reconnexion.'
          : 'Choisissez un emplacement pour votre prochaine connexion.',
      action: IconButton(
        tooltip: context.tr('Actualiser les emplacements'),
        onPressed: controller.isLoadingLocations
            ? null
            : controller.refreshLocations,
        icon: const Icon(Icons.refresh),
      ),
      child: controller.isLoadingLocations
          ? const Center(
              child: Padding(
                padding: EdgeInsets.all(72),
                child: CircularProgressIndicator(),
              ),
            )
          : !controller.apiReachable
          ? _NoticeCard(
              icon: Icons.cloud_off_outlined,
              title: 'Service indisponible',
              message:
                  'La liste des emplacements ne peut pas être chargée pour le moment.',
              actionLabel: 'Réessayer',
              onAction: controller.refreshLocations,
            )
          : controller.locations.isEmpty
          ? const _NoticeCard(
              icon: Icons.public_off_outlined,
              title: 'Aucun emplacement disponible',
              message:
                  'Revenez dans quelques instants ou contactez l’assistance.',
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: scheme.surface,
                    border: Border.all(color: scheme.outlineVariant),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: LayoutBuilder(
                    builder: (context, constraints) {
                      final search = TextField(
                        key: const ValueKey('location-search'),
                        controller: _searchController,
                        onChanged: (value) {
                          setState(() => _query = value);
                          _scrollToTop();
                        },
                        decoration: InputDecoration(
                          labelText: context.tr('Rechercher un emplacement'),
                          hintText: context.tr('Ville, pays ou serveur'),
                          prefixIcon: const Icon(Icons.search),
                          suffixIcon: _query.isEmpty
                              ? null
                              : IconButton(
                                  tooltip: context.tr('Effacer la recherche'),
                                  onPressed: () {
                                    _searchController.clear();
                                    setState(() => _query = '');
                                    _scrollToTop();
                                  },
                                  icon: const Icon(Icons.close),
                                ),
                        ),
                      );
                      final favoriteFilter = FilterChip(
                        key: const ValueKey('location-filter-favorites'),
                        selected: _favoritesOnly,
                        showCheckmark: false,
                        avatar: Icon(
                          _favoritesOnly ? Icons.star : Icons.star_outline,
                          size: 18,
                        ),
                        label: Text(
                          '${context.tr('Favori')} · $favoriteCount',
                          style: theme.textTheme.labelLarge,
                        ),
                        onSelected: (selected) {
                          setState(() => _favoritesOnly = selected);
                          _scrollToTop();
                        },
                      );
                      final inline =
                          constraints.maxWidth >= 640 &&
                          MediaQuery.textScalerOf(context).scale(14) <= 18;
                      return inline
                          ? Row(
                              children: [
                                Expanded(child: search),
                                const SizedBox(width: 16),
                                favoriteFilter,
                              ],
                            )
                          : Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                search,
                                const SizedBox(height: 8),
                                Wrap(children: [favoriteFilter]),
                              ],
                            );
                    },
                  ),
                ),
                const SizedBox(height: 24),
                if (!filtering && country != null) ...[
                  Wrap(
                    spacing: 4,
                    runSpacing: 4,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      TextButton.icon(
                        key: const ValueKey('location-back-countries'),
                        onPressed: () => _navigate(),
                        icon: Icon(
                          Directionality.of(context) == TextDirection.rtl
                              ? Icons.arrow_forward
                              : Icons.arrow_back,
                          size: 18,
                        ),
                        label: Text(context.tr('Tous les pays')),
                      ),
                      if (city != null)
                        TextButton(
                          key: const ValueKey('location-back-cities'),
                          onPressed: () =>
                              _navigate(countryCode: country.countryCode),
                          child: Text(
                            _countryName(context, country.countryCode),
                          ),
                        ),
                      Text(
                        city?.city ??
                            _countryName(context, country.countryCode),
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w700),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                ],
                Padding(
                  padding: const EdgeInsetsDirectional.only(start: 4, end: 4),
                  child: Wrap(
                    spacing: 16,
                    runSpacing: 8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Text(
                        listTitle,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Text(
                        _count(
                          visibleLocations.length,
                          '1 serveur',
                          '{count} serveurs',
                        ),
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: scheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                if (rows.isEmpty)
                  const _NoticeCard(
                    icon: Icons.search_off_outlined,
                    title: 'Aucun emplacement trouvé',
                    message:
                        'Essayez une autre ville, un autre pays ou un autre nom de serveur.',
                  )
                else
                  Container(
                    decoration: BoxDecoration(
                      color: scheme.surface,
                      border: Border.all(color: scheme.outlineVariant),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    clipBehavior: Clip.antiAlias,
                    child: ListView.separated(
                      shrinkWrap: true,
                      physics: const NeverScrollableScrollPhysics(),
                      itemCount: rows.length,
                      separatorBuilder: (_, _) => const Divider(height: 1),
                      itemBuilder: (_, index) => rows[index],
                    ),
                  ),
              ],
            ),
    );
  }
}

/// Two independent controls: selecting never drills down, opening never
/// changes the selected server or starts a VPN operation.
class _LocationGroupRow extends StatelessWidget {
  const _LocationGroupRow({
    required this.selectionKey,
    required this.expansionKey,
    required this.countryCode,
    required this.name,
    required this.count,
    required this.candidateLabel,
    required this.selected,
    required this.onSelect,
    required this.selectionLabel,
    required this.openLabel,
    required this.openTooltip,
    required this.onOpen,
  });

  final Key selectionKey;
  final Key expansionKey;
  final String countryCode;
  final String name;
  final String count;
  final String candidateLabel;
  final bool selected;
  final VoidCallback? onSelect;
  final String selectionLabel;
  final String openLabel;
  final String openTooltip;
  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return LayoutBuilder(
      builder: (context, constraints) {
        final compact =
            constraints.maxWidth < 600 ||
            MediaQuery.textScalerOf(context).scale(14) > 18;
        final countLabel = Text(
          count,
          style: theme.textTheme.bodySmall?.copyWith(
            color: scheme.onSurfaceVariant,
          ),
        );
        final nameLabel = Text(
          name,
          style: theme.textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w700,
          ),
        );
        return IntrinsicHeight(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Expanded(
                child: Semantics(
                  button: true,
                  enabled: onSelect != null,
                  selected: selected,
                  label: '$selectionLabel, $candidateLabel, $count',
                  onTap: onSelect,
                  excludeSemantics: true,
                  child: Material(
                    color: selected
                        ? scheme.primaryContainer
                        : Colors.transparent,
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        border: BorderDirectional(
                          start: BorderSide(
                            color: selected
                                ? AppTheme.signal
                                : Colors.transparent,
                            width: 3,
                          ),
                        ),
                      ),
                      child: InkWell(
                        key: selectionKey,
                        onTap: onSelect,
                        child: Padding(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 16,
                            vertical: 16,
                          ),
                          child: Row(
                            children: [
                              _CountryFlag(
                                countryCode: countryCode,
                                width: 36,
                                height: 24,
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    if (compact) ...[
                                      nameLabel,
                                      const SizedBox(height: 4),
                                      countLabel,
                                    ] else
                                      Row(
                                        children: [
                                          Expanded(child: nameLabel),
                                          const SizedBox(width: 12),
                                          Flexible(child: countLabel),
                                        ],
                                      ),
                                    const SizedBox(height: 8),
                                    Text(
                                      candidateLabel,
                                      style: theme.textTheme.bodySmall
                                          ?.copyWith(
                                            color: scheme.onSurfaceVariant,
                                          ),
                                    ),
                                  ],
                                ),
                              ),
                              if (selected) ...[
                                const SizedBox(width: 8),
                                Icon(
                                  Icons.check_circle,
                                  size: 20,
                                  color: scheme.onPrimaryContainer,
                                ),
                              ],
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
              VerticalDivider(
                width: 1,
                thickness: 1,
                color: scheme.outlineVariant,
              ),
              if (compact)
                Padding(
                  padding: const EdgeInsets.all(8),
                  child: IconButton(
                    key: expansionKey,
                    tooltip: openTooltip,
                    onPressed: onOpen,
                    icon: Icon(
                      Directionality.of(context) == TextDirection.rtl
                          ? Icons.chevron_left
                          : Icons.chevron_right,
                      size: 20,
                    ),
                  ),
                )
              else
                SizedBox(
                  width: 124,
                  child: Tooltip(
                    message: openTooltip,
                    child: TextButton(
                      key: expansionKey,
                      onPressed: onOpen,
                      style: TextButton.styleFrom(
                        minimumSize: const Size(48, 56),
                        padding: const EdgeInsets.all(12),
                        shape: const RoundedRectangleBorder(),
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Flexible(
                            child: Text(openLabel, textAlign: TextAlign.center),
                          ),
                          const SizedBox(width: 4),
                          Icon(
                            Directionality.of(context) == TextDirection.rtl
                                ? Icons.chevron_left
                                : Icons.chevron_right,
                            size: 20,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
            ],
          ),
        );
      },
    );
  }
}
