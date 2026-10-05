// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';

abstract final class AppTheme {
  // Shared with fuzevpn.com. Gold identifies an action, never a VPN status.
  static const brand = Color(0xFF101820);
  static const ivory = Color(0xFFF3EFE6);
  static const signal = Color(0xFFF4C95D);
  static const network = Color(0xFF17242C);
  static const signalSoft = Color(0xFFF8E9BB);
  static const success = Color(0xFF167A58);
  static const warning = Color(0xFFC66A13);
  static const danger = Color(0xFFB43A36);

  static Color successFor(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark
      ? const Color(0xFF66D9AA)
      : const Color(0xFF126B4D);
  static Color warningFor(BuildContext context) =>
      Theme.of(context).brightness == Brightness.dark
      ? const Color(0xFFFFBE70)
      : const Color(0xFF9A4C00);

  static ThemeData light({Locale? locale}) => _build(Brightness.light, locale);
  static ThemeData dark({Locale? locale}) => _build(Brightness.dark, locale);

  static bool _needsNaturalSpacing(Locale? locale) => const {
    'ar',
    'fa',
    'ur',
    'hi',
    'th',
    'ja',
    'ko',
    'zh',
  }.contains(locale?.languageCode);

  static double tracking(BuildContext context, double latinValue) =>
      _needsNaturalSpacing(Localizations.maybeLocaleOf(context))
      ? 0
      : latinValue;

  static double headingHeight(BuildContext context, double latinValue) =>
      _needsNaturalSpacing(Localizations.maybeLocaleOf(context))
      ? 1.25
      : latinValue;

  static List<String> _fontFallback(Locale? locale) => [
    'Segoe UI',
    ...switch (locale?.languageCode) {
      'ja' => ['Yu Gothic UI', 'Meiryo'],
      'ko' => ['Malgun Gothic'],
      'zh' =>
        locale?.scriptCode == 'Hant' ||
                const {'TW', 'HK', 'MO'}.contains(locale?.countryCode)
            ? ['Microsoft JhengHei UI', 'Microsoft JhengHei']
            : ['Microsoft YaHei UI', 'Microsoft YaHei'],
      'hi' => ['Nirmala UI'],
      'th' => ['Leelawadee UI', 'Tahoma'],
      'ar' || 'fa' || 'ur' => ['Tahoma', 'Nirmala UI'],
      _ => <String>[],
    },
    'Arial',
  ];

  static ThemeData _build(Brightness brightness, Locale? locale) {
    final naturalSpacing = _needsNaturalSpacing(locale);
    final isDark = brightness == Brightness.dark;
    final background = isDark ? brand : ivory;
    final surface = isDark ? const Color(0xFF172129) : const Color(0xFFFAF8F3);
    final surfaceMuted = isDark
        ? const Color(0xFF25343E)
        : const Color(0xFFEAE4D9);
    final foreground = isDark ? const Color(0xFFF3EFE6) : brand;
    // Controls need a stronger boundary than the site's decorative separators.
    final border = isDark ? const Color(0xFF78858D) : const Color(0xFF8F8270);
    final separator = isDark
        ? const Color(0xFF344149)
        : const Color(0xFFD1C9BD);
    final scheme = ColorScheme(
      brightness: brightness,
      primary: isDark ? signal : brand,
      onPrimary: isDark ? brand : ivory,
      primaryContainer: isDark ? const Color(0xFF393526) : signalSoft,
      onPrimaryContainer: foreground,
      secondary: isDark ? signal : brand,
      onSecondary: isDark ? brand : ivory,
      secondaryContainer: surfaceMuted,
      onSecondaryContainer: foreground,
      tertiary: isDark ? const Color(0xFF66D9AA) : success,
      onTertiary: isDark ? background : Colors.white,
      error: isDark ? const Color(0xFFFF8C85) : danger,
      onError: isDark ? background : Colors.white,
      surface: surface,
      onSurface: foreground,
      surfaceContainerLowest: isDark ? const Color(0xFF121C23) : Colors.white,
      surfaceContainerLow: surface,
      surfaceContainer: surfaceMuted,
      surfaceContainerHigh: surfaceMuted,
      surfaceContainerHighest: surfaceMuted,
      onSurfaceVariant: isDark
          ? const Color(0xFFC6BEB2)
          : const Color(0xFF625D54),
      outline: border,
      outlineVariant: separator,
      shadow: Colors.black,
      scrim: Colors.black,
      inverseSurface: foreground,
      onInverseSurface: background,
      inversePrimary: background,
    );
    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme,
      scaffoldBackgroundColor: background,
      fontFamily: 'Archivo',
      fontFamilyFallback: _fontFallback(locale),
      dividerColor: separator,
      splashFactory: InkRipple.splashFactory,
      visualDensity: VisualDensity.standard,
      focusColor: foreground.withValues(alpha: 0.16),
      textTheme: ThemeData(brightness: brightness).textTheme
          .copyWith(
            displayLarge: TextStyle(
              color: foreground,
              fontSize: 52,
              height: naturalSpacing ? 1.25 : 1.05,
              letterSpacing: naturalSpacing ? 0 : -2.2,
              fontWeight: FontWeight.w700,
            ),
            headlineLarge: TextStyle(
              color: foreground,
              fontSize: 36,
              height: naturalSpacing ? 1.25 : 1.1,
              letterSpacing: naturalSpacing ? 0 : -1.3,
              fontWeight: FontWeight.w700,
            ),
            headlineMedium: TextStyle(
              color: foreground,
              fontSize: 28,
              height: naturalSpacing ? 1.25 : 1.16,
              letterSpacing: naturalSpacing ? 0 : -0.75,
              fontWeight: FontWeight.w700,
            ),
            titleLarge: TextStyle(
              color: foreground,
              fontSize: 21,
              fontWeight: FontWeight.w700,
            ),
            bodyLarge: TextStyle(color: foreground, fontSize: 15, height: 1.5),
            bodyMedium: TextStyle(color: foreground, fontSize: 14, height: 1.5),
            labelLarge: TextStyle(
              color: foreground,
              fontWeight: FontWeight.w700,
              letterSpacing: naturalSpacing ? 0 : 0.1,
            ),
          )
          .apply(
            fontFamily: 'Archivo',
            fontFamilyFallback: _fontFallback(locale),
          ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: scheme.surface,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: BorderSide(color: separator),
        ),
      ),
      appBarTheme: AppBarTheme(
        elevation: 0,
        scrolledUnderElevation: 0,
        backgroundColor: surface,
        foregroundColor: foreground,
        shape: Border(bottom: BorderSide(color: separator)),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: isDark ? const Color(0xFF121C23) : Colors.white,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 15,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: BorderSide(color: border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: BorderSide(color: border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: BorderSide(color: scheme.primary, width: 2),
        ),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: scheme.surface,
        indicatorColor: scheme.primaryContainer,
        selectedIconTheme: IconThemeData(color: scheme.primary),
        selectedLabelTextStyle: TextStyle(
          color: scheme.primary,
          fontWeight: FontWeight.w700,
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: signal,
          foregroundColor: brand,
          disabledBackgroundColor: signal.withValues(
            alpha: isDark ? 0.18 : 0.3,
          ),
          disabledForegroundColor: scheme.onSurface.withValues(alpha: 0.55),
          minimumSize: const Size(0, 46),
          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 14),
          textStyle: TextStyle(
            fontFamily: 'Archivo',
            fontFamilyFallback: _fontFallback(locale),
            fontWeight: FontWeight.w700,
          ),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(0, 46),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
          side: BorderSide(color: border),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          minimumSize: const Size(0, 44),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
        ),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
          side: BorderSide(color: separator),
        ),
      ),
      dividerTheme: DividerThemeData(color: separator, thickness: 1, space: 1),
      switchTheme: SwitchThemeData(
        trackOutlineColor: WidgetStatePropertyAll(border),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: surface,
        selectedColor: scheme.primaryContainer,
        side: BorderSide(color: separator),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
        labelStyle: TextStyle(
          fontFamily: 'Archivo',
          fontFamilyFallback: _fontFallback(locale),
          color: foreground,
          fontWeight: FontWeight.w600,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(
        color: isDark ? signal : brand,
        linearTrackColor: surfaceMuted,
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: network,
        contentTextStyle: const TextStyle(color: ivory, fontFamily: 'Archivo'),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      ),
      tooltipTheme: TooltipThemeData(
        decoration: BoxDecoration(
          color: foreground,
          borderRadius: BorderRadius.circular(4),
        ),
        textStyle: TextStyle(
          fontFamily: 'Archivo',
          fontFamilyFallback: _fontFallback(locale),
          color: background,
          fontSize: 12,
        ),
      ),
    );
  }
}
