// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'app_controller.dart';
import 'app_exit.dart';
import 'app_shell.dart';
import 'app_theme.dart';
import 'brand_config.dart';
import 'core/tray_controller.dart';
import 'l10n/app_localizations.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = AppController();
  final navigatorKey = GlobalKey<NavigatorState>();
  await TrayController(
    controller,
    onQuitRequested: () async {
      final context = navigatorKey.currentContext;
      if (context != null) await requestAppExit(context, controller);
    },
  ).initialize();
  runApp(FuzeVpnApp(controller: controller, navigatorKey: navigatorKey));
}

class FuzeVpnApp extends StatefulWidget {
  const FuzeVpnApp({super.key, this.controller, this.navigatorKey});

  final AppController? controller;
  final GlobalKey<NavigatorState>? navigatorKey;

  @override
  State<FuzeVpnApp> createState() => _FuzeVpnAppState();
}

class _FuzeVpnAppState extends State<FuzeVpnApp> with WidgetsBindingObserver {
  late final AppController _controller = widget.controller ?? AppController();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _controller.initialize();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    if (widget.controller == null) {
      _controller.dispose();
    }
    super.dispose();
  }

  @override
  void didChangeLocales(List<Locale>? locales) {
    if (_controller.language == AppLanguage.system) setState(() {});
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: _controller,
    builder: (context, _) => MaterialApp(
      navigatorKey: widget.navigatorKey,
      title: BrandConfig.appName,
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light(
        locale: AppStrings.resolveLocale(
          _controller.language.locale ??
              WidgetsBinding.instance.platformDispatcher.locale,
        ),
      ),
      darkTheme: AppTheme.dark(
        locale: AppStrings.resolveLocale(
          _controller.language.locale ??
              WidgetsBinding.instance.platformDispatcher.locale,
        ),
      ),
      themeMode: _controller.themeMode,
      locale: _controller.language.locale,
      supportedLocales: AppStrings.supportedLocales,
      localizationsDelegates: [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      localeResolutionCallback: (locale, supportedLocales) =>
          AppStrings.resolveLocale(locale),
      home: AppShell(controller: _controller),
    ),
  );
}
