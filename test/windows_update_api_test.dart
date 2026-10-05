// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/windows_update_models.dart';

import 'windows_update_models_test.dart' show manifest;

void main() {
  test(
    'all eight publications have separate requests, caches and ETags',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      final publications =
          <({String arch, String channel, WindowsUpdatePackage package})>[
            for (final arch in ['x64', 'arm64'])
              for (final channel in ['stable', 'beta'])
                for (final package in WindowsUpdatePackage.values)
                  (arch: arch, channel: channel, package: package),
          ];
      final releases = <WindowsUpdateRelease>[];
      for (var index = 0; index < publications.length; index++) {
        final publication = publications[index];
        server.responses.add(
          _Response(
            body: {
              ...manifest(version: '1.2.$index'),
              'download_url':
                  'https://downloads.example.test/${publication.arch}-${publication.channel}.${publication.package == WindowsUpdatePackage.portable ? 'zip' : 'exe'}',
            },
            etag: '"publication-$index"',
          ),
        );
        releases.add(
          (await server.api.latestWindowsUpdate(
            arch: publication.arch,
            channel: publication.channel,
            package: publication.package,
          ))!,
        );
        expect(server.requests.last.uri.queryParameters, {
          'arch': publication.arch,
          'channel': publication.channel,
          'package': publication.package.name,
        });
        expect(
          server.requests.last.headers.value(HttpHeaders.ifNoneMatchHeader),
          isNull,
        );
      }
      for (var index = 0; index < publications.length; index++) {
        final publication = publications[index];
        expect(
          await server.api.latestWindowsUpdate(
            arch: publication.arch,
            channel: publication.channel,
            package: publication.package,
          ),
          same(releases[index]),
        );
      }
      expect(server.requests, hasLength(8));
      for (var index = 0; index < publications.length; index++) {
        final publication = publications[index];
        server.responses.add(
          _Response(status: 304, etag: '"publication-$index"'),
        );
        expect(
          await server.api.latestWindowsUpdate(
            arch: publication.arch,
            channel: publication.channel,
            package: publication.package,
            revalidate: true,
          ),
          same(releases[index]),
        );
        expect(
          server.requests.last.headers.value(HttpHeaders.ifNoneMatchHeader),
          '"publication-$index"',
        );
      }
    },
  );

  test(
    'an unpublished beta does not fall back to stable or clear its cache',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        _Response(body: manifest(), etag: '"stable"'),
        const _Response(status: 404, body: {'error': 'update_not_available'}),
      ]);
      final stable = await server.api.latestWindowsUpdate();
      expect(await server.api.latestWindowsUpdate(channel: 'beta'), isNull);
      expect(await server.api.latestWindowsUpdate(), same(stable));
      expect(server.requests, hasLength(2));
      expect(server.requests.last.uri.queryParameters['channel'], 'beta');
    },
  );

  test(
    'unknown channels never issue a request or use a stable cache',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      await expectLater(
        server.api.latestWindowsUpdate(channel: 'nightly'),
        throwsFormatException,
      );
      expect(server.requests, isEmpty);
    },
  );
  for (final arch in ['x64', 'arm64']) {
    test(
      '$arch installer and portable URLs/cache/ETags are independent',
      () async {
        final server = await _Server.open();
        addTearDown(server.close);
        server.responses.addAll([
          _Response(body: manifest(), etag: '"installer"'),
          _Response(
            body: {
              ...manifest(),
              'download_url': 'https://downloads.example.test/FuzeVPN.zip',
            },
            etag: '"portable"',
          ),
          const _Response(status: 304, etag: '"portable"'),
        ]);
        final installer = await server.api.latestWindowsUpdate(arch: arch);
        final portable = await server.api.latestWindowsUpdate(
          arch: arch,
          package: WindowsUpdatePackage.portable,
        );
        expect(installer?.package, WindowsUpdatePackage.installer);
        expect(portable?.package, WindowsUpdatePackage.portable);
        expect(server.requests[0].uri.queryParameters, {
          'arch': arch,
          'channel': 'stable',
          'package': 'installer',
        });
        expect(server.requests[1].uri.queryParameters, {
          'arch': arch,
          'channel': 'stable',
          'package': 'portable',
        });
        expect(
          server.requests[1].headers.value(HttpHeaders.ifNoneMatchHeader),
          isNull,
        );
        expect(
          await server.api.latestWindowsUpdate(arch: arch),
          same(installer),
        );
        expect(
          await server.api.latestWindowsUpdate(
            arch: arch,
            package: WindowsUpdatePackage.portable,
          ),
          same(portable),
        );
        expect(
          await server.api.latestWindowsUpdate(
            arch: arch,
            package: WindowsUpdatePackage.portable,
            revalidate: true,
          ),
          same(portable),
        );
        expect(
          server.requests[2].headers.value(HttpHeaders.ifNoneMatchHeader),
          '"portable"',
        );
        expect(
          server.requests[2].headers.value(HttpHeaders.cacheControlHeader),
          'no-cache',
        );
      },
    );
  }

  test(
    'portable query refuses an EXE instead of silently installing it',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.add(_Response(body: manifest()));
      await expectLater(
        server.api.latestWindowsUpdate(package: WindowsUpdatePackage.portable),
        throwsFormatException,
      );
      expect(server.requests.single.uri.queryParameters['package'], 'portable');
    },
  );
  test('ARM64 release cache and ETag stay separate from x64', () async {
    final server = await _Server.open();
    addTearDown(server.close);
    server.responses.addAll([
      _Response(
        body: manifest(version: '1.2.3'),
        etag: '"x64-release"',
      ),
      _Response(
        body: manifest(version: '1.2.4'),
        etag: '"arm64-release"',
      ),
      const _Response(status: 304, etag: '"arm64-release"'),
    ]);
    final x64 = await server.api.latestWindowsUpdate();
    final arm64 = await server.api.latestWindowsUpdate(arch: 'arm64');
    expect(arm64?.version.toString(), '1.2.4');
    expect(await server.api.latestWindowsUpdate(), same(x64));
    expect(await server.api.latestWindowsUpdate(arch: 'arm64'), same(arm64));
    expect(server.requests, hasLength(2));
    expect(server.requests[1].uri.queryParameters['arch'], 'arm64');
    expect(
      server.requests[1].headers.value(HttpHeaders.ifNoneMatchHeader),
      isNull,
    );
    expect(
      await server.api.latestWindowsUpdate(arch: 'arm64', revalidate: true),
      same(arm64),
    );
    expect(
      server.requests[2].headers.value(HttpHeaders.ifNoneMatchHeader),
      '"arm64-release"',
    );
    await expectLater(
      server.api.latestWindowsUpdate(arch: 'x86'),
      throwsFormatException,
    );
    expect(server.requests, hasLength(3));
  });

  test(
    'CDN Age and server max-age reduce the remaining cache lifetime',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        _Response(
          body: manifest(),
          cacheControl: 'public, max-age=60',
          age: '55',
        ),
        _Response(
          body: manifest(version: '1.2.4'),
          cacheControl: 'max-age=2',
        ),
        _Response(
          body: manifest(version: '1.2.5'),
          cacheControl: 'no-cache',
        ),
        _Response(body: manifest(version: '1.2.6')),
      ]);
      await server.api.latestWindowsUpdate();
      server.time = const Duration(seconds: 4);
      expect(
        (await server.api.latestWindowsUpdate())?.version.toString(),
        '1.2.3',
      );
      server.time = const Duration(seconds: 5);
      expect(
        (await server.api.latestWindowsUpdate())?.version.toString(),
        '1.2.4',
      );
      server.time = const Duration(seconds: 7);
      expect(
        (await server.api.latestWindowsUpdate())?.version.toString(),
        '1.2.5',
      );
      expect(
        (await server.api.latestWindowsUpdate())?.version.toString(),
        '1.2.6',
      );
      expect(server.requests, hasLength(4));
    },
  );

  test(
    'public endpoint includes stable x64 query and caches for exactly 60 seconds',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        _Response(body: manifest(), etag: '"release-1"'),
        const _Response(status: 304, etag: '"release-1"'),
      ]);
      final first = await server.api.latestWindowsUpdate();
      server.time = const Duration(seconds: 59);
      expect(await server.api.latestWindowsUpdate(), same(first));
      expect(server.requests, hasLength(1));
      server.time = const Duration(seconds: 60);
      expect(await server.api.latestWindowsUpdate(), same(first));
      expect(server.requests, hasLength(2));
      expect(server.requests.first.uri.path, '/v1/updates/windows/latest');
      expect(server.requests.first.uri.queryParameters, {
        'arch': 'x64',
        'channel': 'stable',
        'package': 'installer',
      });
      expect(
        server.requests.first.headers.value(HttpHeaders.authorizationHeader),
        isNull,
      );
      expect(
        server.requests[1].headers.value(HttpHeaders.ifNoneMatchHeader),
        '"release-1"',
      );
    },
  );

  test(
    'forced safety revalidation bypasses the cache with no-cache and ETag',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        _Response(body: manifest(), etag: 'W/"a"'),
        const _Response(status: 304, etag: 'W/"a"'),
      ]);
      await server.api.latestWindowsUpdate();
      expect(
        (await server.api.latestWindowsUpdate(
          revalidate: true,
        ))?.version.toString(),
        '1.2.3',
      );
      expect(
        server.requests.last.headers.value(HttpHeaders.cacheControlHeader),
        'no-cache',
      );
      expect(
        server.requests.last.headers.value(HttpHeaders.ifNoneMatchHeader),
        'W/"a"',
      );
    },
  );

  test(
    'only the precise 404 update_not_available response means no release',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        _Response(body: manifest(), etag: '"a"'),
        const _Response(status: 404, body: {'error': 'update_not_available'}),
        const _Response(status: 404, body: {'error': 'not_found'}),
        const _Response(status: 400, body: {'error': 'update_not_available'}),
        const _Response(status: 401, body: {'error': 'unauthorized'}),
      ]);
      await server.api.latestWindowsUpdate();
      expect(await server.api.latestWindowsUpdate(revalidate: true), isNull);
      expect(await server.api.latestWindowsUpdate(), isNull);
      expect(server.requests, hasLength(2));
      for (final status in [404, 400, 401]) {
        await expectLater(
          server.api.latestWindowsUpdate(revalidate: true),
          throwsA(
            isA<ApiException>().having(
              (error) => error.statusCode,
              'status',
              status,
            ),
          ),
        );
      }
      expect(
        server.requests[2].headers.value(HttpHeaders.ifNoneMatchHeader),
        isNull,
      );
    },
  );

  test(
    'unsolicited 304 and malformed replacements invalidate the previous cache',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        const _Response(status: 304),
        _Response(body: manifest(), etag: '"a"'),
        const _Response(body: {'version': '1.3.0'}, etag: '"b"'),
        _Response(body: manifest(version: '1.4.0')),
      ]);
      await expectLater(
        server.api.latestWindowsUpdate(),
        throwsFormatException,
      );
      await server.api.latestWindowsUpdate();
      await expectLater(
        server.api.latestWindowsUpdate(revalidate: true),
        throwsFormatException,
      );
      expect(
        (await server.api.latestWindowsUpdate())?.version.toString(),
        '1.4.0',
      );
      expect(
        server.requests.last.headers.value(HttpHeaders.ifNoneMatchHeader),
        isNull,
      );
    },
  );

  test('HTTP failure does not silently reuse stale release metadata', () async {
    final server = await _Server.open();
    addTearDown(server.close);
    server.responses.addAll([
      _Response(body: manifest(), etag: '"a"'),
      const _Response(status: 503, body: {'error': 'unavailable'}),
      _Response(body: manifest(version: '1.4.0')),
    ]);
    await server.api.latestWindowsUpdate();
    await expectLater(
      server.api.latestWindowsUpdate(revalidate: true),
      throwsA(isA<ApiException>()),
    );
    expect(
      (await server.api.latestWindowsUpdate())?.version.toString(),
      '1.4.0',
    );
    expect(
      server.requests.last.headers.value(HttpHeaders.ifNoneMatchHeader),
      isNull,
    );
  });

  test(
    'concurrent ordinary checks coalesce, forced checks revalidate afterwards',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      final gate = Completer<void>();
      server.responses.addAll([
        _Response(body: manifest(), etag: '"a"', gate: gate.future),
        const _Response(status: 304, etag: '"a"'),
      ]);
      final first = server.api.latestWindowsUpdate();
      final second = server.api.latestWindowsUpdate();
      final forced = server.api.latestWindowsUpdate(revalidate: true);
      gate.complete();
      final results = await Future.wait([first, second, forced]);
      expect(results.every((value) => identical(value, results.first)), isTrue);
      expect(server.requests, hasLength(2));
      expect(
        server.requests.last.headers.value(HttpHeaders.cacheControlHeader),
        'no-cache',
      );
    },
  );

  test(
    'redirects never become installer metadata and no-store is respected',
    () async {
      final server = await _Server.open();
      addTearDown(server.close);
      server.responses.addAll([
        const _Response(status: 302, body: {}),
        _Response(body: manifest(), etag: '"a"', cacheControl: 'no-store'),
        _Response(body: manifest()),
      ]);
      await expectLater(
        server.api.latestWindowsUpdate(),
        throwsA(isA<ApiException>()),
      );
      await server.api.latestWindowsUpdate();
      await server.api.latestWindowsUpdate();
      expect(server.requests, hasLength(3));
      expect(
        server.requests.last.headers.value(HttpHeaders.ifNoneMatchHeader),
        isNull,
      );
    },
  );
}

class _Response {
  const _Response({
    this.status = 200,
    this.body,
    this.etag,
    this.gate,
    this.cacheControl,
    this.age,
  });
  final int status;
  final Object? body;
  final String? etag;
  final Future<void>? gate;
  final String? cacheControl;
  final String? age;
}

class _Server {
  _Server(this.server) {
    api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
      windowsUpdateClock: () => time,
    );
    server.listen((request) async {
      requests.add(request);
      final reply = responses.removeAt(0);
      await reply.gate;
      request.response.statusCode = reply.status;
      if (reply.etag != null) {
        request.response.headers.set(HttpHeaders.etagHeader, reply.etag!);
      }
      if (reply.cacheControl != null) {
        request.response.headers.set(
          HttpHeaders.cacheControlHeader,
          reply.cacheControl!,
        );
      }
      if (reply.age != null) {
        request.response.headers.set(HttpHeaders.ageHeader, reply.age!);
      }
      if (reply.status == 302) {
        request.response.headers.set(HttpHeaders.locationHeader, '/wrong');
      }
      if (reply.body != null) request.response.write(jsonEncode(reply.body));
      await request.response.close();
    });
  }
  static Future<_Server> open() async =>
      _Server(await HttpServer.bind(InternetAddress.loopbackIPv4, 0));
  final HttpServer server;
  late final ApiClient api;
  Duration time = Duration.zero;
  final responses = <_Response>[];
  final requests = <HttpRequest>[];
  Future<void> close() async {
    api.close();
    await server.close(force: true);
  }
}
