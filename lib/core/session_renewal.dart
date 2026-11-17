// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'api_client.dart';
import 'models.dart';
import 'secure_store.dart';

enum _Answer { renewed, refused, upgradeConflict, upgradeUnknown, unavailable }

typedef _Outcome = ({String? token, Object? failure});

/// Converts, renews and ends the account session as the API's session
/// renewal contract describes.
///
/// Every operation and every replacement or removal of the stored session
/// runs in one queue, so none of them overlap. A request is stored with its
/// route, presented token and request ID before it is sent and, until it is
/// answered, only that same request is sent again. A refresh token that a
/// rotation may have retired is therefore never presented with a new request
/// ID, which the server would treat as a replay and revoke the session.
class SessionRenewal {
  SessionRenewal({
    required this._api,
    required this._store,
    DateTime Function()? now,
    Future<void> Function(Duration delay)? wait,
    Random? random,
  }) : _now = now ?? DateTime.now,
       _wait = wait ?? Future<void>.delayed,
       _random = random ?? Random.secure();

  /// Access that expires within this margin is renewed before it is used.
  static const renewalMargin = Duration(minutes: 5);
  // Waits between the attempts of one operation when the server gave no
  // Retry-After. After the last attempt, or before a longer Retry-After, the
  // request stays stored and is sent again by a later use after that time.
  static const _retryDelays = [Duration(seconds: 1), Duration(seconds: 3)];
  static const _retryPause = Duration(seconds: 10);
  static const _longestWait = Duration(seconds: 30);

  final ApiClient _api;
  final SecureStore _store;
  final DateTime Function() _now;
  final Future<void> Function(Duration) _wait;
  final Random _random;

  Future<void> _queue = Future.value();
  int _running = 0;
  Future<_Outcome>? _settling;
  // Changes when the stored session is replaced or ended: retries stop.
  int _generation = 0;
  // The upgrade route is unknown or the session was converted elsewhere:
  // the classic session stays as it is in this run.
  bool _upgradeClosed = false;
  // A presented token the server refused in this run.
  String? _refused;
  // The access token the last rotation replaced. Requests still carrying it
  // are answered 401 and are retried once with the new one.
  String? _retired;
  DateTime? _retryAt;
  Object? _failure;

  /// The API gives every access token as 43 base64url characters (32 bytes)
  /// and its upgrade route refuses any other bearer. A stored token of
  /// another form is a classic session this client neither converts nor
  /// renews.
  static bool isApiToken(String value) =>
      RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(value);

  /// The access token for an authenticated call, renewed first when it
  /// expires within [renewalMargin]. Null when no session is stored.
  Future<String?> accessToken() => _store.token().then<String?>((token) {
    // A classic token of another form is handed out as stored, without
    // delaying the caller.
    if (token == null || !isApiToken(token)) return token;
    return current(token);
  });

  /// [token], as just read from storage, once a pending request has been
  /// answered, the access renewed when due and, with [upgrade], a classic
  /// session converted. A temporary failure keeps the token in use.
  Future<String> current(String token, {bool upgrade = false}) async {
    if (!isApiToken(token)) return token;
    return (await _settle(upgrade: upgrade)).token ?? token;
  }

  /// After an account route answered [rejected] with 401: the token for a
  /// single retry when the stored session was renewed meanwhile, or when its
  /// access had expired and renewing it succeeded. A temporary renewal
  /// failure is thrown instead of the 401, so the local session is kept.
  /// Null leaves the 401 to the caller's usual handling.
  Future<String?> retryToken(String rejected) async {
    if (!isApiToken(rejected)) return null;
    if (rejected != _retired && rejected != await _store.token()) return null;
    // The server refused this access: it is renewed without waiting for the
    // local clock, which may run behind the server's, to call it due.
    final outcome = await _serial(
      () => _run(upgrade: false, expired: rejected),
    );
    // A failure first: a token restored by the request may itself have
    // expired, and presenting it would end the session.
    if (outcome.failure case final failure?) throw failure;
    final token = outcome.token;
    return token != null && token != rejected ? token : null;
  }

  /// Stores a new classic session (sign-in).
  Future<void> save(String token) => _replace(() => _store.saveToken(token));

  /// Removes the stored session (expired or refused).
  Future<void> clear() => _replace(_store.clearToken);

  /// Ends a renewable session on the server with its refresh token, best
  /// effort with the client's usual timeout, then removes the stored session
  /// whatever the answer. A classic session is only removed locally.
  Future<void> signOut() => _replace(() async {
    try {
      final token = await _store.token();
      final refreshToken = token != null && isApiToken(token)
          ? (await _store.renewableSession())?.tokens?.refreshToken
          : null;
      if (refreshToken != null) await _api.logout(refreshToken);
    } catch (_) {
      // The local session ends now whatever happened on the server.
    }
    await _store.clearToken();
  });

  /// Stops retrying (the controller is disposed).
  void close() => _generation++;

  Future<void> _replace(Future<void> Function() change) {
    _generation++;
    return _serial(() {
      _refused = null;
      _retired = null;
      _retryAt = null;
      _failure = null;
      return change();
    });
  }

  // Runs at once when nothing else runs, else after everything queued.
  Future<T> _serial<T>(Future<T> Function() operation) {
    Future<T> run() async {
      try {
        return await operation();
      } finally {
        _running--;
      }
    }

    final result = _running++ == 0 ? run() : _queue.then((_) => run());
    _queue = result.then<void>((_) {}, onError: (Object _) {});
    return result;
  }

  // Concurrent callers share one operation. A conversion is queued on its own.
  Future<_Outcome> _settle({required bool upgrade}) {
    if (upgrade) return _serial(() => _run(upgrade: true));
    return _settling ??= _serial(
      () => _run(upgrade: false),
    ).whenComplete(() => _settling = null);
  }

  /// [expired]: an access token the server refused, renewed even when the
  /// local clock does not call it due, if it is still the stored one.
  Future<_Outcome> _run({required bool upgrade, String? expired}) async {
    final generation = _generation;
    var session = await _store.renewableSession();
    final classic = session == null ? await _store.token() : null;
    Object? failure;
    // A pending request found in storage may restore an access that has
    // expired since: then, and only then, one new request follows at once.
    // A fresh request is never followed by another, so that a clock running
    // ahead cannot rotate twice and retire tokens still in use.
    final rotations = session?.pending != null ? 2 : 1;
    for (
      var rotation = 0;
      rotation < rotations && generation == _generation;
      rotation++
    ) {
      final tokens = session?.tokens;
      var pending = session?.pending;
      if (pending == null) {
        if (tokens != null) {
          final refused = rotation == 0 && tokens.accessToken == expired;
          if ((!_due(tokens.expiresAt) && !refused) ||
              tokens.refreshToken == _refused) {
            break;
          }
          pending = PendingSessionRequest(
            upgrade: false,
            token: tokens.refreshToken,
            requestId: _requestId(),
          );
        } else {
          if (!upgrade ||
              classic == null ||
              !isApiToken(classic) ||
              _upgradeClosed ||
              classic == _refused) {
            break;
          }
          pending = PendingSessionRequest(
            upgrade: true,
            token: classic,
            requestId: _requestId(),
          );
        }
        final next = RenewableSession(tokens: tokens, pending: pending);
        // Stored before it is sent: the server may commit it and its answer
        // be lost, and only this same request can then recover the result.
        // Unstored, it is not sent, and the session in use stays as it is.
        try {
          await _store.saveRenewableSession(next);
        } catch (error) {
          failure = error;
          break;
        }
        session = next;
      } else if (pending.token == _refused) {
        break;
      }
      final (answer, renewed) = await _send(pending, generation);
      if (answer == _Answer.renewed) {
        _retired = session!.accessToken;
        session = RenewableSession(tokens: renewed);
        // One replacement stores the pair and drops the answered request.
        await _store.saveRenewableSession(session);
      } else if (answer == _Answer.refused ||
          answer == _Answer.upgradeConflict) {
        // Another instance may have stored a newer result meanwhile.
        final latest = await _store.renewableSession();
        if (latest != null &&
            latest.pending == null &&
            latest.accessToken != session!.accessToken) {
          session = latest;
        } else if (answer == _Answer.refused) {
          // Sign-in again follows from the 401 of the next account call.
          _refused = pending.token;
          break;
        } else {
          _upgradeClosed = true;
          await _store.clearRenewableSession();
          session = null;
        }
      } else if (answer == _Answer.upgradeUnknown) {
        // The server does not know the contract yet.
        _upgradeClosed = true;
        await _store.clearRenewableSession();
        session = null;
      } else {
        // The request stays stored, to be sent again as it is.
        failure = _failure;
        break;
      }
    }
    return (token: session?.accessToken ?? classic, failure: failure);
  }

  Future<(_Answer, SessionTokens?)> _send(
    PendingSessionRequest pending,
    int generation,
  ) async {
    if (_retryAt case final retryAt? when _now().isBefore(retryAt)) {
      return (_Answer.unavailable, null);
    }
    for (
      var attempt = 0;
      attempt == 0 || generation == _generation;
      attempt++
    ) {
      Duration? retryAfter;
      try {
        final tokens = await _api.rotateSession(
          upgrade: pending.upgrade,
          token: pending.token,
          requestId: pending.requestId,
        );
        _retryAt = null;
        _failure = null;
        return (_Answer.renewed, tokens);
      } on ApiException catch (error) {
        final status = error.observedHttpStatus;
        if (error.isUnauthorized && status == HttpStatus.unauthorized) {
          return (_Answer.refused, null);
        }
        if (pending.upgrade && status == HttpStatus.notFound) {
          return (_Answer.upgradeUnknown, null);
        }
        if (pending.upgrade &&
            status == HttpStatus.conflict &&
            error.errorCode == 'session_upgrade_conflict') {
          return (_Answer.upgradeConflict, null);
        }
        // 409 session_transition, 429, 5xx, an invalid answer or a local
        // failure: the request may or may not have been committed.
        _failure = error;
        if (error.retryAfterSeconds case final seconds?) {
          retryAfter = Duration(seconds: seconds);
        }
      } catch (error) {
        // A lost answer or an unreachable server.
        _failure = error;
      }
      final delay =
          retryAfter ??
          (attempt < _retryDelays.length ? _retryDelays[attempt] : _retryPause);
      if (attempt == _retryDelays.length || delay > _longestWait) {
        _retryAt = _now().add(delay);
        break;
      }
      await _wait(delay);
    }
    return (_Answer.unavailable, null);
  }

  bool _due(DateTime expiresAt) =>
      !_now().isBefore(expiresAt.subtract(renewalMargin));

  String _requestId() => base64Url
      .encode(List<int>.generate(32, (_) => _random.nextInt(256)))
      .replaceAll('=', '');
}
