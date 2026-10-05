#ifndef RUNNER_TESTS_BROKER_PASSIVE_CONNECT_TEST_H_
#define RUNNER_TESTS_BROKER_PASSIVE_CONNECT_TEST_H_

#include "../broker_passive_connect.h"

#include <iostream>
#include <optional>
#include <vector>

namespace fuzevpn_passive_connect_test {

// These handles, service responses and ticks are synthetic. No pipe, process,
// SCM handle, timer or VPN operation is created by these regression tests.
struct Fixture {
  static constexpr DWORD kServicePid = 420;
  ULONGLONG ticks = 0;
  ULONGLONG query_cost = 0;
  ULONGLONG open_cost = 0;
  std::vector<DWORD> open_errors;
  std::vector<std::optional<DWORD>> query_results{kServicePid};
  DWORD query_error = ERROR_ACCESS_DENIED;
  bool always_busy = false;
  unsigned cancel_on_check = 0;
  std::optional<ULONGLONG> cancel_at_tick;
  unsigned open_calls = 0;
  unsigned query_calls = 0;
  unsigned cancel_checks = 0;
  std::vector<DWORD> pauses;

  static HANDLE ConnectedPipe() {
    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x420));
  }

  HANDLE Run(DWORD initial_error = ERROR_PIPE_BUSY,
             DWORD expected_pid = kServicePid) {
    return fuzevpn_ipc::RetryRunningServicePipe(expected_pid, initial_error,
        [this] {
          ++open_calls;
          ticks += open_cost;
          if (open_calls <= open_errors.size()) {
            SetLastError(open_errors[open_calls - 1]);
            return INVALID_HANDLE_VALUE;
          }
          if (always_busy) {
            SetLastError(ERROR_PIPE_BUSY);
            return INVALID_HANDLE_VALUE;
          }
          return ConnectedPipe();
        },
        [this] {
          const size_t index = query_calls < query_results.size()
              ? query_calls : query_results.size() - 1;
          ++query_calls;
          ticks += query_cost;
          const auto result = query_results[index];
          // Successful SCM reads intentionally overwrite thread LastError:
          // the helper must retain the last pipe error on a later timeout.
          SetLastError(result.has_value() ? ERROR_SUCCESS : query_error);
          return result;
        },
        [this] {
          ++cancel_checks;
          return (cancel_on_check != 0 && cancel_checks >= cancel_on_check) ||
              (cancel_at_tick.has_value() && ticks >= *cancel_at_tick);
        },
        [this] { return ticks; },
        [this](DWORD milliseconds) {
          pauses.push_back(milliseconds);
          ticks += milliseconds;
        });
  }
};

inline bool Check(bool condition, const char* description) {
  if (!condition) std::cerr << "Passive broker retry: " << description << '\n';
  return condition;
}

}  // namespace fuzevpn_passive_connect_test

inline bool TestPassiveServicePipeRetry() {
  using fuzevpn_passive_connect_test::Check;
  using fuzevpn_passive_connect_test::Fixture;
  bool passed = true;

  {
    Fixture fixture;
    fixture.open_errors = {ERROR_PIPE_BUSY, ERROR_PIPE_BUSY};
    const HANDLE result = fixture.Run();
    passed &= Check(result == Fixture::ConnectedPipe() &&
        fixture.open_calls == 3 && fixture.query_calls == 3 &&
        fixture.ticks == 150 && fixture.pauses == std::vector<DWORD>({75, 75}),
        "a busy authenticated service listener becomes ready without mutation");
  }
  {
    Fixture fixture;
    fixture.always_busy = true;
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    bool bounded_pauses = !fixture.pauses.empty();
    DWORD total = 0;
    for (DWORD duration : fixture.pauses) {
      bounded_pauses &= duration > 0 && duration <= 75;
      total += duration;
    }
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_PIPE_BUSY &&
        fixture.ticks == 2000 && total == 2000 && bounded_pauses &&
        fixture.pauses.back() == 50 && fixture.open_calls == 27 &&
        fixture.query_calls == fixture.open_calls,
        "persistent busy stops at two seconds and preserves the pipe error");
  }
  {
    Fixture fixture;
    fixture.open_errors = {ERROR_FILE_NOT_FOUND, ERROR_NO_DATA};
    const HANDLE result = fixture.Run(ERROR_PATH_NOT_FOUND);
    passed &= Check(result == Fixture::ConnectedPipe() && fixture.open_calls == 3,
        "transient absence and listener teardown are retried for the same service");
  }
  {
    Fixture fixture;
    fixture.cancel_on_check = 1;
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_CANCELLED &&
        fixture.query_calls == 0 && fixture.open_calls == 0 && fixture.pauses.empty(),
        "pre-existing cancellation performs no observation or open");
  }
  {
    Fixture fixture;
    fixture.cancel_on_check = 2;
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_CANCELLED &&
        fixture.query_calls == 1 && fixture.open_calls == 0 && fixture.pauses.empty(),
        "cancellation after SCM observation prevents an opening attempt");
  }
  {
    Fixture fixture;
    fixture.always_busy = true;
    fixture.cancel_at_tick = 75;
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_CANCELLED &&
        fixture.open_calls == 1 && fixture.query_calls == 1 && fixture.ticks == 75,
        "cancellation during the bounded wait stops before another attempt");
  }
  {
    Fixture fixture;
    fixture.open_errors = {ERROR_PIPE_BUSY, ERROR_ACCESS_DENIED};
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_ACCESS_DENIED &&
        fixture.open_calls == 2 && fixture.query_calls == 2 && fixture.ticks == 75 &&
        fixture.pauses.size() == 1,
        "server authentication denial is terminal without another wait or open");
  }
  for (DWORD observed_pid : {DWORD{0}, Fixture::kServicePid + 1}) {
    Fixture fixture;
    fixture.query_results = {Fixture::kServicePid, observed_pid};
    fixture.always_busy = true;
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE &&
        error == ERROR_SERVICE_NOT_ACTIVE && fixture.open_calls == 1 &&
        fixture.query_calls == 2 && fixture.ticks == 75,
        "a stopped or replaced service cannot inherit the retry");
  }
  for (DWORD observation_error : {DWORD{ERROR_ACCESS_DENIED}, DWORD{ERROR_NOT_READY},
                                  DWORD{ERROR_INVALID_PARAMETER}}) {
    Fixture fixture;
    fixture.query_results = {std::nullopt};
    fixture.query_error = observation_error;
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == observation_error &&
        fixture.open_calls == 0 && fixture.query_calls == 1 && fixture.pauses.empty(),
        "unknown SCM status preserves its error and never becomes absence");
  }
  for (DWORD initial_error : {DWORD{ERROR_ACCESS_DENIED}, DWORD{ERROR_INVALID_DATA},
                              DWORD{ERROR_INVALID_PARAMETER}}) {
    Fixture fixture;
    const HANDLE result = fixture.Run(initial_error);
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == initial_error &&
        fixture.open_calls == 0 && fixture.query_calls == 0 && fixture.pauses.empty(),
        "a non-transient initial error has no retry side effects");
  }
  {
    Fixture fixture;
    const HANDLE result = fixture.Run(ERROR_FILE_NOT_FOUND, 0);
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_FILE_NOT_FOUND &&
        fixture.open_calls == 0 && fixture.query_calls == 0 && fixture.pauses.empty(),
        "an absent initial service is never started by a passive read");
  }
  {
    Fixture fixture;
    fixture.query_cost = 2000;
    const HANDLE result = fixture.Run(ERROR_SEM_TIMEOUT);
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_SEM_TIMEOUT &&
        fixture.query_calls == 1 && fixture.open_calls == 0 && fixture.pauses.empty(),
        "SCM observation consuming the deadline cannot initiate another open");
  }
  {
    Fixture fixture;
    fixture.open_cost = 2000;
    fixture.open_errors = {ERROR_PIPE_NOT_CONNECTED};
    const HANDLE result = fixture.Run();
    const DWORD error = GetLastError();
    passed &= Check(result == INVALID_HANDLE_VALUE && error == ERROR_PIPE_NOT_CONNECTED &&
        fixture.query_calls == 1 && fixture.open_calls == 1 && fixture.pauses.empty(),
        "an opening attempt consuming the deadline retains its latest error");
  }
  return passed;
}

#endif  // RUNNER_TESTS_BROKER_PASSIVE_CONNECT_TEST_H_
