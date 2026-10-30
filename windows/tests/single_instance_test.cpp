// SPDX-License-Identifier: MPL-2.0
// Only GUID-named test objects are created. No product process/window is used.
#include <windows.h>
#include <objbase.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include "single_instance.h"

namespace {
void Check(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
struct Handle {
  HANDLE value = nullptr;
  ~Handle() { if (value) CloseHandle(value); }
};
}

int main() {
  try {
    GUID guid{};
    Check(SUCCEEDED(CoCreateGuid(&guid)), "test GUID unavailable");
    wchar_t guid_text[40]{};
    Check(StringFromGUID2(guid, guid_text, 40) != 0, "test GUID formatting failed");
    const std::wstring name = L"Local\\FuzeVPN.SingleInstance.Test." + std::wstring(guid_text);
    Handle first{CreateMutexW(nullptr, TRUE, name.c_str())};
    const DWORD first_error = GetLastError();
    Check(first.value != nullptr, "isolated first mutex failed");
    unsigned activations = 0, errors = 0;
    auto decision = FuzeVpnDecideSingleInstanceStartup(first.value, first_error,
        [&]() { ++activations; return false; }, [&]() { ++errors; });
    Check(decision == FuzeVpnSingleInstanceDecision::primary && activations == 0 && errors == 0,
          "new primary must not activate or report an error");
    Handle second{CreateMutexW(nullptr, TRUE, name.c_str())};
    const DWORD second_error = GetLastError();
    Check(second.value != nullptr && second_error == ERROR_ALREADY_EXISTS,
          "isolated duplicate mutex did not collide");
    unsigned searches = 0, waits = 0, posts = 0;
    decision = FuzeVpnDecideSingleInstanceStartup(second.value, second_error,
        [&]() {
          ++activations;
          return FuzeVpnTryActivateExistingWindow([&]() -> HWND { ++searches; return nullptr; },
              [&](HWND) { ++posts; return true; }, [&]() { ++waits; }, 4);
        }, [&]() { ++errors; });
    Check(decision == FuzeVpnSingleInstanceDecision::unavailable && errors == 1 &&
          activations == 1 && searches == 4 && waits == 3 && posts == 0,
          "mutex without validated window must report failure and never become primary");
    searches = waits = posts = 0;
    const HWND valid_window = reinterpret_cast<HWND>(static_cast<ULONG_PTR>(101));
    decision = FuzeVpnDecideSingleInstanceStartup(second.value, second_error,
        [&]() {
          return FuzeVpnTryActivateExistingWindow(
              [&]() -> HWND { return ++searches >= 3 ? valid_window : nullptr; },
              [&](HWND window) { ++posts; return window == valid_window; },
              [&]() { ++waits; }, 4);
        }, [&]() { ++errors; });
    Check(decision == FuzeVpnSingleInstanceDecision::activated && errors == 1 &&
          searches == 3 && waits == 2 && posts == 1,
          "late genuine window must produce successful activation without an error");
    searches = waits = 0;
    Check(FuzeVpnTryActivateExistingWindow(
        [&]() -> HWND { return ++searches >= 60 ? valid_window : nullptr; },
        [](HWND) { return true; }, [&]() { ++waits; }) && searches == 60 && waits == 59,
        "normal startup window must tolerate initialization beyond the former two seconds");
    Check(!FuzeVpnTryActivateExistingWindow([&]() { return valid_window; },
        [](HWND) { return false; }, []() {}, 4),
        "failed activation post must not count as success");
    Handle event{CreateEventW(nullptr, TRUE, FALSE, (name + L".Event").c_str())};
    Check(event.value != nullptr, "isolated event failed");
    Handle collision{CreateMutexW(nullptr, TRUE, (name + L".Event").c_str())};
    const DWORD collision_error = GetLastError();
    Check(collision.value == nullptr && collision_error == ERROR_INVALID_HANDLE,
          "isolated event must block the mutex name");
    decision = FuzeVpnDecideSingleInstanceStartup(collision.value, collision_error,
        [&]() { ++activations; return true; }, [&]() { ++errors; });
    Check(decision == FuzeVpnSingleInstanceDecision::unavailable && errors == 2 && activations == 1,
          "unavailable object must report failure without activating or starting a second UI");
    ReleaseMutex(first.value);
    std::cout << "PASS: GUID-isolated single instance startup, collisions, delayed activation and failed delivery\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
  }
}
