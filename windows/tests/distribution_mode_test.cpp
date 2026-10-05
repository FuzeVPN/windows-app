// SPDX-License-Identifier: MPL-2.0
#include "distribution_mode.h"
#include <iostream>

bool TestCurrentModeDiscovery();

int main() {
  using namespace fuzevpn_distribution;
  unsigned failures = 0;
  auto check = [&](bool condition, const char* message) {
    if (!condition) { std::cerr << message << '\n'; ++failures; }
  };
  check(ClassifyMode(true, true, false, LR"(D:\Applications\FuzeVPN\)",
        LR"(d:\applications\fuzevpn)") == Mode::installed, "custom registered directory");
  check(ClassifyMode(true, true, false, LR"(D:\Applications\FuzeVPN)",
        LR"(C:\Users\Tester\Portable)") == Mode::portable, "moved copy is portable");
  check(ClassifyMode(true, false, false, {}, LR"(E:\FuzeVPN)") == Mode::portable,
        "unregistered archive");
  check(ClassifyMode(true, true, true, LR"(D:\FuzeVPN)", LR"(D:\FuzeVPN)") == Mode::portable,
        "marker overrides MSI registration");
  check(ClassifyMode(false, true, false, LR"(D:\FuzeVPN)", LR"(D:\FuzeVPN)") == Mode::unavailable,
        "registry read error fails closed");
  check(ClassifyMode(false, true, true, LR"(D:\FuzeVPN)", LR"(C:\Users\Tester\Portable)") == Mode::portable,
        "explicit portable marker remains usable when HKLM installation metadata is access denied");
  check(ClassifyMode(false, false, true, {}, LR"(C:\Users\Tester\Portable)") == Mode::portable,
        "portable marker does not require knowing whether another installation exists");
  check(ClassifyMode(false, false, false, {}, LR"(C:\Users\Tester\Portable)") == Mode::unavailable,
        "unmarked copy must not reinterpret unreadable registration as absent");
  for (const auto* path : {L"", L"relative", LR"(\\server\share\FuzeVPN)", LR"(C:\Apps\..\FuzeVPN)"})
    check(ClassifyMode(false, true, true, LR"(D:\FuzeVPN)", path) == Mode::unavailable,
          "portable marker cannot override invalid current path");
  check(ClassifyMode(true, true, false, L"FuzeVPN", LR"(D:\FuzeVPN)") == Mode::unavailable,
        "malformed registry path");
  check(ClassifyMode(true, false, false, {}, {}) == Mode::unavailable, "unknown current path");
  check(ClassifyMode(true, true, false, LR"(D:\Other\..\FuzeVPN)", LR"(D:\FuzeVPN)") == Mode::unavailable,
        "traversal in registry is rejected");
  check(ClassifyMode(true, true, false, LR"(D:\FuzeVPN)", LR"(D:\FuzeVPN2)") == Mode::portable,
        "prefix sibling is distinct");
  check(TestCurrentModeDiscovery(), "production CurrentMode discovery regression");
  return failures ? 1 : 0;
}
