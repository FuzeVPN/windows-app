#include "../installer_version.h"
#include <cstdlib>
#include <iostream>
int main() {
  using namespace fuzevpn::installer;
  Version first{}, next{}, major{};
  if (!ParseVersion(L"0.1.0.1", &first) || !ParseVersion(L"0.1.0.2", &next) ||
      !UpgradeAllowed(first, next) || UpgradeAllowed(next, first) || !UpgradeAllowed(first, first)) return EXIT_FAILURE;
  if (!ParseVersion(L"65535.65535.65535.65535", &major) || !UpgradeAllowed(next, major) ||
      !ParseVersion(L"0.1.0", &first) || first[3] != 0) return EXIT_FAILURE;
  for (const auto text : {L"1.2", L"1.2.3.4.5", L"1..3", L"1.2.65536.0", L"-1.2.3", L"1.2.3.", L"1.2.3x"})
    if (ParseVersion(text, &first)) return EXIT_FAILURE;
  std::cout << "Installer version policy passed; no installer or OS changes executed.\n";
}
