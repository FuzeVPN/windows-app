// SPDX-License-Identifier: MPL-2.0
// Read-only probe using the unmodified updater shared by 1.0.6--1.0.8.
#include "update_security.h"
#include <iostream>

int main(int argc, char** argv) {
  using namespace fuzevpn_update;
  if (argc != 3 && argc != 5) return 2;
  const std::filesystem::path bundle = Wide(argv[1]);
  Version expected, actual;
  if (!ParseVersion(argv[2], &expected) || !ReadVersion(bundle, &actual, true) ||
      !(actual == expected)) {
    std::cerr << "Legacy updater metadata rejected\n";
    return 1;
  }
  if (argc == 5) {
    PinnedFile reference, package;
    std::vector<BYTE> publisher;
    Failure failure;
    if (!reference.Open(Wide(argv[4])) || !TrustedPublisher(reference, &publisher) ||
        !package.Open(bundle) || !VerifyBundle(package, argv[3], expected, publisher, &failure)) {
      std::cerr << "Legacy updater verification rejected: " << failure.code << '\n';
      return 1;
    }
  }
  std::cout << "Legacy updater contract PASS: " << actual.text() << '\n';
  return 0;
}
