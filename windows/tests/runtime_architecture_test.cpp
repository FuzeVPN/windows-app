// SPDX-License-Identifier: MPL-2.0
#include "runtime_architecture.h"
#include <iostream>

int main() {
  using namespace fuzevpn_architecture;
  unsigned failures = 0;
  const auto check = [&](bool valid, const char* message) {
    if (!valid) { std::cerr << message << '\n'; ++failures; }
  };
  check(NativeMachineMatches(IMAGE_FILE_MACHINE_UNKNOWN, kX64Machine, kX64Machine), "native x64 rejected");
  check(NativeMachineMatches(IMAGE_FILE_MACHINE_UNKNOWN, kArm64Machine, kArm64Machine), "native ARM64 rejected");
  check(NativeMachineMatches(kX64Machine, kX64Machine, kX64Machine), "explicit x64 process rejected");
  check(NativeMachineMatches(kArm64Machine, kArm64Machine, kArm64Machine), "explicit ARM64 process rejected");
  check(!NativeMachineMatches(kX64Machine, kArm64Machine, kX64Machine), "x64 emulation accepted with x64 driver");
  check(!NativeMachineMatches(kX64Machine, kArm64Machine, kArm64Machine), "emulated process accepted as ARM64 build");
  check(!NativeMachineMatches(IMAGE_FILE_MACHINE_I386, kX64Machine, kX64Machine), "x86 process accepted");
  check(!NativeMachineMatches(IMAGE_FILE_MACHINE_UNKNOWN, kX64Machine, kArm64Machine), "wrong native OS accepted");
  check(!NativeMachineMatches(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_UNKNOWN, kBuildMachine), "unknown native OS accepted");
  check(!NativeMachineMatches(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_I386), "unsupported build accepted");
  return failures ? 1 : 0;
}
