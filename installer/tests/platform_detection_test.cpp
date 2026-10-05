#include "../platform_detection.h"
#include <cstdlib>
#include <iostream>

int main() {
  using namespace fuzevpn::installer;
  // The policy uses the registry snapshot, independent of the MSI-compatible
  // VersionNT=603 / WindowsBuild=9600 reported on current Windows 11 hosts.
  PlatformSnapshot platform{10, 0, 22631, kTargetMachine, ERROR_SUCCESS, L"complete"};
  if (EvaluatePlatform(platform) != PlatformStatus::supported) return EXIT_FAILURE;
  platform.build = 10240;
  if (EvaluatePlatform(platform) != PlatformStatus::supported) return EXIT_FAILURE;
  platform.build = 19045;
  if (EvaluatePlatform(platform) != PlatformStatus::supported) return EXIT_FAILURE;
  platform.native_machine = IMAGE_FILE_MACHINE_ARM64;
  if (EvaluatePlatform(platform, IMAGE_FILE_MACHINE_ARM64) != PlatformStatus::supported) return EXIT_FAILURE;
  if (EvaluatePlatform(platform, IMAGE_FILE_MACHINE_AMD64) != PlatformStatus::unsupported_architecture) return EXIT_FAILURE;
  platform.native_machine = IMAGE_FILE_MACHINE_AMD64;
  if (EvaluatePlatform(platform, IMAGE_FILE_MACHINE_AMD64) != PlatformStatus::supported) return EXIT_FAILURE;
  if (EvaluatePlatform(platform, IMAGE_FILE_MACHINE_ARM64) != PlatformStatus::unsupported_architecture) return EXIT_FAILURE;
  if (EvaluatePlatform(platform, IMAGE_FILE_MACHINE_UNKNOWN) != PlatformStatus::unsupported_architecture) return EXIT_FAILURE;
  platform.native_machine = IMAGE_FILE_MACHINE_I386;
  if (EvaluatePlatform(platform) != PlatformStatus::unsupported_architecture) return EXIT_FAILURE;
  platform.native_machine = kTargetMachine;
  platform.major = 6; platform.minor = 3; platform.build = 9600;
  if (EvaluatePlatform(platform) != PlatformStatus::unsupported_os) return EXIT_FAILURE;
  platform.major = 10; platform.minor = 0;
  if (EvaluatePlatform(platform) != PlatformStatus::unsupported_os) return EXIT_FAILURE;
  platform.build = 22631; platform.error = ERROR_ACCESS_DENIED;
  if (EvaluatePlatform(platform) != PlatformStatus::detection_failed) return EXIT_FAILURE;
  platform.error = ERROR_SUCCESS; platform.native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
  if (EvaluatePlatform(platform) != PlatformStatus::detection_failed) return EXIT_FAILURE;
  DWORD build = 0;
  for (const auto valid : {L"10240", L"19045", L"22631", L"26100"})
    if (!ParseBuildNumber(valid, &build)) return EXIT_FAILURE;
  for (const auto invalid : {L"", L"0", L"-1", L"22631x", L"22631 ", L"10.0.22631", L"4294967296"})
    if (ParseBuildNumber(invalid, &build)) return EXIT_FAILURE;
  if (ParseBuildNumber(std::wstring_view(L"22631\0junk", 10), &build)) return EXIT_FAILURE;
  std::cout << "Installer platform policy passed; no registry, service or installer changes.\n";
  return EXIT_SUCCESS;
}
