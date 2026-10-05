// SPDX-License-Identifier: MPL-2.0
#ifndef FUZEVPN_INSTALLER_PLATFORM_DETECTION_H_
#define FUZEVPN_INSTALLER_PLATFORM_DETECTION_H_

#include <windows.h>
#include <limits>
#include <string>
#include <string_view>

namespace fuzevpn::installer {
#if defined(_M_ARM64)
inline constexpr USHORT kTargetMachine = IMAGE_FILE_MACHINE_ARM64;
inline constexpr const wchar_t* kTargetArchitecture = L"ARM64";
#else
inline constexpr USHORT kTargetMachine = IMAGE_FILE_MACHINE_AMD64;
inline constexpr const wchar_t* kTargetArchitecture = L"x64";
#endif
enum class PlatformStatus { supported, unsupported_os, unsupported_architecture, detection_failed };
struct PlatformSnapshot {
  DWORD major = 0;
  DWORD minor = 0;
  DWORD build = 0;
  USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
  DWORD error = ERROR_SUCCESS;
  const wchar_t* stage = L"not_started";
};
inline bool ParseBuildNumber(std::wstring_view text, DWORD* result) {
  if (text.empty() || !result) return false;
  DWORD value = 0;
  for (const wchar_t digit : text) {
    if (digit < L'0' || digit > L'9') return false;
    const DWORD part = static_cast<DWORD>(digit - L'0');
    if (value > (std::numeric_limits<DWORD>::max() - part) / 10) return false;
    value = value * 10 + part;
  }
  if (value == 0) return false;
  *result = value;
  return true;
}
inline PlatformStatus EvaluatePlatform(const PlatformSnapshot& platform,
                                       USHORT expected_machine = kTargetMachine) {
  if (platform.error != ERROR_SUCCESS || platform.major == 0 || platform.build == 0 ||
      platform.native_machine == IMAGE_FILE_MACHINE_UNKNOWN) return PlatformStatus::detection_failed;
  if (platform.major < 10 || (platform.major == 10 && platform.build < 10240))
    return PlatformStatus::unsupported_os;
  if ((expected_machine != IMAGE_FILE_MACHINE_AMD64 && expected_machine != IMAGE_FILE_MACHINE_ARM64) ||
      platform.native_machine != expected_machine)
    return PlatformStatus::unsupported_architecture;
  return PlatformStatus::supported;
}
PlatformSnapshot ReadPlatform();
std::wstring PlatformDiagnostic(const PlatformSnapshot& platform);
}  // namespace fuzevpn::installer
#endif
