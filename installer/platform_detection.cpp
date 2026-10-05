// SPDX-License-Identifier: MPL-2.0
#include "platform_detection.h"

#include <array>
#include <iomanip>
#include <sstream>

namespace fuzevpn::installer {
namespace {
struct Key { HKEY value = nullptr; ~Key() { if (value) RegCloseKey(value); } };
}
PlatformSnapshot ReadPlatform() {
  PlatformSnapshot platform;
  // MSI deliberately reports compatibility versions (for example 6.3/9600)
  // even on Windows 11. Query the installed OS values directly in the native
  // registry view; neither VersionNT nor a process version API is authoritative
  // for this custom action. Do not use ProductName or legacy CurrentVersion.
  platform.stage = L"registry_open_64";
  Key key;
  LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key.value);
  if (status != ERROR_SUCCESS) { platform.error = static_cast<DWORD>(status); return platform; }
  const auto read_number = [&](const wchar_t* name, DWORD* number) {
    platform.stage = name;
    DWORD bytes = sizeof(*number);
    const LSTATUS result = RegGetValueW(key.value, nullptr, name, RRF_RT_REG_DWORD,
        nullptr, number, &bytes);
    platform.error = result == ERROR_SUCCESS && bytes != sizeof(*number)
        ? ERROR_INVALID_DATA : static_cast<DWORD>(result);
    return platform.error == ERROR_SUCCESS;
  };
  if (!read_number(L"CurrentMajorVersionNumber", &platform.major) ||
      !read_number(L"CurrentMinorVersionNumber", &platform.minor)) return platform;
  platform.stage = L"CurrentBuildNumber";
  std::array<wchar_t, 32> build{};
  DWORD bytes = static_cast<DWORD>(sizeof(build));
  status = RegGetValueW(key.value, nullptr, L"CurrentBuildNumber", RRF_RT_REG_SZ,
      nullptr, build.data(), &bytes);
  if (status != ERROR_SUCCESS) { platform.error = static_cast<DWORD>(status); return platform; }
  if (bytes < 2 * sizeof(wchar_t) || bytes > sizeof(build) || bytes % sizeof(wchar_t) != 0 ||
      build[bytes / sizeof(wchar_t) - 1] != L'\0' ||
      !ParseBuildNumber(std::wstring_view(build.data(), bytes / sizeof(wchar_t) - 1), &platform.build)) {
    platform.error = ERROR_INVALID_DATA; return platform;
  }
  using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  const auto kernel = GetModuleHandleW(L"kernel32.dll");
  const auto architecture = kernel ? reinterpret_cast<IsWow64Process2Function>(
      GetProcAddress(kernel, "IsWow64Process2")) : nullptr;
  if (architecture) {
    platform.stage = L"IsWow64Process2";
    USHORT process = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!architecture(GetCurrentProcess(), &process, &platform.native_machine)) {
      platform.error = GetLastError();
      if (platform.error == ERROR_SUCCESS) platform.error = ERROR_GEN_FAILURE;
      return platform;
    }
  } else {
    // Windows 10 versions predating this API also predate x64-on-ARM64.
    // On newer Windows a missing API is not safe to interpret as native x64.
    platform.stage = L"GetNativeSystemInfo_legacy";
    if (platform.major > 10 || (platform.major == 10 && platform.build >= 16299)) {
      platform.error = ERROR_PROC_NOT_FOUND; return platform;
    }
    SYSTEM_INFO system{}; GetNativeSystemInfo(&system);
    switch (system.wProcessorArchitecture) {
      case PROCESSOR_ARCHITECTURE_AMD64: platform.native_machine = IMAGE_FILE_MACHINE_AMD64; break;
      case PROCESSOR_ARCHITECTURE_INTEL: platform.native_machine = IMAGE_FILE_MACHINE_I386; break;
      case PROCESSOR_ARCHITECTURE_ARM64: platform.native_machine = IMAGE_FILE_MACHINE_ARM64; break;
      default: platform.error = ERROR_NOT_SUPPORTED; return platform;
    }
  }
  if (platform.major == 0 || platform.native_machine == IMAGE_FILE_MACHINE_UNKNOWN) {
    platform.error = ERROR_INVALID_DATA; return platform;
  }
  platform.stage = L"complete";
  return platform;
}
std::wstring PlatformDiagnostic(const PlatformSnapshot& platform) {
  std::wostringstream text;
  text << L"FuzeVPN platform: source=registry64; version=" << platform.major << L'.'
       << platform.minor << L'.' << platform.build << L"; native_machine=0x"
       << std::hex << platform.native_machine << std::dec << L"; stage=" << platform.stage
       << L"; error=" << platform.error;
  return text.str();
}
}  // namespace fuzevpn::installer
