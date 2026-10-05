// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RUNTIME_ARCHITECTURE_H_
#define RUNNER_RUNTIME_ARCHITECTURE_H_

#include <windows.h>

namespace fuzevpn_architecture {
constexpr USHORT kX64Machine = IMAGE_FILE_MACHINE_AMD64;
constexpr USHORT kArm64Machine = IMAGE_FILE_MACHINE_ARM64;
#if defined(_M_ARM64) || defined(__aarch64__)
constexpr USHORT kBuildMachine = kArm64Machine;
constexpr const char* kBuildName = "arm64";
#elif defined(_M_X64) || defined(__x86_64__)
constexpr USHORT kBuildMachine = kX64Machine;
constexpr const char* kBuildName = "x64";
#else
#error FuzeVPN requires a native Windows x64 or ARM64 target.
#endif

// A native VPN package must match the OS and its own process. Emulated x64
// processes cannot use the x64 kernel driver on an ARM64 OS.
constexpr bool NativeMachineMatches(USHORT process, USHORT native, USHORT build) {
  return (build == kX64Machine || build == kArm64Machine) && native == build &&
      (process == IMAGE_FILE_MACHINE_UNKNOWN || process == build);
}
inline bool NativeSystemMatchesBuild() {
  using QueryArchitecture = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  const auto query = reinterpret_cast<QueryArchitecture>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
  if (query) {
    USHORT process = 0, native = 0;
    return query(GetCurrentProcess(), &process, &native) &&
        NativeMachineMatches(process, native, kBuildMachine);
  }
  SYSTEM_INFO system{};
  GetNativeSystemInfo(&system);
  const USHORT native = system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
      ? kX64Machine : system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64
      ? kArm64Machine : IMAGE_FILE_MACHINE_UNKNOWN;
  return NativeMachineMatches(IMAGE_FILE_MACHINE_UNKNOWN, native, kBuildMachine);
}

#ifndef FUZEVPN_OPENSSL_SSL_DLL
#if defined(_M_ARM64) || defined(__aarch64__)
#define FUZEVPN_OPENSSL_SSL_DLL "libssl-3-arm64.dll"
#define FUZEVPN_OPENSSL_CRYPTO_DLL "libcrypto-3-arm64.dll"
#else
#define FUZEVPN_OPENSSL_SSL_DLL "libssl-3-x64.dll"
#define FUZEVPN_OPENSSL_CRYPTO_DLL "libcrypto-3-x64.dll"
#endif
#endif
constexpr const char* kOpenSslDll = FUZEVPN_OPENSSL_SSL_DLL;
constexpr const char* kOpenCryptoDll = FUZEVPN_OPENSSL_CRYPTO_DLL;
}  // namespace fuzevpn_architecture

#endif
