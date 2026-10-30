// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RUNTIME_NETWORK_RECOVERY_H_
#define RUNNER_RUNTIME_NETWORK_RECOVERY_H_
#include <windows.h>
// Explicit administrator-only recovery in the OS-DLL-only bootstrap binary.
// Fails without changing WFP if any runtime/tunnel is alive or unobservable.
DWORD RecoverStoppedNetworkFromRuntime();
#endif
