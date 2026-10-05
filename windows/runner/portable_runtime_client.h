// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_RUNTIME_CLIENT_H_
#define RUNNER_PORTABLE_RUNTIME_CLIENT_H_
#include <windows.h>
#include <filesystem>

// Returns a retained QUERY_LIMITED_INFORMATION|SYNCHRONIZE handle to the
// protected engine, or nullptr. Never returns the short-lived helper handle.
HANDLE LaunchPortableRuntime(HANDLE cancelled,
                             std::filesystem::path* engine_path);
#endif
