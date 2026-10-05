// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIAGNOSTICS_LOCAL_H_
#define RUNNER_DIAGNOSTICS_LOCAL_H_
#include <flutter/encodable_value.h>
#include <string_view>

namespace fuzevpn_diagnostics {
// Sanitized support evidence. Kept separate from the closed runtime snapshot
// schema so collection still works when IPC, elevation or the installed service
// is unavailable. The app may include it in a user-requested support bundle;
// this method itself never sends data or forwards a request to the runtime.
flutter::EncodableMap RequestLocalDiagnostics();
void ShutdownLocalDiagnostics();

// Pure closed-schema parser, also used by isolated native regression tests.
// Raw exception messages, arbitrary identifiers and unknown fields are dropped.
flutter::EncodableMap SanitizeNativeDiagnosticTail(std::string_view bytes,
                                                 bool starts_midline = false);
}  // namespace fuzevpn_diagnostics
#endif
