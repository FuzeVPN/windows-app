// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DISTRIBUTION_MODE_H_
#define RUNNER_DISTRIBUTION_MODE_H_

#include <filesystem>
#include <string>

namespace fuzevpn_distribution {
enum class Mode { installed, portable, unavailable };

// Public per-machine MSI registration identifies the copy maintained by MSI.
// The private application registry key is not part of distribution discovery.
// A moved/copied UI uses
// the portable runtime; this classification grants no privileged trust.
Mode ClassifyMode(bool registration_readable, bool registered, bool portable_marker,
                  const std::filesystem::path& registered_directory,
                  const std::filesystem::path& current_directory);
// On unavailable, GetLastError contains the public discovery API error or
// ERROR_BAD_CONFIGURATION for malformed metadata; successful discovery clears it.
Mode CurrentMode();
const char* ModeName(Mode mode);
}  // namespace fuzevpn_distribution
#endif
