// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_UPDATE_H_
#define RUNNER_PORTABLE_UPDATE_H_
#include "update_security.h"

namespace fuzevpn_portable_update {
constexpr unsigned kMaximumArchiveEntries = 1024;
constexpr uint64_t kMaximumExpandedBytes = 1024ull * 1024 * 1024;
constexpr uint64_t kMaximumEntryBytes = 512ull * 1024 * 1024;

// The ZIP is pinned and its expected SHA-256 is checked before parsing or
// writing any archive content. Only the canonical FuzeVPN/ root is accepted.
bool ExtractArchive(const fuzevpn_update::PinnedFile& archive,
                    const std::string& sha256,
                    const std::filesystem::path& empty_destination,
                    fuzevpn_update::Failure* failure);
bool ValidateBundle(const std::filesystem::path& root,
                    const fuzevpn_update::Version& target,
                    const std::vector<BYTE>& publisher,
                    fuzevpn_update::Failure* failure);
bool IsPortableTarget(const std::filesystem::path& root);
// Refuses reparse points and unbounded traversal. Used only for a fresh random
// staging directory owned by this operation, never for the old user folder.
bool RemoveStaging(const std::filesystem::path& root);
// A failed second rename restores the original complete folder. The backup is
// kept on success so user-added files remain recoverable.
bool ReplaceDirectory(const std::filesystem::path& target,
                      const std::filesystem::path& candidate,
                      const std::filesystem::path& backup,
                      fuzevpn_update::Failure* failure);
}  // namespace fuzevpn_portable_update
#endif
