// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_UPDATE_H_
#define RUNNER_PORTABLE_UPDATE_H_
#include "update_security.h"
#include <string_view>

namespace fuzevpn_portable_update {
constexpr unsigned kMaximumArchiveEntries = 1024;
constexpr uint64_t kMaximumExpandedBytes = 1024ull * 1024 * 1024;
constexpr uint64_t kMaximumEntryBytes = 512ull * 1024 * 1024;
constexpr unsigned kInventoryResourceId = 301;
constexpr size_t kMaximumInventoryBytes = 512 * 1024;
// These exact exclusions are part of the V1 signed format: the carrier is
// authenticated by Authenticode, resource 300 authenticates the runtime sidecar,
// the portable marker has fixed contents, and the README is display-only.
constexpr std::string_view kInventoryExclusions =
    "exclude=fuzevpn-runtime.exe;portable-runtime.manifest;fuzevpn.portable;README-PORTABLE.txt";
struct InventoryFile {
  std::string relative_path;
  uint64_t size = 0;
  std::string sha256;
};
struct Inventory {
  fuzevpn_update::Version version;
  std::vector<InventoryFile> files;
};
bool ParseInventory(std::string_view text, Inventory* inventory);
// Pure consistency check for unit fixtures and authenticated inventory data.
// The caller must authenticate the signed resource carrier before trusting it.
bool VerifyInventoryFiles(const std::filesystem::path& root,
                          const Inventory& inventory,
                          fuzevpn_update::Failure* failure = nullptr);
// Replaces a leftover attempt only when Windows permits deletion. An image
// still held by a previous helper is busy, rather than a poisoned preparation.
bool CopyHelperForAttempt(const fuzevpn_update::PinnedFile& source,
                          const std::filesystem::path& destination,
                          fuzevpn_update::Failure* failure = nullptr);

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
