// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PORTABLE_RUNTIME_H_
#define RUNNER_PORTABLE_RUNTIME_H_

#include "update_security.h"
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace fuzevpn_portable {
constexpr unsigned kManifestResourceId = 300;
constexpr std::uint32_t kIpcVersion = 1;
constexpr std::uint32_t kBootstrapMagic = 0x50565a46; // FZVP
constexpr std::size_t kMaximumManifestBytes = 65536;
constexpr std::size_t kMaximumFiles = 128;
constexpr std::uint64_t kMaximumPayloadBytes = 512ull * 1024 * 1024;

struct ManifestFile {
  std::string relative_path;
  std::uint64_t size = 0;
  std::string sha256;
};
struct Manifest {
  fuzevpn_update::Version version;
  std::uint32_t ipc_version = kIpcVersion;
  std::vector<ManifestFile> files;
  std::string sha256; // SHA-256 of the complete authenticated resource bytes.
};
struct BootstrapResult {
  std::uint32_t magic = kBootstrapMagic;
  std::uint32_t version = kIpcVersion;
  std::uint32_t error = ERROR_SUCCESS;
  std::uint32_t pid = 0;
  std::uint64_t handle = 0;
};
static_assert(sizeof(BootstrapResult) == 24);

// Canonical LF text, no BOM/NUL: header, version, ipc, then file=size<TAB>hash<TAB>path.
bool ParseManifest(std::string_view text, Manifest* manifest, DWORD* error = nullptr);
// Data-only resource read. The caller must separately authenticate/pin the
// container before trusting this manifest as an authorization to run code.
bool ReadEmbeddedManifest(const std::filesystem::path& executable, Manifest* manifest,
                          DWORD* error = nullptr);
std::filesystem::path RuntimeCachePath(const Manifest& manifest);
bool VerifyManifestFiles(const std::filesystem::path& root, const Manifest& manifest,
                         DWORD* error = nullptr);
// Additionally checks all owners/ACLs/ancestors and the exact cache location.
bool ValidateProtectedRuntime(const std::filesystem::path& root, const Manifest& manifest,
                              DWORD* error = nullptr);
// Generic pair of native FuzeVPN EXEs: matching PE architecture, exact version,
// trusted machine publisher identity;
// only explicit development builds allow both signatures to be genuinely absent.
bool ValidatePublisherPair(const fuzevpn_update::PinnedFile& first,
                           const fuzevpn_update::PinnedFile& second,
                           const fuzevpn_update::Version& version,
                           DWORD* error = nullptr);
// Elevated bootstrap only. Never overwrites an existing cache or repairs its ACL.
bool PrepareRuntime(const std::filesystem::path& source_root, const Manifest& manifest,
                    std::filesystem::path* destination, DWORD* error = nullptr);
std::wstring BootstrapPipeName(DWORD parent_pid, const std::string& nonce);
} // namespace fuzevpn_portable
#endif
