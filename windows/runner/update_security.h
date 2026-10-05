// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_UPDATE_SECURITY_H_
#define RUNNER_UPDATE_SECURITY_H_
#include <windows.h>
#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fuzevpn_update {
constexpr uint64_t kMaximumDownloadBytes = 512ull * 1024 * 1024;
constexpr DWORD kDownloadDeadlineMs = 300000;
// Only fixed stage names and numeric OS/HTTP status values cross the bridge.
// Raw Windows messages, URLs, filesystem paths and certificate data do not.
struct Failure {
  std::string code;
  std::string stage;
  DWORD windows_error = ERROR_SUCCESS;
  DWORD http_status = 0;
  LONG trust_status = ERROR_SUCCESS;
};
struct Version {
  std::array<unsigned, 3> parts{};
  std::string text() const;
  bool operator<(const Version& other) const { return parts < other.parts; }
  bool operator==(const Version& other) const { return parts == other.parts; }
};
bool ParseVersion(const std::string& value, Version* version);
bool ValidHash(const std::string& value);
bool ValidToken(const std::string& value);
std::string NewToken();
std::wstring Wide(const std::string& value);
std::filesystem::path CurrentExecutable();

class PinnedFile final {
 public:
  PinnedFile() = default;
  ~PinnedFile();
  PinnedFile(const PinnedFile&) = delete;
  PinnedFile& operator=(const PinnedFile&) = delete;
  bool Open(const std::filesystem::path& path, bool strict_ancestors = false);
  HANDLE get() const { return file_; }
  const std::filesystem::path& path() const { return path_; }
 private:
  HANDLE file_ = INVALID_HANDLE_VALUE;
  std::filesystem::path path_;
  std::vector<HANDLE> directories_;
};

// Pins every ancestor against rename/reparse replacement. The final random
// directory is private to the user or (machine=true) administrators/SYSTEM.
class PrivateDirectory final {
 public:
  PrivateDirectory() = default;
  ~PrivateDirectory();
  PrivateDirectory(const PrivateDirectory&) = delete;
  PrivateDirectory& operator=(const PrivateDirectory&) = delete;
  bool Create(bool machine);
  const std::filesystem::path& path() const { return path_; }
  void Keep() { keep_ = true; }
 private:
  std::filesystem::path path_;
  std::vector<HANDLE> directories_;
  bool keep_ = false;
};
bool ReadVersion(const std::filesystem::path& path, Version* version,
                 bool require_product_name);
// Keep retrieval enabled for update/runtime authorization. Cache-only window
// activation may opt out without weakening the verification policy.
bool TrustedPublisher(const PinnedFile& file, std::vector<BYTE>* subject,
                      LONG* trust_status = nullptr,
                      bool allow_chain_retrieval = true);
bool SamePublisher(const std::vector<BYTE>& first, const std::vector<BYTE>& second);
bool MatchesHash(HANDLE file, const std::string& hash);
// Reads the pinned PE32+ header without loading or executing the image.
bool ReadPeMachine(HANDLE file, USHORT* machine);
bool MatchesBuildArchitecture(HANDLE file);
bool VerifyBundle(const PinnedFile& file, const std::string& hash,
                  const Version& target, const std::vector<BYTE>& publisher,
                  Failure* failure = nullptr);
bool CopyFileContents(HANDLE source, HANDLE destination);
}  // namespace fuzevpn_update
#endif
