// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SINGLE_INSTANCE_IDENTITY_H_
#define RUNNER_SINGLE_INSTANCE_IDENTITY_H_

#include "update_security.h"
#include <utility>

// Only window activation uses this identity. It neither starts nor adopts a
// VPN runtime, and must never perform certificate retrieval on a double-click.
class FuzeVpnActivationIdentity final {
 public:
  explicit FuzeVpnActivationIdentity(std::filesystem::path current)
      : current_(std::move(current)) {
    fuzevpn_update::Version version;
    if (IsUiName(current_) && current_file_.Open(current_) &&
        fuzevpn_update::ReadVersion(current_, &version, true)) {
      fuzevpn_update::TrustedPublisher(current_file_, &publisher_, nullptr,
                                      false);
    }
  }

  bool Matches(const std::filesystem::path& candidate) const {
    if (current_.empty() || candidate.empty()) return false;
    // Preserve the existing same-path behavior for unsigned local builds.
    if (CompareStringOrdinal(current_.c_str(), -1, candidate.c_str(), -1,
                             TRUE) == CSTR_EQUAL) return true;
    if (publisher_.empty() || !IsUiName(candidate)) return false;
    fuzevpn_update::PinnedFile file;
    fuzevpn_update::Version version;
    std::vector<BYTE> publisher;
    return file.Open(candidate) &&
        fuzevpn_update::ReadVersion(candidate, &version, true) &&
        fuzevpn_update::TrustedPublisher(file, &publisher, nullptr, false) &&
        fuzevpn_update::SamePublisher(publisher_, publisher);
  }

 private:
  static bool IsUiName(const std::filesystem::path& path) {
    return CompareStringOrdinal(path.filename().c_str(), -1,
                                L"fuzevpn_windows.exe", -1, TRUE) == CSTR_EQUAL;
  }
  std::filesystem::path current_;
  fuzevpn_update::PinnedFile current_file_;
  std::vector<BYTE> publisher_;
};

#endif  // RUNNER_SINGLE_INSTANCE_IDENTITY_H_
