// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RUNTIME_OWNERSHIP_H_
#define RUNNER_RUNTIME_OWNERSHIP_H_

#include <optional>
#include <string>

namespace fuzevpn {

// The service handles one request at a time. Keep the Windows account which
// reserved the machine-wide tunnel, independently of Web login lifetime.
class RuntimeOwnership final {
 public:
  enum class Authorization { allowed, another_user, state_unavailable };

  Authorization AuthorizeMutation(const std::string& user,
                                   std::optional<bool> confirmed_idle) {
    if (user.empty()) return Authorization::state_unavailable;
    if (!owner_.empty()) {
      return owner_ == user ? Authorization::allowed : Authorization::another_user;
    }
    // Do not adopt an orphaned/unknown tunnel after an incomplete startup
    // cleanup. Only the internal service recovery path may remove that state.
    if (!confirmed_idle.has_value() || !*confirmed_idle)
      return Authorization::state_unavailable;
    owner_ = user;
    return Authorization::allowed;
  }

  bool OwnedByAnotherUser(const std::string& user) const {
    return !owner_.empty() && owner_ != user;
  }
  bool HasOwner() const { return !owner_.empty(); }

  void ReleaseIfIdle(std::optional<bool> confirmed_idle) {
    if (confirmed_idle.has_value() && *confirmed_idle) owner_.clear();
  }

 private:
  std::string owner_;
};

}  // namespace fuzevpn
#endif  // RUNNER_RUNTIME_OWNERSHIP_H_
