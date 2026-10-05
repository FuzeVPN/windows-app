// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_RETRYABLE_INSTALLATION_H_
#define RUNNER_RETRYABLE_INSTALLATION_H_

#include <mutex>

namespace fuzevpn {
class RetryableInstallation {
 public:
  template <typename Presence, typename Installer>
  bool Ensure(Presence present, Installer install) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!installed_ || !present()) installed_ = install();
    return installed_;
  }
 private:
  std::mutex mutex_;
  bool installed_ = false;
};
}  // namespace fuzevpn
#endif
