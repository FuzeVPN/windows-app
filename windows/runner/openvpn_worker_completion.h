// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_WORKER_COMPLETION_H_
#define RUNNER_OPENVPN_WORKER_COMPLETION_H_

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <utility>

namespace fuzevpn {
// A thread's exception cannot be caught by the broker request thread. Publish
// completion even when Core or its completion callback throws; the owner can
// then join the thread and run ordinary cleanup without destroying a live Client.
class OpenVpnWorkerCompletion {
 public:
  template <typename Work, typename Complete>
  void Run(std::mutex& state_mutex, std::condition_variable& ready,
           Work&& work, Complete&& complete) noexcept {
    bool failed = false;
    try {
      auto result = std::forward<Work>(work)();
      std::forward<Complete>(complete)(result);
    } catch (...) {
      failed = true;
    }
    {
      // Share the waiter's mutex so completion cannot fall between its final
      // predicate check and wait, losing the only notification.
      std::lock_guard<std::mutex> lock(state_mutex);
      failed_.store(failed, std::memory_order_release);
      finished_.store(true, std::memory_order_release);
    }
    ready.notify_all();
  }
  bool finished() const noexcept { return finished_.load(std::memory_order_acquire); }
  bool failed() const noexcept { return failed_.load(std::memory_order_acquire); }
 private:
  std::atomic<bool> finished_{false};
  std::atomic<bool> failed_{false};
};
}  // namespace fuzevpn
#endif
