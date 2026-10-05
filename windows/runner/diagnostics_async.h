// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIAGNOSTICS_ASYNC_H_
#define RUNNER_DIAGNOSTICS_ASYNC_H_
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace fuzevpn_diagnostics {
// A single passive reader, never executed under the IPC dispatcher or its
// lock. A result is consumable once and only by the same account/generation.
template <class Observation> class AsyncSnapshot final {
 public:
  struct Request {
    std::string user;
    bool owned = false, other_user = false;
    std::uint64_t generation = 0;
    bool Same(const Request& rhs) const {
      return user == rhs.user && owned == rhs.owned && other_user == rhs.other_user &&
          generation == rhs.generation;
    }
  };
  using Reader = std::function<Observation(const Request&)>;
  explicit AsyncSnapshot(Reader reader) : reader_(std::move(reader)) {}
  ~AsyncSnapshot() { Stop(); }
  AsyncSnapshot(const AsyncSnapshot&) = delete;
  AsyncSnapshot& operator=(const AsyncSnapshot&) = delete;

  std::optional<Observation> Poll(const std::string& user, bool owned, bool other_user) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopped_) return std::nullopt;
    Request request{user, owned, other_user, generation_};
    if (completed_) {
      auto value = completed_key_.Same(request) ? std::move(completed_) : std::nullopt;
      completed_.reset();
      if (value) return value;
    }
    if (!working_ && !pending_) {
      if (!worker_.joinable()) worker_ = std::thread([this] {
        // Diagnostics, including allocation failures, cannot terminate the
        // privileged VPN process. A failed worker remains unavailable.
        try { Run(); } catch (...) {
          std::lock_guard<std::mutex> lock(mutex_);
          stopped_ = true;
          pending_.reset(); completed_.reset();
        }
      });
      pending_ = std::move(request);
      changed_.notify_one();
    }
    return std::nullopt;
  }
  void Invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++generation_;
    completed_.reset();
    pending_.reset();
  }
  // Called after network teardown, never from a connect/disconnect request.
  // Native query APIs cannot all be cancelled; don't destroy their inputs or
  // engine globals while a passive reader may still be using them.
  void Stop() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      stopped_ = true;
      ++generation_;
      pending_.reset(); completed_.reset();
      changed_.notify_one();
    }
    if (worker_.joinable()) worker_.join();
  }
 private:
  void Run() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stopped_) {
      changed_.wait(lock, [this] { return stopped_ || pending_.has_value(); });
      if (stopped_) break;
      const auto request = std::move(*pending_);
      pending_.reset(); working_ = true;
      lock.unlock();
      std::optional<Observation> value;
      try { value = reader_(request); } catch (...) { value = Observation{}; }
      lock.lock();
      working_ = false;
      if (!stopped_ && request.generation == generation_) {
        completed_key_ = request;
        completed_ = std::move(value);
      }
    }
  }
  Reader reader_;
  std::mutex mutex_;
  std::condition_variable changed_;
  std::thread worker_;
  std::optional<Request> pending_;
  Request completed_key_;
  std::optional<Observation> completed_;
  std::uint64_t generation_ = 0;
  bool working_ = false, stopped_ = false;
};
}  // namespace fuzevpn_diagnostics
#endif
