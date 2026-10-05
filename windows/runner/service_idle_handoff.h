// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SERVICE_IDLE_HANDOFF_H_
#define RUNNER_SERVICE_IDLE_HANDOFF_H_
#include <windows.h>
#include <atomic>
#include <optional>

namespace fuzevpn_handoff {
constexpr DWORD kYieldIdleControl = 128;
constexpr ULONGLONG kRequestLifetimeMs = 8000;
constexpr ULONGLONG kHelperWaitMs = 12000;
constexpr wchar_t kHelperMutex[] = L"Global\\FuzeVPN-Service-PortableHandoff-v1";

// SCM's handler only queues a request. The serialized service worker makes
// the ownership/network decision before dispatching any further mutation.
class IdleRequest final {
 public:
  bool Queue(ULONGLONG now) {
    ULONGLONG empty = 0;
    return deadline_.compare_exchange_strong(empty, now + kRequestLifetimeMs);
  }
  bool Pending() const { return deadline_.load() != 0; }
  bool Consume(ULONGLONG now, bool has_owner, std::optional<bool> idle) {
    const ULONGLONG deadline = deadline_.exchange(0);
    return deadline != 0 && now < deadline && !has_owner && idle.has_value() && *idle;
  }
  void Clear() { deadline_.store(0); }
 private:
  std::atomic<ULONGLONG> deadline_{0};
};
}  // namespace fuzevpn_handoff
#endif
