// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NETWORK_PROTECTION_FAILURE_H_
#define RUNNER_NETWORK_PROTECTION_FAILURE_H_

#include <atomic>
#include <cstdint>

namespace fuzevpn_network_failure {
// Fixed categories and the API's returned DWORD only. Shared with the engine
// worker so OpenVPN promotion failures survive until the broker replies.
enum class Stage : std::uint32_t {
  none, engine_open, transaction_begin, provider_add, filter_enum_create,
  filter_enum, filter_enum_destroy, filter_delete, sublayer_delete,
  provider_delete, sublayer_add, app_id, filter_add, transaction_commit
};
inline std::atomic<std::uint64_t> failure{0};
inline void Clear() { failure.store(0); }
inline std::uint32_t Capture(Stage stage, std::uint32_t status) {
  if (status) {
    std::uint64_t empty = 0;
    failure.compare_exchange_strong(empty,
        (static_cast<std::uint64_t>(stage) << 32) | status);
  }
  return status;
}
struct Snapshot { const char* stage; std::uint32_t status; };
inline Snapshot Read() {
  const auto value = failure.load();
  const auto stage = static_cast<Stage>(value >> 32);
  const char* name = nullptr;
#define FUZEVPN_WFP_STAGE(value) case Stage::value: name = "wfp_" #value; break
  switch (stage) {
    FUZEVPN_WFP_STAGE(engine_open); FUZEVPN_WFP_STAGE(transaction_begin);
    FUZEVPN_WFP_STAGE(provider_add); FUZEVPN_WFP_STAGE(filter_enum_create);
    FUZEVPN_WFP_STAGE(filter_enum); FUZEVPN_WFP_STAGE(filter_enum_destroy);
    FUZEVPN_WFP_STAGE(filter_delete); FUZEVPN_WFP_STAGE(sublayer_delete);
    FUZEVPN_WFP_STAGE(provider_delete); FUZEVPN_WFP_STAGE(sublayer_add);
    FUZEVPN_WFP_STAGE(app_id); FUZEVPN_WFP_STAGE(filter_add);
    FUZEVPN_WFP_STAGE(transaction_commit);
    default: break;
  }
#undef FUZEVPN_WFP_STAGE
  return {name, static_cast<std::uint32_t>(value)};
}
}  // namespace fuzevpn_network_failure
#endif
