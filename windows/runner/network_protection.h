// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NETWORK_PROTECTION_H_
#define RUNNER_NETWORK_PROTECTION_H_

#include <cstdint>
#include <string>

struct NetworkProtectionOptions {
  bool kill_switch = true;
  bool dns_protection = true;
  bool web_rtc_protection = true;
};

enum class NetworkProtectionOwner { wire_guard, open_vpn };

struct NetworkProtectionStatus {
  bool active = false;
  bool kill_switch = false;
  enum class Phase { inactive, prepared, tunnel } phase = Phase::inactive;
};

// Only the elevated portable broker may supply this path, after authenticating
// and pinning the frontend image and its ancestors through the whole runtime.
// Set it before installing filters; clear it after all owned filters are gone.
bool SetAuthenticatedBrokerUiPath(std::wstring path);
void ClearAuthenticatedBrokerUiPath();

// Installs the fail-closed policy before a tunnel engine starts. When the kill
// switch is enabled, only the privileged engine and the authenticated UI
// executable may use the physical network, besides narrowly scoped DHCP
// and IPv6 neighbour-discovery traffic. With the kill switch disabled this
// preparation is an intentional no-op.
bool PrepareNetworkProtection(NetworkProtectionOwner owner,
                              const NetworkProtectionOptions& options);

// Atomically replaces a prepared policy with the final service-owned policy.
// The final policy permits the privileged VPN engine, the verified tunnel
// interface and the same bounded network-configuration traffic. A failed
// candidate installation leaves the active policy untouched.
bool PromoteNetworkProtection(NetworkProtectionOwner owner,
                              std::uint64_t tunnel_interface_luid,
                              const NetworkProtectionOptions& options);

// Dynamic WFP rules remain active if the UI exits and are removed only by an
// explicit disconnect or when Windows stops the privileged runtime.
void DisableNetworkProtection(NetworkProtectionOwner owner);
bool IsNetworkProtectionActive(NetworkProtectionOwner owner);
bool IsTunnelNetworkProtectionActive(NetworkProtectionOwner owner);
NetworkProtectionStatus GetNetworkProtectionStatus(NetworkProtectionOwner owner);
// A retained handle is not evidence that BFE still holds the committed filters.
// False means the runtime must report an unavailable status and retain ownership.
bool IsNetworkProtectionStateKnown();
// Passive diagnostics only. Captures local policy under try_lock, then queries
// BFE on an independent read session without holding the protection mutex.
// Contention, missing filters and concurrent policy changes yield unknown.
struct NetworkProtectionObservation {
  bool known = false;
  NetworkProtectionStatus wireguard, openvpn;
  std::uint64_t generation = 0;
};
NetworkProtectionObservation ObserveNetworkProtection();
// Cheap local-generation check for an asynchronously collected observation.
// It performs no WFP call and cannot prove BFE has not changed since sampling.
bool IsNetworkProtectionObservationCurrent(const NetworkProtectionObservation& observation);
// Last successfully promoted tunnel. It may still carry bootstrap traffic
// during a prepared migration; callers must verify the adapter is still up.
std::uint64_t NetworkProtectionBootstrapTunnelLuid();

#endif  // RUNNER_NETWORK_PROTECTION_H_
