// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_API_BOOTSTRAP_RESOLVER_H_
#define RUNNER_API_BOOTSTRAP_RESOLVER_H_
#include <cstdint>
#include <string>
#include <vector>

// Resolves only api.fuzevpn.com using bounded direct DNS from the caller
// process. No shared DNS Client exception, configurable host or arbitrary proxy.
bool ResolveApiBootstrapAddresses(std::vector<std::string>* addresses);

// Native-only connection helper, invoked after the Windows runtime owner is
// authorized and the old WireGuard service has stopped. Never exposed as IPC.
// The absolute monotonic deadline shares the enclosing connection's budget.
bool ResolveWireGuardEndpointAddresses(const std::string& host,
                                      std::uint64_t connection_deadline,
                                      std::vector<std::string>* addresses);

#endif
