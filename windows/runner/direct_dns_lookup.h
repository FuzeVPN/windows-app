// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIRECT_DNS_LOOKUP_H_
#define RUNNER_DIRECT_DNS_LOOKUP_H_

#include "api_bootstrap_dns.h"

namespace fuzevpn::bootstrap {
// Shared production lookup state machine. Exchange is bound to exactly one
// configured DNS server/interface by the native caller; tests supply packets.
// No OS resolver, public DNS fallback, or caller-controlled IPC is involved.
template <typename Clock, typename TransactionId, typename Exchange>
bool LookupServer(const std::string& host, bool public_only, std::uint64_t deadline,
                  Clock now, TransactionId transaction_id, Exchange exchange,
                  std::vector<Address>* addresses) {
  if (!addresses) return false;
  for (bool ipv6 : {false, true}) {
    std::string name = host;
    std::vector<std::string> visited;
    for (unsigned hop = 0; hop < 8 && now() < deadline; ++hop) {
      if (std::find(visited.begin(), visited.end(), name) != visited.end()) break;
      visited.push_back(name);
      std::uint16_t id = 0;
      if (!transaction_id(&id)) return false;
      const auto query = QueryForHost(id, ipv6, name);
      if (query.empty()) return false;
      std::vector<std::uint8_t> response;
      if (!exchange(query, false, std::min(deadline, now() + std::uint64_t(1000)), &response)) break;
      std::string alias;
      auto parsed = ParseForHost(response, id, ipv6, name, public_only, addresses, &alias);
      if (parsed == Response::truncated && now() < deadline &&
          exchange(query, true, std::min(deadline, now() + std::uint64_t(1000)), &response)) {
        parsed = ParseForHost(response, id, ipv6, name, public_only, addresses, &alias);
      }
      // API transport retains its fixed question; its recursive DNS answer
      // must contain the complete chain. Only native endpoint lookup follows
      // an incomplete CNAME answer with another bounded question.
      if (parsed != Response::valid || alias.empty() || public_only) break;
      name = std::move(alias);
    }
  }
  return true;
}
}  // namespace fuzevpn::bootstrap
#endif
