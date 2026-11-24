// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SPLIT_TUNNEL_POLICY_H_
#define RUNNER_SPLIT_TUNNEL_POLICY_H_

// Pure split-tunnel policy: parsing, normalization and route arithmetic.
// Deliberately free of Windows headers so it can be included anywhere,
// including before or after <windows.h>, and exercised by isolated tests.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace fuzevpn {

enum class SplitTunnelMode : std::uint8_t { off, exclude, include };

// Bounded by the UI and re-checked at the privileged boundary.
constexpr std::size_t kMaxSplitTunnelPrefixes = 16;
constexpr std::size_t kMaxSplitTunnelPrefixText = 64;

struct IpPrefix {
  bool ipv6 = false;
  // Network byte order. IPv4 uses the first four bytes; the rest stay zero.
  std::array<std::uint8_t, 16> bytes{};
  std::uint8_t length = 0;
};

inline bool SameIpPrefix(const IpPrefix& left, const IpPrefix& right) {
  return left.ipv6 == right.ipv6 && left.length == right.length &&
         left.bytes == right.bytes;
}

inline unsigned IpPrefixBits(bool ipv6) { return ipv6 ? 128u : 32u; }

inline bool IpPrefixBit(const IpPrefix& prefix, unsigned index) {
  return ((prefix.bytes[index / 8] >> (7 - index % 8)) & 1u) != 0;
}

inline void SetIpPrefixBit(IpPrefix* prefix, unsigned index, bool value) {
  const auto mask = static_cast<std::uint8_t>(0x80u >> (index % 8));
  if (value) prefix->bytes[index / 8] |= mask;
  else prefix->bytes[index / 8] &= static_cast<std::uint8_t>(~mask);
}

// True when every bit after the prefix length is zero.
inline bool IsCanonicalIpPrefix(const IpPrefix& prefix) {
  const unsigned bits = IpPrefixBits(prefix.ipv6);
  if (prefix.length > bits) return false;
  for (unsigned index = prefix.length; index < bits; ++index)
    if (IpPrefixBit(prefix, index)) return false;
  for (unsigned index = bits / 8; index < 16; ++index)
    if (prefix.bytes[index] != 0) return false;
  return true;
}

inline bool IpPrefixContains(const IpPrefix& outer, const IpPrefix& inner) {
  if (outer.ipv6 != inner.ipv6 || outer.length > inner.length) return false;
  for (unsigned index = 0; index < outer.length; ++index)
    if (IpPrefixBit(outer, index) != IpPrefixBit(inner, index)) return false;
  return true;
}

inline bool IpPrefixesOverlap(const IpPrefix& left, const IpPrefix& right) {
  return IpPrefixContains(left, right) || IpPrefixContains(right, left);
}

namespace split_tunnel_detail {

inline bool ParseDecimal(std::string_view text, unsigned maximum, unsigned* value) {
  if (text.empty() || text.size() > 3 || (text.size() > 1 && text.front() == '0'))
    return false;
  unsigned result = 0;
  for (const char character : text) {
    if (character < '0' || character > '9') return false;
    result = result * 10 + static_cast<unsigned>(character - '0');
  }
  if (result > maximum) return false;
  *value = result;
  return true;
}

inline bool ParseIpv4(std::string_view text, std::array<std::uint8_t, 16>* bytes) {
  std::array<std::uint8_t, 16> result{};
  for (unsigned part = 0; part < 4; ++part) {
    const auto dot = text.find('.');
    const bool last = part == 3;
    if ((dot == std::string_view::npos) != last) return false;
    unsigned octet = 0;
    if (!ParseDecimal(last ? text : text.substr(0, dot), 255, &octet)) return false;
    result[part] = static_cast<std::uint8_t>(octet);
    if (!last) text.remove_prefix(dot + 1);
  }
  *bytes = result;
  return true;
}

inline int HexValue(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

inline bool ParseIpv6Groups(std::string_view text, std::vector<std::uint16_t>* groups) {
  groups->clear();
  if (text.empty()) return true;
  while (true) {
    const auto colon = text.find(':');
    const auto group = colon == std::string_view::npos ? text : text.substr(0, colon);
    if (group.empty() || group.size() > 4) return false;
    unsigned value = 0;
    for (const char character : group) {
      const int digit = HexValue(character);
      if (digit < 0) return false;
      value = value * 16 + static_cast<unsigned>(digit);
    }
    groups->push_back(static_cast<std::uint16_t>(value));
    if (colon == std::string_view::npos) return true;
    text.remove_prefix(colon + 1);
  }
}

// Embedded dotted IPv4 and zone identifiers are refused: neither belongs in
// a routing prefix and both are rejected by the policy anyway.
inline bool ParseIpv6(std::string_view text, std::array<std::uint8_t, 16>* bytes) {
  if (text.size() < 2 || text.size() > 39) return false;
  const auto gap = text.find("::");
  std::vector<std::uint16_t> head, tail;
  if (gap == std::string_view::npos) {
    if (!ParseIpv6Groups(text, &head) || head.size() != 8) return false;
  } else {
    if (text.find("::", gap + 1) != std::string_view::npos) return false;
    if (!ParseIpv6Groups(text.substr(0, gap), &head) ||
        !ParseIpv6Groups(text.substr(gap + 2), &tail) ||
        head.size() + tail.size() > 7) return false;
  }
  std::array<std::uint8_t, 16> result{};
  for (std::size_t index = 0; index < head.size(); ++index) {
    result[index * 2] = static_cast<std::uint8_t>(head[index] >> 8);
    result[index * 2 + 1] = static_cast<std::uint8_t>(head[index] & 0xff);
  }
  for (std::size_t index = 0; index < tail.size(); ++index) {
    const std::size_t group = 8 - tail.size() + index;
    result[group * 2] = static_cast<std::uint8_t>(tail[index] >> 8);
    result[group * 2 + 1] = static_cast<std::uint8_t>(tail[index] & 0xff);
  }
  *bytes = result;
  return true;
}

}  // namespace split_tunnel_detail

// Accepts "address" (a host) or "address/length". Host bits must be zero.
inline bool ParseIpPrefix(std::string_view text, IpPrefix* prefix) {
  if (!prefix || text.empty() || text.size() > kMaxSplitTunnelPrefixText) return false;
  IpPrefix result;
  const auto slash = text.find('/');
  const auto address = slash == std::string_view::npos ? text : text.substr(0, slash);
  result.ipv6 = address.find(':') != std::string_view::npos;
  if (result.ipv6 ? !split_tunnel_detail::ParseIpv6(address, &result.bytes)
                  : !split_tunnel_detail::ParseIpv4(address, &result.bytes))
    return false;
  const unsigned bits = IpPrefixBits(result.ipv6);
  unsigned length = bits;
  if (slash != std::string_view::npos &&
      !split_tunnel_detail::ParseDecimal(text.substr(slash + 1), bits, &length))
    return false;
  result.length = static_cast<std::uint8_t>(length);
  if (!IsCanonicalIpPrefix(result)) return false;
  *prefix = result;
  return true;
}

inline std::string FormatIpAddress(const IpPrefix& prefix) {
  std::string result;
  if (!prefix.ipv6) {
    for (unsigned index = 0; index < 4; ++index) {
      if (index) result += '.';
      result += std::to_string(prefix.bytes[index]);
    }
    return result;
  }
  std::array<unsigned, 8> groups{};
  for (unsigned index = 0; index < 8; ++index)
    groups[index] = (static_cast<unsigned>(prefix.bytes[index * 2]) << 8) |
                    prefix.bytes[index * 2 + 1];
  // RFC 5952: compress the first longest run of at least two zero groups.
  int best_start = -1, best_length = 0;
  for (int index = 0; index < 8;) {
    if (groups[index] != 0) { ++index; continue; }
    int end = index;
    while (end < 8 && groups[end] == 0) ++end;
    if (end - index > best_length && end - index >= 2) {
      best_start = index;
      best_length = end - index;
    }
    index = end;
  }
  static constexpr char kDigits[] = "0123456789abcdef";
  for (int index = 0; index < 8;) {
    if (index == best_start) {
      result += "::";
      index += best_length;
      continue;
    }
    if (!result.empty() && result.back() != ':') result += ':';
    const unsigned value = groups[index];
    bool started = false;
    for (int shift = 12; shift >= 0; shift -= 4) {
      const unsigned digit = (value >> shift) & 0xf;
      if (digit || started || shift == 0) {
        result += kDigits[digit];
        started = true;
      }
    }
    ++index;
  }
  return result;
}

inline std::string FormatIpPrefix(const IpPrefix& prefix) {
  return FormatIpAddress(prefix) + '/' + std::to_string(prefix.length);
}

// Dotted IPv4 netmask, as OpenVPN's `route` directive expects.
inline std::string FormatIpv4Netmask(unsigned length) {
  std::string result;
  for (unsigned octet = 0; octet < 4; ++octet) {
    unsigned bits = length > octet * 8 ? std::min(8u, length - octet * 8) : 0u;
    const unsigned value = bits == 0 ? 0u : (0xffu << (8 - bits)) & 0xffu;
    if (octet) result += '.';
    result += std::to_string(value);
  }
  return result;
}

inline IpPrefix MakeIpPrefix(std::string_view text) {
  IpPrefix prefix;
  ParseIpPrefix(text, &prefix);
  return prefix;
}

// Ranges a user may never steer: unspecified, loopback, multicast, reserved,
// and IPv4-mapped IPv6. Multicast is reached through the local-network option.
inline const std::vector<IpPrefix>& ForbiddenSplitTunnelPrefixes() {
  static const std::vector<IpPrefix> prefixes{
      MakeIpPrefix("0.0.0.0/8"),     MakeIpPrefix("127.0.0.0/8"),
      MakeIpPrefix("224.0.0.0/4"),   MakeIpPrefix("240.0.0.0/4"),
      MakeIpPrefix("::/128"),        MakeIpPrefix("::1/128"),
      MakeIpPrefix("::ffff:0:0/96"), MakeIpPrefix("ff00::/8")};
  return prefixes;
}

// Fixed, non-routable local ranges. A hostile network can announce any
// on-link subnet; it cannot widen this list (TunnelCrack LocalNet).
inline const std::vector<IpPrefix>& LocalNetworkPrefixes() {
  static const std::vector<IpPrefix> prefixes{
      MakeIpPrefix("10.0.0.0/8"),       MakeIpPrefix("172.16.0.0/12"),
      MakeIpPrefix("192.168.0.0/16"),   MakeIpPrefix("169.254.0.0/16"),
      MakeIpPrefix("224.0.0.0/24"),     MakeIpPrefix("239.0.0.0/8"),
      MakeIpPrefix("255.255.255.255/32"),
      MakeIpPrefix("fe80::/10"),        MakeIpPrefix("fc00::/7"),
      MakeIpPrefix("ff01::/16"),        MakeIpPrefix("ff02::/16"),
      MakeIpPrefix("ff03::/16"),        MakeIpPrefix("ff04::/16"),
      MakeIpPrefix("ff05::/16")};
  return prefixes;
}

inline bool IsAllowedSplitTunnelPrefix(const IpPrefix& prefix) {
  if (prefix.length == 0 || !IsCanonicalIpPrefix(prefix)) return false;
  for (const auto& forbidden : ForbiddenSplitTunnelPrefixes())
    if (IpPrefixesOverlap(prefix, forbidden)) return false;
  return true;
}

// Drops duplicates and prefixes already covered by a wider entry, keeping a
// stable, deterministic order so equal settings compare equal.
inline std::vector<IpPrefix> NormalizeIpPrefixes(std::vector<IpPrefix> prefixes) {
  std::sort(prefixes.begin(), prefixes.end(), [](const IpPrefix& left, const IpPrefix& right) {
    if (left.ipv6 != right.ipv6) return !left.ipv6;
    if (left.bytes != right.bytes) return left.bytes < right.bytes;
    return left.length < right.length;
  });
  std::vector<IpPrefix> result;
  for (const auto& prefix : prefixes) {
    const bool covered = std::any_of(result.begin(), result.end(), [&](const IpPrefix& kept) {
      return IpPrefixContains(kept, prefix);
    });
    if (!covered) result.push_back(prefix);
  }
  return result;
}

// Returns `from` minus every range of `remove`, as a minimal set of
// prefixes. Families never mix.
inline std::vector<IpPrefix> SubtractIpPrefixes(std::vector<IpPrefix> from,
                                                const std::vector<IpPrefix>& remove) {
  for (const auto& removed : remove) {
    std::vector<IpPrefix> next;
    next.reserve(from.size());
    for (const auto& prefix : from) {
      if (!IpPrefixesOverlap(prefix, removed)) {
        next.push_back(prefix);
        continue;
      }
      if (IpPrefixContains(removed, prefix)) continue;
      // `prefix` strictly contains `removed`: keep each sibling along the path.
      IpPrefix cursor = prefix;
      while (cursor.length < removed.length) {
        const unsigned depth = cursor.length;
        const bool bit = IpPrefixBit(removed, depth);
        IpPrefix sibling = cursor;
        sibling.length = static_cast<std::uint8_t>(depth + 1);
        SetIpPrefixBit(&sibling, depth, !bit);
        next.push_back(sibling);
        cursor.length = static_cast<std::uint8_t>(depth + 1);
        SetIpPrefixBit(&cursor, depth, bit);
      }
    }
    from = std::move(next);
  }
  return from;
}

struct SplitTunnelPolicy {
  SplitTunnelMode mode = SplitTunnelMode::off;
  std::vector<IpPrefix> prefixes;
  bool allow_lan = false;

  bool active() const {
    if (mode == SplitTunnelMode::exclude) return !prefixes.empty() || allow_lan;
    if (mode == SplitTunnelMode::include) return !prefixes.empty();
    return false;
  }
};

inline bool SameSplitTunnelPolicy(const SplitTunnelPolicy& left,
                                  const SplitTunnelPolicy& right) {
  if (left.mode != right.mode || left.allow_lan != right.allow_lan ||
      left.prefixes.size() != right.prefixes.size()) return false;
  for (std::size_t index = 0; index < left.prefixes.size(); ++index)
    if (!SameIpPrefix(left.prefixes[index], right.prefixes[index])) return false;
  return true;
}

// Validates the UI's request at the privileged boundary. An inert request
// (no range, or local network outside exclusion mode) normalizes to off.
inline bool DecodeSplitTunnelPolicy(std::string_view mode,
                                    const std::vector<std::string>& ranges,
                                    bool allow_lan, SplitTunnelPolicy* policy) {
  if (!policy || ranges.size() > kMaxSplitTunnelPrefixes) return false;
  SplitTunnelPolicy result;
  if (mode.empty() || mode == "off") result.mode = SplitTunnelMode::off;
  else if (mode == "exclude") result.mode = SplitTunnelMode::exclude;
  else if (mode == "include") result.mode = SplitTunnelMode::include;
  else return false;
  std::vector<IpPrefix> prefixes;
  for (const auto& text : ranges) {
    IpPrefix prefix;
    if (!ParseIpPrefix(text, &prefix) || !IsAllowedSplitTunnelPrefix(prefix)) return false;
    prefixes.push_back(prefix);
  }
  if (result.mode != SplitTunnelMode::off) result.prefixes = NormalizeIpPrefixes(std::move(prefixes));
  result.allow_lan = result.mode == SplitTunnelMode::exclude && allow_lan;
  if (!result.active()) result = SplitTunnelPolicy{};
  *policy = std::move(result);
  return true;
}

// Host prefixes (/32 or /128) for literal addresses; anything else is skipped.
inline std::vector<IpPrefix> SplitTunnelHostPrefixes(const std::vector<std::string>& addresses) {
  std::vector<IpPrefix> result;
  for (const auto& address : addresses) {
    if (address.find('/') != std::string::npos) continue;
    IpPrefix prefix;
    if (ParseIpPrefix(address, &prefix)) result.push_back(prefix);
  }
  return result;
}

// Tunnel routes for an active policy, starting from the engine's full-tunnel
// routes (never a /0: that would arm wireguard-windows' own block-all, which
// a lower-priority provider cannot exempt). VPN DNS servers always stay in
// the tunnel; the VPN endpoint never enters it.
inline std::vector<std::string> SplitTunnelRoutes(const std::vector<std::string>& full_tunnel,
                                                  const SplitTunnelPolicy& policy,
                                                  const std::vector<IpPrefix>& vpn_dns,
                                                  const std::vector<IpPrefix>& endpoint) {
  std::vector<IpPrefix> base;
  bool ipv4 = false, ipv6 = false;
  for (const auto& text : full_tunnel) {
    IpPrefix prefix;
    if (!ParseIpPrefix(text, &prefix)) continue;
    (prefix.ipv6 ? ipv6 : ipv4) = true;
    base.push_back(prefix);
  }
  const auto family = [&](const IpPrefix& prefix) { return prefix.ipv6 ? ipv6 : ipv4; };
  std::vector<IpPrefix> routes;
  if (policy.mode == SplitTunnelMode::include) {
    for (const auto& prefix : policy.prefixes)
      if (family(prefix)) routes.push_back(prefix);
    routes = SubtractIpPrefixes(std::move(routes), endpoint);
  } else {
    routes = SubtractIpPrefixes(std::move(base),
                                SubtractIpPrefixes(policy.prefixes, vpn_dns));
  }
  for (const auto& dns : vpn_dns) {
    if (!family(dns)) continue;
    const bool present = std::any_of(routes.begin(), routes.end(), [&](const IpPrefix& route) {
      return SameIpPrefix(route, dns);
    });
    if (!present) routes.push_back(dns);
  }
  std::vector<std::string> result;
  result.reserve(routes.size());
  for (const auto& route : routes) result.push_back(FormatIpPrefix(route));
  return result;
}

// Profile directives for OpenVPN 3. `routes` receives the tunnel routes the
// activation contract must later find on the adapter.
inline std::string OpenVpnSplitTunnelDirectives(const SplitTunnelPolicy& policy,
                                                const std::vector<IpPrefix>& vpn_dns,
                                                const std::vector<IpPrefix>& endpoint,
                                                bool ipv6_enabled,
                                                std::vector<std::string>* routes) {
  std::string profile;
  const auto add = [&](const IpPrefix& prefix, bool bypass) {
    if (prefix.ipv6) {
      if (!ipv6_enabled) return;
      profile += "route-ipv6 " + FormatIpPrefix(prefix);
    } else {
      profile += "route " + FormatIpAddress(prefix) + ' ' + FormatIpv4Netmask(prefix.length);
    }
    profile += bypass ? " net_gateway\n" : "\n";
    if (!bypass && routes) routes->push_back(FormatIpPrefix(prefix));
  };
  if (policy.mode == SplitTunnelMode::include) {
    profile += "pull-filter ignore \"redirect-gateway\"\n";
    for (const auto& prefix : SubtractIpPrefixes(policy.prefixes, endpoint)) add(prefix, false);
  } else if (policy.mode == SplitTunnelMode::exclude) {
    for (const auto& prefix : SubtractIpPrefixes(policy.prefixes, vpn_dns)) add(prefix, true);
  }
  if (policy.active())
    for (const auto& dns : vpn_dns) add(dns, false);
  return profile;
}

}  // namespace fuzevpn

#endif  // RUNNER_SPLIT_TUNNEL_POLICY_H_
