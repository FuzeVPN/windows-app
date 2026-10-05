// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_API_BOOTSTRAP_DNS_H_
#define RUNNER_API_BOOTSTRAP_DNS_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace fuzevpn::bootstrap {
// This is intentionally not a general-purpose DNS/IPC proxy.
inline constexpr char kHost[] = "api.fuzevpn.com";
inline constexpr std::size_t kMaximumResponse = 8192;
inline constexpr std::size_t kMaximumAddresses = 8;

struct Address {
  bool ipv6 = false;
  std::array<std::uint8_t, 16> bytes{};
  bool operator==(const Address& other) const {
    return ipv6 == other.ipv6 && bytes == other.bytes;
  }
};

inline void Put16(std::vector<std::uint8_t>* out, std::uint16_t value) {
  out->push_back(static_cast<std::uint8_t>(value >> 8));
  out->push_back(static_cast<std::uint8_t>(value));
}

// A DNS name carried by an endpoint is canonicalized once, before any query.
// This is deliberately independent of user names/passwords, which stay UTF-8.
inline bool CanonicalHost(const std::string& input, std::string* output) {
  if (!output || input.empty() || input.size() > 254) return false;
  std::string host = input;
  if (host.back() == '.') host.pop_back();
  if (host.empty() || host.size() > 253) return false;
  for (auto& character : host) {
    if (character >= 'A' && character <= 'Z') character = static_cast<char>(character + ('a' - 'A'));
  }
  for (std::size_t start = 0; start < host.size();) {
    const auto dot = host.find('.', start);
    const auto end = dot == std::string::npos ? host.size() : dot;
    if (end == start || end - start > 63 || host[start] == '-' || host[end - 1] == '-')
      return false;
    for (auto index = start; index < end; ++index) {
      const auto c = host[index];
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    start = end + 1;
  }
  if (host.back() == '.') return false;
  *output = std::move(host);
  return true;
}

inline std::vector<std::uint8_t> QueryForHost(std::uint16_t id, bool ipv6,
                                            const std::string& requested_host) {
  std::string host;
  if (!CanonicalHost(requested_host, &host)) return {};
  std::vector<std::uint8_t> result;
  for (auto value : {id, std::uint16_t(0x0100), std::uint16_t(1),
                     std::uint16_t(0), std::uint16_t(0), std::uint16_t(0)})
    Put16(&result, value);
  for (std::size_t start = 0; start < host.size();) {
    const auto dot = host.find('.', start);
    const auto end = dot == std::string::npos ? host.size() : dot;
    result.push_back(static_cast<std::uint8_t>(end - start));
    result.insert(result.end(), host.begin() + start, host.begin() + end);
    start = end + 1;
  }
  result.push_back(0);
  Put16(&result, ipv6 ? 28 : 1);
  Put16(&result, 1);
  return result;
}

// The API wrapper and its IPC remain fixed to this single hostname.
inline std::vector<std::uint8_t> Query(std::uint16_t id, bool ipv6) {
  return QueryForHost(id, ipv6, kHost);
}

inline bool Read16(const std::vector<std::uint8_t>& data, std::size_t* offset,
                   std::uint16_t* value) {
  if (*offset > data.size() || data.size() - *offset < 2) return false;
  *value = static_cast<std::uint16_t>((data[*offset] << 8) | data[*offset + 1]);
  *offset += 2;
  return true;
}

inline bool ReadName(const std::vector<std::uint8_t>& data, std::size_t* offset,
                     std::string* name) {
  name->clear();
  std::size_t cursor = *offset;
  bool jumped = false;
  for (unsigned steps = 0; steps < 128; ++steps) {
    if (cursor >= data.size()) return false;
    const auto length = data[cursor++];
    if ((length & 0xc0) == 0xc0) {
      if (cursor >= data.size()) return false;
      const auto target = static_cast<std::size_t>(((length & 0x3f) << 8) | data[cursor++]);
      // DNS compression points backward; rejecting forward/self references
      // makes malformed and cyclic messages fail without recursion/allocation.
      if (target >= cursor - 2) return false;
      if (!jumped) *offset = cursor;
      jumped = true;
      cursor = target;
      continue;
    }
    if ((length & 0xc0) != 0 || length > 63) return false;
    if (length == 0) {
      if (!jumped) *offset = cursor;
      return !name->empty();
    }
    if (cursor > data.size() || length > data.size() - cursor) return false;
    if (!name->empty()) name->push_back('.');
    for (unsigned i = 0; i < length; ++i) {
      auto c = data[cursor++];
      if (c >= 'A' && c <= 'Z') c = static_cast<std::uint8_t>(c + ('a' - 'A'));
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
        return false;
      name->push_back(static_cast<char>(c));
    }
    if (name->size() > 253) return false;
  }
  return false;
}

inline bool PublicAddress(const Address& address) {
  const auto& b = address.bytes;
  if (address.ipv6) {
    // API bootstrap must never dial unspecified/loopback/link-local/ULA or a
    // multicast address returned by a hostile resolver. Accept global unicast.
    return (b[0] & 0xe0) == 0x20;
  }
  return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224 &&
         !(b[0] == 169 && b[1] == 254) &&
         !(b[0] == 172 && b[1] >= 16 && b[1] <= 31) &&
         !(b[0] == 192 && b[1] == 168) &&
         !(b[0] == 100 && b[1] >= 64 && b[1] <= 127);
}

enum class Response { invalid, truncated, valid };

inline bool EndpointAddress(const Address& address) {
  // VPN endpoints may legitimately use a private, ULA or loopback address.
  // Do not apply the public-Internet-only policy of the HTTPS API to them.
  if (address.ipv6) {
    return address.bytes[0] != 0xff &&
        std::any_of(address.bytes.begin(), address.bytes.end(), [](auto byte) { return byte != 0; });
  }
  return address.bytes[0] != 0 && address.bytes[0] < 224;
}

inline Response ParseForHost(const std::vector<std::uint8_t>& data, std::uint16_t id,
                      bool ipv6, const std::string& requested_host, bool public_only,
                      std::vector<Address>* addresses, std::string* alias = nullptr) {
  std::string host;
  if (alias) alias->clear();
  if (!CanonicalHost(requested_host, &host)) return Response::invalid;
  if (!addresses || data.size() < 12 || data.size() > kMaximumResponse)
    return Response::invalid;
  std::size_t offset = 0;
  std::uint16_t received_id = 0, flags = 0, questions = 0, answers = 0, ignored = 0;
  if (!Read16(data, &offset, &received_id) || !Read16(data, &offset, &flags) ||
      !Read16(data, &offset, &questions) || !Read16(data, &offset, &answers) ||
      !Read16(data, &offset, &ignored) || !Read16(data, &offset, &ignored) ||
      received_id != id || (flags & 0xf80f) != 0x8000 || questions != 1 || answers > 128)
    return Response::invalid;
  std::string question;
  std::uint16_t type = 0, record_class = 0;
  if (!ReadName(data, &offset, &question) || question != host ||
      !Read16(data, &offset, &type) || type != (ipv6 ? 28 : 1) ||
      !Read16(data, &offset, &record_class) || record_class != 1)
    return Response::invalid;
  if ((flags & 0x0200) != 0) return Response::truncated;

  struct Record { std::string owner, alias; Address address; bool has_address = false; };
  std::vector<Record> records;
  for (unsigned i = 0; i < answers; ++i) {
    Record record;
    std::uint16_t length = 0;
    if (!ReadName(data, &offset, &record.owner) ||
        !Read16(data, &offset, &type) || !Read16(data, &offset, &record_class) ||
        offset > data.size() || data.size() - offset < 4) return Response::invalid;
    offset += 4; // TTL is deliberately not used as a persistent client cache.
    if (!Read16(data, &offset, &length) || offset > data.size() ||
        length > data.size() - offset) return Response::invalid;
    const auto end = offset + length;
    if (record_class == 1 && type == 5) {
      if (!ReadName(data, &offset, &record.alias) || offset != end) return Response::invalid;
    } else if (record_class == 1 && type == (ipv6 ? 28 : 1) &&
               length == (ipv6 ? 16 : 4)) {
      record.address.ipv6 = ipv6;
      std::copy(data.begin() + offset, data.begin() + end, record.address.bytes.begin());
      record.has_address = public_only ? PublicAddress(record.address) : EndpointAddress(record.address);
    }
    offset = end;
    records.push_back(std::move(record));
  }
  std::vector<std::string> chain{host};
  for (unsigned hop = 0; hop < 8; ++hop) {
    bool expanded = false;
    for (const auto& record : records) {
      if (!record.alias.empty() &&
          std::find(chain.begin(), chain.end(), record.owner) != chain.end() &&
          std::find(chain.begin(), chain.end(), record.alias) == chain.end()) {
        if (chain.size() >= 9) return Response::invalid;
        chain.push_back(record.alias);
        expanded = true;
      }
    }
    if (!expanded) break;
  }
  std::vector<Address> candidates;
  for (const auto& record : records) {
    if (record.has_address && std::find(chain.begin(), chain.end(), record.owner) != chain.end() &&
        std::find(candidates.begin(), candidates.end(), record.address) == candidates.end()) {
      if (candidates.size() >= kMaximumAddresses) break;
      candidates.push_back(record.address);
    }
  }
  for (const auto& candidate : candidates) {
    if (addresses->size() >= kMaximumAddresses) break;
    if (std::find(addresses->begin(), addresses->end(), candidate) == addresses->end())
      addresses->push_back(candidate);
  }
  if (alias && candidates.empty() && chain.size() > 1) {
    std::string canonical;
    if (!CanonicalHost(chain.back(), &canonical)) return Response::invalid;
    *alias = std::move(canonical);
  }
  return Response::valid;
}

inline Response Parse(const std::vector<std::uint8_t>& data, std::uint16_t id,
                      bool ipv6, std::vector<Address>* addresses) {
  return ParseForHost(data, id, ipv6, kHost, true, addresses);
}
}  // namespace fuzevpn::bootstrap
#endif
