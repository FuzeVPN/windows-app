// SPDX-License-Identifier: MPL-2.0
#include "diagnostics_network.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>

namespace fuzevpn_diagnostics {
namespace {
NumericAddress FromSocket(const SOCKADDR_INET& address, unsigned prefix = 0) {
  NumericAddress result; result.family = address.si_family; result.prefix = prefix;
  if (result.family == AF_INET) std::memcpy(result.bytes.data(), &address.Ipv4.sin_addr, 4);
  else if (result.family == AF_INET6) std::memcpy(result.bytes.data(), &address.Ipv6.sin6_addr, 16);
  return result;
}
bool SameAdapter(const NetworkExpectation& expected, NET_LUID luid, ULONG index) {
  return expected.luid != 0 && expected.index != 0 &&
      expected.luid == luid.Value && expected.index == index;
}
std::optional<std::vector<NumericAddress>> ReadNrpt(const std::string& rule) {
  // Names are captured from our NRPT writer, never accepted from Flutter.
  if (!rule.starts_with("FuzeVPNDNSRoutingV1-") || rule.size() > 128 ||
      rule.find_first_not_of("FuzeVPNDNSRoutingV1-0123456789X") != std::string::npos) return std::nullopt;
  constexpr wchar_t policy[] = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";
  constexpr wchar_t local[] = L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";
  HKEY parent = nullptr;
  auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, policy, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &parent);
  if (status == ERROR_FILE_NOT_FOUND)
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, local, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &parent);
  if (status == ERROR_FILE_NOT_FOUND) return std::vector<NumericAddress>{};
  if (status != ERROR_SUCCESS) return std::nullopt;
  std::wstring name(rule.begin(), rule.end());
  wchar_t buffer[2048]{}; DWORD bytes = sizeof(buffer);
  status = RegGetValueW(parent, name.c_str(), L"GenericDNSServers", RRF_RT_REG_SZ,
                        nullptr, buffer, &bytes);
  RegCloseKey(parent);
  if (status == ERROR_FILE_NOT_FOUND) return std::vector<NumericAddress>{};
  if (status != ERROR_SUCCESS || bytes < sizeof(wchar_t) || bytes > sizeof(buffer)) return std::nullopt;
  std::string text;
  for (const wchar_t c : buffer) { if (!c) break; if (c > 127) return std::nullopt; text.push_back(static_cast<char>(c)); }
  std::vector<NumericAddress> result;
  for (std::size_t start = 0; start < text.size();) {
    const auto end = text.find(';', start);
    const auto parsed = ParseNumericAddress(text.substr(start, end == text.npos ? text.npos : end - start));
    if (!parsed || result.size() >= 16) return std::nullopt;
    result.push_back(*parsed);
    if (end == text.npos) break;
    start = end + 1;
  }
  return result;
}
}

std::optional<NumericAddress> ParseNumericAddress(const std::string& text, bool route) {
  if (text.empty() || text.size() > 128 || text.find('\0') != text.npos) return std::nullopt;
  const auto slash = text.find('/');
  const auto ip = text.substr(0, slash);
  NumericAddress value;
  if (InetPtonA(AF_INET, ip.c_str(), value.bytes.data()) == 1) value.family = AF_INET;
  else if (InetPtonA(AF_INET6, ip.c_str(), value.bytes.data()) == 1) value.family = AF_INET6;
  else return std::nullopt;
  if (route) {
    if (slash == text.npos || slash + 1 == text.size()) return std::nullopt;
    for (std::size_t i = slash + 1; i < text.size(); ++i) {
      if (text[i] < '0' || text[i] > '9' || value.prefix > 128) return std::nullopt;
      value.prefix = value.prefix * 10 + (text[i] - '0');
    }
    if (value.prefix > (value.family == AF_INET ? 32u : 128u)) return std::nullopt;
  }
  return value;
}

CheckResult EvaluateAddresses(const NetworkExpectation& expected, ADDRESS_FAMILY family,
    std::span<const MIB_UNICASTIPADDRESS_ROW> rows, unsigned* configured_count) {
  *configured_count = 0;
  std::vector<NumericAddress> wanted;
  for (const auto& text : expected.addresses) {
    const auto value = ParseNumericAddress(text);
    if (!value) return CheckResult::unknown;
    if (value->family == family && std::find(wanted.begin(), wanted.end(), *value) == wanted.end()) wanted.push_back(*value);
  }
  if (wanted.empty()) return CheckResult::skipped;
  for (const auto& address : wanted) {
    bool configured = false, conflicting = false;
    for (const auto& row : rows) {
      if (!SameAdapter(expected, row.InterfaceLuid, row.InterfaceIndex) || FromSocket(row.Address) != address) continue;
      if (row.DadState == IpDadStateTentative || row.DadState == IpDadStatePreferred) configured = true;
      else conflicting = true;
    }
    if (configured && !conflicting) ++*configured_count;
  }
  return *configured_count == wanted.size() ? CheckResult::passed : CheckResult::failed;
}
CheckResult EvaluateRoutes(const NetworkExpectation& expected, std::span<const MIB_IPFORWARD_ROW2> rows) {
  if (expected.routes.empty()) return CheckResult::skipped;
  for (const auto& text : expected.routes) {
    const auto wanted = ParseNumericAddress(text, true);
    if (!wanted) return CheckResult::unknown;
    bool found = false;
    for (const auto& row : rows) {
      if (SameAdapter(expected, row.InterfaceLuid, row.InterfaceIndex) &&
          FromSocket(row.DestinationPrefix.Prefix, row.DestinationPrefix.PrefixLength) == *wanted) { found = true; break; }
    }
    if (!found) return CheckResult::failed;
  }
  return CheckResult::passed;
}
CheckResult EvaluateDns(const std::vector<std::string>& expected, const std::vector<NumericAddress>& actual) {
  if (expected.empty()) return CheckResult::skipped;
  for (const auto& text : expected) {
    const auto wanted = ParseNumericAddress(text);
    if (!wanted) return CheckResult::unknown;
    if (std::find(actual.begin(), actual.end(), *wanted) == actual.end()) return CheckResult::failed;
  }
  return CheckResult::passed;
}

NetworkObservation ReadNetworkObservation(const NetworkExpectation& expected) {
  NetworkObservation out;
  if (!expected.luid || !expected.index) return out;
  out.adapter = out.ipv4 = out.ipv6 = out.routing = out.dns = CheckResult::unknown;
  MIB_IF_ROW2 iface{}; iface.InterfaceLuid.Value = expected.luid;
  const auto interface_status = GetIfEntry2(&iface);
  if (interface_status == NO_ERROR)
    out.adapter = iface.InterfaceIndex == expected.index && iface.OperStatus == IfOperStatusUp ? CheckResult::passed : CheckResult::failed;
  else if (interface_status == ERROR_NOT_FOUND) out.adapter = CheckResult::failed;
  MIB_UNICASTIPADDRESS_TABLE* unicast = nullptr;
  if (GetUnicastIpAddressTable(AF_UNSPEC, &unicast) == NO_ERROR) {
    const std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&FreeMibTable)> table(unicast, &FreeMibTable);
    if (unicast->NumEntries <= 65536) {
      unsigned count4 = 0, count6 = 0;
      const auto rows = std::span<const MIB_UNICASTIPADDRESS_ROW>(unicast->Table, unicast->NumEntries);
      out.ipv4 = EvaluateAddresses(expected, AF_INET, rows, &count4);
      out.ipv6 = EvaluateAddresses(expected, AF_INET6, rows, &count6);
      if (out.ipv4 != CheckResult::unknown) out.ipv4_count = count4;
      if (out.ipv6 != CheckResult::unknown) out.ipv6_count = count6;
    }
  }
  MIB_IPFORWARD_TABLE2* routes = nullptr;
  if (GetIpForwardTable2(AF_UNSPEC, &routes) == NO_ERROR) {
    const std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> table(routes, &FreeMibTable);
    if (routes->NumEntries <= 65536) out.routing = EvaluateRoutes(expected,
        std::span<const MIB_IPFORWARD_ROW2>(routes->Table, routes->NumEntries));
  }
  ULONG size = 16384, status = ERROR_BUFFER_OVERFLOW;
  std::vector<BYTE> buffer;
  for (unsigned attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024; ++attempt) {
    buffer.resize(size);
    status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
      nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (status == NO_ERROR) {
    std::vector<NumericAddress> dns;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
      if (!SameAdapter(expected, adapter->Luid, adapter->IfIndex)) continue;
      for (auto* entry = adapter->FirstDnsServerAddress; entry; entry = entry->Next) {
        const auto* address = entry->Address.lpSockaddr;
        if (!address || dns.size() >= 256) break;
        SOCKADDR_INET value{};
        if (address->sa_family == AF_INET && entry->Address.iSockaddrLength >= sizeof(SOCKADDR_IN))
          std::memcpy(&value.Ipv4, address, sizeof(SOCKADDR_IN));
        else if (address->sa_family == AF_INET6 && entry->Address.iSockaddrLength >= sizeof(SOCKADDR_IN6))
          std::memcpy(&value.Ipv6, address, sizeof(SOCKADDR_IN6));
        else continue;
        dns.push_back(FromSocket(value));
      }
    }
    out.dns = EvaluateDns(expected.dns, dns);
    if (!expected.nrpt_rule.empty() && !expected.dns.empty()) {
      const auto nrpt = ReadNrpt(expected.nrpt_rule);
      if (!nrpt) out.dns = CheckResult::unknown;
      else if (EvaluateDns(expected.dns, *nrpt) != CheckResult::passed) out.dns = CheckResult::failed;
    }
  }
  return out;
}
}  // namespace fuzevpn_diagnostics
