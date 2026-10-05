// SPDX-License-Identifier: MPL-2.0
#include "api_bootstrap_resolver.h"
#include "api_bootstrap_dns.h"
#include "direct_dns_lookup.h"
#include "network_protection.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace {
class Socket {
 public:
  explicit Socket(SOCKET value) : value_(value) {}
  ~Socket() { if (value_ != INVALID_SOCKET) closesocket(value_); }
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  SOCKET get() const { return value_; }
 private:
  SOCKET value_;
};

struct Server {
  SOCKADDR_STORAGE address{};
  int length = 0;
  NET_IFINDEX interface_index = 0;
};

bool IsAutomaticIpv6DnsPlaceholder(const IN6_ADDR& address) {
  // Windows reports these obsolete defaults on virtual adapters which have
  // no configured IPv6 DNS. They must not consume the bounded server list
  // before a real adapter's configured DNS is examined.
  constexpr std::array<std::uint8_t, 16> prefix{
      0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0};
  return std::equal(prefix.begin(), prefix.end() - 1, address.u.Byte) &&
      address.u.Byte[15] >= 1 && address.u.Byte[15] <= 3;
}

std::vector<Server> Servers() {
  ULONG size = 15 * 1024;
  std::vector<BYTE> buffer;
  ULONG status = ERROR_BUFFER_OVERFLOW;
  for (unsigned attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
    if (size > 1024 * 1024) return {};
    buffer.resize(size);
    status = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (status != NO_ERROR) return {};
  std::vector<Server> servers;
  const auto preferred_luid = NetworkProtectionBootstrapTunnelLuid();
  // WireGuard /0 also installs its own service-SID firewall. The main runtime
  // must use tunnel DNS while that firewall exists, even with the same EXE.
  for (bool preferred : {true, false}) {
  for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
       adapter && servers.size() < 8; adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp ||
        adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    if ((preferred_luid != 0 && adapter->Luid.Value == preferred_luid) != preferred)
      continue;
    for (auto* dns = adapter->FirstDnsServerAddress; dns && servers.size() < 8;
         dns = dns->Next) {
      const auto* source = dns->Address.lpSockaddr;
      if (!source) continue;
      Server server;
      if (source->sa_family == AF_INET &&
          dns->Address.iSockaddrLength >= static_cast<int>(sizeof(SOCKADDR_IN))) {
        auto* ipv4 = reinterpret_cast<SOCKADDR_IN*>(&server.address);
        *ipv4 = *reinterpret_cast<const SOCKADDR_IN*>(source);
        const auto address = ntohl(ipv4->sin_addr.s_addr);
        if (!address || address == 0xffffffffU || (address & 0xf0000000U) == 0xe0000000U)
          continue;
        ipv4->sin_port = htons(53);
        server.length = sizeof(*ipv4);
        server.interface_index = adapter->IfIndex;
      } else if (source->sa_family == AF_INET6 &&
                 dns->Address.iSockaddrLength >= static_cast<int>(sizeof(SOCKADDR_IN6))) {
        auto* ipv6 = reinterpret_cast<SOCKADDR_IN6*>(&server.address);
        *ipv6 = *reinterpret_cast<const SOCKADDR_IN6*>(source);
        if (IN6_IS_ADDR_UNSPECIFIED(&ipv6->sin6_addr) || IN6_IS_ADDR_MULTICAST(&ipv6->sin6_addr) ||
            IsAutomaticIpv6DnsPlaceholder(ipv6->sin6_addr))
          continue;
        ipv6->sin6_port = htons(53);
        if (IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr) && !ipv6->sin6_scope_id)
          ipv6->sin6_scope_id = adapter->Ipv6IfIndex;
        server.length = sizeof(*ipv6);
        server.interface_index = adapter->Ipv6IfIndex;
      } else continue;
      bool duplicate = false;
      for (const auto& previous : servers) {
        if (previous.length == server.length &&
            previous.interface_index == server.interface_index &&
            std::memcmp(&previous.address, &server.address, server.length) == 0)
          duplicate = true;
      }
      if (!duplicate) servers.push_back(server);
    }
  }
  }
  return servers;
}

bool Ready(SOCKET socket, bool write, ULONGLONG deadline) {
  const auto now = GetTickCount64();
  if (now >= deadline) return false;
  const auto remaining = deadline - now;
  timeval timeout{static_cast<long>(remaining / 1000),
                  static_cast<long>((remaining % 1000) * 1000)};
  fd_set handles;
  FD_ZERO(&handles);
  FD_SET(socket, &handles);
  return select(0, write ? nullptr : &handles, write ? &handles : nullptr,
                nullptr, &timeout) > 0;
}

bool Connect(SOCKET socket, const Server& server, ULONGLONG deadline) {
  if (!server.interface_index) return false;
  const DWORD index = server.address.ss_family == AF_INET
      ? htonl(server.interface_index) : server.interface_index;
  if (setsockopt(socket, server.address.ss_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
                 server.address.ss_family == AF_INET ? IP_UNICAST_IF : IPV6_UNICAST_IF,
                 reinterpret_cast<const char*>(&index), sizeof(index)) != 0) return false;
  u_long nonblocking = 1;
  if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0) return false;
  if (connect(socket, reinterpret_cast<const SOCKADDR*>(&server.address), server.length) == 0)
    return true;
  if (WSAGetLastError() != WSAEWOULDBLOCK || !Ready(socket, true, deadline)) return false;
  int error = 0;
  int size = sizeof(error);
  return getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) == 0 &&
         error == 0;
}

bool Transfer(SOCKET socket, std::uint8_t* bytes, std::size_t count,
              bool write, ULONGLONG deadline) {
  std::size_t transferred = 0;
  while (transferred < count) {
    if (!Ready(socket, write, deadline)) return false;
    const auto remaining = static_cast<int>(count - transferred);
    const int result = write
        ? send(socket, reinterpret_cast<const char*>(bytes + transferred), remaining, 0)
        : recv(socket, reinterpret_cast<char*>(bytes + transferred), remaining, 0);
    if (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
    if (result <= 0) return false;
    transferred += static_cast<std::size_t>(result);
  }
  return true;
}

bool Exchange(const Server& server, std::vector<std::uint8_t> query,
              bool tcp, ULONGLONG deadline, std::vector<std::uint8_t>* response) {
  Socket socket(WSASocketW(server.address.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM,
      tcp ? IPPROTO_TCP : IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
  if (socket.get() == INVALID_SOCKET || !Connect(socket.get(), server, deadline)) return false;
  if (tcp) {
    std::vector<std::uint8_t> frame;
    fuzevpn::bootstrap::Put16(&frame, static_cast<std::uint16_t>(query.size()));
    frame.insert(frame.end(), query.begin(), query.end());
    if (!Transfer(socket.get(), frame.data(), frame.size(), true, deadline)) return false;
    std::uint8_t prefix[2]{};
    if (!Transfer(socket.get(), prefix, sizeof(prefix), false, deadline)) return false;
    const auto length = static_cast<std::size_t>((prefix[0] << 8) | prefix[1]);
    if (length < 12 || length > fuzevpn::bootstrap::kMaximumResponse) return false;
    response->resize(length);
    return Transfer(socket.get(), response->data(), response->size(), false, deadline);
  }
  if (!Ready(socket.get(), true, deadline) ||
      send(socket.get(), reinterpret_cast<const char*>(query.data()),
           static_cast<int>(query.size()), 0) != static_cast<int>(query.size()) ||
      !Ready(socket.get(), false, deadline)) return false;
  response->resize(fuzevpn::bootstrap::kMaximumResponse);
  const int size = recv(socket.get(), reinterpret_cast<char*>(response->data()),
                        static_cast<int>(response->size()), 0);
  if (size <= 0) return false;
  response->resize(static_cast<std::size_t>(size));
  return true;
}
bool ResolveDirectAddresses(const std::string& host, bool public_only,
                            std::uint64_t connection_deadline,
                            std::vector<std::string>* addresses) {
  if (!addresses) return false;
  addresses->clear();
  std::string canonical_host;
  if (!fuzevpn::bootstrap::CanonicalHost(host, &canonical_host)) return false;
  const std::uint64_t started = GetTickCount64();
  const auto deadline = connection_deadline
      ? std::min(started + 6000, connection_deadline) : started + 6000;
  if (started >= deadline) return false;
  WSADATA winsock{};
  if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return false;
  struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
  HCRYPTPROV provider = 0;
  if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    return false;
  struct CryptoCleanup {
    HCRYPTPROV provider;
    ~CryptoCleanup() { CryptReleaseContext(provider, 0); }
  } crypto_cleanup{provider};
  std::vector<fuzevpn::bootstrap::Address> resolved;
  for (const auto& server : Servers()) {
    if (!fuzevpn::bootstrap::LookupServer(canonical_host, public_only, deadline,
        []() -> std::uint64_t { return GetTickCount64(); },
        [provider](std::uint16_t* id) {
          return CryptGenRandom(provider, sizeof(*id), reinterpret_cast<BYTE*>(id)) != FALSE;
        },
        [&server](const std::vector<std::uint8_t>& query, bool tcp,
                  std::uint64_t attempt_deadline, std::vector<std::uint8_t>* response) {
          return Exchange(server, query, tcp, attempt_deadline, response);
        }, &resolved)) return false;
    if (!resolved.empty() || GetTickCount64() >= deadline) break;
  }
  for (const auto& address : resolved) {
    char text[INET6_ADDRSTRLEN]{};
    if (InetNtopA(address.ipv6 ? AF_INET6 : AF_INET, address.bytes.data(), text,
                  static_cast<DWORD>(sizeof(text)))) addresses->emplace_back(text);
  }
  return !addresses->empty();
}
}  // namespace

bool ResolveApiBootstrapAddresses(std::vector<std::string>* addresses) {
  return ResolveDirectAddresses(fuzevpn::bootstrap::kHost, true, 0, addresses);
}

bool ResolveWireGuardEndpointAddresses(const std::string& host,
                                      std::uint64_t connection_deadline,
                                      std::vector<std::string>* addresses) {
  return ResolveDirectAddresses(host, false, connection_deadline, addresses);
}
