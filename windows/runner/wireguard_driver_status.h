// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_DRIVER_STATUS_H_
#define RUNNER_WIREGUARD_DRIVER_STATUS_H_

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstddef>

namespace fuzevpn::wireguard_abi {
// Layout of the published WireGuardNT 1.x configuration ABI. Only the first
// (and sole configured) peer is read. No setters or private keys are exposed.
// https://git.zx2c4.com/wireguard-nt/plain/api/wireguard.h
struct alignas(8) Interface {
  DWORD flags;
  WORD listen_port;
  BYTE private_key[32];
  BYTE public_key[32];
  WORD padding_before_count;
  DWORD peers_count;
  DWORD padding_at_end;
};
struct alignas(8) Peer {
  DWORD flags;
  DWORD reserved;
  BYTE public_key[32];
  BYTE preshared_key[32];
  WORD persistent_keepalive;
  SOCKADDR_INET endpoint;
  DWORD64 tx_bytes;
  DWORD64 rx_bytes;
  DWORD64 last_handshake;
  DWORD allowed_ips_count;
  DWORD padding_at_end;
};
static_assert(sizeof(Interface) == 80);
static_assert(sizeof(Peer) == 136);
static_assert(offsetof(Peer, tx_bytes) == 104);
static_assert(offsetof(Peer, last_handshake) == 120);
}  // namespace fuzevpn::wireguard_abi
#endif
