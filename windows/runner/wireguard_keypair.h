// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_WIREGUARD_KEYPAIR_H_
#define RUNNER_WIREGUARD_KEYPAIR_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>

namespace fuzevpn {
using WireGuardKey = std::array<unsigned char, 32>;

// Curve25519 scalar clamping exactly as WireGuardGenerateKeypair applies it.
inline void ClampWireGuardPrivateKey(WireGuardKey* key) {
  (*key)[0] = static_cast<unsigned char>((*key)[0] & 248);
  (*key)[31] = static_cast<unsigned char>(((*key)[31] & 127) | 64);
}

namespace keypair_detail {
// A failure leaves nothing on this thread's OpenSSL error queue: callers run
// on the long-lived broker request thread, whose later OpenSSL users must not
// inherit a stale error.
inline bool DeriveX25519PublicKey(const unsigned char* private_key, size_t private_size,
                                  WireGuardKey* public_key) {
  if (public_key == nullptr) return false;
  EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                               private_key, private_size);
  size_t length = public_key->size();
  const bool derived = key != nullptr &&
                       EVP_PKEY_get_raw_public_key(key, public_key->data(), &length) == 1 &&
                       length == public_key->size();
  EVP_PKEY_free(key);
  if (!derived) {
    SecureZeroMemory(public_key->data(), public_key->size());
    ERR_clear_error();
  }
  return derived;
}
}  // namespace keypair_detail

// X25519(private, basepoint). OpenSSL clamps internally, as RFC 7748 does, so
// an already clamped WireGuard scalar yields the same public key.
inline bool DeriveWireGuardPublicKey(const WireGuardKey& private_key,
                                     WireGuardKey* public_key) {
  return keypair_detail::DeriveX25519PublicKey(private_key.data(), private_key.size(),
                                               public_key);
}

template <typename Random>
bool GenerateWireGuardKeypairWith(Random random, WireGuardKey* public_key,
                                  WireGuardKey* private_key) {
  if (public_key == nullptr || private_key == nullptr) return false;
  if (random(private_key->data(), static_cast<ULONG>(private_key->size()))) {
    ClampWireGuardPrivateKey(private_key);
    if (DeriveWireGuardPublicKey(*private_key, public_key)) return true;
  }
  SecureZeroMemory(private_key->data(), private_key->size());
  SecureZeroMemory(public_key->data(), public_key->size());
  return false;
}

// Byte-identical to tunnel.dll's WireGuardGenerateKeypair (wireguard-windows
// embeddable-dll-service): 32 CSPRNG bytes, clamping, X25519 base point. That
// export lives in a Go c-shared runtime which can never be unloaded, so the
// GUI, service and portable engine generate identities here instead.
inline bool GenerateWireGuardKeypair(WireGuardKey* public_key, WireGuardKey* private_key) {
  return GenerateWireGuardKeypairWith(
      [](unsigned char* bytes, ULONG size) {
        return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, bytes, size,
                                              BCRYPT_USE_SYSTEM_PREFERRED_RNG));
      },
      public_key, private_key);
}
}  // namespace fuzevpn
#endif  // RUNNER_WIREGUARD_KEYPAIR_H_
