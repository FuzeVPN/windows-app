// SPDX-License-Identifier: MPL-2.0
// Known-answer and policy checks for the in-process WireGuard key generator.
// Only OpenSSL and the OS CSPRNG are used: no key store, tunnel.dll, driver,
// service or network state is touched.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "wireguard_keypair.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <set>
#include <string_view>

namespace {
int failures = 0;
void Check(bool condition, const char* message) {
  if (!condition) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}

fuzevpn::WireGuardKey Hex(std::string_view text) {
  fuzevpn::WireGuardKey key{};
  const auto nibble = [](char value) {
    return value <= '9' ? value - '0' : value - 'a' + 10;
  };
  for (size_t index = 0; index < key.size() && index * 2 + 1 < text.size(); ++index)
    key[index] = static_cast<unsigned char>(nibble(text[index * 2]) * 16 + nibble(text[index * 2 + 1]));
  return key;
}

bool Clamped(const fuzevpn::WireGuardKey& key) {
  return (key[0] & 7) == 0 && (key[31] & 0x80) == 0 && (key[31] & 0x40) != 0;
}

void KnownAnswers() {
  // RFC 7748 section 6.1. X25519 clamps internally, so the unclamped RFC
  // scalars and their WireGuard-clamped form must give the same public key.
  const auto alice_private = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const auto alice_public = Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  const auto bob_private = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  const auto bob_public = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  fuzevpn::WireGuardKey derived{};
  Check(fuzevpn::DeriveWireGuardPublicKey(alice_private, &derived) && derived == alice_public,
        "RFC 7748 Alice public key");
  Check(fuzevpn::DeriveWireGuardPublicKey(bob_private, &derived) && derived == bob_public,
        "RFC 7748 Bob public key");
  auto clamped = alice_private;
  fuzevpn::ClampWireGuardPrivateKey(&clamped);
  Check(clamped[0] == 0x70 && clamped[31] == 0x6a &&
        std::memcmp(clamped.data() + 1, alice_private.data() + 1, 30) == 0,
        "clamping changes only the WireGuard scalar bits");
  Check(fuzevpn::DeriveWireGuardPublicKey(clamped, &derived) && derived == alice_public,
        "a clamped scalar derives the same X25519 public key");
  Check(!fuzevpn::DeriveWireGuardPublicKey(alice_private, nullptr), "missing output rejected");
}

void FailedDerivationLeavesNoError() {
  // Production derives on the long-lived broker request thread. A rejected
  // key must leave no partial public key and no OpenSSL error (seeded here,
  // as a failing EVP call may leave one) for a later caller on that thread.
  const auto alice_private = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  fuzevpn::WireGuardKey derived{};
  derived.fill(0x33);
  ERR_clear_error();
  ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
  Check(ERR_peek_error() != 0, "OpenSSL error queue fixture");
  Check(!fuzevpn::keypair_detail::DeriveX25519PublicKey(alice_private.data(),
                                                        alice_private.size() - 1, &derived) &&
        derived == fuzevpn::WireGuardKey{} && ERR_peek_error() == 0,
        "a rejected X25519 key leaves no partial key and no queued OpenSSL error");
  ERR_clear_error();
}

void ClampingBits() {
  fuzevpn::WireGuardKey ones{};
  ones.fill(0xff);
  fuzevpn::ClampWireGuardPrivateKey(&ones);
  Check(ones[0] == 0xf8 && ones[31] == 0x7f && ones[15] == 0xff, "high scalar clamped");
  fuzevpn::WireGuardKey zeros{};
  fuzevpn::ClampWireGuardPrivateKey(&zeros);
  Check(zeros[0] == 0 && zeros[31] == 0x40 && zeros[15] == 0, "low scalar clamped");
}

void GeneratorPolicy() {
  // Same sequence as WireGuardGenerateKeypair: CSPRNG bytes, clamp, X25519.
  const auto rfc_private = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  fuzevpn::WireGuardKey public_key{};
  fuzevpn::WireGuardKey private_key{};
  ULONG requested = 0;
  Check(fuzevpn::GenerateWireGuardKeypairWith([&](unsigned char* bytes, ULONG size) {
          requested = size;
          std::memcpy(bytes, rfc_private.data(), rfc_private.size());
          return true;
        }, &public_key, &private_key) && requested == 32 && Clamped(private_key) &&
        public_key == Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
        "deterministic generation matches the WireGuard algorithm");
  public_key.fill(0x11);
  private_key.fill(0x22);
  const fuzevpn::WireGuardKey empty{};
  Check(!fuzevpn::GenerateWireGuardKeypairWith([](unsigned char* bytes, ULONG size) {
          std::memset(bytes, 0x5a, size);
          return false;
        }, &public_key, &private_key) && public_key == empty && private_key == empty,
        "CSPRNG failure reports no key and leaves no partial secret");
  Check(!fuzevpn::GenerateWireGuardKeypair(nullptr, &private_key) &&
        !fuzevpn::GenerateWireGuardKeypair(&public_key, nullptr), "missing outputs rejected");

  std::set<fuzevpn::WireGuardKey> seen;
  for (int round = 0; round < 16; ++round) {
    fuzevpn::WireGuardKey derived{};
    const bool generated = fuzevpn::GenerateWireGuardKeypair(&public_key, &private_key);
    Check(generated && Clamped(private_key) && private_key != empty &&
          fuzevpn::DeriveWireGuardPublicKey(private_key, &derived) && derived == public_key,
          "system CSPRNG pair is clamped and self-consistent");
    seen.insert(private_key);
  }
  Check(seen.size() == 16, "system CSPRNG scalars are distinct");
  SecureZeroMemory(private_key.data(), private_key.size());
}
}  // namespace

int main() {
  KnownAnswers();
  FailedDerivationLeavesNoError();
  ClampingBits();
  GeneratorPolicy();
  std::cout << (failures == 0 ? "PASS" : "FAIL")
            << ": WireGuard X25519 key generation without tunnel.dll\n";
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
