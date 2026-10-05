// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_OPENVPN_IDENTITY_RECORD_H_
#define RUNNER_OPENVPN_IDENTITY_RECORD_H_

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace fuzevpn {
inline void EraseSecret(std::string& value) {
  volatile char* bytes = value.empty() ? nullptr : value.data();
  for (size_t i = 0; i < value.size(); ++i) bytes[i] = 0;
  value.clear();
}

// One DPAPI write publishes the complete identity, so interruption cannot pair
// a new key with an old CSR/account. The legacy separate values are read only
// during migration and never used after the complete record exists.
struct OpenVpnIdentityRecord {
  std::string key;
  std::string csr;
  std::string account;
  std::string device;
  ~OpenVpnIdentityRecord() {
    EraseSecret(key);
    EraseSecret(csr);
    EraseSecret(account);
    EraseSecret(device);
  }

  std::string Encode() const {
    std::string result = "OVI1";
    for (const auto* field : {&key, &csr, &account, &device}) {
      const auto length = static_cast<std::uint32_t>(field->size());
      for (unsigned shift = 0; shift < 32; shift += 8)
        result.push_back(static_cast<char>((length >> shift) & 0xff));
      result += *field;
    }
    return result;
  }

  static bool Decode(std::string_view input, OpenVpnIdentityRecord* output) {
    if (!output || input.substr(0, 4) != "OVI1") return false;
    input.remove_prefix(4);
    OpenVpnIdentityRecord candidate;
    std::array<std::string*, 4> fields{
        &candidate.key, &candidate.csr, &candidate.account, &candidate.device};
    for (size_t index = 0; index < fields.size(); ++index) {
      if (input.size() < 4) return false;
      std::uint32_t size = 0;
      for (unsigned byte = 0; byte < 4; ++byte)
        size |= static_cast<std::uint32_t>(
                    static_cast<unsigned char>(input[byte])) << (byte * 8);
      input.remove_prefix(4);
      const size_t limit = index < 2 ? 65536 : 128;
      if (size == 0 || size > limit || size > input.size()) return false;
      fields[index]->assign(input.substr(0, size));
      input.remove_prefix(size);
    }
    if (!input.empty()) return false;
    *output = candidate;
    return true;
  }
};
}  // namespace fuzevpn
#endif
