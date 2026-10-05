// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_BROKER_PROTOCOL_H_
#define RUNNER_BROKER_PROTOCOL_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string_view>

namespace fuzevpn_ipc {

// Validate the small application protocol before invoking Flutter's general
// codec. This reader allocates nothing, never recurses for requests, and rejects
// a length before any buffer or collection can be allocated from that length.
class ProtocolReader final {
 public:
  ProtocolReader(const uint8_t* bytes, size_t size) : bytes_(bytes), size_(size) {}

  bool Byte(uint8_t* value) {
    if (position_ >= size_) return false;
    *value = bytes_[position_++];
    return true;
  }
  bool Skip(size_t count) {
    if (count > size_ - position_) return false;
    position_ += count;
    return true;
  }
  bool Length(size_t* length) {
    uint8_t first = 0;
    if (!Byte(&first)) return false;
    if (first < 254) {
      *length = first;
      return true;
    }
    const size_t width = first == 254 ? 2 : 4;
    if (width > size_ - position_) return false;
    *length = 0;
    for (size_t index = 0; index < width; ++index)
      *length |= static_cast<size_t>(bytes_[position_++]) << (index * 8);
    return true;
  }
  bool String(size_t limit, std::string_view* value = nullptr) {
    uint8_t type = 0;
    size_t length = 0;
    if (!Byte(&type) || type != 7 || !Length(&length) || length > limit ||
        length > size_ - position_) return false;
    if (value != nullptr) {
      *value = std::string_view(
          reinterpret_cast<const char*>(bytes_ + position_), length);
    }
    position_ += length;
    return true;
  }
  bool Null() {
    uint8_t type = 0;
    return Byte(&type) && type == 0;
  }
  bool Boolean() {
    uint8_t type = 0;
    return Byte(&type) && (type == 1 || type == 2);
  }
  bool End() const { return position_ == size_; }

  enum class FieldKind { text, boolean, text_list };
  struct Field {
    const char* name;
    FieldKind kind;
    bool required;
    size_t limit;
    size_t items = 0;
  };

  bool Arguments(const Field* fields, size_t field_count) {
    if (field_count > 32) return false;
    uint8_t type = 0;
    size_t length = 0;
    if (!Byte(&type) || type != 13 || !Length(&length) || length > field_count)
      return false;
    std::array<bool, 32> seen{};
    for (size_t entry = 0; entry < length; ++entry) {
      std::string_view key;
      if (!String(40, &key)) return false;
      size_t index = 0;
      for (; index < field_count && key != fields[index].name; ++index) {}
      if (index == field_count || seen[index]) return false;
      seen[index] = true;
      const Field& field = fields[index];
      if (field.kind == FieldKind::boolean) {
        if (!Boolean()) return false;
      } else if (field.kind == FieldKind::text) {
        if (!String(field.limit)) return false;
      } else {
        size_t count = 0;
        if (!Byte(&type) || type != 12 || !Length(&count) || count > field.items)
          return false;
        for (size_t item = 0; item < count; ++item) {
          if (!String(field.limit)) return false;
        }
      }
    }
    for (size_t index = 0; index < field_count; ++index) {
      if (fields[index].required && !seen[index]) return false;
    }
    return true;
  }

  // Responses currently use null/bool/string and shallow string-keyed maps or
  // lists. Bound all of them too, before the GUI decodes a response envelope.
  bool Value(unsigned depth = 0) {
    if (depth > 8 || ++nodes_ > 2048) return false;
    uint8_t type = 0;
    if (!Byte(&type)) return false;
    if (type <= 2) return true;
    if (type == 3) return Skip(4);
    if (type == 4) return Skip(8);
    if (type == 6) {
      const size_t padding = (8 - position_ % 8) % 8;
      return Skip(padding) && Skip(8);
    }
    if (type == 7) {
      size_t length = 0;
      return Length(&length) && length <= 256 * 1024 && Skip(length);
    }
    if (type == 12 || type == 13) {
      size_t length = 0;
      if (!Length(&length) || length > (type == 12 ? 256u : 32u)) return false;
      for (size_t index = 0; index < length; ++index) {
        if (type == 13 && !String(80)) return false;
        if (!Value(depth + 1)) return false;
      }
      return true;
    }
    return false;
  }

 private:
  const uint8_t* bytes_;
  size_t size_;
  size_t position_ = 0;
  size_t nodes_ = 0;
};

inline bool ValidateMethodRequest(const uint8_t* bytes, size_t size) {
  if (bytes == nullptr || size == 0 || size > 1024 * 1024) return false;
  ProtocolReader reader(bytes, size);
  std::string_view method;
  if (!reader.String(80, &method)) return false;
  using Field = ProtocolReader::Field;
  using Kind = ProtocolReader::FieldKind;
  constexpr Field protection[] = {
      {"killSwitch", Kind::boolean, false, 0},
      {"dnsProtection", Kind::boolean, false, 0},
      {"webRtcProtection", Kind::boolean, false, 0},
  };
  constexpr Field account[] = {{"accountId", Kind::text, true, 128}};
  constexpr Field identity[] = {
      {"accountId", Kind::text, true, 128},
      {"deviceId", Kind::text, true, 128},
  };
  constexpr Field wireguard[] = {
      {"deviceId", Kind::text, false, 128},
      {"address", Kind::text, true, 128},
      {"addresses", Kind::text_list, false, 128, 16},
      {"serverPublicKey", Kind::text, true, 128},
      {"endpoint", Kind::text, true, 512},
      {"dns", Kind::text_list, true, 128, 16},
      {"allowedIps", Kind::text_list, true, 128, 256},
      {"killSwitch", Kind::boolean, false, 0},
      {"dnsProtection", Kind::boolean, false, 0},
      {"webRtcProtection", Kind::boolean, false, 0},
  };
  constexpr Field openvpn[] = {
      {"certificatePem", Kind::text, true, 128 * 1024},
      {"caCertificatePem", Kind::text, true, 256 * 1024},
      {"tlsCryptV2ClientKey", Kind::text, true, 64 * 1024},
      {"endpoint", Kind::text, true, 512},
      {"address", Kind::text, true, 128},
      {"addresses", Kind::text_list, false, 128, 16},
      {"allowedIps", Kind::text_list, false, 128, 256},
      {"dns", Kind::text_list, true, 128, 16},
      {"serverName", Kind::text, true, 512},
      {"remoteCertTlsServer", Kind::boolean, true, 0},
      {"ciphers", Kind::text_list, true, 128, 16},
      {"ipv6Enabled", Kind::boolean, false, 0},
      {"killSwitch", Kind::boolean, false, 0},
      {"dnsProtection", Kind::boolean, false, 0},
      {"webRtcProtection", Kind::boolean, false, 0},
  };
  bool valid = false;
  if (method == "wireguard.prepareConnection" || method == "openvpn.prepareConnection") {
    valid = reader.Arguments(protection, std::size(protection));
  } else if (method == "wireguard.getOrCreatePublicKey" ||
             method == "wireguard.prepareIdentityForAccount" ||
             method == "wireguard.recreateIdentityForAccount") {
    valid = reader.Arguments(account, std::size(account));
  } else if (method == "openvpn.getOrCreateCsr" || method == "openvpn.renewCsr") {
    valid = reader.Arguments(identity, std::size(identity));
  } else if (method == "wireguard.connect") {
    valid = reader.Arguments(wireguard, std::size(wireguard));
  } else if (method == "openvpn.importAndConnect") {
    valid = reader.Arguments(openvpn, std::size(openvpn));
  } else if (method == "broker.shutdown" || method == "diagnostics.collectSnapshot" ||
             method == "wireguard.isConnected" || method == "openvpn.isConnected" ||
             method == "wireguard.isNetworkProtectionActive" ||
             method == "openvpn.isNetworkProtectionActive" ||
             method == "wireguard.networkProtectionStatus" ||
             method == "openvpn.networkProtectionStatus" ||
             method == "wireguard.resolveApiAddresses" ||
             method == "wireguard.reconnect" || method == "openvpn.reconnect" ||
             method == "wireguard.disconnect" || method == "openvpn.disconnect" ||
             method == "wireguard.suspendForMigration" ||
             method == "openvpn.suspendForMigration" ||
             method == "wireguard.resetIdentity" || method == "openvpn.deleteProfile") {
    valid = reader.Null();
  }
  return valid && reader.End();
}

inline bool ValidateResponseEnvelope(const uint8_t* bytes, size_t size) {
  if (bytes == nullptr || size == 0 || size > 1024 * 1024) return false;
  ProtocolReader reader(bytes, size);
  uint8_t flag = 0;
  if (!reader.Byte(&flag)) return false;
  if (flag == 0) return reader.Value() && reader.End();
  if (flag != 1 || !reader.String(80)) return false;
  // A Flutter error message is either a string or null. Do not let an
  // unexpected type reach the codec's std::get<std::string> operation.
  ProtocolReader with_message = reader;
  if (with_message.String(2048)) reader = with_message;
  else if (!reader.Null()) return false;
  return reader.Value() && reader.End();
}

}  // namespace fuzevpn_ipc
#endif  // RUNNER_BROKER_PROTOCOL_H_
