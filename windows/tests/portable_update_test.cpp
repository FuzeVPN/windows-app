// SPDX-License-Identifier: MPL-2.0
#include "portable_update.h"
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<BYTE>;
using fuzevpn_update::Failure;
void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
void U16(Bytes* bytes, unsigned value) {
  bytes->push_back(static_cast<BYTE>(value));
  bytes->push_back(static_cast<BYTE>(value >> 8));
}
void U32(Bytes* bytes, uint32_t value) {
  U16(bytes, value & 0xffff); U16(bytes, value >> 16);
}
void Put32(Bytes* bytes, size_t offset, uint32_t value) {
  Require(offset + 4 <= bytes->size(), "fixture patch overflow");
  for (unsigned i = 0; i < 4; ++i) (*bytes)[offset + i] = static_cast<BYTE>(value >> (i * 8));
}
uint32_t Crc(const std::string& text) {
  uint32_t crc = 0xffffffffu;
  for (unsigned char byte : text) {
    crc ^= byte;
    for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
  }
  return crc ^ 0xffffffffu;
}
std::string Hash(const Bytes& bytes) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0, actual = 0;
  Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0,
          "fixture hash algorithm failed");
  Require(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
          sizeof(object_size), &actual, 0) == 0, "fixture hash object failed");
  Bytes object(object_size), digest(32);
  Require(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) == 0 &&
      BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0) == 0 &&
      BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0, "fixture hash failed");
  BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
  constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (BYTE byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  return result;
}
void Write(const std::filesystem::path& path, const Bytes& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  Require(static_cast<bool>(stream), "fixture file open failed");
  stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  Require(static_cast<bool>(stream), "fixture file write failed");
}
void WriteText(const std::filesystem::path& path, const std::string& text) {
  Write(path, Bytes(text.begin(), text.end()));
}
std::string ReadText(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}
struct Entry {
  std::string name, content = "hello", local_name;
  uint16_t method = 0, flags = 0;
  uint32_t attributes = 0, expanded = 0xffffffffu;
  Bytes extra, compressed;
  bool corrupt_crc = false;
  explicit Entry(std::string value) : name(std::move(value)) {}
};
Bytes Zip(const std::vector<Entry>& entries) {
  Bytes bytes, central;
  for (const auto& entry : entries) {
    const auto offset = static_cast<uint32_t>(bytes.size());
    const auto& local_name = entry.local_name.empty() ? entry.name : entry.local_name;
    const auto compressed = entry.compressed.empty() && entry.method == 0
        ? Bytes(entry.content.begin(), entry.content.end()) : entry.compressed;
    const auto crc = Crc(entry.content) ^ (entry.corrupt_crc ? 1u : 0u);
    const auto expanded = entry.expanded == 0xffffffffu
        ? static_cast<uint32_t>(entry.content.size()) : entry.expanded;
    U32(&bytes, 0x04034b50); U16(&bytes, 20); U16(&bytes, entry.flags); U16(&bytes, entry.method);
    U32(&bytes, 0); U32(&bytes, (entry.flags & 8) ? 0 : crc);
    U32(&bytes, (entry.flags & 8) ? 0 : static_cast<uint32_t>(compressed.size()));
    U32(&bytes, (entry.flags & 8) ? 0 : expanded);
    U16(&bytes, static_cast<unsigned>(local_name.size())); U16(&bytes, static_cast<unsigned>(entry.extra.size()));
    bytes.insert(bytes.end(), local_name.begin(), local_name.end());
    bytes.insert(bytes.end(), entry.extra.begin(), entry.extra.end());
    bytes.insert(bytes.end(), compressed.begin(), compressed.end());
    if (entry.flags & 8) { U32(&bytes, 0x08074b50); U32(&bytes, crc);
      U32(&bytes, static_cast<uint32_t>(compressed.size())); U32(&bytes, expanded); }
    U32(&central, 0x02014b50); U16(&central, 20); U16(&central, 20);
    U16(&central, entry.flags); U16(&central, entry.method); U32(&central, 0);
    U32(&central, crc); U32(&central, static_cast<uint32_t>(compressed.size())); U32(&central, expanded);
    U16(&central, static_cast<unsigned>(entry.name.size())); U16(&central, static_cast<unsigned>(entry.extra.size()));
    U16(&central, 0); U16(&central, 0); U16(&central, 0); U32(&central, entry.attributes); U32(&central, offset);
    central.insert(central.end(), entry.name.begin(), entry.name.end());
    central.insert(central.end(), entry.extra.begin(), entry.extra.end());
  }
  const auto central_offset = static_cast<uint32_t>(bytes.size());
  bytes.insert(bytes.end(), central.begin(), central.end());
  U32(&bytes, 0x06054b50); U16(&bytes, 0); U16(&bytes, 0);
  U16(&bytes, static_cast<unsigned>(entries.size())); U16(&bytes, static_cast<unsigned>(entries.size()));
  U32(&bytes, static_cast<uint32_t>(central.size())); U32(&bytes, central_offset); U16(&bytes, 0);
  return bytes;
}
size_t FindSignature(const Bytes& bytes, uint32_t signature) {
  for (size_t offset = 0; offset + 4 <= bytes.size(); ++offset) {
    const uint32_t candidate = bytes[offset] | static_cast<uint32_t>(bytes[offset + 1]) << 8 |
        static_cast<uint32_t>(bytes[offset + 2]) << 16 | static_cast<uint32_t>(bytes[offset + 3]) << 24;
    if (candidate == signature) return offset;
  }
  throw std::runtime_error("fixture signature missing");
}
class Fixtures {
 public:
  explicit Fixtures(std::filesystem::path root) : root_(std::move(root)) {
    Require(root_.is_absolute() && root_ != root_.root_path(), "unsafe fixture root");
    std::filesystem::create_directories(root_);
    root_ /= L"run-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    Require(!std::filesystem::exists(root_) && std::filesystem::create_directory(root_),
        "test fixture must be fresh and empty");
  }
  bool Extract(const Bytes& bytes, Failure* failure, bool bad_hash = false) {
    current_ = root_ / (L"case-" + std::to_wstring(++index_));
    std::filesystem::create_directory(current_);
    const auto archive = current_ / L"archive.zip";
    output_ = current_ / L"output";
    std::filesystem::create_directory(output_);
    Write(archive, bytes);
    fuzevpn_update::PinnedFile file;
    Require(file.Open(archive, true), "fixture pin failed");
    return fuzevpn_portable_update::ExtractArchive(file, bad_hash ? std::string(64, '0') : Hash(bytes), output_, failure);
  }
  void Reject(const Bytes& bytes, const char* code) {
    Failure failure;
    Require(!Extract(bytes, &failure), "unsafe archive accepted");
    Require(failure.code == code, "unexpected rejection code");
  }
  const std::filesystem::path& output() const { return output_; }
  const std::filesystem::path& root() const { return root_; }
 private:
  std::filesystem::path root_, current_, output_;
  unsigned index_ = 0;
};
void PortableFolder(const std::filesystem::path& root, const std::string& value) {
  std::filesystem::create_directory(root);
  WriteText(root / L"fuzevpn.portable", "FuzeVPN portable v1\n");
  WriteText(root / L"generation.txt", value);
}
void RunCases(Fixtures* fixtures) {
  using namespace fuzevpn_portable_update;
  Failure failure;
  auto good = Zip({Entry("FuzeVPN/data/example.txt")});
  Require(fixtures->Extract(good, &failure), "stored ZIP rejected");
  Require(ReadText(fixtures->output() / L"data/example.txt") == "hello", "stored output incorrect");
  Entry deflate("FuzeVPN/deflated.txt");
  deflate.method = 8; deflate.compressed = {0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00};
  Require(fixtures->Extract(Zip({deflate}), &failure), "raw DEFLATE rejected");
  Require(ReadText(fixtures->output() / L"deflated.txt") == "hello", "deflate output incorrect");
  deflate.flags = 8;
  Require(fixtures->Extract(Zip({deflate}), &failure), "data descriptor rejected");
  Require(!fixtures->Extract(good, &failure, true) && failure.code == "update_hash_mismatch" &&
      std::filesystem::is_empty(fixtures->output()), "hash check did not precede extraction");
  for (const char* name : {"../escape.txt", "FuzeVPN/../escape.txt", "FuzeVPN/data/../../escape.txt",
      "FuzeVPN//escape.txt", "FuzeVPN/./escape.txt", "FuzeVPN/C:/escape.txt", "FuzeVPN/CON.txt",
      "FuzeVPN/NUL", "FuzeVPN/LPT1.txt", "FuzeVPN/trailing.", "FuzeVPN/trailing ",
      "FuzeVPN/file.txt:stream", "FuzeVPN/data\\escape.txt", "OtherRoot/file.txt"}) {
    fixtures->Reject(Zip({Entry(name)}), "update_archive_unsafe");
  }
  fixtures->Reject(Zip({Entry("FuzeVPN/a.txt"), Entry("FuzeVPN/A.txt")}), "update_archive_unsafe");
  fixtures->Reject(Zip({Entry("FuzeVPN/data"), Entry("FuzeVPN/data/item.txt")}), "update_archive_unsafe");
  Entry symlink("FuzeVPN/link"); symlink.attributes = 0120777u << 16;
  fixtures->Reject(Zip({symlink}), "update_archive_unsafe");
  symlink.attributes = FILE_ATTRIBUTE_REPARSE_POINT;
  fixtures->Reject(Zip({symlink}), "update_archive_unsafe");
  Entry encrypted("FuzeVPN/file.txt"); encrypted.flags = 1;
  fixtures->Reject(Zip({encrypted}), "update_archive_unsafe");
  Entry unsupported("FuzeVPN/file.txt"); unsupported.method = 12;
  fixtures->Reject(Zip({unsupported}), "update_archive_unsafe");
  Entry alternate("FuzeVPN/file.txt"); alternate.extra = {0x75, 0x70, 0, 0};
  fixtures->Reject(Zip({alternate}), "update_archive_unsafe");
  alternate.extra = {1, 0, 0, 0};
  fixtures->Reject(Zip({alternate}), "update_archive_unsafe");
  Entry mismatch("FuzeVPN/file.txt"); mismatch.local_name = "FuzeVPN/evil.txt";
  fixtures->Reject(Zip({mismatch}), "update_archive_invalid");
  Entry damaged("FuzeVPN/file.txt"); damaged.corrupt_crc = true;
  fixtures->Reject(Zip({damaged}), "update_archive_invalid");
  auto descriptor = Zip({deflate});
  Put32(&descriptor, FindSignature(descriptor, 0x08074b50) + 4, 1);
  fixtures->Reject(descriptor, "update_archive_invalid");
  auto overlap = Zip({Entry("FuzeVPN/a.txt"), Entry("FuzeVPN/b.txt")});
  const auto first_central = FindSignature(overlap, 0x02014b50);
  const size_t second_central = first_central + 46 + std::string("FuzeVPN/a.txt").size();
  Put32(&overlap, second_central + 42, 0);
  fixtures->Reject(overlap, "update_archive_invalid");
  auto trailing = good; trailing.push_back(0);
  fixtures->Reject(trailing, "update_archive_invalid");
  Entry bomb("FuzeVPN/bomb.txt"); bomb.method = 8; bomb.compressed = {3, 0};
  bomb.expanded = static_cast<uint32_t>(kMaximumEntryBytes + 1);
  fixtures->Reject(Zip({bomb}), "update_archive_too_large");
  bomb.expanded = 400000000;
  Entry bomb2 = bomb; bomb2.name = "FuzeVPN/bomb2.txt";
  Entry bomb3 = bomb; bomb3.name = "FuzeVPN/bomb3.txt";
  fixtures->Reject(Zip({bomb, bomb2, bomb3}), "update_archive_too_large");
  std::vector<Entry> many;
  for (unsigned index = 0; index <= kMaximumArchiveEntries; ++index)
    many.emplace_back("FuzeVPN/f-" + std::to_string(index));
  fixtures->Reject(Zip(many), "update_archive_too_large");

  const auto rename_root = fixtures->root() / L"rename";
  std::filesystem::create_directory(rename_root);
  const auto target = rename_root / L"FuzeVPN", candidate = rename_root / L"candidate", backup = rename_root / L"backup";
  PortableFolder(target, "old"); PortableFolder(candidate, "new");
  Require(ReplaceDirectory(target, candidate, backup, &failure), "transaction replacement rejected");
  Require(ReadText(target / L"generation.txt") == "new" && ReadText(backup / L"generation.txt") == "old" &&
      !std::filesystem::exists(candidate), "transaction generations incorrect");
  const auto rollback_root = fixtures->root() / L"rollback";
  std::filesystem::create_directory(rollback_root);
  const auto old = rollback_root / L"FuzeVPN", next = rollback_root / L"candidate", saved = rollback_root / L"backup";
  PortableFolder(old, "old"); PortableFolder(next, "new");
  HANDLE lock = CreateFileW(next.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  Require(lock != INVALID_HANDLE_VALUE, "rollback fixture lock failed");
  const bool replaced = ReplaceDirectory(old, next, saved, &failure);
  CloseHandle(lock);
  Require(!replaced && failure.stage == "portable_replace" && ReadText(old / L"generation.txt") == "old" &&
      ReadText(next / L"generation.txt") == "new" && !std::filesystem::exists(saved), "rollback lost old folder");
  PortableFolder(saved, "unrelated");
  Require(!ReplaceDirectory(old, next, saved, &failure) && failure.code == "update_portable_target_invalid" &&
      ReadText(saved / L"generation.txt") == "unrelated", "existing backup overwritten");
  Require(!RemoveStaging(fixtures->root().root_path()), "volume root deletion accepted");
  Require(RemoveStaging(next) && !std::filesystem::exists(next), "bounded staging removal failed");
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 5 && std::string(argv[1]) == "--verify-archive") {
      // ZIP integrity/extraction is architecture-independent. Release PE/AOT
      // architecture, signature and manifest audits remain separate checks.
      const auto archive_path = std::filesystem::absolute(argv[2]).lexically_normal();
      const auto output = std::filesystem::absolute(argv[4]).lexically_normal();
      Require(!std::filesystem::exists(output), "release fixture must not already exist");
      std::filesystem::create_directories(output);
      fuzevpn_update::PinnedFile archive;
      Require(archive.Open(archive_path, true), "release archive pin failed");
      Failure failure;
      if (!fuzevpn_portable_update::ExtractArchive(archive, argv[3], output, &failure)) {
        std::cerr << "ZIP verification failed: " << failure.code << " stage=" << failure.stage << '\n';
        return 1;
      }
      std::cout << "Portable ZIP hash and safe extraction verified without execution\n";
      return 0;
    }
    if (argc == 7 && std::string(argv[1]) == "--verify-package") {
      // Read-only release verification plus extraction into a fresh test folder.
      // Neither updater helper nor application nor VPN engine is executed.
      const auto archive_path = std::filesystem::absolute(argv[2]).lexically_normal();
      const auto publisher_path = std::filesystem::absolute(argv[4]).lexically_normal();
      const auto output = std::filesystem::absolute(argv[6]).lexically_normal();
      Require(!std::filesystem::exists(output), "release fixture must not already exist");
      std::filesystem::create_directories(output);
      fuzevpn_update::PinnedFile archive, publisher;
      Require(archive.Open(archive_path, true) && publisher.Open(publisher_path, true), "release file pin failed");
      std::vector<BYTE> subject;
      Require(fuzevpn_update::TrustedPublisher(publisher, &subject), "expected GUI publisher untrusted");
      fuzevpn_update::Version version;
      Require(fuzevpn_update::ParseVersion(argv[5], &version), "target version invalid");
      Failure failure;
      if (!fuzevpn_portable_update::ExtractArchive(archive, argv[3], output, &failure) ||
          !fuzevpn_portable_update::ValidateBundle(output, version, subject, &failure)) {
        std::cerr << "Release verification failed: " << failure.code << " stage=" << failure.stage << '\n';
        return 1;
      }
      std::cout << "Portable ZIP hash, extraction, architecture, signatures, publisher and manifest verified without execution\n";
      return 0;
    }
    Require(argc == 2, "provide fresh absolute test fixture directory");
    Fixtures fixtures(std::filesystem::absolute(argv[1]).lexically_normal());
    RunCases(&fixtures);
    std::cout << "Portable ZIP security, integrity and transaction/rollback cases passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "Portable update tests failed: " << error.what() << '\n';
    return 1;
  }
}
