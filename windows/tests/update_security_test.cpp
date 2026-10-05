// SPDX-License-Identifier: MPL-2.0
#include "update_security.h"
#include "runtime_architecture.h"
#include "single_instance_identity.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <softpub.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstring>

namespace {
void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
std::vector<BYTE> Name(const wchar_t* value) {
  DWORD bytes = 0;
  Require(CertStrToNameW(X509_ASN_ENCODING, value, CERT_X500_NAME_STR, nullptr, nullptr, &bytes, nullptr) != FALSE, "name size");
  std::vector<BYTE> name(bytes);
  Require(CertStrToNameW(X509_ASN_ENCODING, value, CERT_X500_NAME_STR, nullptr, name.data(), &bytes, nullptr) != FALSE, "name");
  return name;
}
void PeFixture(const std::filesystem::path& path, USHORT machine, bool pe64 = true,
               LONG offset = static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)), bool truncated = false) {
  IMAGE_DOS_HEADER dos{};
  dos.e_magic = IMAGE_DOS_SIGNATURE;
  dos.e_lfanew = offset;
  IMAGE_NT_HEADERS64 nt{};
  nt.Signature = IMAGE_NT_SIGNATURE;
  nt.FileHeader.Machine = machine;
  nt.FileHeader.NumberOfSections = 1;
  nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt.OptionalHeader.Magic = pe64 ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  IMAGE_SECTION_HEADER section{};
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  file.write(reinterpret_cast<const char*>(&dos), sizeof(dos));
  if (!truncated) {
    file.write(reinterpret_cast<const char*>(&nt), sizeof(nt));
    file.write(reinterpret_cast<const char*>(&section), sizeof(section));
  }
  Require(static_cast<bool>(file), "PE fixture write");
}
std::string FixtureHash(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  std::vector<BYTE> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
      "fixture hash provider");
  BYTE digest[32]{};
  const auto status = BCryptHash(algorithm, nullptr, 0, bytes.data(),
      static_cast<ULONG>(bytes.size()), digest, sizeof(digest));
  BCryptCloseAlgorithmProvider(algorithm, 0);
  Require(status >= 0, "fixture hash calculation");
  constexpr char alphabet[] = "0123456789abcdef";
  std::string result;
  for (BYTE byte : digest) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; }
  return result;
}
}
int main(int argc, char** argv) {
  using namespace fuzevpn_update;
  try {
    Version version;
    for (const char* value : {"0.1.0", "255.255.65535", "1.10.2"})
      Require(ParseVersion(value, &version) && version.text() == value, "valid MSI version");
    for (const char* value : {"", "01.2.3", "1.02.3", "1.2", "1.2.3.4", "256.0.0", "1.256.0", "1.0.65536", "1.2.3+1", "1.2.3-beta", "1.2.3 ", "-1.2.3"})
      Require(!ParseVersion(value, &version), "invalid MSI version accepted");
    Require(!ParseVersion(std::string("1.2.3\0", 6), &version), "NUL version");
    Version old, next;
    Require(ParseVersion("1.9.99", &old) && ParseVersion("1.10.0", &next) && old < next, "numeric comparison");
    const auto token = NewToken();
    Require(ValidToken(token) && token != NewToken(), "opaque random token");
    Require(!ValidToken("../../payload") && !ValidToken(std::string(32, 'g')), "token validation");
    const std::string hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    Require(ValidHash(hash) && !ValidHash(std::string(64, 'z')), "hash syntax");
    const auto identity = Name(L"CN=Example Software,O=Example,C=FR");
    Require(SamePublisher(identity, identity), "same certified subject");
    Require(!SamePublisher(identity, Name(L"CN=Example Software,O=Another,C=FR")), "display-name collision");
    Require(!SamePublisher({}, identity), "empty publisher");
    Require(argc == 2 || argc == 3, "explicit workspace scratch required");
    const auto root = std::filesystem::absolute(argv[1]);
    std::filesystem::create_directories(root);
    const auto directory = root / Wide(NewToken());
    std::filesystem::create_directory(directory);
    const auto path = directory / L"fixture.exe";
    for (const auto machine : {fuzevpn_architecture::kX64Machine, fuzevpn_architecture::kArm64Machine}) {
      PeFixture(path, machine);
      PinnedFile pe;
      USHORT actual = IMAGE_FILE_MACHINE_UNKNOWN;
      Require(pe.Open(path) && ReadPeMachine(pe.get(), &actual) && actual == machine,
          "supported PE architecture not read");
      Require(MatchesBuildArchitecture(pe.get()) == (machine == fuzevpn_architecture::kBuildMachine),
          "cross-architecture update package accepted");
      Failure failure;
      Require(!VerifyBundle(pe, std::string(64, '0'), next, identity, &failure),
          "unverified fixture accepted");
      Require(failure.code == (machine == fuzevpn_architecture::kBuildMachine ?
          "update_hash_mismatch" : "update_package_architecture_mismatch"),
          "architecture/hash rejection reason lost");
      Require(failure.stage == (machine == fuzevpn_architecture::kBuildMachine ?
          "package_hash" : "package_architecture"), "verification stage lost");
      if (machine == fuzevpn_architecture::kBuildMachine) {
        Require(!VerifyBundle(pe, FixtureHash(path), next, identity, &failure) &&
            failure.code == "update_signature_invalid" && failure.stage == "package_signature" &&
            failure.trust_status != ERROR_SUCCESS, "unsigned PE rejection reason lost");
        std::vector<BYTE> subject = identity;
        LONG trust_status = ERROR_SUCCESS;
        Require(!TrustedPublisher(pe, &subject, &trust_status) && subject.empty() &&
            trust_status == failure.trust_status, "signature reason or stale publisher");
      }
    }
    {
      PinnedFile application;
      std::vector<BYTE> publisher = identity;
      LONG trust_status = ERROR_SUCCESS;
      Require(application.Open(CurrentExecutable()), "pin unsigned regression executable");
      Require(!TrustedPublisher(application, &publisher, &trust_status) && publisher.empty() &&
          trust_status == TRUST_E_NOSIGNATURE, "unsigned application classification");
      Require(!TrustedPublisher(application, &publisher, &trust_status, false) && publisher.empty() &&
          trust_status == TRUST_E_NOSIGNATURE, "cache-only trust keeps unsigned images rejected");
      const FuzeVpnActivationIdentity local(CurrentExecutable());
      Require(local.Matches(CurrentExecutable()) && !local.Matches(path),
          "unsigned development instance can activate only its own executable path");
    }
    if (argc == 3) {
      // Optional real release evidence, never launch the supplied application.
      const auto release = std::filesystem::absolute(argv[2]);
      const auto left = directory / L"installed";
      const auto right = directory / L"portable";
      std::filesystem::create_directory(left);
      std::filesystem::create_directory(right);
      const auto first = left / L"fuzevpn_windows.exe";
      const auto second = right / L"fuzevpn_windows.exe";
      const auto wrong_name = right / L"another_product.exe";
      std::filesystem::copy_file(release, first);
      std::filesystem::copy_file(release, second);
      std::filesystem::copy_file(release, wrong_name);
      {
        const FuzeVpnActivationIdentity portable(second);
        Require(portable.Matches(first),
            "cross-distribution activation also works from portable to installed");
      }
      {
        const FuzeVpnActivationIdentity installed(first);
        Require(installed.Matches(second),
            "signed FuzeVPN UI activates the existing instance from another distribution");
        Require(!installed.Matches(wrong_name),
            "a differently named signed executable cannot impersonate the UI");
        std::fstream changed(second, std::ios::binary | std::ios::in | std::ios::out);
        changed.seekg(0x20);
        char byte = 0;
        changed.read(&byte, 1);
        Require(static_cast<bool>(changed), "read signed regression fixture");
        byte ^= 1;
        changed.seekp(0x20);
        changed.write(&byte, 1);
        changed.close();
        Require(!installed.Matches(second),
            "a tampered FuzeVPN executable cannot acquire cross-distribution activation");
        Require(DeleteFileW(second.c_str()), "remove tampered regression fixture");
        std::filesystem::copy_file(CurrentExecutable(), second);
        Require(!installed.Matches(second),
            "an unsigned same-named executable cannot impersonate the UI");
      }
      Require(DeleteFileW(first.c_str()) && DeleteFileW(second.c_str()) &&
          DeleteFileW(wrong_name.c_str()) && RemoveDirectoryW(left.c_str()) &&
          RemoveDirectoryW(right.c_str()), "signed identity fixture cleanup");
    }
    for (unsigned variant = 0; variant < 4; ++variant) {
      const auto machine = variant == 0 ? static_cast<USHORT>(IMAGE_FILE_MACHINE_I386)
          : fuzevpn_architecture::kBuildMachine;
      PeFixture(path, machine, variant != 1,
          variant == 2 ? 0x7fffffff : static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)), variant == 3);
      PinnedFile malformed;
      USHORT actual = IMAGE_FILE_MACHINE_UNKNOWN;
      Require(malformed.Open(path) && !ReadPeMachine(malformed.get(), &actual),
          "unsupported or malformed PE accepted");
    }
    { std::ofstream file(path, std::ios::binary); file << "abc"; }
    {
      PinnedFile pinned;
      Require(pinned.Open(path), "pin regular file");
      Require(MatchesHash(pinned.get(), hash), "stream SHA256");
      Require(!MatchesHash(pinned.get(), std::string(64, '0')), "wrong hash rejected");
      HANDLE writer = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
      Require(writer == INVALID_HANDLE_VALUE, "file cannot change after verification");
      Require(!MoveFileW(path.c_str(), (directory / L"replacement.exe").c_str()), "file cannot be swapped");
      Require(!MoveFileW(directory.c_str(), (root / L"replacement-directory").c_str()), "parent cannot be swapped");
      std::vector<BYTE> publisher;
      Require(!TrustedPublisher(pinned, &publisher), "unsigned test file must fail closed");
    }
    const auto alias = directory / L"alias.exe";
    {
      PinnedFile strict;
      Require(strict.Open(path, true), "strict portable ancestor pins");
      HANDLE writer = CreateFileW(directory.c_str(), GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
          OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      Require(writer == INVALID_HANDLE_VALUE, "portable parent cannot be opened for reparse mutation");
      if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    }
    Require(CreateHardLinkW(alias.c_str(), path.c_str(), nullptr) != FALSE, "create local hard-link fixture");
    { PinnedFile linked; Require(!linked.Open(path), "multiply-linked file rejected"); }
    Require(DeleteFileW(alias.c_str()) && DeleteFileW(path.c_str()) && RemoveDirectoryW(directory.c_str()), "fixture cleanup");
    std::cout << "Update policy, publisher identity, SHA256 and immutable file tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
  }
}
