// SPDX-License-Identifier: MPL-2.0
#include "portable_runtime.h"
#include "installation_security.h"
#include "runtime_architecture.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <softpub.h>
#include <wintrust.h>

namespace {
void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
constexpr const char* kHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const char* const kFiles[] = {
  "fuzevpn-service.exe", "lz4.dll", fuzevpn_architecture::kOpenSslDll,
  fuzevpn_architecture::kOpenCryptoDll,
  "tunnel.dll", "wireguard.dll", "concrt140.dll", "msvcp140.dll", "msvcp140_1.dll",
  "msvcp140_2.dll", "msvcp140_atomic_wait.dll", "msvcp140_codecvt_ids.dll",
  "vcruntime140.dll",
#if defined(_M_X64) || defined(__x86_64__)
  "vcruntime140_1.dll",
#endif
  "openvpn-dco/NOTICE.md",
  "openvpn-dco/win10/ovpn-dco.inf", "openvpn-dco/win10/ovpn-dco.cat",
  "openvpn-dco/win10/ovpn-dco.sys", "openvpn-dco/win11/ovpn-dco.inf",
  "openvpn-dco/win11/ovpn-dco.cat", "openvpn-dco/win11/ovpn-dco.sys",
  "THIRD_PARTY_NOTICES.md", "WIREGUARD_NOTICE.md", "licenses/OpenVPN3-corresponding-source.zip"};
std::string Text() {
  std::string text = "FUZEVPN_RUNTIME_V1\nversion=0.1.0\nipc=1\n";
  for (const char* file : kFiles) text += std::string("file=3\t") + kHash + "\t" + file + "\n";
  return text;
}
std::filesystem::path Relative(const char* value) {
  auto path = std::filesystem::path(value);
  return path.make_preferred();
}
void Write(const std::filesystem::path& path, const char* bytes) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  Require(static_cast<bool>(file), "fixture open failed");
  file << bytes;
  Require(static_cast<bool>(file), "fixture write failed");
}
bool SignatureAbsent(const fuzevpn_update::PinnedFile& file) {
  WINTRUST_FILE_INFO info{};
  info.cbStruct = sizeof(info); info.pcwszFilePath = file.path().c_str(); info.hFile = file.get();
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
  trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &info;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const LONG status = WinVerifyTrust(nullptr, &action, &trust);
  trust.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &action, &trust);
  return status == TRUST_E_NOSIGNATURE;
}
} // namespace

int main(int argc, char** argv) {
  using namespace fuzevpn_portable;
  try {
    if (argc == 3 && (std::string(argv[1]) == "--bundle" ||
        std::string(argv[1]) == "--reject-unsigned-bundle")) {
      // Read-only release integration check, also suitable for a ZIP extracted
      // under a path with spaces. No cache creation, elevation or VPN process.
      const auto root = std::filesystem::absolute(argv[2]).lexically_normal();
      fuzevpn_update::PinnedFile gui, helper, service;
      Manifest release;
      DWORD release_error = ERROR_SUCCESS;
      Require(gui.Open(root / L"fuzevpn_windows.exe", true) &&
          helper.Open(root / L"fuzevpn-runtime.exe", true) &&
          service.Open(root / L"fuzevpn-service.exe", true), "release executable pin failed");
      Require(ReadEmbeddedManifest(helper.path(), &release, &release_error), "real helper RCDATA300 invalid");
      Require(VerifyManifestFiles(root, release, &release_error), "real runtime payload differs from signed manifest");
      for (const auto* file : {&gui, &helper, &service}) {
        fuzevpn_update::Version version;
        Require(fuzevpn_update::ReadVersion(file->path(), &version, true) && version == release.version,
            "bundle executable metadata differs from manifest");
      }
      if (std::string(argv[1]) == "--reject-unsigned-bundle") {
        Require(SignatureAbsent(gui) && SignatureAbsent(helper) && SignatureAbsent(service),
            "production rejection test requires three genuinely unsigned EXEs");
        Require(!ValidatePublisherPair(helper, gui, release.version, &release_error) &&
            release_error == ERROR_ACCESS_DENIED, "production accepted unsigned helper/GUI pair");
        Require(!ValidatePublisherPair(helper, service, release.version, &release_error) &&
            release_error == ERROR_ACCESS_DENIED, "production accepted unsigned helper/engine pair");
        std::cout << "Production policy refused both unsigned pairs despite valid manifest, payload and versions\n";
        return 0;
      }
      Require(ValidatePublisherPair(helper, gui, release.version, &release_error), "helper/GUI identity or version differs");
      Require(ValidatePublisherPair(helper, service, release.version, &release_error), "helper/engine identity or version differs");
      std::cout << "Portable release resource, payload, version and publisher policy passed; version="
                << release.version.text() << " files=" << release.files.size()
                << " manifest_sha256=" << release.sha256 << '\n';
      return 0;
    }
    Manifest manifest;
    DWORD error = 0;
    const auto text = Text();
    Require(ParseManifest(text, &manifest, &error), "canonical runtime manifest rejected");
    Require(manifest.files.size() == std::size(kFiles) && manifest.version.text() == "0.1.0" &&
        manifest.ipc_version == 1 && manifest.sha256.size() == 64, "manifest metadata incomplete");
    Manifest again;
    Require(ParseManifest(text, &again) && again.sha256 == manifest.sha256, "manifest cache key is not stable");
    const auto cache = RuntimeCachePath(manifest);
    Require(cache.is_absolute() && cache.filename().wstring() ==
        fuzevpn_update::Wide("0.1.0-" + manifest.sha256), "cache name must bind full manifest hash");
    auto changed = text;
    changed.replace(changed.find("version=0.1.0"), 13, "version=0.1.1");
    Require(ParseManifest(changed, &again) && again.sha256 != manifest.sha256, "version changes cache identity");
    for (const auto& invalid : {
        std::string{}, text + "\n", text.substr(0, text.size() - 1), text + "unknown=1\n",
        std::string("\xEF\xBB\xBF") + text, text + std::string(1, '\0'),
        text + "file=3\t" + kHash + "\tFUZEvpn-service.exe\n",
        text + "file=3\t" + kHash + "\tfuzevpn-service.exe/extra.dll\n",
        std::string(kMaximumManifestBytes + 1, 'x')}) {
      Require(!ParseManifest(invalid, &again), "malformed manifest accepted");
    }
    for (const char* path : {"../x.dll", "a/../x.dll", "a//b.dll", "a\\b.dll", "/x.dll",
         "C:/x.dll", "a.dll:stream", "a./x.dll", "CON.txt", "a/LPT1.dll", "a/NUL", "a b.dll"}) {
      Require(!ParseManifest(text + "file=3\t" + kHash + "\t" + path + "\n", &again),
          "unsafe manifest relative path accepted");
    }
    for (const char* size : {"0", "-1", "01", "536870913", "184467440737095516160"}) {
      Require(!ParseManifest(text + "file=" + size + "\t" + kHash + "\textra.dll\n", &again),
          "invalid or overflowing file size accepted");
    }
    for (const char* version : {"1.2.3.4", "256.0.0", "1.0.65536"}) {
      auto invalid = text;
      invalid.replace(invalid.find("version=0.1.0"), 13, std::string("version=") + version);
      Require(!ParseManifest(invalid, &again), "non-contract version accepted");
    }
    auto missing = text;
    const auto missing_start = missing.find("file=3\t");
    missing.erase(missing_start, missing.find('\n', missing_start) - missing_start + 1);
    Require(!ParseManifest(missing, &again), "manifest without mandatory engine accepted");
    auto wrong_architecture = text;
    const std::string wrong_ssl = fuzevpn_architecture::kBuildMachine == fuzevpn_architecture::kX64Machine
        ? "libssl-3-arm64.dll" : "libssl-3-x64.dll";
    const std::string expected_ssl = fuzevpn_architecture::kOpenSslDll;
    wrong_architecture.replace(wrong_architecture.find(expected_ssl), expected_ssl.size(), wrong_ssl);
    Require(!ParseManifest(wrong_architecture, &again), "manifest with another architecture's OpenSSL accepted");
    auto bad_ipc = text;
    bad_ipc.replace(bad_ipc.find("ipc=1"), 5, "ipc=2");
    Require(!ParseManifest(bad_ipc, &again), "unknown IPC accepted");
    Require(BootstrapPipeName(42, std::string(32, 'a')) ==
        L"\\\\.\\pipe\\FuzeVPN-PortableBootstrap-42-" + std::wstring(32, L'a'), "bootstrap pipe identity");
    Require(BootstrapPipeName(0, std::string(32, 'a')).empty() &&
        BootstrapPipeName(42, "../").empty(), "invalid bootstrap endpoint accepted");

    Require(argc == 2, "explicit project-local fixture directory required");
    const auto scratch = std::filesystem::absolute(argv[1]).lexically_normal();
    // CTest supplies the project's native-tests directory, never Program Files.
    Require(!fuzevpn_installation::IsDescendant(scratch, cache.parent_path().parent_path()),
        "tests must never create a real runtime cache");
    std::filesystem::create_directories(scratch);
    const auto root = scratch / fuzevpn_update::Wide(fuzevpn_update::NewToken());
    Require(std::filesystem::create_directory(root), "fresh fixture root required");
    for (const char* name : kFiles) {
      const auto path = root / Relative(name);
      std::filesystem::create_directories(path.parent_path());
      Write(path, "abc");
    }
    Require(VerifyManifestFiles(root, manifest, &error), "valid pinned manifest files rejected");
    const auto service = root / L"fuzevpn-service.exe";
    Write(service, "abd");
    Require(!VerifyManifestFiles(root, manifest), "same-size changed payload accepted");
    Write(service, "abc");
    const auto alias = root / L"hardlink.exe";
    Require(CreateHardLinkW(alias.c_str(), service.c_str(), nullptr) != FALSE, "local hardlink fixture");
    Require(!VerifyManifestFiles(root, manifest), "multiply-linked source accepted");
    Require(DeleteFileW(alias.c_str()) != FALSE, "hardlink cleanup");
    Require(DeleteFileW(service.c_str()) != FALSE, "remove source fixture");
    Require(!VerifyManifestFiles(root, manifest), "missing declared file accepted");
    Write(service, "abc");
    Require(!ValidateProtectedRuntime(root, manifest), "arbitrary source directory accepted as protected cache");
    Require(!ReadEmbeddedManifest(service, &again), "non-PE fixture accepted as signed resource container");
    // Delete only the exact fixtures created above; no recursive path deletion.
    for (const char* name : kFiles) Require(DeleteFileW((root / Relative(name)).c_str()) != FALSE, "file cleanup");
    for (const wchar_t* directory : {L"openvpn-dco\\win10", L"openvpn-dco\\win11", L"openvpn-dco", L"licenses"})
      Require(RemoveDirectoryW((root / directory).c_str()) != FALSE, "directory cleanup");
    Require(RemoveDirectoryW(root.c_str()) != FALSE, "fixture root cleanup");
    std::cout << "Portable manifest, payload integrity, path and IPC policy tests passed\n";
    return 0;
  } catch (const std::exception& exception) {
    std::cerr << exception.what() << '\n';
    return 1;
  }
}
