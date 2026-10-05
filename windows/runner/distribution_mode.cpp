// SPDX-License-Identifier: MPL-2.0
#include "distribution_mode.h"
#include "installation_security.h"

#include <windows.h>
#include <msi.h>
#include <mutex>
#include <string_view>
#include <vector>

namespace fuzevpn_distribution {
namespace {
constexpr wchar_t kServiceComponent[] = L"{7BFDFB64-AEB8-4957-8C31-F4B4C62EE911}";
std::mutex discovery_mutex;
std::wstring Normalized(const std::filesystem::path& path) {
  if (!path.is_absolute() || !path.has_root_directory() ||
      path.native().find(L'\0') != std::wstring::npos) return {};
  // Distribution detection never follows a path supplied through MSI metadata
  // to execute code. Runtime/authentication perform their own handle checks.
  auto value = path.wstring();
  while (value.size() > 3 && (value.back() == L'\\' || value.back() == L'/'))
    value.pop_back();
  for (auto& character : value) if (character == L'/') character = L'\\';
  if (!fuzevpn_installation::IsCanonicalLocalAbsolutePath(value)) return {};
  return value;
}
}

Mode ClassifyMode(bool registration_readable, bool registered, bool portable_marker,
                  const std::filesystem::path& registered_directory,
                  const std::filesystem::path& current_directory) {
  const auto current = Normalized(current_directory);
  if (current.empty()) return Mode::unavailable;
  if (portable_marker) return Mode::portable;
  if (!registration_readable) return Mode::unavailable;
  if (!registered) return Mode::portable;
  const auto installed = Normalized(registered_directory);
  if (installed.empty()) return Mode::unavailable;
  return CompareStringOrdinal(current.c_str(), -1, installed.c_str(), -1, TRUE)
          == CSTR_EQUAL ? Mode::installed : Mode::portable;
}

Mode CurrentMode() {
  const auto unavailable = [](DWORD error) {
    SetLastError(error == ERROR_SUCCESS ? ERROR_BAD_CONFIGURATION : error);
    return Mode::unavailable;
  };
  const auto available = [](Mode mode) { SetLastError(ERROR_SUCCESS); return mode; };
  try {
    std::wstring image(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
    if (!length) return unavailable(GetLastError());
    if (length >= image.size()) return unavailable(ERROR_INSUFFICIENT_BUFFER);
    image.resize(length);
    const auto directory = std::filesystem::path(image).parent_path();
    if (Normalized(directory).empty()) return unavailable(ERROR_BAD_CONFIGURATION);
    const auto marker = directory / L"fuzevpn.portable";
    const auto marker_attributes = GetFileAttributesW(marker.c_str());
    const bool marked = marker_attributes != INVALID_FILE_ATTRIBUTES &&
        !(marker_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
    if (marker_attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD marker_error = GetLastError();
      if (marker_error != ERROR_FILE_NOT_FOUND && marker_error != ERROR_PATH_NOT_FOUND)
        return unavailable(marker_error);
    }
    // A marked archive is portable without querying another installation's
    // metadata. This selects the existing authenticated
    // portable bootstrap; it grants no privilege and bypasses no runtime trust.
    if (marked) return available(Mode::portable);
    // The installer key intentionally has a private DACL and may remain
    // inaccessible after a legacy upgrade. MSI exposes component registration
    // to ordinary users without weakening that key or granting runtime trust.
    // The stable service component also covers pre-1.0 installer metadata.
    // Windows Installer maintains an enumeration cursor. Finish each sequence
    // on this thread before looking up paths or returning, and prevent our
    // platform/dispatcher threads from interleaving those sequences.
    const std::lock_guard discovery_lock(discovery_mutex);
    struct Client { std::wstring product; MSIINSTALLCONTEXT context; };
    std::vector<Client> clients;
    bool complete = false;
    for (DWORD index = 0; index < 256; ++index) {
      wchar_t product[39]{};
      MSIINSTALLCONTEXT context = MSIINSTALLCONTEXT_NONE;
      const UINT enumerated = MsiEnumClientsExW(kServiceComponent, nullptr,
          MSIINSTALLCONTEXT_MACHINE, index, product, &context, nullptr, nullptr);
      if (enumerated == ERROR_NO_MORE_ITEMS || enumerated == ERROR_UNKNOWN_COMPONENT) {
        complete = true;
        break;
      }
      if (enumerated != ERROR_SUCCESS) return unavailable(enumerated);
      clients.push_back({product, context});
    }
    if (!complete) return unavailable(ERROR_BAD_CONFIGURATION);
    for (const auto& client : clients) {
      if (client.context != MSIINSTALLCONTEXT_MACHINE) return unavailable(ERROR_BAD_CONFIGURATION);
      std::vector<wchar_t> value(32768);
      DWORD characters = static_cast<DWORD>(value.size());
      const auto state = MsiGetComponentPathExW(client.product.c_str(), kServiceComponent, nullptr,
          MSIINSTALLCONTEXT_MACHINE, value.data(), &characters);
      if (state != INSTALLSTATE_LOCAL || characters == 0 || characters >= value.size() ||
          value[characters] != L'\0' ||
          std::wstring_view(value.data(), characters).find(L'\0') != std::wstring_view::npos)
        return unavailable(state == INSTALLSTATE_MOREDATA ? ERROR_MORE_DATA : ERROR_BAD_CONFIGURATION);
      const std::filesystem::path service(value.data());
      if (Normalized(service).empty() || CompareStringOrdinal(
          service.filename().c_str(), -1, L"fuzevpn-service.exe", -1, TRUE) != CSTR_EQUAL)
        return unavailable(ERROR_BAD_CONFIGURATION);
      const auto classified = ClassifyMode(true, true, false, service.parent_path(), directory);
      if (classified != Mode::portable)
        return classified == Mode::unavailable ? unavailable(ERROR_BAD_CONFIGURATION) : available(classified);
    }
    return available(Mode::portable);
  } catch (...) { return unavailable(ERROR_BAD_CONFIGURATION); }
}

const char* ModeName(Mode mode) {
  switch (mode) {
    case Mode::installed: return "installed";
    case Mode::portable: return "portable";
    case Mode::unavailable: return "unavailable";
  }
  return "unavailable";
}
}  // namespace fuzevpn_distribution
