// SPDX-License-Identifier: MPL-2.0
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <shlobj.h>
#include <objbase.h>
#include <tlhelp32.h>
#include <array>
#include <string>
#include <vector>
#include <cwchar>
#include "l10n/generated/installer_catalogs.h"
#include "installer_version.h"
#include "transaction_data.h"
#include "platform_detection.h"
#include "maintenance_state.h"
#include "installation_security.h"
#include "desktop_preference.h"

namespace {
namespace localization = fuzevpn::installer::l10n;
using Message = localization::Message;
std::wstring Property(MSIHANDLE install, const wchar_t* name) {
  DWORD length = 0;
  wchar_t empty[1]{};
  const auto first = MsiGetPropertyW(install, name, empty, &length);
  if (first != ERROR_SUCCESS && first != ERROR_MORE_DATA) return {};
  std::wstring result(length + 1, L'\0');
  DWORD capacity = static_cast<DWORD>(result.size());
  if (MsiGetPropertyW(install, name, result.data(), &capacity) != ERROR_SUCCESS) return {};
  result.resize(capacity);
  return result;
}
const localization::Catalog& SelectedCatalog(MSIHANDLE install) {
  const auto data = Property(install, L"CustomActionData");
  if (!data.empty()) {
    const auto last = data.rfind(L'\n');
    if (last != std::wstring::npos) {
      if (const auto* catalog = localization::Find(data.substr(last + 1))) return *catalog;
    }
    // Old cached packages used four fields, with no locale. Never read paths as language codes.
    return localization::Resolve(1033);
  }
  const auto supplied = Property(install, L"FUZEVPN_LANGUAGE");
  if (!supplied.empty() && supplied.size() <= 5 && supplied.find_first_not_of(L"0123456789") == std::wstring::npos) {
    const auto value = std::wcstoul(supplied.c_str(), nullptr, 10);
    if (value <= 65535) return localization::Resolve(static_cast<unsigned>(value));
  }
  return localization::Resolve(GetUserDefaultUILanguage());
}
const wchar_t* T(MSIHANDLE install, Message message) {
  return localization::Text(SelectedCatalog(install), message);
}
void Replace(std::wstring* text, const std::wstring& token, const std::wstring& value) {
  size_t position = 0;
  while ((position = text->find(token, position)) != std::wstring::npos) {
    text->replace(position, token.size(), value);
    position += value.size();
  }
}
UINT Fail(MSIHANDLE install, const wchar_t* message) {
  MSIHANDLE record = MsiCreateRecord(1);
  if (record) {
    MsiRecordSetStringW(record, 0, L"FuzeVPN: [1]");
    MsiRecordSetStringW(record, 1, message);
    MsiProcessMessage(install, INSTALLMESSAGE_ERROR, record);
    MsiCloseHandle(record);
  }
  return ERROR_INSTALL_FAILURE;
}
UINT FailCode(MSIHANDLE install, const wchar_t* message, DWORD error) {
  std::wstring detail = T(install, Message::WindowsCode);
  Replace(&detail, L"{code}", std::to_wstring(error));
  Replace(&detail, L"{message}", message);
  return Fail(install, detail.c_str());
}
std::wstring EffectiveTokenDiagnostic() {
  HANDLE token = nullptr;
  DWORD error = ERROR_SUCCESS;
  if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    error = GetLastError();
    if (error == ERROR_NO_TOKEN) {
      if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) error = ERROR_SUCCESS;
      else error = GetLastError();
    }
  }
  std::wstring system = L"unknown", elevated = L"unknown";
  if (token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size && size <= 65536) {
      std::vector<BYTE> storage(size);
      if (GetTokenInformation(token, TokenUser, storage.data(), size, &size)) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
        system = IsWellKnownSid(user->User.Sid, WinLocalSystemSid) ? L"true" : L"false";
      } else error = GetLastError();
    } else error = ERROR_INVALID_DATA;
    TOKEN_ELEVATION state{};
    if (GetTokenInformation(token, TokenElevation, &state, sizeof(state), &size))
      elevated = state.TokenIsElevated ? L"true" : L"false";
    else error = GetLastError();
    CloseHandle(token);
  }
  return L" is_system=" + system + L" elevated=" + elevated +
      L" token_query_error=" + std::to_wstring(error);
}
UINT RestartWarning(MSIHANDLE install, DWORD error) {
  MSIHANDLE record = MsiCreateRecord(2);
  if (record) {
    MsiRecordSetStringW(record, 0, T(install, Message::WarningFormat));
    MsiRecordSetStringW(record, 1, T(install, Message::Native1));
    MsiRecordSetInteger(record, 2, static_cast<int>(error));
    MsiProcessMessage(install, INSTALLMESSAGE_WARNING, record);
    MsiCloseHandle(record);
  }
  // A service could already have mapped the new files. Starting a rollback
  // after an ambiguous start would replace those files underneath the process.
  return ERROR_SUCCESS;
}
std::wstring Normalize(std::wstring value) {
  std::wstring path(32768, L'\0');
  const DWORD size = GetFullPathNameW(value.c_str(), static_cast<DWORD>(path.size()), path.data(), nullptr);
  if (!size || size >= path.size()) return {};
  path.resize(size);
  while (!path.empty() && (path.back() == L'\\' || path.back() == L'/')) path.pop_back();
  return path;
}
bool ValidInstallDirectory(std::wstring supplied) {
  // MSI directory properties conventionally end in a separator. Validate the
  // actual requested path before normalization could hide relative/traversal
  // input. The elevated maintenance action validates owners, ACLs and reparse
  // points again before any installed file is replaced.
  while (!supplied.empty() && (supplied.back() == L'\\' || supplied.back() == L'/')) supplied.pop_back();
  return fuzevpn_installation::IsCanonicalLocalAbsolutePath(std::filesystem::path(supplied));
}
bool VersionAllowed(const std::wstring& directory, const std::wstring& incoming) {
  fuzevpn::installer::Version target;
  if (!fuzevpn::installer::ParseVersion(incoming, &target)) return false;
  const auto executable = Normalize(directory) + L"\\fuzevpn_windows.exe";
  if (GetFileAttributesW(executable.c_str()) == INVALID_FILE_ATTRIBUTES)
    return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND;
  DWORD ignored = 0;
  const DWORD bytes = GetFileVersionInfoSizeW(executable.c_str(), &ignored);
  if (!bytes || bytes > 1024 * 1024) return false;
  std::vector<BYTE> data(bytes);
  if (!GetFileVersionInfoW(executable.c_str(), 0, bytes, data.data())) return false;
  VS_FIXEDFILEINFO* info = nullptr; UINT length = 0;
  if (!VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &length) ||
      !info || length < sizeof(*info) || info->dwSignature != 0xFEEF04BD) return false;
  const fuzevpn::installer::Version installed{HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS),
      HIWORD(info->dwFileVersionLS), LOWORD(info->dwFileVersionLS)};
  return fuzevpn::installer::UpgradeAllowed(installed, target);
}
bool ApplicationProcessesExited(const std::wstring& directory) {
  const auto root = Normalize(directory);
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
  bool exited = true;
  if (!Process32FirstW(snapshot, &entry)) exited = GetLastError() == ERROR_NO_MORE_FILES;
  else do {
    if (_wcsicmp(entry.szExeFile, L"fuzevpn_windows.exe") != 0 &&
        _wcsicmp(entry.szExeFile, L"fuzevpn-update.exe") != 0) continue;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE, entry.th32ProcessID);
    if (!process) {
      if (GetLastError() != ERROR_INVALID_PARAMETER) exited = false;
      continue;
    }
    wchar_t path[32768]{}; DWORD size = static_cast<DWORD>(std::size(path));
    if (WaitForSingleObject(process, 0) != WAIT_OBJECT_0) {
      if (!QueryFullProcessImageNameW(process, 0, path, &size)) exited = false;
      else {
        const auto normalized = Normalize(path);
        for (const auto* name : {L"fuzevpn_windows.exe", L"fuzevpn-update.exe"})
          if (_wcsicmp(normalized.c_str(), (root + L"\\" + name).c_str()) == 0) exited = false;
      }
    }
    CloseHandle(process);
  } while (Process32NextW(snapshot, &entry));
  CloseHandle(snapshot);
  return exited;
}
bool WaitForApplicationExit(const std::wstring& directory) {
  const auto deadline = GetTickCount64() + 30000;
  do {
    if (ApplicationProcessesExited(directory)) return true;
    Sleep(100);
  } while (GetTickCount64() < deadline);
  return false;
}
struct Transaction { std::wstring token, directory, version; bool restart = false; };
bool ReadTransaction(MSIHANDLE install, Transaction* transaction) {
  auto data = Property(install, L"CustomActionData");
  const auto parsed = fuzevpn::installer::SplitTransactionData(data);
  if (!parsed) return false;
  const auto& fields = *parsed;
  GUID guid{};
  const auto braced_token = L"{" + fields[0] + L"}";
  if (fields[0].size() != 36 || CLSIDFromString(braced_token.c_str(), &guid) != S_OK || !ValidInstallDirectory(fields[1]) ||
      (fields[3] != L"0" && fields[3] != L"1")) return false;
  *transaction = {fields[0], Normalize(fields[1]), fields[2], fields[3] == L"1"};
  return true;
}
}

extern "C" __declspec(dllexport) UINT __stdcall InitializeLocalization(MSIHANDLE install) {
  try {
    const auto& catalog = SelectedCatalog(install);
    struct LocalizedProperty { const wchar_t* name; Message message; };
    const LocalizedProperty properties[] = {
      {L"FUZEVPN_DOWNGRADE", Message::Downgrade},
      {L"FUZEVPN_WINDOWS_X64", Message::WindowsX64},
      {L"FUZEVPN_ROLLBACK", Message::Rollback},
      {L"FUZEVPN_SERVICE_NAME", Message::ServiceDisplayName},
      {L"FUZEVPN_SERVICE_DESCRIPTION", Message::ServiceDescription},
    };
    for (const auto& property : properties) {
      std::wstring text = localization::Text(catalog, property.message);
      Replace(&text, L"{Architecture}", fuzevpn::installer::kTargetArchitecture);
      if (MsiSetPropertyW(install, property.name, text.c_str()) != ERROR_SUCCESS) return ERROR_INSTALL_FAILURE;
    }
    return MsiSetPropertyW(install, L"FUZEVPN_LANGUAGE", std::to_wstring(catalog.language_id).c_str());
  } catch (...) { return ERROR_INSTALL_FAILURE; }
}

extern "C" __declspec(dllexport) UINT __stdcall InitializeDesktopShortcut(MSIHANDLE install) {
  try {
    const auto preference = fuzevpn::installer::ResolveDesktopPreference(
        Property(install, L"DESKTOP_SHORTCUT"), MsiEnumRelatedProductsW, MsiQueryComponentStateW);
    if (preference.error != ERROR_SUCCESS) {
      MSIHANDLE record = MsiCreateRecord(1);
      if (record) {
        MsiRecordSetStringW(record, 0,
            L"FuzeVPN: previous desktop shortcut could not be queried (Windows code [1]); defaulting to no shortcut.");
        MsiRecordSetInteger(record, 1, static_cast<int>(preference.error));
        MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
        MsiCloseHandle(record);
      }
    }
    return preference.value ? MsiSetPropertyW(install, L"DESKTOP_SHORTCUT", preference.value) : ERROR_SUCCESS;
  } catch (...) { return ERROR_INSTALL_FAILURE; }
}

extern "C" __declspec(dllexport) UINT __stdcall InitializeMaintenance(MSIHANDLE install) {
  try {
    const auto platform = fuzevpn::installer::ReadPlatform();
    MSIHANDLE record = MsiCreateRecord(1);
    if (record) {
      MsiRecordSetStringW(record, 0, L"[1]");
      MsiRecordSetStringW(record, 1, fuzevpn::installer::PlatformDiagnostic(platform).c_str());
      MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
      MsiCloseHandle(record);
    }
    switch (fuzevpn::installer::EvaluatePlatform(platform)) {
      case fuzevpn::installer::PlatformStatus::detection_failed:
        return FailCode(install, T(install, Message::Native2), platform.error);
      case fuzevpn::installer::PlatformStatus::unsupported_os:
        return Fail(install, T(install, Message::Native3));
      case fuzevpn::installer::PlatformStatus::unsupported_architecture:
        {
          std::wstring text = T(install, Message::Native4);
          Replace(&text, L"{Architecture}", fuzevpn::installer::kTargetArchitecture);
          return Fail(install, text.c_str());
        }
      case fuzevpn::installer::PlatformStatus::supported:
        break;
    }
    if (!Property(install, L"RollbackDisabled").empty())
      return Fail(install, T(install, Message::Native5));
    const auto requested_directory = Property(install, L"INSTALLFOLDER");
    if (!ValidInstallDirectory(requested_directory)) return Fail(install, T(install, Message::Native6));
    const auto directory = Normalize(requested_directory);
    const auto version = Property(install, L"FUZEVPN_VERSION4");
    const bool removing = Property(install, L"REMOVE") == L"ALL";
    if (!removing && !VersionAllowed(directory, version))
      return Fail(install, T(install, Message::Native7));
    GUID id{}; wchar_t token[40]{};
    if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, token, 40)) return ERROR_INSTALL_FAILURE;
    const std::wstring data = std::wstring(token + 1, 36) + L"\n" + directory + L"\n" + version + L"\n" + (removing ? L"0" : L"1") + L"\n" + SelectedCatalog(install).code;
    for (const auto* action : {L"BeginMaintenance", L"CommitMaintenance", L"RollbackMaintenance"})
      if (MsiSetPropertyW(install, action, data.c_str()) != ERROR_SUCCESS) return ERROR_INSTALL_FAILURE;
    return ERROR_SUCCESS;
  } catch (...) { return Fail(install, T(install, Message::Native8)); }
}
extern "C" __declspec(dllexport) UINT __stdcall BeginMaintenance(MSIHANDLE install) {
  try {
    Transaction transaction;
    if (!ReadTransaction(install, &transaction) ||
        (transaction.restart && !VersionAllowed(transaction.directory, transaction.version)))
      return Fail(install, T(install, Message::Native9));
    DWORD error = ERROR_SUCCESS;
    if (!fuzevpn_maintenance::BeginInstallerMaintenance(transaction.token, transaction.directory, &error)) {
      MSIHANDLE diagnostic = MsiCreateRecord(0);
      if (diagnostic) {
        const std::wstring text = L"FuzeVPN maintenance: stage=" +
            std::wstring(fuzevpn_maintenance::LastInstallerMaintenanceStage()) +
            L" win32=" + std::to_wstring(error) + EffectiveTokenDiagnostic();
        MsiRecordSetStringW(diagnostic, 0, text.c_str());
        MsiProcessMessage(install, INSTALLMESSAGE_INFO, diagnostic);
        MsiCloseHandle(diagnostic);
      }
      return FailCode(install, T(install, Message::Native10), error);
    }
    if (!WaitForApplicationExit(transaction.directory))
      return Fail(install, T(install, Message::Native11));
    return ERROR_SUCCESS;
  } catch (...) { return Fail(install, T(install, Message::Native12)); }
}
extern "C" __declspec(dllexport) UINT __stdcall CommitMaintenance(MSIHANDLE install) {
  bool restart_attempted = false;
  try {
    Transaction transaction; DWORD error = ERROR_SUCCESS;
    if (!ReadTransaction(install, &transaction)) return ERROR_INSTALL_FAILURE;
    if (!fuzevpn_maintenance::EndInstallerMaintenance(transaction.token, transaction.restart, &error, &restart_attempted)) {
      if (restart_attempted) return RestartWarning(install, error);
      return FailCode(install, T(install, Message::Native13), error);
    }
    return ERROR_SUCCESS;
  } catch (...) { return restart_attempted ? RestartWarning(install, ERROR_UNHANDLED_EXCEPTION) : ERROR_INSTALL_FAILURE; }
}
extern "C" __declspec(dllexport) UINT __stdcall RollbackMaintenance(MSIHANDLE install) {
  try {
    Transaction transaction; DWORD error = ERROR_SUCCESS;
    if (!ReadTransaction(install, &transaction) || !fuzevpn_maintenance::EndInstallerMaintenance(transaction.token, true, &error))
      return FailCode(install, T(install, Message::Native14), error);
    return ERROR_SUCCESS;
  } catch (...) { return ERROR_INSTALL_FAILURE; }
}
