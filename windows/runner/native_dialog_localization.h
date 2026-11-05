// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_NATIVE_DIALOG_LOCALIZATION_H_
#define RUNNER_NATIVE_DIALOG_LOCALIZATION_H_

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <string_view>
#include <vector>

#include "generated_native_catalogs.h"

namespace fuzevpn::l10n {

inline std::wstring NormalizeNativeLocale(std::wstring_view value) {
  std::wstring normalized;
  for (const wchar_t character : value) {
    if (character >= L'A' && character <= L'Z') {
      normalized += static_cast<wchar_t>(character + (L'a' - L'A'));
    } else if ((character >= L'a' && character <= L'z') ||
               (character >= L'0' && character <= L'9') ||
               character == L'_') {
      normalized += character;
    } else if (character == L'-') {
      normalized += L'_';
    } else {
      return {};
    }
  }
  return normalized;
}

inline const NativeCatalog* FindNativeCatalog(std::wstring_view code) {
  for (const auto& catalog : native_catalogs) {
    if (catalog.code == code) return &catalog;
  }
  return nullptr;
}

inline const NativeCatalog* NativeStoredCatalog(std::wstring_view value) {
  if (value.size() > 64) return nullptr;
  std::wstring code(value);
  for (auto& character : code) {
    if (character == L'-') character = L'_';
  }
  if (const auto* catalog = FindNativeCatalog(code)) return catalog;
  constexpr struct { const wchar_t* saved; const wchar_t* catalog; } aliases[] = {
      {L"pt", L"pt_BR"}, {L"no", L"nb"}, {L"tl", L"fil"}, {L"iw", L"he"},
      {L"pa_Guru", L"pa"}, {L"az_Latn", L"az"}, {L"uz_Latn", L"uz"},
      {L"sr_Cyrl", L"sr"}, {L"ha_Latn", L"ha"},
      {L"zh", L"zh_Hans"}, {L"zh_CN", L"zh_Hans"}, {L"zh_SG", L"zh_Hans"},
      {L"zh_TW", L"zh_Hant"}, {L"zh_HK", L"zh_Hant"}, {L"zh_MO", L"zh_Hant"},
  };
  for (const auto& alias : aliases) {
    if (code == alias.saved) return FindNativeCatalog(alias.catalog);
  }
  return nullptr;
}

inline const NativeCatalog& NativeSystemCatalog(std::wstring_view locale) {
  const auto normalized = NormalizeNativeLocale(locale);
  const auto first_separator = normalized.find(L'_');
  const auto language = normalized.substr(0, first_separator);
  std::wstring script, region;
  if (first_separator != std::wstring::npos) {
    const auto second_separator = normalized.find(L'_', first_separator + 1);
    const auto second = normalized.substr(first_separator + 1,
        second_separator == std::wstring::npos ? std::wstring::npos :
        second_separator - first_separator - 1);
    if (second.size() == 4) script = second;
    else region = second;
    if (second_separator != std::wstring::npos) {
      region = normalized.substr(second_separator + 1);
    }
  }
  if (language == L"zh") {
    const bool traditional = script == L"hant" ||
        (script != L"hans" &&
         (region == L"tw" || region == L"hk" || region == L"mo"));
    return *FindNativeCatalog(traditional ? L"zh_Hant" : L"zh_Hans");
  }
  const auto* selected = NativeStoredCatalog(language);
  const auto* fallback = FindNativeCatalog(L"fr");
  if (selected == nullptr) return *fallback;
  const std::wstring_view code = selected->code;
  const wchar_t* required_script = nullptr;
  if (code == L"pa") required_script = L"guru";
  if (code == L"az" || code == L"uz" || code == L"ha") {
    required_script = L"latn";
  }
  if (code == L"sr") required_script = L"cyrl";
  if (required_script != nullptr && !script.empty() && script != required_script) {
    return *fallback;
  }
  if (script.empty() && ((code == L"pa" && region == L"pk") ||
      (code == L"az" && region == L"ir") ||
      (code == L"uz" && region == L"af"))) {
    return *fallback;
  }
  return *selected;
}

inline std::wstring NativeSystemLocaleName() {
  ULONG languages = 0, size = 0;
  if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &languages, nullptr, &size) &&
      size > 1 && size <= 32768) {
    std::vector<wchar_t> names(size);
    if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &languages,
                                    names.data(), &size) && names.front()) {
      return names.data();
    }
  }
  wchar_t locale[LOCALE_NAME_MAX_LENGTH]{};
  if (LCIDToLocaleName(MAKELCID(GetUserDefaultUILanguage(), SORT_DEFAULT), locale,
                      LOCALE_NAME_MAX_LENGTH, 0)) {
    return locale;
  }
  return L"fr";
}

inline const NativeCatalog& ResolveNativeCatalog(std::wstring_view saved,
                                                 std::wstring_view system) {
  const auto* selected = NativeStoredCatalog(saved);
  return selected != nullptr ? *selected : NativeSystemCatalog(system);
}

inline const NativeCatalog& ResolveNativeCatalog(std::string_view saved) {
  return ResolveNativeCatalog(std::wstring(saved.begin(), saved.end()),
                              NativeSystemLocaleName());
}

inline bool NativeRightToLeft(const NativeCatalog& catalog) {
  const std::wstring_view code = catalog.code;
  return code == L"ar" || code == L"fa" || code == L"ur" ||
         code == L"he" || code == L"ps";
}

inline std::wstring PortableUpdateFailureText(const NativeCatalog& catalog,
                                               DWORD error) {
  std::wstring windows_error = catalog.windows_error;
  const auto placeholder = windows_error.find(L"{code}");
  if (placeholder != std::wstring::npos) {
    windows_error.replace(placeholder, 6, std::to_wstring(error));
  }
  return std::wstring(catalog.portable_update_failure) + L"\n\n" +
      catalog.error_code + L" : \u2066update_portable_replace_failed\u2069\n" +
      windows_error;
}

inline void ShowNativeError(const NativeCatalog& catalog,
                            const std::wstring& title,
                            const std::wstring& message) {
  const TASKDIALOG_BUTTON close_button{IDCLOSE, catalog.close};
  TASKDIALOGCONFIG dialog{};
  dialog.cbSize = sizeof(dialog);
  dialog.dwFlags = static_cast<TASKDIALOG_FLAGS>(TDF_ALLOW_DIALOG_CANCELLATION |
      (NativeRightToLeft(catalog) ? TDF_RTL_LAYOUT : 0));
  dialog.pszWindowTitle = title.c_str();
  dialog.pszMainIcon = TD_ERROR_ICON;
  dialog.pszContent = message.c_str();
  dialog.cButtons = 1;
  dialog.pButtons = &close_button;
  dialog.nDefaultButton = IDCLOSE;
  if (FAILED(TaskDialogIndirect(&dialog, nullptr, nullptr, nullptr))) {
    MessageBoxW(nullptr, message.c_str(), title.c_str(), MB_OK | MB_ICONERROR |
        (NativeRightToLeft(catalog) ? MB_RTLREADING | MB_RIGHT : 0));
  }
}

}  // namespace fuzevpn::l10n

#endif  // RUNNER_NATIVE_DIALOG_LOCALIZATION_H_
