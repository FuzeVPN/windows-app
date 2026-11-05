// SPDX-License-Identifier: MPL-2.0
// Pure catalog selection and formatting checks. No dialog or product is opened.
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include "native_dialog_localization.h"

namespace {
void Check(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void Selected(std::wstring_view saved, std::wstring_view system,
              std::wstring_view expected) {
  Check(fuzevpn::l10n::ResolveNativeCatalog(saved, system).code == expected,
        "native dialog selected a different language from the application");
}
}  // namespace

int main() {
  try {
    using namespace fuzevpn::l10n;
    Check(std::size(native_catalogs) == 70, "all 70 native catalogs are required");
    unsigned right_to_left = 0;
    for (const auto& catalog : native_catalogs) {
      Selected(catalog.code, L"en-US", catalog.code);
      Check(catalog.startup_failure[0] && catalog.portable_update_failure[0] &&
            catalog.updates[0] && catalog.error_code[0] &&
            catalog.windows_error[0] && catalog.close[0],
            "native dialog has an empty translation");
      const auto message = PortableUpdateFailureText(catalog, 1234567890);
      Check(message.find(L"1234567890") != std::wstring::npos &&
            message.find(L"{code}") == std::wstring::npos &&
            message.find(L"update_portable_replace_failed") != std::wstring::npos,
            "localized portable failure lost its technical references");
      Check(message.find(catalog.portable_update_failure) != std::wstring::npos &&
            message.find(catalog.error_code) != std::wstring::npos,
            "portable failure omitted localized content");
      if (NativeRightToLeft(catalog)) ++right_to_left;
    }
    Check(right_to_left == 5, "right-to-left languages must match Flutter");
    Selected(L"fr", L"en-US", L"fr");
    Selected(L"system", L"de-DE", L"de");
    Selected(L"invalid-language", L"ja-JP", L"ja");
    Selected(L"EN", L"de-DE", L"de");
    Selected(L"", L"unsupported", L"fr");
    Selected(L"", L"", L"fr");
    Selected(L"pt", L"en-US", L"pt_BR");
    Selected(L"no", L"en-US", L"nb");
    Selected(L"tl", L"en-US", L"fil");
    Selected(L"iw", L"en-US", L"he");
    Selected(L"pa_Guru", L"en-US", L"pa");
    Selected(L"az_Latn", L"en-US", L"az");
    Selected(L"uz_Latn", L"en-US", L"uz");
    Selected(L"sr_Cyrl", L"en-US", L"sr");
    Selected(L"ha_Latn", L"en-US", L"ha");
    Selected(L"zh-TW", L"en-US", L"zh_Hant");
    Selected(L"zh-CN", L"en-US", L"zh_Hans");
    Selected(L"system", L"zh-Hant-CN", L"zh_Hant");
    Selected(L"system", L"zh-Hans-TW", L"zh_Hans");
    Selected(L"system", L"zh-HK", L"zh_Hant");
    Selected(L"system", L"pt-PT", L"pt_BR");
    Selected(L"system", L"pa-PK", L"fr");
    Selected(L"system", L"pa-Guru-PK", L"pa");
    Selected(L"system", L"az-IR", L"fr");
    Selected(L"system", L"uz-AF", L"fr");
    Selected(L"system", L"sr-Latn-RS", L"fr");
    Selected(L"system", L"ha-Arab-NG", L"fr");
    Selected(L"system", L"sr-Cyrl-RS", L"sr");
    Check(NativeStoredCatalog(L"en --source bad") == nullptr &&
          NativeStoredCatalog(L"en\"bad") == nullptr &&
          NativeStoredCatalog(L"en-US") == nullptr,
          "helper locale must resolve to a whitelisted stored language");
    std::cout << "PASS: 70 native dialog languages, saved/system precedence, aliases, scripts, RTL and error references\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
