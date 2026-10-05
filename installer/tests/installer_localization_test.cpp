#include "../l10n/generated/installer_catalogs.h"
#include "../transaction_data.h"
#include <iterator>
#include <string>

int main() {
  namespace loc = fuzevpn::installer::l10n;
  if (std::size(loc::catalogs) != 30) return 1;
  for (const auto& catalog : loc::catalogs) {
    if (loc::Find(catalog.code) != &catalog || &loc::Resolve(catalog.language_id) != &catalog) return 2;
    for (const auto* text : catalog.text) if (!text || !*text) return 3;
  }
  for (const auto id : {1028u, 3076u, 5124u, 31748u})
    if (std::wstring_view(loc::Resolve(id).code) != L"zh_Hant") return 4;
  for (const auto id : {2052u, 4100u, 4u})
    if (std::wstring_view(loc::Resolve(id).code) != L"zh_Hans") return 5;
  if (std::wstring_view(loc::Resolve(0xffff).code) != L"en") return 6;
  if (std::wstring_view(loc::Resolve(2057).code) != L"en") return 7; // en-GB fallback.
  const std::wstring legacy = L"token\nC:\\Program Files\\FuzeVPN\n1.2.3.0\n1";
  const auto previous = fuzevpn::installer::SplitTransactionData(legacy);
  if (!previous || (*previous)[4] != L"en") return 8;
  for (const auto& catalog : loc::catalogs) {
    const auto current = fuzevpn::installer::SplitTransactionData(legacy + L"\n" + catalog.code);
    if (!current || (*current)[4] != catalog.code) return 9;
    for (size_t i = 0; i < 4; ++i) if ((*current)[i] != (*previous)[i]) return 10;
  }
  for (const auto& invalid : {legacy + L"\nunknown", legacy + L"\nar\nextra", legacy + L"\n", std::wstring(L"one\ntwo\nthree")})
    if (fuzevpn::installer::SplitTransactionData(invalid)) return 11;
  return 0;
}
