#include "../desktop_preference.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
void Require(bool valid, const char* message) {
  if (!valid) { std::cerr << message << '\n'; std::exit(1); }
}
struct Product { UINT query_error = ERROR_SUCCESS; INSTALLSTATE state = INSTALLSTATE_ABSENT; };
struct Fixture {
  std::vector<Product> products;
  UINT enumerate_error = ERROR_SUCCESS;
  size_t enumerations = 0, queries = 0;
  fuzevpn::installer::DesktopPreference Resolve(std::wstring_view supplied = L"-1") {
    return fuzevpn::installer::ResolveDesktopPreference(supplied,
        [this](const wchar_t* upgrade, DWORD reserved, DWORD index, wchar_t* product) -> UINT {
          ++enumerations;
          Require(std::wstring_view(upgrade) == fuzevpn::installer::kProductUpgradeCode && reserved == 0,
              "Wrong legacy upgrade identity.");
          if (enumerate_error != ERROR_SUCCESS) return enumerate_error;
          if (index >= products.size()) return ERROR_NO_MORE_ITEMS;
          const auto text = std::to_wstring(index);
          std::copy(text.begin(), text.end(), product);
          product[text.size()] = L'\0';
          return ERROR_SUCCESS;
        },
        [this](const wchar_t* product, const wchar_t* sid, MSIINSTALLCONTEXT context,
            const wchar_t* component, INSTALLSTATE* state) -> UINT {
          ++queries;
          Require(sid == nullptr && context == MSIINSTALLCONTEXT_MACHINE,
              "Desktop preference must query public per-machine MSI metadata.");
          Require(std::wstring_view(component) == fuzevpn::installer::kDesktopComponentCode,
              "Wrong legacy desktop component identity.");
          const auto& item = products[std::stoul(product)];
          *state = item.state;
          return item.query_error;
        });
  }
};
void IsValue(const fuzevpn::installer::DesktopPreference& result, const wchar_t* value) {
  Require(result.error == ERROR_SUCCESS && result.value && std::wstring_view(result.value) == value,
      "Unexpected restored preference.");
}
}

int main() {
  for (const auto* supplied : {L"0", L"1", L"", L"invalid"}) {
    Fixture fixture;
    const auto result = fixture.Resolve(supplied);
    Require(result.error == ERROR_SUCCESS && result.value == nullptr && fixture.enumerations == 0 && fixture.queries == 0,
        "Explicit caller preference was overwritten or queried.");
  }
  Fixture fresh;
  IsValue(fresh.Resolve(), L"0");
  Fixture installed{{{ERROR_SUCCESS, INSTALLSTATE_LOCAL}}};
  IsValue(installed.Resolve(), L"1");
  for (auto state : {INSTALLSTATE_ABSENT, INSTALLSTATE_UNKNOWN, INSTALLSTATE_NOTUSED, INSTALLSTATE_SOURCE}) {
    Fixture absent{{{ERROR_SUCCESS, state}}};
    IsValue(absent.Resolve(), L"0");
  }
  Fixture later{{{ERROR_UNKNOWN_COMPONENT, INSTALLSTATE_UNKNOWN}, {ERROR_SUCCESS, INSTALLSTATE_LOCAL}}};
  IsValue(later.Resolve(), L"1");
  Require(later.queries == 2, "Existing later related product was ignored.");
  Fixture removed{{{ERROR_UNKNOWN_PRODUCT, INSTALLSTATE_LOCAL}}};
  IsValue(removed.Resolve(), L"0");
  Fixture denied{{{ERROR_ACCESS_DENIED, INSTALLSTATE_LOCAL}}};
  const auto denied_result = denied.Resolve();
  Require(denied_result.error == ERROR_ACCESS_DENIED && std::wstring_view(denied_result.value) == L"0",
      "A metadata error must retain its diagnostic and choose the safe default.");
  Fixture corrupt;
  corrupt.enumerate_error = ERROR_BAD_CONFIGURATION;
  const auto corrupt_result = corrupt.Resolve();
  Require(corrupt_result.error == ERROR_BAD_CONFIGURATION && corrupt.queries == 0,
      "Enumeration errors must not query an uninitialized product.");
  Fixture bounded;
  bounded.products.resize(257);
  const auto bounded_result = bounded.Resolve();
  Require(bounded_result.error == ERROR_BAD_CONFIGURATION && bounded.enumerations == 256,
      "Corrupt product enumeration must be bounded.");
  std::cout << "Desktop preference metadata, defaults and caller overrides passed.\n";
}
