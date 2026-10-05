// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <array>
#include <optional>
#include <string>
#include "l10n/generated/installer_catalogs.h"

namespace fuzevpn::installer {
// Only the locale code is added to the existing opaque maintenance data. Paths,
// tokens, versions and restart flags retain their original validation downstream.
inline std::optional<std::array<std::wstring, 5>> SplitTransactionData(const std::wstring& data) {
  std::array<std::wstring, 5> fields;
  size_t begin = 0;
  size_t count = 0;
  for (;;) {
    if (count == fields.size()) return std::nullopt;
    const auto separator = data.find(L'\n', begin);
    fields[count++] = data.substr(begin, separator == std::wstring::npos ? separator : separator - begin);
    if (separator == std::wstring::npos) break;
    begin = separator + 1;
  }
  if (count == 4) fields[4] = L"en"; // Cached pre-localization package compatibility.
  else if (count != 5) return std::nullopt;
  if (!l10n::Find(fields[4])) return std::nullopt;
  return fields;
}
} // namespace fuzevpn::installer
