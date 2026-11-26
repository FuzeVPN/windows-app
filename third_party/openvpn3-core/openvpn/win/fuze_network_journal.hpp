// SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdint>
#include <cwchar>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <openvpn/win/dco_adapter_reuse.hpp>
#include <openvpn/win/nrpt_session.hpp>

namespace openvpn::Win {

// Windows network state that a FuzeVPN OpenVPN runtime created: the routes it
// owns, on any interface, and the DCO adapter it holds. A runtime that ends
// abnormally cannot remove them; a later one does, and only for an owner
// process that no longer exists. The key is volatile: a Windows restart
// clears it together with that state. Writing it requires administrator
// rights, like the routes it describes.
inline constexpr wchar_t kFuzeNetworkJournalParent[] = L"SOFTWARE\\FuzeVPN";
inline constexpr wchar_t kFuzeNetworkJournalKey[] = L"SOFTWARE\\FuzeVPN\\OpenVpnNetworkState";
inline constexpr wchar_t kFuzeJournalAdapterValue[] = L"Adapter";

struct JournalOwner {
    DWORD pid = 0;
    std::uint64_t created = 0;
    bool operator==(const JournalOwner&) const = default;
};

inline std::wstring JournalOwnerName(const JournalOwner& owner) {
    return std::to_wstring(owner.pid) + L"-" + std::to_wstring(owner.created);
}

inline bool ParseJournalOwnerName(std::wstring_view name, JournalOwner* owner) {
    const auto dash = name.find(L'-');
    if (!owner || dash == std::wstring_view::npos) return false;
    std::uint64_t pid = 0, created = 0;
    if (!NrptNumber(name.substr(0, dash), MAXDWORD, &pid) || !pid ||
        !NrptNumber(name.substr(dash + 1), (std::numeric_limits<std::uint64_t>::max)(), &created) ||
        !created) return false;
    *owner = {static_cast<DWORD>(pid), created};
    return true;
}

inline JournalOwner CurrentJournalOwner() {
    return {GetCurrentProcessId(), ProcessCreationValue(GetCurrentProcess())};
}

// "R|<4|6>|<interface LUID, 16 hex digits>|<destination>|<prefix>|<next hop>":
// the exact tuple IP Helper needs to delete the route.
inline std::optional<std::wstring> JournalRouteName(const MIB_IPFORWARD_ROW2& row) {
    const ADDRESS_FAMILY family = row.DestinationPrefix.Prefix.si_family;
    if (family != AF_INET && family != AF_INET6) return std::nullopt;
    NET_LUID luid = row.InterfaceLuid;
    if (!luid.Value && ConvertInterfaceIndexToLuid(row.InterfaceIndex, &luid) != NO_ERROR)
        return std::nullopt;
    if (!luid.Value) return std::nullopt;
    wchar_t destination[INET6_ADDRSTRLEN]{}, next_hop[INET6_ADDRSTRLEN]{};
    const void* prefix = family == AF_INET
        ? static_cast<const void*>(&row.DestinationPrefix.Prefix.Ipv4.sin_addr)
        : static_cast<const void*>(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr);
    const void* hop = family == AF_INET
        ? static_cast<const void*>(&row.NextHop.Ipv4.sin_addr)
        : static_cast<const void*>(&row.NextHop.Ipv6.sin6_addr);
    if (!InetNtopW(family, prefix, destination, INET6_ADDRSTRLEN) ||
        !InetNtopW(family, hop, next_hop, INET6_ADDRSTRLEN)) return std::nullopt;
    wchar_t interface_luid[17]{};
    swprintf_s(interface_luid, L"%016llx", static_cast<unsigned long long>(luid.Value));
    return std::wstring(L"R|") + (family == AF_INET ? L"4" : L"6") + L"|" + interface_luid +
        L"|" + destination + L"|" + std::to_wstring(row.DestinationPrefix.PrefixLength) + L"|" +
        next_hop;
}

inline bool ParseJournalRouteName(std::wstring_view name, MIB_IPFORWARD_ROW2* row) {
    if (!row) return false;
    std::vector<std::wstring> fields;
    for (size_t start = 0;;) {
        const auto bar = name.find(L'|', start);
        fields.emplace_back(name.substr(start, bar == std::wstring_view::npos ? bar : bar - start));
        if (bar == std::wstring_view::npos) break;
        start = bar + 1;
    }
    if (fields.size() != 6 || fields[0] != L"R" || (fields[1] != L"4" && fields[1] != L"6") ||
        fields[2].size() != 16) return false;
    const ADDRESS_FAMILY family = fields[1] == L"4" ? AF_INET : AF_INET6;
    std::uint64_t luid = 0;
    for (const wchar_t c : fields[2]) {
        const int digit = c >= L'0' && c <= L'9' ? c - L'0' : c >= L'a' && c <= L'f' ? c - L'a' + 10 : -1;
        if (digit < 0) return false;
        luid = (luid << 4) | static_cast<std::uint64_t>(digit);
    }
    std::uint64_t prefix = 0;
    if (!luid || !NrptNumber(fields[4], family == AF_INET ? 32 : 128, &prefix)) return false;
    MIB_IPFORWARD_ROW2 parsed{};
    parsed.InterfaceLuid.Value = luid;
    parsed.DestinationPrefix.Prefix.si_family = family;
    parsed.NextHop.si_family = family;
    void* destination = family == AF_INET
        ? static_cast<void*>(&parsed.DestinationPrefix.Prefix.Ipv4.sin_addr)
        : static_cast<void*>(&parsed.DestinationPrefix.Prefix.Ipv6.sin6_addr);
    void* next_hop = family == AF_INET ? static_cast<void*>(&parsed.NextHop.Ipv4.sin_addr)
                                       : static_cast<void*>(&parsed.NextHop.Ipv6.sin6_addr);
    if (InetPtonW(family, fields[3].c_str(), destination) != 1 ||
        InetPtonW(family, fields[5].c_str(), next_hop) != 1) return false;
    parsed.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix);
    *row = parsed;
    return true;
}

class JournalKey {
public:
    JournalKey() = default;
    explicit JournalKey(HKEY key) : key_(key) {}
    JournalKey(const JournalKey&) = delete;
    JournalKey& operator=(const JournalKey&) = delete;
    ~JournalKey() { if (key_) RegCloseKey(key_); }
    HKEY get() const { return key_; }
private:
    HKEY key_ = nullptr;
};

inline HKEY OpenJournalOwnerKey(const JournalOwner& owner, bool create) {
    const std::wstring path = std::wstring(kFuzeNetworkJournalKey) + L"\\" + JournalOwnerName(owner);
    HKEY key = nullptr;
    if (!create) {
        return RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_SET_VALUE | KEY_QUERY_VALUE,
                             &key) == ERROR_SUCCESS ? key : nullptr;
    }
    // The parent stays persistent: other FuzeVPN keys below it are not
    // volatile, and a volatile parent would refuse them.
    HKEY parent = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kFuzeNetworkJournalParent, 0, nullptr, 0,
                        KEY_CREATE_SUB_KEY, nullptr, &parent, nullptr) != ERROR_SUCCESS) return nullptr;
    RegCloseKey(parent);
    return RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, REG_OPTION_VOLATILE,
                           KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS
        ? key : nullptr;
}

// Best effort: a missing entry only loses crash recovery, never a connection.
inline void JournalOwnedRoute(const MIB_IPFORWARD_ROW2& row, bool present) noexcept {
    try {
        const auto name = JournalRouteName(row);
        if (!name) return;
        const JournalKey key(OpenJournalOwnerKey(CurrentJournalOwner(), present));
        if (!key.get()) return;
        if (present) RegSetValueExW(key.get(), name->c_str(), 0, REG_NONE, nullptr, 0);
        else RegDeleteValueW(key.get(), name->c_str());
    } catch (...) {
    }
}

inline bool JournalHasOwnedRoute(const MIB_IPFORWARD_ROW2& row) noexcept {
    try {
        const auto name = JournalRouteName(row);
        if (!name) return false;
        const JournalKey key(OpenJournalOwnerKey(CurrentJournalOwner(), false));
        return key.get() &&
            RegQueryValueExW(key.get(), name->c_str(), nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
    } catch (...) {
        return false;
    }
}

inline void JournalDcoAdapter(ULONG index) noexcept {
    NET_LUID luid{};
    if (ConvertInterfaceIndexToLuid(index, &luid) != NO_ERROR || !luid.Value) return;
    const JournalKey key(OpenJournalOwnerKey(CurrentJournalOwner(), true));
    if (key.get())
        RegSetValueExW(key.get(), kFuzeJournalAdapterValue, 0, REG_QWORD,
                       reinterpret_cast<const BYTE*>(&luid.Value), sizeof(luid.Value));
}

struct JournalEntry {
    std::wstring name;
    JournalOwner owner;
    std::optional<std::uint64_t> adapter;
    std::vector<std::wstring> routes;
};

inline bool ReadNetworkJournal(std::vector<JournalEntry>* entries) {
    HKEY root = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kFuzeNetworkJournalKey, 0, KEY_READ, &root);
    if (opened == ERROR_FILE_NOT_FOUND) return true;
    if (opened != ERROR_SUCCESS) return false;
    const JournalKey root_key(root);
    for (DWORD index = 0;; ++index) {
        wchar_t name[64]{};
        DWORD length = static_cast<DWORD>(std::size(name));
        const auto status = RegEnumKeyExW(root, index, name, &length, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) return false;
        JournalEntry entry;
        entry.name.assign(name, length);
        if (!ParseJournalOwnerName(entry.name, &entry.owner)) continue;
        HKEY owner = nullptr;
        if (RegOpenKeyExW(root, entry.name.c_str(), 0, KEY_QUERY_VALUE, &owner) != ERROR_SUCCESS) return false;
        const JournalKey owner_key(owner);
        for (DWORD value = 0;; ++value) {
            wchar_t value_name[256]{};
            DWORD value_length = static_cast<DWORD>(std::size(value_name));
            DWORD type = 0;
            std::uint64_t data = 0;
            DWORD size = sizeof(data);
            const auto read = RegEnumValueW(owner, value, value_name, &value_length, nullptr, &type,
                                            reinterpret_cast<BYTE*>(&data), &size);
            if (read == ERROR_NO_MORE_ITEMS) break;
            if (read != ERROR_SUCCESS) continue;
            const std::wstring_view value_view(value_name, value_length);
            if (value_view == kFuzeJournalAdapterValue && type == REG_QWORD && size == sizeof(data))
                entry.adapter = data;
            else if (value_view.starts_with(L"R|"))
                entry.routes.emplace_back(value_view);
        }
        entries->push_back(std::move(entry));
    }
    return true;
}

inline NrptProcessState ProbeJournalOwner(const JournalOwner& owner) {
    if (owner == CurrentJournalOwner()) return NrptProcessState::matching_live;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, owner.pid);
    if (!process)
        return GetLastError() == ERROR_INVALID_PARAMETER ? NrptProcessState::orphaned
                                                         : NrptProcessState::unavailable;
    const auto created = ProcessCreationValue(process);
    const auto exited = WaitForSingleObject(process, 0);
    CloseHandle(process);
    if (!created || exited == WAIT_FAILED) return NrptProcessState::unavailable;
    return exited == WAIT_OBJECT_0 || created != owner.created ? NrptProcessState::orphaned
                                                               : NrptProcessState::matching_live;
}

// Deletes the exact routes an orphaned owner created. A route already gone,
// for instance with its interface, is not an error.
inline bool RemoveJournalRoutes(const JournalEntry& entry) {
    HKEY owner = nullptr;
    const std::wstring path = std::wstring(kFuzeNetworkJournalKey) + L"\\" + entry.name;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_SET_VALUE, &owner) != ERROR_SUCCESS)
        return false;
    const JournalKey owner_key(owner);
    bool success = true;
    for (const auto& name : entry.routes) {
        MIB_IPFORWARD_ROW2 row{};
        if (ParseJournalRouteName(name, &row)) {
            const auto status = DeleteIpForwardEntry2(&row);
            if (status != NO_ERROR && status != ERROR_NOT_FOUND && status != ERROR_FILE_NOT_FOUND) {
                success = false;
                continue;
            }
        }
        RegDeleteValueW(owner, name.c_str());
    }
    return success;
}

inline void DeleteJournalOwner(const JournalEntry& entry) {
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kFuzeNetworkJournalKey, 0, KEY_SET_VALUE | DELETE, &root) ==
        ERROR_SUCCESS) {
        RegDeleteTreeW(root, entry.name.c_str());
        RegCloseKey(root);
    }
}

// At runtime start: removes the routes of every owner process that is gone.
// An owner that held a DCO adapter keeps its entry until that adapter is
// reclaimed with an exclusive handle (see ReclaimOrphanedDcoAdapter).
inline void RecoverOrphanedRoutes() noexcept {
    try {
        std::vector<JournalEntry> entries;
        if (!ReadNetworkJournal(&entries)) return;
        for (auto& entry : entries) {
            if (ProbeJournalOwner(entry.owner) != NrptProcessState::orphaned) continue;
            if (!RemoveJournalRoutes(entry)) continue;
            // An adapter that is gone or already clean leaves nothing to
            // reclaim: the entry would otherwise remain until Windows restarts.
            NET_IFINDEX index = 0;
            NET_LUID luid{};
            if (entry.adapter) luid.Value = *entry.adapter;
            if (!entry.adapter || ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR ||
                DcoAdapterNetworkStateReusable(index))
                DeleteJournalOwner(entry);
        }
    } catch (...) {
    }
}

// Called while this process holds the adapter's exclusive handle. Its
// leftover configuration is removed only when every claim on it comes from a
// FuzeVPN process that is gone; unknown or live state is never touched.
inline bool ReclaimOrphanedDcoAdapter(ULONG index) noexcept {
    try {
        NET_LUID luid{};
        if (ConvertInterfaceIndexToLuid(index, &luid) != NO_ERROR || !luid.Value) return false;
        std::vector<JournalEntry> entries, orphaned;
        if (!ReadNetworkJournal(&entries)) return false;
        for (auto& entry : entries) {
            if (entry.adapter != luid.Value) continue;
            if (ProbeJournalOwner(entry.owner) != NrptProcessState::orphaned) return false;
            orphaned.push_back(std::move(entry));
        }
        if (orphaned.empty()) return false;
        for (const auto& entry : orphaned) RemoveJournalRoutes(entry);

        MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
        if (GetUnicastIpAddressTable(AF_UNSPEC, &addresses) == NO_ERROR) {
            for (ULONG i = 0; i < addresses->NumEntries; ++i) {
                auto& row = addresses->Table[i];
                if (row.InterfaceIndex == index && !AutomaticDcoAddress(row))
                    DeleteUnicastIpAddressEntry(&row);
            }
            FreeMibTable(addresses);
        }
        MIB_IPFORWARD_TABLE2* routes = nullptr;
        if (GetIpForwardTable2(AF_UNSPEC, &routes) == NO_ERROR) {
            for (ULONG i = 0; i < routes->NumEntries; ++i) {
                auto& row = routes->Table[i];
                if (row.InterfaceIndex == index && !AutomaticDcoRoute(row)) DeleteIpForwardEntry2(&row);
            }
            FreeMibTable(routes);
        }
        const bool reusable = DcoAdapterNetworkStateReusable(index);
        if (reusable)
            for (const auto& entry : orphaned) DeleteJournalOwner(entry);
        return reusable;
    } catch (...) {
        return false;
    }
}
} // namespace openvpn::Win
