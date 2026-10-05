#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace openvpn::Win {
struct CleanupCommand {
    enum class Kind { route, address, dns } kind;
    ADDRESS_FAMILY family = AF_UNSPEC;
    DWORD interface_index = 0;
    SOCKADDR_INET address{};
    unsigned prefix = 0;
    SOCKADDR_INET gateway{};
    bool has_gateway = false;
};
inline bool CleanupNumber(const std::string& text, DWORD maximum, DWORD* value) {
    if (text.empty()) return false;
    std::uint64_t number = 0;
    for (const auto c : text) {
        if (c < '0' || c > '9') return false;
        number = number * 10 + (c - '0');
        if (number > maximum) return false;
    }
    *value = static_cast<DWORD>(number); return true;
}
inline bool CleanupAddress(const std::string& text, ADDRESS_FAMILY family, SOCKADDR_INET* address) {
    if (text.find('\0') != std::string::npos) return false;
    address->si_family = family;
    return InetPtonA(family, text.c_str(), family == AF_INET ?
        static_cast<void*>(&address->Ipv4.sin_addr) : static_cast<void*>(&address->Ipv6.sin6_addr)) == 1;
}
inline bool ParseCleanupCommand(const std::string& command, CleanupCommand* parsed) {
    if (!parsed || command.find('\0') != std::string::npos) return false;
    std::istringstream input(command); std::vector<std::string> fields;
    for (std::string field; input >> field;) fields.push_back(std::move(field));
    if (fields.size() < 7 || fields[0] != "netsh" || fields[1] != "interface" ||
        (fields[2] != "ip" && fields[2] != "ipv6") || fields[3] != "delete") return false;
    parsed->family = fields[2] == "ip" ? AF_INET : AF_INET6;
    std::string index;
    if (fields[4] == "route") {
        parsed->kind = CleanupCommand::Kind::route;
        const auto slash = fields[5].find('/');
        DWORD prefix = 0;
        if (slash == std::string::npos || !CleanupNumber(fields[5].substr(slash + 1),
            parsed->family == AF_INET ? 32 : 128, &prefix) ||
            !CleanupAddress(fields[5].substr(0, slash), parsed->family, &parsed->address)) return false;
        parsed->prefix = prefix;
        index = fields[6];
        if (index.starts_with("interface=")) index.erase(0, 10);
        parsed->has_gateway = fields.size() > 7 && fields[7].find('=') == std::string::npos;
        if (parsed->has_gateway && !CleanupAddress(fields[7], parsed->family, &parsed->gateway)) return false;
    } else if (fields[4] == "address") {
        parsed->kind = CleanupCommand::Kind::address; index = fields[5];
        if (!CleanupAddress(fields[6], parsed->family, &parsed->address)) return false;
    } else if ((fields[4] == "dnsservers" || fields[4] == "dnsserver") && fields[6] == "all") {
        parsed->kind = CleanupCommand::Kind::dns; index = fields[5];
    } else return false;
    return CleanupNumber(index, MAXDWORD, &parsed->interface_index) && parsed->interface_index != 0;
}
inline bool SameCleanupAddress(const SOCKADDR_INET& a, const SOCKADDR_INET& b) {
    return a.si_family == b.si_family && (a.si_family == AF_INET
        ? a.Ipv4.sin_addr.S_un.S_addr == b.Ipv4.sin_addr.S_un.S_addr
        : std::memcmp(&a.Ipv6.sin6_addr, &b.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0);
}
// A nonzero delete exit can mean Windows already removed the resource. Only
// accept that case after a typed, read-only check; never parse localized stderr.
inline bool NetworkCleanupAlreadyComplete(const std::string& command) {
    CleanupCommand parsed{};
    if (!ParseCleanupCommand(command, &parsed)) return false;
    bool absent = true;
    if (parsed.kind == CleanupCommand::Kind::route) {
        MIB_IPFORWARD_TABLE2* table = nullptr;
        if (GetIpForwardTable2(parsed.family, &table) != NO_ERROR) return false;
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const auto& route = table->Table[i];
            if (route.InterfaceIndex == parsed.interface_index && route.DestinationPrefix.PrefixLength == parsed.prefix &&
                SameCleanupAddress(route.DestinationPrefix.Prefix, parsed.address) &&
                (!parsed.has_gateway || SameCleanupAddress(route.NextHop, parsed.gateway))) absent = false;
        }
        FreeMibTable(table);
    } else if (parsed.kind == CleanupCommand::Kind::address) {
        MIB_UNICASTIPADDRESS_TABLE* table = nullptr;
        if (GetUnicastIpAddressTable(parsed.family, &table) != NO_ERROR) return false;
        for (ULONG i = 0; i < table->NumEntries; ++i)
            if (table->Table[i].InterfaceIndex == parsed.interface_index &&
                SameCleanupAddress(table->Table[i].Address, parsed.address)) absent = false;
        FreeMibTable(table);
    } else {
        ULONG size = 16 * 1024; std::vector<BYTE> buffer(size);
        ULONG result = ERROR_BUFFER_OVERFLOW;
        for (unsigned attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
            if (size > 1024 * 1024) return false;
            buffer.resize(size);
            result = GetAdaptersAddresses(parsed.family, GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
        }
        if (result != NO_ERROR) return false;
        for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
            if (adapter->IfIndex != parsed.interface_index && adapter->Ipv6IfIndex != parsed.interface_index) continue;
            for (auto* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next)
                if (dns->Address.lpSockaddr && dns->Address.lpSockaddr->sa_family == parsed.family) absent = false;
        }
    }
    return absent;
}
} // namespace openvpn::Win
