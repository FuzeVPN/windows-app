// SPDX-License-Identifier: MPL-2.0
// Exercise production observation with synthetic Win32 readers only. No real
// adapter, registry, service, network or VPN state is queried or changed.
#include "diagnostics_network.h"
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {
ULONG adapter_status = NO_ERROR;
LSTATUS nrpt_status = ERROR_SUCCESS;
const char* fixture_adapter_dns = nullptr;
unsigned adapter_queries = 0, nrpt_queries = 0;
DWORD WINAPI SyntheticIf(MIB_IF_ROW2* row) {
  row->InterfaceIndex = 12; row->OperStatus = IfOperStatusUp; return NO_ERROR;
}
DWORD WINAPI SyntheticUnicast(ADDRESS_FAMILY, PMIB_UNICASTIPADDRESS_TABLE*) { return ERROR_ACCESS_DENIED; }
DWORD WINAPI SyntheticRoutes(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2*) { return ERROR_ACCESS_DENIED; }
ULONG WINAPI SyntheticAdapters(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES out, PULONG size) {
  ++adapter_queries;
  if (adapter_status != NO_ERROR) return adapter_status;
  if (*size < sizeof(*out)) { *size = sizeof(*out); return ERROR_BUFFER_OVERFLOW; }
  *out = {}; out->Length = sizeof(*out); out->Luid.Value = 800; out->IfIndex = 12;
  static SOCKADDR_IN address;
  static IP_ADAPTER_DNS_SERVER_ADDRESS entry;
  if (fixture_adapter_dns) {
    address = {}; address.sin_family = AF_INET;
    if (InetPtonA(AF_INET, fixture_adapter_dns, &address.sin_addr) != 1) return ERROR_INVALID_DATA;
    entry = {}; entry.Length = sizeof(entry);
    entry.Address.lpSockaddr = reinterpret_cast<SOCKADDR*>(&address);
    entry.Address.iSockaddrLength = sizeof(address);
    out->FirstDnsServerAddress = &entry;
  }
  return NO_ERROR;
}
LSTATUS WINAPI SyntheticRegOpen(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY key) {
  ++nrpt_queries;
  if (nrpt_status != ERROR_SUCCESS) return nrpt_status;
  *key = reinterpret_cast<HKEY>(static_cast<uintptr_t>(123)); return ERROR_SUCCESS;
}
LSTATUS WINAPI SyntheticRegGet(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID value, LPDWORD size) {
  constexpr wchar_t dns[] = L"10.8.0.1";
  if (*size < sizeof(dns)) return ERROR_MORE_DATA;
  std::memcpy(value, dns, sizeof(dns)); *size = sizeof(dns); return ERROR_SUCCESS;
}
LSTATUS WINAPI SyntheticRegClose(HKEY) { return ERROR_SUCCESS; }
void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
}
#define GetIfEntry2 SyntheticIf
#define GetUnicastIpAddressTable SyntheticUnicast
#define GetIpForwardTable2 SyntheticRoutes
#define GetAdaptersAddresses SyntheticAdapters
#define RegOpenKeyExW SyntheticRegOpen
#define RegGetValueW SyntheticRegGet
#define RegCloseKey SyntheticRegClose
#include "../runner/diagnostics_network.cpp"
#undef GetIfEntry2
#undef GetUnicastIpAddressTable
#undef GetIpForwardTable2
#undef GetAdaptersAddresses
#undef RegOpenKeyExW
#undef RegGetValueW
#undef RegCloseKey

int main() {
  using namespace fuzevpn_diagnostics;
  try {
    NetworkExpectation expected;
    expected.luid = 800; expected.index = 12; expected.dns = {"10.8.0.1"};
    expected.nrpt_rule = "FuzeVPNDNSRoutingV1-123-456-0";
    expected.dns_mode = DnsConfigurationMode::nrpt;
    adapter_status = ERROR_ACCESS_DENIED;
    Check(ReadNetworkObservation(expected).dns == CheckResult::passed && adapter_queries == 0 && nrpt_queries == 1,
        "NRPT-only uses its correct rule without requiring adapter DNS or adapter enumeration");

    expected.dns_mode = DnsConfigurationMode::adapter;
    adapter_status = NO_ERROR; fixture_adapter_dns = "10.8.0.1"; nrpt_status = ERROR_ACCESS_DENIED;
    nrpt_queries = 0;
    Check(ReadNetworkObservation(expected).dns == CheckResult::passed && nrpt_queries == 0,
        "adapter-only uses its DNS without requiring an unrelated NRPT read");
    expected.dns_mode = DnsConfigurationMode::adapter_and_nrpt;
    nrpt_status = ERROR_SUCCESS;
    Check(ReadNetworkObservation(expected).dns == CheckResult::passed, "combined mode passes with both required sources");
    fixture_adapter_dns = nullptr;
    Check(ReadNetworkObservation(expected).dns == CheckResult::failed,
        "correct NRPT cannot conceal missing adapter DNS when both are required");
    fixture_adapter_dns = "10.8.0.99";
    Check(ReadNetworkObservation(expected).dns == CheckResult::failed,
        "correct NRPT cannot conceal divergent adapter DNS when both are required");
    fixture_adapter_dns = "10.8.0.1"; nrpt_status = ERROR_FILE_NOT_FOUND;
    Check(ReadNetworkObservation(expected).dns == CheckResult::failed,
        "correct adapter cannot conceal absent NRPT when both are required");
    nrpt_status = ERROR_ACCESS_DENIED;
    Check(ReadNetworkObservation(expected).dns == CheckResult::unknown, "inaccessible required NRPT cannot pass");
    nrpt_status = ERROR_SUCCESS; adapter_status = ERROR_ACCESS_DENIED;
    Check(ReadNetworkObservation(expected).dns == CheckResult::unknown, "inaccessible required adapter cannot pass");
    expected.dns_mode = DnsConfigurationMode::nrpt; nrpt_status = ERROR_FILE_NOT_FOUND;
    Check(ReadNetworkObservation(expected).dns == CheckResult::failed, "missing NRPT-only rule fails");
    nrpt_status = ERROR_ACCESS_DENIED;
    Check(ReadNetworkObservation(expected).dns == CheckResult::unknown, "inaccessible NRPT-only rule stays unknown");
    std::cout << "diagnostics network: adapter, NRPT and combined production readers passed\n";
    return 0;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
