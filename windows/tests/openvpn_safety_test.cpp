// SPDX-License-Identifier: MPL-2.0
#include "openvpn_ip_validation.h"
#include "openvpn_driver_version.h"
#include "openvpn_diagnostic_state.h"
#include "openvpn_failure_classification_test.h"
#include "openvpn_address_configuration_test.h"
#include "openvpn_cleanup_diagnostic_test.h"
#include <openvpn/win/bounded_process.hpp>
#include <openvpn/win/command_context.hpp>
#include <openvpn/win/nrpt_session.hpp>
#include <openvpn/win/network_postcondition.hpp>
#include <openvpn/win/network_command_cleanup.hpp>
#include <openvpn/win/owned_route_state.hpp>
#include <openvpn/win/owned_route_row.hpp>
#include <openvpn/win/adapter_dns_commands.hpp>
#define OPENVPN_LOG_STRING(message) do { (void)(message); } while (false)
#include <openvpn/common/action.hpp>
#undef OPENVPN_LOG_STRING

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <thread>

namespace {
void Check(bool condition, const char* message) {
  if (!condition) { std::cerr << message << '\n'; std::exit(EXIT_FAILURE); }
}
template<typename Operation> bool Rejected(Operation operation) {
  try { operation(); return false; } catch (const std::exception&) { return true; }
}
void AddressValidation() {
  Check(fuzevpn::IsStrictOpenVpnIPv4("192.0.2.1"), "ordinary IPv4 accepted");
  for (const auto& value : {std::string("192.0.2.1\0x", 11), std::string("1.1.1.1\0", 8),
      std::string("1.1.1.1\nremote x"), std::string("1.1.1.999"), std::string("::1")})
    Check(!fuzevpn::IsStrictOpenVpnIPv4(value), "entire untrusted address is validated");
}
void DriverVersions() {
  std::uint64_t bundled = 0, installed = 0;
  Check(fuzevpn::ParseOpenVpnDriverVersion(L"2.8.6.0", &bundled), "bundled driver version parsed");
  Check(fuzevpn::ParseOpenVpnDriverVersion(L"2.8.5.0", &installed) &&
      !fuzevpn::OpenVpnDriverVersionCompatible(installed, bundled), "old driver must be upgraded");
  Check(fuzevpn::ParseOpenVpnDriverVersion(L"2.9.0.0", &installed) &&
      fuzevpn::OpenVpnDriverVersionCompatible(installed, bundled), "newer compatible driver is retained");
  Check(fuzevpn::ParseOpenVpnDriverVersion(L"3.0.0.0", &installed) &&
      !fuzevpn::OpenVpnDriverVersionCompatible(installed, bundled), "unknown major ABI not silently accepted");
  for (const auto* bad : {L"2.8.6", L"2.8.6.0.1", L"-2.8.6.0", L"2.65536.0.0", L"2.8..0"})
    Check(!fuzevpn::ParseOpenVpnDriverVersion(bad, &installed), "malformed driver version rejected");
}
void SanitizedDiagnostics() {
  fuzevpn::OpenVpnDiagnosticState state;
  const std::string secret = "203.0.113.77 CERTIFICATE token=private_name";
  state.Event(secret);
  state.Log("Contacting " + secret);
  state.Failure(secret);
  auto text = fuzevpn::FormatOpenVpnDiagnostic(state.Snapshot(), false, secret);
  Check(text.find(secret) == std::string::npos && text.find("stage=starting") != text.npos &&
      text.find("failure_before_stop=other") != text.npos, "unknown diagnostic inputs are never retained");
  state.Log("Open TAP device " + secret + " SUCCEEDED");
  state.Dco(fuzevpn::OpenVpnDcoDiagnostic::peer_ready);
  state.Dco(fuzevpn::OpenVpnDcoDiagnostic::send_attempt);
  state.Dco(fuzevpn::OpenVpnDcoDiagnostic::send_ok);
  state.Dco(fuzevpn::OpenVpnDcoDiagnostic::receive_ok);
  state.Event("CONNECTING");
  Check(state.Snapshot().stage == 3 && state.Snapshot().received == 1,
      "first received packet is distinct from mere peer creation");
  state.Event("GET_CONFIG");
  state.Event("ASSIGN_IP");
  state.Event("ADD_ROUTES");
  state.Failure("openvpn_adapter_failed");
  state.Event("RECONNECTING");
  state.Failure("openvpn_transport_started");
  state.Log("Connecting to " + secret);
  const auto snapshot = state.Snapshot();
  text = fuzevpn::FormatOpenVpnDiagnostic(snapshot, true, "openvpn_transport_started");
  Check(snapshot.stage == 6 && snapshot.reconnects == 1 && snapshot.send_ok == 1 &&
      text.find("first_error=openvpn_adapter_failed") != text.npos &&
      text.find("command_failed=1") != text.npos && text.find(secret) == text.npos,
      "retry progress cannot erase earlier setup failure or expose raw messages");
  state.Event("DISCONNECTED");
  Check(std::string_view(snapshot.last_event) == "RECONNECTING",
      "pre-stop snapshot is stable when cleanup emits later events");
  {
    fuzevpn::ScopedOpenVpnDiagnosticState scope(&state);
    fuzevpn::RecordOpenVpnDcoDiagnostic(fuzevpn::OpenVpnDcoDiagnostic::send_failed);
  }
  fuzevpn::RecordOpenVpnDcoDiagnostic(fuzevpn::OpenVpnDcoDiagnostic::send_failed);
  Check(state.Snapshot().send_failed == 1, "diagnostic hook is scoped to the connection worker");
}
void NrptRecovery() {
  using namespace openvpn::Win;
  const auto stale = NrptSessionRule(101, 1001);
  const auto reused = NrptSessionRule(102, 1002, 0);
  const auto live = NrptSessionRule(103, 1003);
  const auto inaccessible = NrptSessionRule(104, 1004);
  const std::vector<std::wstring> names{L"OpenVPNDNSRouting-101", L"OtherPolicy", stale, reused, live,
      inaccessible, L"FuzeVPNDNSRoutingV1-1-0", L"FuzeVPNDNSRoutingV1-4294967296-5",
      L"FuzeVPNDNSRoutingV1-12-18446744073709551616", L"FuzeVPNDNSRoutingV1-1-2-X0-junk"};
  std::vector<std::wstring> removed;
  const auto probe = [](const NrptSession& session) {
    if (session.pid == 103) return NrptProcessState::matching_live;
    if (session.pid == 104) return NrptProcessState::unavailable;
    return NrptProcessState::orphaned;
  };
  Check(!RecoverNrptSessions(names, probe, [&](const auto& name) { removed.push_back(name); return true; }),
      "unknown process identity reports incomplete recovery");
  Check(removed == std::vector<std::wstring>{stale, reused},
      "only exact owned orphan generations removed; third-party/GPO/live/unknown rules preserved");
  Check(!RecoverNrptSessions(std::vector<std::wstring>{stale}, probe, [](const auto&) { return false; }),
      "failed removal is not reported successful");
}
void NetworkPostconditions() {
  using namespace openvpn::Win;
  NetworkPostcondition expected{{"10.1.0.2"}, {"0.0.0.0/1", "128.0.0.0/1"}, {"10.1.0.1"}};
  Check(NetworkPostconditionsMet(expected, expected, true, true), "complete tunnel state accepted");
  auto incomplete = expected; incomplete.routes.pop_back();
  Check(!NetworkPostconditionsMet(expected, incomplete, true, true), "missing half-default route blocks CONNECTED");
  incomplete = expected; incomplete.addresses = {"10.1.0.3"};
  Check(!NetworkPostconditionsMet(expected, incomplete, true, true), "wrong assigned address rejected");
  incomplete = expected; incomplete.dns = {"192.168.1.1"};
  Check(!NetworkPostconditionsMet(expected, incomplete, true, true), "physical DNS does not satisfy VPN DNS");
  Check(!NetworkPostconditionsMet(expected, expected, false, true) &&
      !NetworkPostconditionsMet(expected, expected, true, false), "stopped adapter or absent DNS policy rejected");
  Check(NetworkPostconditionFailures(expected, {}, false, false) == 31,
      "all missing postconditions have separate fixed bits");
  Check(NetworkPostconditionFailures(expected, expected, false, false) == 17,
      "adapter and NRPT diagnostics are independent of addresses and routes");
  Check(NetworkPostconditionFailures(expected, incomplete, true, true) == 8,
      "wrong DNS is identified without retaining its address");
}
void AdapterDnsCommands() {
  using openvpn::Win::BuildAdapterDnsCommands;
  // Exact merged list produced when local dhcp-option and PUSH_REPLY both
  // advertise the first resolver. Build the production command plan, not a
  // mock duplicate-removal implementation; never execute netsh in this test.
  const auto merged = BuildAdapterDnsCommands({"10.1.0.1", "10.1.0.2", "10.1.0.1", "10.1.0.3"}, "12", false);
  Check(merged.create == std::vector<std::string>{
      "netsh interface ip set dnsservers 12 static 10.1.0.1 register=primary validate=no",
      "netsh interface ip add dnsservers 12 10.1.0.2 2 validate=no",
      "netsh interface ip add dnsservers 12 10.1.0.3 3 validate=no"},
      "local and pushed duplicates produce one command per resolver with contiguous indexes");
  Check(merged.cleanup == std::vector<std::string>{"netsh interface ip delete dnsservers 12 all validate=no"},
      "DNS cleanup remains exactly once per configured family");
  const auto repeated = BuildAdapterDnsCommands({"10.1.0.1", "10.1.0.1"}, "12", false);
  Check(repeated.create.size() == 1 && repeated.cleanup.size() == 1,
      "identical local and pushed single DNS never generates a failing add");
  const auto mixed = BuildAdapterDnsCommands({"fd00:0:0:0:0:0:0:1", "10.1.0.1", "FD00::1",
      "10.1.0.1", "fd00::2", "10.1.0.2"}, "12", false);
  Check(mixed.create == std::vector<std::string>{
      "netsh interface ipv6 set dnsservers 12 static fd00::1 register=primary validate=no",
      "netsh interface ip set dnsservers 12 static 10.1.0.1 register=primary validate=no",
      "netsh interface ipv6 add dnsservers 12 fd00::2 2 validate=no",
      "netsh interface ip add dnsservers 12 10.1.0.2 2 validate=no"} && mixed.cleanup.size() == 2,
      "equivalent IPv6 spellings deduplicate and family priorities stay independent");
  const auto blocked = BuildAdapterDnsCommands({"fd00::1", "10.1.0.1", "FD00::1", "10.1.0.2"}, "12", true);
  Check(blocked.create.size() == 2 && blocked.create[1] ==
      "netsh interface ip add dnsservers 12 10.1.0.2 2 validate=no" && blocked.cleanup.size() == 1,
      "blocked IPv6 never consumes an IPv4 index or receives a command");
  Check(BuildAdapterDnsCommands({}, "12", false).create.empty(), "empty DNS list does not change Windows");
  Check(Rejected([&] { BuildAdapterDnsCommands({std::string("10.1.0.1\0ignored", 16)}, "12", false); }) &&
      Rejected([&] { BuildAdapterDnsCommands({"not-an-address"}, "12", false); }),
      "deduplication does not relax address validation");
}
void CommandDiagnostics() {
  using namespace openvpn::Win;
  Check(ClassifyNetworkCommand("netsh interface ip add route 192.0.2.1/32 12 192.0.2.2 store=active") ==
      DiagnosticAction::command_route_add, "IPv4 route command classified without arguments");
  Check(ClassifyNetworkCommand("netsh interface ipv6 delete route 2000::/4 interface=1 store=active") ==
      DiagnosticAction::command_route_delete, "IPv6 route command classified without arguments");
  Check(ClassifyNetworkCommand("netsh interface ip set address 12 static 10.1.0.2 255.255.255.0") ==
      DiagnosticAction::command_address_set, "address command has fixed category");
  Check(ClassifyNetworkCommand("netsh interface ip set dnsservers 12 static 10.1.0.1") ==
      DiagnosticAction::command_dns_set, "DNS command has fixed category");
  Check(ClassifyNetworkCommand("untrusted arbitrary message") == DiagnosticAction::command_other &&
      std::string(CommandFailureActionName(static_cast<DiagnosticAction>(999))) == "unknown",
      "unknown diagnostic input cannot become raw output");
  CommandControl control;
  ScopedCommandControl scope(&control);
  { ScopedCommandCleanup cleanup;
    RecordCommandFailure(DiagnosticAction::route_remove, ERROR_ACCESS_DENIED); }
  Check(control.first_failed_action.load() == DiagnosticAction::none,
      "cleanup does not become the connection failure");
  RecordCommandFailure(DiagnosticAction::command_address_set, ERROR_INVALID_PARAMETER);
  RecordCommandFailure(DiagnosticAction::setup_actions, 1);
  Check(control.first_failed_action.load() == DiagnosticAction::command_address_set &&
      control.first_failed_code.load() == ERROR_INVALID_PARAMETER,
      "first failed operation and numeric code survive later failures");
}
void CleanupRetries() {
  using namespace openvpn::Win;
  CleanupCommand command{};
  Check(ParseCleanupCommand("netsh interface ip delete route 128.0.0.0/1 12 10.1.0.1 store=active", &command) &&
      command.kind == CleanupCommand::Kind::route && command.interface_index == 12 &&
      command.prefix == 1 && command.has_gateway, "route cleanup checks exact prefix, interface and gateway");
  Check(ParseCleanupCommand("netsh interface ipv6 delete route 2000::/4 interface=1 store=active", &command) &&
      command.family == AF_INET6 && !command.has_gateway, "IPv6 block route cleanup is recognized");
  Check(ParseCleanupCommand("netsh interface ip delete address 12 10.1.0.2 gateway=all store=active", &command) &&
      command.kind == CleanupCommand::Kind::address, "address cleanup is recognized");
  Check(ParseCleanupCommand("netsh interface ip delete dnsservers 12 all", &command) &&
      command.kind == CleanupCommand::Kind::dns, "DNS cleanup is recognized");
  for (const auto* invalid : {"netsh interface ip add route 0.0.0.0/1 12 10.1.0.1", "netsh interface ip delete route 0.0.0.0/33 12",
       "netsh interface ip delete address 0 10.1.0.2", "netsh interface ip delete dnsservers 12 10.1.0.1"})
    Check(!ParseCleanupCommand(invalid, &command), "other operations cannot use idempotent-delete fallback");
  CommandControl control;
  int attempts = 0, successful = 0;
  control.cleanup_actions.emplace_back([&] { return ++attempts == 2; });
  control.cleanup_actions.emplace_back([&] { ++successful; return true; });
  Check(!RetryCommandCleanup(&control) && control.cleanup_actions.size() == 1,
      "incomplete cleanup is retained instead of reporting successful disconnect");
  Check(RetryCommandCleanup(&control) && attempts == 2 && successful == 1,
      "retry only replays failed cleanup actions");
  control.cleanup_actions.emplace_back([]() -> bool { throw std::runtime_error("fixture failure"); });
  Check(!RetryCommandCleanup(&control) && control.cleanup_actions.size() == 1,
      "cleanup exception preserves the retry and fail-closed state");
}
void OwnedRoutes() {
  using namespace openvpn::Win;
  OwnedRouteState route;
  unsigned removed = 0;
  Check(route.CreateRoute([] { return ERROR_OBJECT_ALREADY_EXISTS; }) == ERROR_SUCCESS && !route.owned(),
      "preexisting or concurrently created exact tuple is borrowed without ownership");
  Check(route.RemoveRoute([&] { ++removed; return ERROR_SUCCESS; }) == ERROR_SUCCESS && removed == 0,
      "rollback never removes the borrowed route");
  Check(route.CreateRoute([] { return ERROR_ACCESS_DENIED; }) == ERROR_ACCESS_DENIED && !route.owned(),
      "creation failure propagates without acquiring cleanup ownership");
  Check(route.RemoveRoute([&] { ++removed; return ERROR_SUCCESS; }) == ERROR_SUCCESS && removed == 0,
      "failed creation does not remove somebody else's route");
  Check(route.CreateRoute([] { return ERROR_SUCCESS; }) == ERROR_SUCCESS && route.owned(),
      "only successful atomic creation acquires ownership");
  Check(route.RemoveRoute([&] { ++removed; return ERROR_ACCESS_DENIED; }) == ERROR_ACCESS_DENIED && route.owned(),
      "failed removal retains ownership for a later cleanup retry");
  Check(route.RemoveRoute([&] { ++removed; return ERROR_NOT_FOUND; }) == ERROR_SUCCESS && !route.owned(),
      "route concurrently removed by Windows satisfies cleanup");
  Check(route.RemoveRoute([&] { ++removed; return ERROR_SUCCESS; }) == ERROR_SUCCESS && removed == 2,
      "completed cleanup never replays a deletion");
  route.MarkUncertain();
  Check(route.ReconcileUncertain(ERROR_SUCCESS) == ERROR_RETRY && route.uncertain() && !route.owned(),
      "timed-out CLI cannot claim a present tuple that might belong to another creator");
  Check(route.ReconcileUncertain(ERROR_ACCESS_DENIED) == ERROR_ACCESS_DENIED && route.uncertain(),
      "unreadable uncertain route retains incomplete cleanup state");
  Check(route.ReconcileUncertain(ERROR_NOT_FOUND) == ERROR_SUCCESS && !route.uncertain(),
      "confirmed absent tuple safely resolves uncertain CLI creation");
  MIB_IPFORWARD_ROW2 row{};
  Check(BuildOwnedRouteRow("fc00::1234", 64, 12, "fe80::8", 42, &row) &&
      row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte[15] == 0 &&
      row.NextHop.Ipv6.sin6_addr.u.Byte[15] == 8 && row.InterfaceIndex == 12 &&
      row.DestinationPrefix.PrefixLength == 64 && row.Metric == 42 &&
      row.ValidLifetime == (std::numeric_limits<ULONG>::max)() && !row.Publish,
      "IPv6 prefix normalization preserves next hop, interface, metric and active route lifetime");
  Check(BuildOwnedRouteRow("128.0.0.0", 1, 12, "10.1.0.1", (std::numeric_limits<ULONG>::max)(), &row) &&
      row.DestinationPrefix.Prefix.si_family == AF_INET && row.Metric == (std::numeric_limits<ULONG>::max)(),
      "IP Helper default metric remains unchanged");
  Check(!BuildOwnedRouteRow("128.0.0.0", 33, 12, "10.1.0.1", 256, &row) &&
      !BuildOwnedRouteRow("::", 1, 0, "fe80::8", 256, &row), "invalid route tuple rejected before mutation");
}
void ActionFailures() {
  class FixtureAction final : public openvpn::Action {
  public:
    FixtureAction(int* count, bool fail) : count_(count), fail_(fail) {}
    void execute(std::ostream&) override {
      ++*count_;
      if (fail_) throw std::runtime_error("controlled configuration failure");
    }
    std::string to_string() const override { return "fixture"; }
  private:
    int* count_; bool fail_;
  };
  int calls = 0;
  openvpn::ActionList actions;
  actions.add(new FixtureAction(&calls, false));
  actions.add(new FixtureAction(&calls, true));
  actions.add(new FixtureAction(&calls, false));
  std::ostringstream output;
  Check(!actions.execute(output).empty() && calls == 3,
      "unmarked action failure is returned while best-effort cleanup continues");
  actions.halt();
  Check(actions.execute_failures(output).size() == 3 && calls == 3,
      "halted unexecuted actions cannot be reported successful");
}
void ChildProcesses(const std::wstring& executable) {
  using namespace openvpn::Win;
  auto result = RunBoundedProcess(executable, L"--fixture-output", GetTickCount64() + 5000);
  Check(result.exit_code == 17 && result.output == std::string(16384, 'x'),
      "child output fully drained and nonzero exit code retained");
  const auto before = GetTickCount64();
  Check(Rejected([&] { RunBoundedProcess(executable, L"--fixture-hang", GetTickCount64() + 100); }),
      "silent child is terminated on timeout");
  Check(GetTickCount64() - before < 3000, "child timeout remains bounded");
  std::atomic<bool> cancelled{false};
  std::thread cancel([&] { Sleep(50); cancelled.store(true); });
  const bool aborted = Rejected([&] {
    RunBoundedProcess(executable, L"--fixture-hang", GetTickCount64() + 5000,
        [&] { return cancelled.load(); });
  });
  cancel.join();
  Check(aborted, "caller can cancel a child that never exits");
  Check(Rejected([&] { RunBoundedProcess(executable, L"--fixture-output", GetTickCount64() + 5000, {}, 32); }),
      "unbounded child output is rejected and child job closed");
  CommandControl control; control.cancelled.store(true); control.connection_deadline = GetTickCount64() - 1;
  ScopedCommandControl scope(&control);
  Check(CommandCancelled(), "connection commands see cancellation");
  { ScopedCommandCleanup cleanup;
    Check(!CommandCancelled() && CommandDeadline(GetTickCount64(), 10000) > GetTickCount64(),
        "rollback has its own finite deadline after connection cancellation"); }
  Check(CommandCancelled(), "cleanup does not clear the requested cancellation");
}
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && std::wstring_view(argv[1]) == L"--fixture-hang") { Sleep(INFINITE); return 0; }
  if (argc == 2 && std::wstring_view(argv[1]) == L"--fixture-output") {
    const std::string output(16384, 'x');
    DWORD written = 0;
    return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output.data(), static_cast<DWORD>(output.size()),
        &written, nullptr) && written == output.size() ? 17 : 18;
  }
  Check(argc == 1, "fixtures cannot run arbitrary commands");
  OpenVpnFailureClassificationTests();
  OpenVpnAddressConfigurationTests();
  OpenVpnCleanupDiagnosticTests();
  std::wstring executable(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
  Check(length && length < executable.size(), "test executable path available");
  executable.resize(length);
  AddressValidation(); DriverVersions(); SanitizedDiagnostics(); NrptRecovery(); NetworkPostconditions(); AdapterDnsCommands(); CommandDiagnostics(); CleanupRetries(); OwnedRoutes(); ActionFailures(); ChildProcesses(executable);
  std::cout << "OpenVPN safety tests passed (no VPN, service, registry writes or network).\n";
  return EXIT_SUCCESS;
}
