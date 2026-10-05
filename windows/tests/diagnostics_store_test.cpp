// SPDX-License-Identifier: MPL-2.0
#include "../runner/diagnostics_store.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
using namespace fuzevpn_diagnostics;
void Check(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
constexpr int64_t now = 1789552800000ll;
Report MakeReport(unsigned index = 1, bool manual = true) {
  Report report;
  report.id = "10000000-0000-4000-8000-00000000000";
  report.id += "0123456789abcdef"[index % 16];
  const std::string text = "{\"synthetic\":\"PRIVATE_REPORT_SENTINEL\"}";
  report.body.assign(text.begin(), text.end());
  report.created_at = now; report.expires_at = now + kRetentionMs; report.manual = manual;
  return report;
}
State MakeState() { State state; state.account = "synthetic-account-A"; state.last_seen = now; return state; }
void TestPolicy() {
  auto state = MakeState(); const auto report = MakeReport();
  Check(Enqueue(&state, report, now).empty(), "manual report can be queued without automatic opt-in");
  Check(Enqueue(&state, report, now).empty() && state.reports.size() == 1, "same immutable report is idempotent");
  auto altered = report; altered.body.push_back(' ');
  Check(Enqueue(&state, altered, now) == "diagnostic_conflict", "same UUID cannot change bytes");
  Check(Enqueue(&state, MakeReport(2, false), now) == "diagnostic_consent_required", "automatic collection requires account consent");
  state.automatic_consent = true;
  Check(Enqueue(&state, MakeReport(2, false), now).empty(), "explicit account opt-in permits simple queue");
  for (unsigned i = 0; i != 5; ++i) Check(MarkAttempt(&state, report.id, true, now).empty(), "five automatic attempts allowed");
  Check(!MarkAttempt(&state, report.id, true, now).empty(), "sixth automatic attempt rejected");
  Check(state.reports[0].attempts == 5 && state.reports[0].automatic_attempts == 5 && state.rate_attempts.size() == 5,
      "attempt and rate ledger change together");
  const auto frozen = state.reports[0].body;
  Check(UpdateReport(&state, report.id, now + 10000, false, "", now + 30000).empty(), "Retry-After metadata update");
  Check(MarkAttempt(&state, state.reports[1].id, false, now) == "diagnostic_rate_limited", "account Retry-After blocks another report too");
  Check(UpdateReport(&state, report.id, 0, true, "", now + 5000).empty() && state.retry_after_until == now + 30000,
      "a later update cannot shorten account backoff");
  Check(MarkAttempt(&state, report.id, false, now + 30000) == "diagnostic_not_ready", "auth pause blocks even manual retry");
  Check(UpdateReport(&state, report.id, 0, false, "invalid_diagnostic").empty(), "permanent failure persisted");
  Check(MarkAttempt(&state, report.id, false, now + 30000) == "diagnostic_not_ready" && state.reports[0].body == frozen,
      "permanent failure does not mutate payload or retry");

  state = MakeState();
  for (unsigned i = 0; i != 10; ++i) Check(Enqueue(&state, MakeReport(i), now).empty(), "ten reports allowed");
  Check(Enqueue(&state, MakeReport(10), now) == "diagnostic_queue_full", "eleventh report rejected without eviction");
  auto oversized = MakeReport(11); oversized.body.assign(kMaximumReportBytes + 1, 'a');
  Check(Enqueue(&state, std::move(oversized), now) == "invalid_argument", "per-report size enforced before encryption");
  Check(Purge(&state, now + kRetentionMs) && state.reports.empty(), "exact 24-hour boundary expires reports");
  state = MakeState(); state.automatic_consent = true;
  Check(Enqueue(&state, report, now).empty(), "queue rollback fixture");
  Check(Purge(&state, now - kClockToleranceMs - 1) && state.reports.empty() && !state.automatic_consent,
      "clock rollback never prolongs retention or opt-in");
  Check(Enqueue(&state, report, now - kClockToleranceMs - 1) == "storage_clock_invalid", "rollback cannot recreate purged reports");

  state = MakeState(); Check(Enqueue(&state, report, now).empty(), "budget fixture");
  for (unsigned i = 0; i != 20; ++i) Check(MarkAttempt(&state, report.id, false, now).empty(), "twenty account attempts allowed");
  Check(MarkAttempt(&state, report.id, false, now) == "diagnostic_rate_limited", "twenty-first request blocked locally");
  Check(MarkAttempt(&state, report.id, false, now + kHourMs).empty(), "budget recovers only after its rolling hour");
  state = MakeState();
  for (unsigned i = 0; i != 3; ++i) Check(Enqueue(&state, MakeReport(i), now).empty(), "automatic budget fixture");
  for (unsigned i = 0; i != 10; ++i)
    Check(MarkAttempt(&state, state.reports[i / 5].id, true, now).empty(), "ten automatic account attempts allowed");
  Check(MarkAttempt(&state, state.reports[2].id, true, now) == "diagnostic_rate_limited", "eleventh automatic attempt blocked across reports");

  SessionFence fence;
  Check(fence.Bind(1), "bind first generation"); const auto revision = fence.revision();
  Check(fence.Matches(1, revision), "active job accepted"); fence.Invalidate();
  Check(!fence.Matches(1, revision) && !fence.Bind(1), "clear rejects queued work and repeated generation");
  Check(fence.Bind(2) && !fence.Matches(1, fence.revision()), "new account rejects old generation");
}
void TestCodec() {
  auto state = MakeState(); auto report = MakeReport();
  report.body.assign(kMaximumReportBytes, 'a');
  Check(Enqueue(&state, report, now).empty(), "full 2 MiB UTF-8 payload accepted");
  std::vector<uint8_t> bytes; Check(Encode(state, &bytes), "encode full report and envelope");
  State decoded; Check(Decode(bytes, &decoded) && decoded.account == state.account && decoded.reports[0].body == report.body,
      "binary round trip preserves exact bytes and account");
  bytes.push_back(0); Check(!Decode(bytes, &decoded), "trailing bytes rejected"); bytes.pop_back();
  bytes.resize(40); Check(!Decode(bytes, &decoded), "truncated state rejected without huge allocation");
  Check(!ValidReportId("10000000-0000-4000-8000-00000000000A") && !ValidAccount(std::string("A\0B", 3)), "IDs and embedded NUL are bounded");
  state.reports.clear();
  for (unsigned i = 0; i != 9; ++i) { report.id = MakeReport(i).id; Check(Enqueue(&state, report, now).empty(), "bounded full reports fit"); }
  report.id = MakeReport(10).id;
  Check(Enqueue(&state, report, now) == "diagnostic_queue_full", "20 MiB cap includes serialized metadata");
  Wipe(&state); Wipe(&decoded);
}
void TestManualPriority() {
  auto state = MakeState(); state.automatic_consent = true;
  for (unsigned i = 0; i != 10; ++i) {
    auto report = MakeReport(i, false);
    if (i == 7) { report.created_at -= 1000; report.expires_at -= 1000; }
    Check(Enqueue(&state, std::move(report), now).empty(), "automatic priority fixture");
  }
  Check(MarkAttempt(&state, MakeReport(0).id, true, now).empty(), "retain budget during eviction");
  Check(Enqueue(&state, MakeReport(10, false), now) == "diagnostic_queue_full" && state.reports.size() == 10,
      "automatic report cannot evict existing reports");
  const auto manual = MakeReport(10);
  Check(Enqueue(&state, manual, now).empty() && state.reports.size() == 10 &&
        std::none_of(state.reports.begin(), state.reports.end(), [](const Report& r) { return r.id == MakeReport(7).id; }) &&
        state.reports.back().id == manual.id && state.rate_attempts.size() == 1,
      "manual report replaces oldest automatic report without resetting retry budget");
  Wipe(&state); state = MakeState(); state.automatic_consent = true;
  for (unsigned i = 0; i != 8; ++i) {
    auto report = MakeReport(i); report.body.assign(kMaximumReportBytes, 'a');
    Check(Enqueue(&state, std::move(report), now).empty(), "manual byte-limit fixture");
  }
  auto automatic = MakeReport(8, false); automatic.body.assign(kMaximumReportBytes, 'a');
  Check(Enqueue(&state, automatic, now).empty(), "large automatic byte-limit fixture");
  auto full = MakeReport(9); full.body.assign(kMaximumReportBytes, 'b');
  Check(Enqueue(&state, full, now).empty() && state.reports.size() == 9 &&
        std::all_of(state.reports.begin(), state.reports.end(), [](const Report& r) { return r.manual; }),
      "manual admission also evicts automatic payload for serialized byte quota below count limit");
  Check(Enqueue(&state, MakeReport(10, false), now).empty(), "small automatic occupies final count slot");
  std::vector<uint8_t> before, after;
  Check(Encode(state, &before), "encode atomic rollback baseline");
  full.id = MakeReport(11).id;
  Check(Enqueue(&state, full, now) == "diagnostic_queue_full" && Encode(state, &after) && before == after,
      "unsatisfiable manual admission preserves automatic report after candidate eviction and encode failure");
  SecureZeroMemory(before.data(), before.size()); SecureZeroMemory(after.data(), after.size());
  Wipe(&state); state = MakeState();
  for (unsigned i = 0; i != 10; ++i) Check(Enqueue(&state, MakeReport(i), now).empty(), "ten manual reports fixture");
  Check(Enqueue(&state, MakeReport(10), now) == "diagnostic_queue_full" && state.reports.size() == 10,
      "manual admission never evicts another manual report");
  Wipe(&state);
}
void TestFiles(std::filesystem::path base) {
  // CTest uses forward separators in its absolute argv. Only the synthetic
  // fixture adapter normalizes them; production keeps its strict path policy.
  base.make_preferred();
  Check(base.is_absolute() && base.filename() == L"diagnostics-fixtures", "isolated fixture root argument required");
  std::filesystem::create_directories(base);
  const auto directory = base / (L"queue-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
  FileStore store(directory); State state = MakeState(), restored;
  auto report = MakeReport(); report.body.resize(kMaximumReportBytes, 'a');
  Check(Enqueue(&state, report, now).empty(), "enqueue DPAPI fixture");
  const auto write_error = store.Save(state, [] { return true; });
  if (!write_error.empty()) throw std::runtime_error("DPAPI initial save: " + write_error);
  const auto file = directory / L"pending.bin";
  {
    std::ifstream input(file, std::ios::binary); std::string cipher((std::istreambuf_iterator<char>(input)), {});
    Check(cipher.find("PRIVATE_REPORT_SENTINEL") == std::string::npos && cipher.find("synthetic-account-A") == std::string::npos,
        "neither account nor report is written in plaintext");
  }
  Check(store.Load(&restored).empty() && restored.reports[0].body == report.body && restored.account == state.account,
      "CurrentUser DPAPI round trip preserves exact body");
  unsigned publish_checks = 0;
  bool parent_write_blocked = false, parent_delete_blocked = false;
  Check(store.Save(state, [&] {
    if (++publish_checks == 2) {
      HANDLE write = CreateFileW(directory.c_str(), GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      parent_write_blocked = write == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
      if (write != INVALID_HANDLE_VALUE) CloseHandle(write);
      HANDLE remove = CreateFileW(directory.c_str(), DELETE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
      parent_delete_blocked = remove == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION;
      if (remove != INVALID_HANDLE_VALUE) CloseHandle(remove);
    }
    return true;
  }).empty() && parent_write_blocked && parent_delete_blocked,
      "atomic replacement preserves parent write and replacement pins");
  auto changed = state; changed.reports[0].body.back() = 'b'; unsigned checks = 0;
  Check(store.Save(changed, [&] { return ++checks == 1; }) == "operation_cancelled", "generation invalidation before publish cancels encrypted temp");
  Check(store.Load(&restored).empty() && restored.reports[0].body == report.body, "cancelled write preserves previous committed state");
  Check(std::distance(std::filesystem::directory_iterator(directory), std::filesystem::directory_iterator()) == 1,
      "cancelled encrypted temporary removed by handle");
  const auto alias = directory / L"alias.bin";
  Check(CreateHardLinkW(alias.c_str(), file.c_str(), nullptr) != FALSE, "create isolated hardlink fixture");
  Check(store.Load(&restored) == "storage_access_denied", "multiply-linked queue is rejected");
  Check(DeleteFileW(alias.c_str()) != FALSE, "remove fixture hardlink");
  Check(store.PurgeExpired(now + kRetentionMs).empty() && store.Load(&restored).empty() && restored.reports.empty(),
      "expiry purge survives restart and encrypted rewrite");
  { std::ofstream corrupted(file, std::ios::binary | std::ios::trunc); corrupted << "corrupt"; }
  Check(store.Load(&restored) == "storage_decryption_failed", "corruption is never treated as a valid empty queue");
  Check(!store.PurgeExpired(now).empty() && !std::filesystem::exists(file), "unreadable report payload is discarded by maintenance");
  Check(RemoveDirectoryW(directory.c_str()) != FALSE, "remove only known empty fixture directory");
  const auto unprotected = base / (L"unprotected-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
  Check(CreateDirectoryW(unprotected.c_str(), nullptr) != FALSE, "create inherited-ACL fixture");
  FileStore unsafe(unprotected);
  Check(!unsafe.Save(state, [] { return true; }).empty(), "preexisting unprotected directory is refused, never repaired");
  Check(RemoveDirectoryW(unprotected.c_str()) != FALSE, "remove empty unprotected fixture");
  Wipe(&state); Wipe(&changed); Wipe(&restored);
}
}  // namespace
int wmain(int argc, wchar_t** argv) {
  try {
    Check(argc == 2, "pass only a workspace diagnostics-fixtures directory");
    TestPolicy(); TestCodec(); TestManualPriority(); TestFiles(argv[1]);
    std::cout << "Diagnostics DPAPI store, immutable queue, account fence, expiry and retry tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "Diagnostics store: " << error.what() << " (Win32 " << GetLastError() << ")\n";
    return 1;
  }
}
