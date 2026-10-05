// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_DIAGNOSTICS_STORE_H_
#define RUNNER_DIAGNOSTICS_STORE_H_
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace fuzevpn_diagnostics {
constexpr size_t kMaximumReportBytes = 2 * 1024 * 1024;
constexpr size_t kMaximumQueueBytes = 20 * 1024 * 1024;
constexpr size_t kMaximumReports = 10;
constexpr int64_t kRetentionMs = 24ll * 60 * 60 * 1000;
constexpr int64_t kHourMs = 60ll * 60 * 1000;
constexpr int64_t kClockToleranceMs = 5ll * 60 * 1000;
struct Report {
  std::string id;
  std::vector<uint8_t> body;
  int64_t created_at = 0;
  int64_t expires_at = 0;
  bool manual = true;
  unsigned attempts = 0;
  unsigned automatic_attempts = 0;
  int64_t next_attempt_at = 0;
  bool paused_for_auth = false;
  std::string terminal_code;
};
struct RateAttempt { int64_t at = 0; bool automatic = false; };
struct State {
  std::string account;
  bool automatic_consent = false;
  unsigned notice_version = 1;
  int64_t last_seen = 0;
  int64_t retry_after_until = 0;
  std::vector<Report> reports;
  std::vector<RateAttempt> rate_attempts;
};
int64_t NowMs();
bool ValidAccount(const std::string& account);
bool ValidReportId(const std::string& id);
void Wipe(State* state);
// Clock rollback discards pending payloads and revokes automatic consent.
bool Purge(State* state, int64_t now);
std::string Enqueue(State* state, Report report, int64_t now);
std::string MarkAttempt(State* state, const std::string& id, bool automatic, int64_t now);
std::string UpdateReport(State* state, const std::string& id, int64_t next_attempt_at,
                         bool paused_for_auth, const std::string& terminal_code,
                         int64_t account_retry_after = 0);
bool Encode(const State& state, std::vector<uint8_t>* bytes);
bool Decode(const std::vector<uint8_t>& bytes, State* state);
class SessionFence final {
 public:
  bool Bind(int64_t next) {
    if (next < 0 || next <= generation_.load()) return false;
    generation_ = next; ++revision_; return true;
  }
  void Invalidate() { ++revision_; }
  int64_t generation() const { return generation_.load(); }
  uint64_t revision() const { return revision_.load(); }
  bool Matches(int64_t generation, uint64_t revision) const {
    return generation == generation_.load() && revision == revision_.load();
  }
 private:
  std::atomic<int64_t> generation_{-1};
  std::atomic<uint64_t> revision_{0};
};

// GUI-user DPAPI only. The alternate directory is solely for isolated native
// tests; no path is accepted from the Flutter channel.
class FileStore final {
 public:
  FileStore();
  explicit FileStore(std::filesystem::path test_directory);
  std::string Load(State* state);
  std::string Save(const State& state, const std::function<bool()>& current);
  std::string Erase();
  std::string PurgeExpired(int64_t now);
 private:
  std::filesystem::path directory_;
};
}  // namespace fuzevpn_diagnostics

#ifndef FUZEVPN_DIAGNOSTICS_STORE_NO_CHANNEL
#include <flutter/flutter_engine.h>
constexpr UINT kDiagnosticsStoreCompletedMessage = WM_APP + 44;
class DiagnosticsStoreChannel final {
 public:
  DiagnosticsStoreChannel(flutter::FlutterEngine* engine, HWND window);
  ~DiagnosticsStoreChannel();
  void ProcessCompletions();
  void PurgeExpired();
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
#endif
#endif
