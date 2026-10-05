// SPDX-License-Identifier: MPL-2.0
#include "tls_trust_channel.h"

#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "tls_trust.h"

namespace {

using flutter::EncodableMap;
using flutter::EncodableValue;
using MethodResult = flutter::MethodResult<EncodableValue>;
constexpr size_t kMaximumPendingRequests = 4;

const EncodableValue* Field(const EncodableMap& arguments, const char* key) {
  const auto found = arguments.find(EncodableValue(key));
  return found == arguments.end() ? nullptr : &found->second;
}

}  // namespace

struct TlsTrustChannel::Impl {
  struct Job {
    uint64_t id = 0;
    std::vector<uint8_t> certificate_der;
    std::string hostname;
  };
  struct Completion {
    uint64_t id = 0;
    fuzevpn_tls::TlsTrustVerification verification;
    bool failed = false;
  };
  struct WorkerState {
    HWND window = nullptr;
    bool stopping = false;
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Job> jobs;
    std::deque<Completion> completions;
  };

  std::unique_ptr<flutter::MethodChannel<EncodableValue>> channel;
  std::shared_ptr<WorkerState> state;
  // Flutter results never leave the platform thread, including destruction.
  std::map<uint64_t, std::unique_ptr<MethodResult>> pending;
  uint64_t next_id = 1;

  Impl(flutter::FlutterEngine* engine, HWND window)
      : state(std::make_shared<WorkerState>()) {
    state->window = window;
    channel = std::make_unique<flutter::MethodChannel<EncodableValue>>(
        engine->messenger(), "com.fuzevpn/windows_tls_trust",
        &flutter::StandardMethodCodec::GetInstance());
    // Detached work owns only this shared data. Shutdown cancels queued work and
    // replies before Flutter is destroyed; an in-flight Windows retrieval never
    // holds up the GUI or accesses an Impl/engine that has been destroyed.
    std::thread([worker_state = state] { Work(worker_state); }).detach();
    channel->SetMethodCallHandler([this](const auto& call, auto result) {
      Submit(call, std::move(result));
    });
  }

  ~Impl() {
    channel->SetMethodCallHandler(nullptr);
    {
      std::lock_guard<std::mutex> lock(state->mutex);
      state->stopping = true;
      state->window = nullptr;
      state->jobs.clear();
      state->completions.clear();
    }
    state->ready.notify_all();
    for (auto& request : pending) {
      request.second->Error("tls_trust_cancelled");
    }
  }

  void Submit(const flutter::MethodCall<EncodableValue>& call,
              std::unique_ptr<MethodResult> result) {
    if (call.method_name() != "verifyApiCertificate") {
      result->NotImplemented();
      return;
    }
    const auto* arguments =
        call.arguments() == nullptr
            ? nullptr
            : std::get_if<EncodableMap>(call.arguments());
    const auto* certificate_value =
        arguments == nullptr ? nullptr : Field(*arguments, "certificate_der");
    const auto* hostname_value =
        arguments == nullptr ? nullptr : Field(*arguments, "hostname");
    const auto* certificate =
        certificate_value == nullptr
            ? nullptr
            : std::get_if<std::vector<uint8_t>>(certificate_value);
    const auto* hostname =
        hostname_value == nullptr ? nullptr
                                  : std::get_if<std::string>(hostname_value);
    if (arguments == nullptr || arguments->size() != 2 ||
        certificate == nullptr || certificate->empty() ||
        certificate->size() > fuzevpn_tls::kMaximumCertificateBytes ||
        hostname == nullptr || *hostname != "api.fuzevpn.com") {
      result->Error("invalid_argument");
      return;
    }
    if (pending.size() >= kMaximumPendingRequests) {
      result->Error("tls_trust_busy");
      return;
    }
    Job job;
    job.id = next_id++;
    job.certificate_der = *certificate;
    job.hostname = *hostname;
    const auto id = job.id;
    {
      std::lock_guard<std::mutex> lock(state->mutex);
      if (state->stopping || state->window == nullptr) {
        result->Error("tls_trust_unavailable");
        return;
      }
      // Install the reply before making its job visible to the worker.
      pending.emplace(id, std::move(result));
      state->jobs.push_back(std::move(job));
    }
    state->ready.notify_one();
  }

  static void Work(const std::shared_ptr<WorkerState>& worker_state) {
    for (;;) {
      Job job;
      {
        std::unique_lock<std::mutex> lock(worker_state->mutex);
        worker_state->ready.wait(lock, [&] {
          return worker_state->stopping || !worker_state->jobs.empty();
        });
        if (worker_state->stopping) return;
        job = std::move(worker_state->jobs.front());
        worker_state->jobs.pop_front();
      }
      Completion completion;
      completion.id = job.id;
      try {
        completion.verification = fuzevpn_tls::VerifyApiCertificate(
            job.certificate_der, job.hostname);
      } catch (...) {
        completion.failed = true;
      }
      {
        std::lock_guard<std::mutex> lock(worker_state->mutex);
        if (worker_state->stopping) return;
        worker_state->completions.push_back(std::move(completion));
        // No pointer is sent through the window message. The lock also fences
        // shutdown from posting to a handle after this channel is stopped.
        PostMessageW(worker_state->window, kTlsTrustCompletedMessage, 0, 0);
      }
    }
  }

  void ProcessCompletions() {
    std::deque<Completion> completed;
    {
      std::lock_guard<std::mutex> lock(state->mutex);
      completed.swap(state->completions);
    }
    for (auto& completion : completed) {
      auto found = pending.find(completion.id);
      if (found == pending.end()) continue;
      auto result = std::move(found->second);
      pending.erase(found);
      if (completion.failed) {
        result->Error("tls_trust_verification_failed");
        continue;
      }
      const auto& verification = completion.verification;
      EncodableMap value;
      value.emplace(EncodableValue("trusted"),
                    EncodableValue(verification.trusted));
      value.emplace(EncodableValue("certificate_role"),
                    EncodableValue(verification.certificate_is_ca ? "ca"
                                                                 : "server"));
      value.emplace(EncodableValue("trust_status"),
                    EncodableValue(static_cast<int64_t>(verification.trust_status)));
      value.emplace(EncodableValue("windows_error"),
                    EncodableValue(static_cast<int64_t>(verification.windows_error)));
      if (verification.trusted) {
        value.emplace(EncodableValue("anchor_der"),
                      EncodableValue(verification.anchor_der));
      }
      result->Success(EncodableValue(std::move(value)));
    }
  }
};

TlsTrustChannel::TlsTrustChannel(flutter::FlutterEngine* engine, HWND window)
    : impl_(std::make_unique<Impl>(engine, window)) {}

TlsTrustChannel::~TlsTrustChannel() = default;

void TlsTrustChannel::ProcessCompletions() { impl_->ProcessCompletions(); }
