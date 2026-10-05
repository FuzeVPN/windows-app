// SPDX-License-Identifier: MPL-2.0
#include "update_channel.h"
#include "update_security.h"
#include "installation_security.h"
#include "maintenance_state.h"
#include "distribution_mode.h"
#include "runtime_architecture.h"
#include "portable_update.h"
#include <winhttp.h>
#include <shellapi.h>
#include <softpub.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

namespace {
using flutter::EncodableMap;
using flutter::EncodableValue;
using Result = flutter::MethodResult<EncodableValue>;
using namespace fuzevpn_update;
struct Internet { HINTERNET value = nullptr; ~Internet() { if (value) WinHttpCloseHandle(value); } };
struct FileHandle {
  HANDLE value = INVALID_HANDLE_VALUE;
  ~FileHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
Failure Failed(const char* code, const char* stage, DWORD windows_error = ERROR_SUCCESS,
               DWORD http_status = 0, LONG trust_status = ERROR_SUCCESS) {
  return {code, stage, windows_error, http_status, trust_status};
}
Failure NetworkFailure(const char* stage) {
  const DWORD error = GetLastError();
  return Failed(error == ERROR_WINHTTP_TIMEOUT ? "update_download_timeout" :
      "update_download_network_error", stage, error);
}
EncodableValue FailureDetails(const Failure& failure) {
  EncodableMap details;
  if (!failure.stage.empty()) details.emplace(EncodableValue("stage"), EncodableValue(failure.stage));
  if (failure.windows_error != ERROR_SUCCESS)
    details.emplace(EncodableValue("windows_error"), EncodableValue(static_cast<int64_t>(failure.windows_error)));
  if (failure.http_status != 0)
    details.emplace(EncodableValue("http_status"), EncodableValue(static_cast<int32_t>(failure.http_status)));
  if (failure.trust_status != ERROR_SUCCESS)
    details.emplace(EncodableValue("trust_status"), EncodableValue(static_cast<int32_t>(failure.trust_status)));
  return EncodableValue(details);
}
const std::string* Argument(const EncodableValue* arguments, const char* key) {
  const auto* map = arguments ? std::get_if<EncodableMap>(arguments) : nullptr;
  if (!map) return nullptr;
  const auto found = map->find(EncodableValue(key));
  return found == map->end() ? nullptr : std::get_if<std::string>(&found->second);
}
Failure Download(const std::string& source, const std::filesystem::path& path,
                 const std::atomic<bool>& cancelled) {
  const auto url = Wide(source);
  if (url.empty() || url.size() > 8192 || url.find_first_of(L"\r\n\t") != std::wstring::npos)
    return Failed("update_download_url_invalid", "download_url");
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength =
      parts.dwUserNameLength = parts.dwPasswordLength = static_cast<DWORD>(-1);
  if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &parts))
    return Failed("update_download_url_invalid", "download_url", GetLastError());
  if (parts.nScheme != INTERNET_SCHEME_HTTPS || parts.dwHostNameLength == 0 ||
      parts.dwUserNameLength != 0 || parts.dwPasswordLength != 0 ||
      source.find('#') != std::string::npos)
    return Failed("update_download_url_invalid", "download_url");
  const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
  std::wstring object = parts.dwUrlPathLength ?
      std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength) : L"/";
  if (parts.dwExtraInfoLength) object.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
  // No cookies, credentials or ambient proxy authentication are attached.
  Internet session{WinHttpOpen(L"FuzeVPN-Updater/1", WINHTTP_ACCESS_TYPE_NO_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
  if (!session.value) return NetworkFailure("download_session");
  if (!WinHttpSetTimeouts(session.value, 5000, 5000, 5000, 5000))
    return NetworkFailure("download_options");
  Internet connection{WinHttpConnect(session.value, host.c_str(), parts.nPort, 0)};
  if (!connection.value) return NetworkFailure("download_connect");
  Internet request{WinHttpOpenRequest(connection.value, L"GET", object.c_str(), nullptr,
      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)};
  if (!request.value) return NetworkFailure("download_request");
  DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  DWORD disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
  DWORD logon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
  if (!WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)) ||
      !WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) ||
      !WinHttpSetOption(request.value, WINHTTP_OPTION_AUTOLOGON_POLICY, &logon, sizeof(logon)))
    return NetworkFailure("download_options");
  const ULONGLONG deadline = GetTickCount64() + kDownloadDeadlineMs;
  if (cancelled) return Failed("update_cancelled", "download_send");
  if (!WinHttpSendRequest(request.value, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
      WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return NetworkFailure("download_send");
  if (!WinHttpReceiveResponse(request.value, nullptr)) return NetworkFailure("download_receive");
  DWORD status = 0, length = sizeof(status);
  if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
      WINHTTP_HEADER_NAME_BY_INDEX, &status, &length, WINHTTP_NO_HEADER_INDEX))
    return NetworkFailure("download_headers");
  if (status != 200) return Failed(status >= 300 && status < 400 ?
      "update_download_redirect_rejected" : "update_download_http_error", "download_http", 0, status);
  FileHandle file{CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
  if (file.value == INVALID_HANDLE_VALUE)
    return Failed("update_storage_failed", "download_create_file", GetLastError());
  std::array<BYTE, 65536> buffer{};
  uint64_t total = 0;
  for (;;) {
    if (cancelled) return Failed("update_cancelled", "download_read");
    if (GetTickCount64() >= deadline)
      return Failed("update_download_timeout", "download_deadline", ERROR_TIMEOUT);
    DWORD read = 0, written = 0;
    if (!WinHttpReadData(request.value, buffer.data(), static_cast<DWORD>(buffer.size()), &read))
      return NetworkFailure("download_read");
    if (!read) break;
    total += read;
    if (total > kMaximumDownloadBytes) return Failed("update_download_too_large", "download_size");
    if (!WriteFile(file.value, buffer.data(), read, &written, nullptr))
      return Failed("update_storage_failed", "download_write", GetLastError());
    if (written != read) return Failed("update_storage_failed", "download_write", ERROR_WRITE_FAULT);
  }
  if (cancelled) return Failed("update_cancelled", "download_read");
  if (GetTickCount64() >= deadline)
    return Failed("update_download_timeout", "download_deadline", ERROR_TIMEOUT);
  if (total == 0) return Failed("update_download_empty", "download_empty");
  if (!FlushFileBuffers(file.value))
    return Failed("update_storage_failed", "download_flush", GetLastError());
  return {};
}
EncodableMap Environment() {
  if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return {};
  Version version;
  OSVERSIONINFOEXW os{};
  os.dwOSVersionInfoSize = sizeof(os);
  using GetVersion = LONG(WINAPI*)(OSVERSIONINFOEXW*);
  const auto get_version = reinterpret_cast<GetVersion>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
  if (!ReadVersion(CurrentExecutable(), &version, true) || !get_version || get_version(&os) != 0) return {};
  return {{EncodableValue("version"), EncodableValue(version.text())},
          {EncodableValue("windows_build"), EncodableValue(static_cast<int32_t>(os.dwBuildNumber))},
          {EncodableValue("arch"), EncodableValue(fuzevpn_architecture::kBuildName)},
          {EncodableValue("installation_mode"), EncodableValue(
              fuzevpn_distribution::ModeName(fuzevpn_distribution::CurrentMode()))}};
}
}  // namespace

struct UpdateChannel::Impl {
  struct Prepared {
    std::unique_ptr<PrivateDirectory> directory;
    std::unique_ptr<PinnedFile> file;
    std::string token, hash;
    Version version;
    bool portable = false;
    ~Prepared() {
      file.reset();
      if (portable && directory) {
        fuzevpn_portable_update::RemoveStaging(directory->path() / L"portable");
        DeleteFileW((directory->path() / L"FuzeVPN-Portable.zip").c_str());
        DeleteFileW((directory->path() / L"fuzevpn-update.exe").c_str());
      }
    }
  };
  struct Job {
    std::string method, first, second, third, package;
    std::unique_ptr<Result> result;
  };
  struct Completion {
    std::unique_ptr<Result> result;
    Failure error;
    EncodableValue value;
  };
  HWND window;
  std::unique_ptr<flutter::MethodChannel<EncodableValue>> channel;
  std::atomic<bool> stopping{false};
  std::mutex mutex;
  std::condition_variable ready;
  std::deque<Job> jobs;
  std::deque<Completion> completions;
  bool busy = false;
  std::unique_ptr<Prepared> prepared;
  std::thread worker;

  Impl(flutter::FlutterEngine* engine, HWND handle) : window(handle) {
    channel = std::make_unique<flutter::MethodChannel<EncodableValue>>(
        engine->messenger(), "fuzevpn/update", &flutter::StandardMethodCodec::GetInstance());
    channel->SetMethodCallHandler([this](const auto& call, auto result) {
      if (call.method_name() == "getEnvironment") {
        const auto environment = Environment();
        if (environment.empty()) result->Error("update_environment_unavailable");
        else result->Success(EncodableValue(environment));
        return;
      }
      Job job;
      job.method = call.method_name();
      if (job.method == "prepareUpdate") {
        const auto* url = Argument(call.arguments(), "download_url");
        const auto* hash = Argument(call.arguments(), "sha256");
        const auto* version = Argument(call.arguments(), "version");
        const auto* package = Argument(call.arguments(), "package");
        Version parsed;
        if (!url || !hash || !version || !ValidHash(*hash) || !ParseVersion(*version, &parsed)) {
          result->Error("invalid_argument"); return;
        }
        job.first = *url; job.second = *hash; job.third = *version;
        job.package = package ? *package : "installer";
        if (job.package != "installer" && job.package != "portable") {
          result->Error("invalid_argument"); return;
        }
      } else if (job.method == "installUpdate" || job.method == "discardUpdate") {
        const auto* token = Argument(call.arguments(), "token");
        if (!token || !ValidToken(*token)) { result->Error("invalid_argument"); return; }
        job.first = *token;
      } else { result->NotImplemented(); return; }
      std::lock_guard<std::mutex> lock(mutex);
      if (busy || stopping) { result->Error("update_busy"); return; }
      busy = true;
      job.result = std::move(result);
      jobs.push_back(std::move(job));
      ready.notify_one();
    });
    worker = std::thread([this] { Work(); });
  }
  ~Impl() {
    channel->SetMethodCallHandler(nullptr);
    stopping = true;
    ready.notify_all();
    if (worker.joinable()) worker.join();
    for (auto& completion : completions) completion.result->Error("update_cancelled");
    for (auto& job : jobs) job.result->Error("update_cancelled");
    prepared.reset();
  }
  Failure Prepare(const Job& job, EncodableValue* value) {
    prepared.reset();
    if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return Failed("update_unsupported", "environment");
    const auto mode = fuzevpn_distribution::CurrentMode();
    const bool portable = mode == fuzevpn_distribution::Mode::portable;
    if (!portable && mode != fuzevpn_distribution::Mode::installed) return Failed("update_environment_unavailable", "environment");
    if ((job.package == "portable") != portable)
      return Failed("update_package_mode_mismatch", "environment");
    if (portable && !fuzevpn_portable_update::IsPortableTarget(CurrentExecutable().parent_path()))
      return Failed("update_portable_target_invalid", "portable_target");
    PinnedFile application;
    std::vector<BYTE> publisher;
    Version installed, target;
    if (!application.Open(CurrentExecutable()))
      return Failed("update_application_open_failed", "application_open");
    if (!MatchesBuildArchitecture(application.get()))
      return Failed("update_application_architecture_mismatch", "application_architecture");
    LONG trust_status = ERROR_SUCCESS;
    if (!TrustedPublisher(application, &publisher, &trust_status))
      return Failed(trust_status == TRUST_E_NOSIGNATURE ? "update_unsigned_application" :
          "update_application_signature_invalid", "application_signature", 0, 0, trust_status);
    if (!ReadVersion(application.path(), &installed, true))
      return Failed("update_version_invalid", "application_version");
    if (!ParseVersion(job.third, &target) || !(installed < target))
      return Failed("update_version_invalid", "target_version");
    auto next = std::make_unique<Prepared>();
    next->portable = portable;
    next->directory = std::make_unique<PrivateDirectory>();
    if (!next->directory->Create(false)) return Failed("update_storage_failed", "staging_create");
    const auto path = next->directory->path() / (portable ? L"FuzeVPN-Portable.zip" : L"FuzeVPN-Setup.exe");
    const auto downloaded = Download(job.first, path, stopping);
    if (!downloaded.code.empty()) return downloaded;
    next->file = std::make_unique<PinnedFile>();
    if (!next->file->Open(path)) return Failed("update_storage_failed", "package_open");
    Failure verification;
    if (portable) {
      const auto extracted = next->directory->path() / L"portable";
      if (!CreateDirectoryW(extracted.c_str(), nullptr)) return Failed("update_storage_failed", "portable_extract", GetLastError());
      if (!fuzevpn_portable_update::ExtractArchive(*next->file, job.second, extracted, &verification) ||
          !fuzevpn_portable_update::ValidateBundle(extracted, target, publisher, &verification)) return verification;
    } else if (!VerifyBundle(*next->file, job.second, target, publisher, &verification)) return verification;
    next->token = NewToken(); next->hash = job.second; next->version = target;
    if (next->token.empty()) return Failed("update_storage_failed", "token_create");
    *value = EncodableValue(next->token);
    prepared = std::move(next);
    return {};
  }
  Failure InstallPortable(const std::filesystem::path& directory,
                          const PinnedFile& helper, const std::vector<BYTE>& publisher) {
    if (!fuzevpn_portable_update::IsPortableTarget(directory))
      return Failed("update_portable_target_invalid", "portable_target");
    if (!MatchesHash(prepared->file->get(), prepared->hash))
      return Failed("update_hash_mismatch", "portable_hash");
    const auto copied_helper = prepared->directory->path() / L"fuzevpn-update.exe";
    {
      FileHandle output{CreateFileW(copied_helper.c_str(), GENERIC_WRITE, 0, nullptr,
          CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
      if (output.value == INVALID_HANDLE_VALUE || !CopyFileContents(helper.get(), output.value))
        return Failed("update_storage_failed", "portable_helper_copy", GetLastError());
    }
    PinnedFile pinned_helper;
    std::vector<BYTE> helper_publisher;
    LONG trust_status = ERROR_SUCCESS;
    if (!pinned_helper.Open(copied_helper, true) || !MatchesBuildArchitecture(pinned_helper.get()) ||
        !TrustedPublisher(pinned_helper, &helper_publisher, &trust_status) ||
        !SamePublisher(helper_publisher, publisher))
      return Failed("update_verification_failed", "portable_helper_signature", 0, 0, trust_status);
    FileHandle read_pipe, write_pipe, parent_process;
    SECURITY_ATTRIBUTES inheritable{sizeof(inheritable), nullptr, TRUE};
    if (!CreatePipe(&read_pipe.value, &write_pipe.value, &inheritable, 0) ||
        !SetHandleInformation(read_pipe.value, HANDLE_FLAG_INHERIT, 0) ||
        !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &parent_process.value,
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0))
      return Failed("update_install_failed", "portable_launch", GetLastError());
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    std::vector<BYTE> attribute_bytes(attribute_size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_bytes.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size))
      return Failed("update_install_failed", "portable_launch", GetLastError());
    struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Attributes() { DeleteProcThreadAttributeList(value); } } cleanup{attributes};
    HANDLE inherited[] = {write_pipe.value, parent_process.value};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
        sizeof(inherited), nullptr, nullptr))
      return Failed("update_install_failed", "portable_launch", GetLastError());
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW; startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + copied_helper.wstring() + L"\" --apply-portable --source \"" +
        prepared->file->path().wstring() + L"\" --sha256 " + Wide(prepared->hash) +
        L" --version " + Wide(prepared->version.text()) + L" --target \"" + directory.wstring() +
        L"\" --parent-handle " + std::to_wstring(reinterpret_cast<uintptr_t>(parent_process.value)) +
        L" --ready-handle " + std::to_wstring(reinterpret_cast<uintptr_t>(write_pipe.value));
    if (!CreateProcessW(copied_helper.c_str(), command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr,
        prepared->directory->path().c_str(), &startup.StartupInfo, &process))
      return Failed("update_install_failed", "portable_launch", GetLastError());
    FileHandle launched{process.hProcess}; CloseHandle(process.hThread);
    CloseHandle(write_pipe.value); write_pipe.value = INVALID_HANDLE_VALUE;
    const ULONGLONG deadline = GetTickCount64() + 120000;
    DWORD available = 0;
    for (;;) {
      if (!PeekNamedPipe(read_pipe.value, nullptr, 0, nullptr, &available, nullptr))
        return Failed("update_install_failed", "portable_ready", GetLastError());
      if (available >= sizeof(DWORD)) break;
      if (stopping || GetTickCount64() >= deadline)
        return Failed(stopping ? "update_cancelled" : "update_install_failed", "portable_ready", ERROR_TIMEOUT);
      if (WaitForSingleObject(launched.value, 50) == WAIT_OBJECT_0)
        return Failed("update_install_failed", "portable_ready", ERROR_PROCESS_ABORTED);
    }
    DWORD result = ERROR_INVALID_DATA, read = 0;
    if (!ReadFile(read_pipe.value, &result, sizeof(result), &read, nullptr) || read != sizeof(result))
      return Failed("update_install_failed", "portable_ready", GetLastError());
    if (result != ERROR_SUCCESS)
      return Failed("update_install_failed", "portable_ready", result);
    // The helper waits for this process to exit; keeping its random private
    // directory lets it continue after the prepared object is released.
    prepared->directory->Keep();
    prepared.reset();
    return {};
  }
  Failure Install(const Job& job) {
    if (!fuzevpn_architecture::NativeSystemMatchesBuild()) return Failed("update_unsupported", "environment");
    const auto mode = fuzevpn_distribution::CurrentMode();
    const bool portable = mode == fuzevpn_distribution::Mode::portable;
    if (!portable && mode != fuzevpn_distribution::Mode::installed) return Failed("update_environment_unavailable", "environment");
    if (!prepared || prepared->token != job.first) return Failed("update_not_prepared", "environment");
    if (prepared->portable != portable) return Failed("update_package_mode_mismatch", "environment");
    if (fuzevpn_maintenance::IsBlocked()) return Failed("maintenance_in_progress", "environment");
    const auto directory = CurrentExecutable().parent_path();
    fuzevpn_installation::ProtectedInstallation installation;
    if (!portable && !installation.Validate(directory / L"fuzevpn-service.exe"))
      return Failed("update_installation_unprotected", "installation_security");
    PinnedFile application, helper;
    std::vector<BYTE> publisher, helper_publisher;
    const auto helper_path = directory / L"fuzevpn-update.exe";
    if (!application.Open(CurrentExecutable()))
      return Failed("update_application_open_failed", "application_open");
    if (!MatchesBuildArchitecture(application.get()))
      return Failed("update_application_architecture_mismatch", "application_architecture");
    LONG trust_status = ERROR_SUCCESS;
    if (!TrustedPublisher(application, &publisher, &trust_status))
      return Failed(trust_status == TRUST_E_NOSIGNATURE ? "update_unsigned_application" :
          "update_application_signature_invalid", "application_signature", 0, 0, trust_status);
    if (!helper.Open(helper_path)) return Failed("update_verification_failed", "helper_open");
    if (!MatchesBuildArchitecture(helper.get())) return Failed("update_verification_failed", "helper_architecture");
    if (!TrustedPublisher(helper, &helper_publisher, &trust_status))
      return Failed("update_verification_failed", "helper_signature", 0, 0, trust_status);
    if (!SamePublisher(publisher, helper_publisher)) return Failed("update_verification_failed", "helper_publisher");
    if (portable) return InstallPortable(directory, helper, publisher);
    Failure verification;
    if (!VerifyBundle(*prepared->file, prepared->hash, prepared->version, publisher, &verification)) return verification;
    const std::wstring arguments = L"--apply --source \"" + prepared->file->path().wstring() +
        L"\" --sha256 " + Wide(prepared->hash) + L" --version " + Wide(prepared->version.text());
    SHELLEXECUTEINFOW launch{};
    launch.cbSize = sizeof(launch); launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.hwnd = window; launch.lpVerb = L"runas"; launch.lpFile = helper_path.c_str();
    launch.lpParameters = arguments.c_str(); launch.lpDirectory = directory.c_str();
    launch.nShow = SW_HIDE;
    if (!ShellExecuteExW(&launch)) {
      const DWORD error = GetLastError();
      return Failed(error == ERROR_CANCELLED ? "update_cancelled" : "update_install_failed", "install_launch", error);
    }
    if (!launch.hProcess) return Failed("update_install_failed", "install_launch");
    // The helper only copies/verifies/starts setup, then exits. It never waits
    // for MSI while holding files in the installation directory open.
    const DWORD wait = WaitForSingleObject(launch.hProcess, 120000);
    DWORD exit_code = ERROR_TIMEOUT;
    const DWORD wait_error = wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
    if (wait == WAIT_OBJECT_0 && !GetExitCodeProcess(launch.hProcess, &exit_code)) exit_code = GetLastError();
    CloseHandle(launch.hProcess);
    if (wait != WAIT_OBJECT_0) return Failed("update_install_failed", "install_wait", wait_error);
    if (exit_code != ERROR_SUCCESS) return Failed("update_install_failed", "install_exit", exit_code);
    prepared.reset();
    return {};
  }
  void Work() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    for (;;) {
      Job job;
      {
        std::unique_lock<std::mutex> lock(mutex);
        ready.wait(lock, [this] { return stopping || !jobs.empty(); });
        if (stopping) break;
        job = std::move(jobs.front()); jobs.pop_front();
      }
      Completion completion;
      try {
        if (job.method == "prepareUpdate") completion.error = Prepare(job, &completion.value);
        else if (job.method == "installUpdate") completion.error = Install(job);
        else if (prepared && prepared->token == job.first) prepared.reset();
      } catch (...) {
        completion.error = job.method == "prepareUpdate" ?
            Failed("update_prepare_failed", "prepare_exception") : Failed("update_install_failed", "install_exception");
      }
      completion.result = std::move(job.result);
      {
        std::lock_guard<std::mutex> lock(mutex);
        completions.push_back(std::move(completion));
      }
      PostMessageW(window, kUpdateCompletedMessage, 0, 0);
    }
    CoUninitialize();
  }
};
UpdateChannel::UpdateChannel(flutter::FlutterEngine* engine, HWND window)
    : impl_(std::make_unique<Impl>(engine, window)) {}
UpdateChannel::~UpdateChannel() = default;
void UpdateChannel::ProcessCompletions() {
  std::deque<Impl::Completion> completions;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    completions.swap(impl_->completions);
    if (!completions.empty()) impl_->busy = false;
  }
  for (auto& completion : completions) {
    if (completion.error.code.empty()) completion.result->Success(completion.value);
    else completion.result->Error(completion.error.code, "", FailureDetails(completion.error));
  }
}
