#pragma once

#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace openvpn::Win {
struct ProcessResult { DWORD exit_code = 0; std::string output; };
class ProcessHandle {
public:
    explicit ProcessHandle(HANDLE value = nullptr) : value_(value) {}
    ~ProcessHandle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE release() { const auto value = value_; value_ = nullptr; return value; }
private:
    HANDLE value_;
};

// The executable is explicit; the command line is never interpreted by a shell.
// A kill-on-close job owns all descendants. Output is polled before ReadFile,
// making cancellation effective even when the child never writes or exits.
inline ProcessResult RunBoundedProcess(const std::wstring& executable,
    const std::wstring& arguments, std::uint64_t deadline,
    const std::function<bool()>& cancelled = {}, std::size_t output_limit = 256 * 1024) {
    if (executable.empty() || executable.find(L'\0') != std::wstring::npos ||
        arguments.find(L'\0') != std::wstring::npos)
        throw std::runtime_error("invalid child process arguments");
    if (GetTickCount64() >= deadline || (cancelled && cancelled()))
        throw std::runtime_error("child process cancelled");
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_raw = nullptr, write_raw = nullptr;
    if (!CreatePipe(&read_raw, &write_raw, &security, 0))
        throw std::runtime_error("cannot create child output pipe");
    ProcessHandle reader(read_raw), writer(write_raw);
    if (!SetHandleInformation(reader.get(), HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("cannot protect child output handle");
    ProcessHandle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
    job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.get() || !SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                               &job_limits, sizeof(job_limits)))
        throw std::runtime_error("cannot supervise child process");
    SIZE_T attribute_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
    if (!attribute_size) throw std::runtime_error("cannot size child handles");
    std::vector<unsigned char> attribute_bytes(attribute_size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_bytes.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size))
        throw std::runtime_error("cannot initialize child handles");
    struct AttributeCleanup {
        LPPROC_THREAD_ATTRIBUTE_LIST value;
        ~AttributeCleanup() { DeleteProcThreadAttributeList(value); }
    } attribute_cleanup{attributes};
    HANDLE inherited[] = {writer.get()};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                    inherited, sizeof(inherited), nullptr, nullptr))
        throw std::runtime_error("cannot restrict child handles");
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = writer.get();
    startup.StartupInfo.hStdError = writer.get();
    startup.lpAttributeList = attributes;
    std::wstring command = L"\"" + executable + L"\"" + (arguments.empty() ? L"" : L" " + arguments);
    PROCESS_INFORMATION information{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        nullptr, nullptr, &startup.StartupInfo, &information))
        throw std::runtime_error("cannot start child process");
    ProcessHandle process(information.hProcess), thread(information.hThread);
    if (!AssignProcessToJobObject(job.get(), process.get())) {
        TerminateProcess(process.get(), ERROR_PROCESS_ABORTED);
        WaitForSingleObject(process.get(), 2000);
        throw std::runtime_error("cannot assign child supervision");
    }
    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
        throw std::runtime_error("cannot resume child process");
    CloseHandle(writer.release());
    ProcessResult result;
    for (;;) {
        if (GetTickCount64() >= deadline || (cancelled && cancelled())) {
            TerminateJobObject(job.get(), ERROR_TIMEOUT);
            WaitForSingleObject(process.get(), 2000);
            throw std::runtime_error("child process cancelled or timed out");
        }
        DWORD available = 0;
        const bool pipe_open = PeekNamedPipe(reader.get(), nullptr, 0, nullptr, &available, nullptr) != FALSE;
        if (!pipe_open && GetLastError() != ERROR_BROKEN_PIPE)
            throw std::runtime_error("cannot read child output");
        if (available) {
            char buffer[4096];
            DWORD count = 0;
            if (!ReadFile(reader.get(), buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr))
                throw std::runtime_error("cannot read child output");
            if (count > output_limit - result.output.size())
                throw std::runtime_error("child output limit exceeded");
            result.output.append(buffer, count);
            continue;
        }
        const DWORD state = WaitForSingleObject(process.get(), 0);
        if (state == WAIT_FAILED) throw std::runtime_error("cannot wait for child process");
        if (state == WAIT_OBJECT_0) {
            // The child may have written and exited between the first pipe
            // probe and the process check. Drain that last output as well.
            DWORD final_available = 0;
            if (PeekNamedPipe(reader.get(), nullptr, 0, nullptr, &final_available, nullptr) && final_available)
                continue;
            if (!GetExitCodeProcess(process.get(), &result.exit_code))
                throw std::runtime_error("cannot read child exit code");
            return result;
        }
        Sleep(10);
    }
}
} // namespace openvpn::Win
