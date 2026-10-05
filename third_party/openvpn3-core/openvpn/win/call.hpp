//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// execute a Windows command, capture the output

#ifndef OPENVPN_WIN_CALL_H
#define OPENVPN_WIN_CALL_H

#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>

#include <cstring>

#include <openvpn/common/uniqueptr.hpp>
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/unicode.hpp>
#include <openvpn/win/bounded_process.hpp>
#include <openvpn/win/command_context.hpp>
#include <openvpn/win/network_command_cleanup.hpp>

namespace openvpn::Win {

OPENVPN_EXCEPTION(win_call);
class win_call_exit : public win_call {
public:
    explicit win_call_exit(DWORD code) : win_call("Windows network command failed with exit code " + std::to_string(code)), code_(code) {}
    DWORD code() const { return code_; }
private:
    DWORD code_;
};

inline std::string call(const std::string &cmd, bool record_failure = true)
{
    if (cmd.find('\0') != std::string::npos)
        throw win_call("invalid Windows command");
    // split command name from args
    std::string name;
    std::string args;
    const size_t spcidx = cmd.find_first_of(" ");
    if (spcidx != std::string::npos)
    {
        name = cmd.substr(0, spcidx);
        if (spcidx + 1 < cmd.length())
            args = cmd.substr(spcidx + 1);
    }
    else
        name = cmd;

    // get system path
    wchar_t *syspath_ptr = nullptr;
    if (::SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &syspath_ptr) != S_OK)
        throw win_call("cannot get system path using SHGetKnownFolderPath");
    unique_ptr_del<wchar_t> syspath(syspath_ptr,
                                    [](wchar_t *p)
                                    { ::CoTaskMemFree(p); });
    UTF16 wide_name(Win::utf16(name + ".exe"));
    UTF16 wide_args(Win::utf16(args));
    const std::wstring executable = std::wstring(syspath.get()) + L"\\" + wide_name.get();
    ProcessResult result;
    const auto deadline = CommandDeadline(GetTickCount64(), 10000);
    try {
        result = RunBoundedProcess(executable, wide_args.get(),
            deadline, CommandCancelled);
    } catch (...) {
        const DWORD code = GetTickCount64() >= deadline ? ERROR_TIMEOUT
            : CommandCancelled() ? ERROR_OPERATION_ABORTED : ERROR_GEN_FAILURE;
        RecordNetworkCommandFailure(ClassifyNetworkCommand(cmd), code, record_failure);
        throw;
    }
    if (result.exit_code != ERROR_SUCCESS && !NetworkCleanupAlreadyComplete(cmd)) {
        RecordNetworkCommandFailure(ClassifyNetworkCommand(cmd), result.exit_code, record_failure);
        throw win_call_exit(result.exit_code);
    }
    std::string out = std::move(result.output);

    // decode output using console codepage, convert to utf16
    // console codepage, used to decode output
    UTF16 utf16output(Win::utf16(out, ::GetOEMCP()));

    // re-encode utf16 to utf8
    UTF8 utf8output(Win::utf8(utf16output.get()));
    out.assign(utf8output.get());

    return out;
}
} // namespace openvpn::Win

#endif
