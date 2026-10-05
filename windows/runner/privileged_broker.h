// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PRIVILEGED_BROKER_H_
#define RUNNER_PRIVILEGED_BROKER_H_

#include <memory>
#include <optional>
#include <string>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <flutter/encodable_value.h>
#include <flutter/method_call.h>
#include <flutter/method_result.h>

// Returns an exit code only for the native broker command line. Normal Flutter
// launches return std::nullopt and stay at the caller's unelevated integrity.
std::optional<int> RunPrivilegedBrokerIfRequested();

// Sends one allow-listed VPN operation to the elevated broker. The original
// Flutter result receives the broker's standard success/error envelope. The
// only identity material that may be returned is a WireGuard public key.
void ForwardPrivilegedCall(
    const std::string& scope,
    const flutter::MethodCall<flutter::EncodableValue>& call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result,
    bool start_if_missing);

bool IsPrivilegedBrokerRunning();
// false only for confirmed absence; nullopt preserves SCM/process-query errors.
std::optional<bool> PrivilegedRuntimePresence(bool* detection_failed = nullptr);

// Reports an unknown runtime state without implying that a VPN disconnect
// failed. Only a fixed error code and the numeric Windows error leave native
// code; registry paths and other users' runtime information are never exposed.
void CompleteRuntimeStatusFailure(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result,
    bool detection_failed = false);
void CompleteRuntimeStatusFailure(
    flutter::MethodResult<flutter::EncodableValue>* result,
    bool detection_failed = false);

// True only when the signed persistent service is available. The UI uses this
// distinction at shutdown so it never tears down a service-owned tunnel or
// kill switch merely because the window/process exits.
bool IsPersistentVpnServiceRunning();

#ifndef FUZEVPN_SERVICE_PROCESS
constexpr UINT kPrivilegedCallCompletedMessage = 0x8000 + 42;  // WM_APP + 42.
bool InitializePrivilegedCallDispatcher(HWND window);
void ProcessPrivilegedCallCompletions();
// Must run on the platform thread, before the Flutter engine is destroyed.
void ShutdownPrivilegedCallDispatcher();
#endif

// Best-effort lifecycle cleanup used after both tunnel engines are stopped.
void ShutdownPrivilegedBroker();

#endif  // RUNNER_PRIVILEGED_BROKER_H_
