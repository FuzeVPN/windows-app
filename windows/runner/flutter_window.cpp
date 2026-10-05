#include "flutter_window.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shellapi.h>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

#include "flutter/generated_plugin_registrant.h"
#include "openvpn_tunnel.h"
#include "privileged_broker.h"
#include "secure_store_channel.h"
#include "diagnostics_snapshot.h"
#include "diagnostics_local.h"
#include "single_instance.h"
#include "utils.h"
#include "wireguard_tunnel.h"

namespace {

constexpr UINT kConnectivityRestoredMessage = WM_APP + 41;
constexpr wchar_t kStartupRegistryPath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kStartupValueName[] = L"FuzeVPN";

std::wstring ExecutablePath() {
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetModuleFileNameW(
      nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) return {};
  return std::wstring(buffer.data(), length);
}

std::wstring StartupCommand() {
  const auto executable = ExecutablePath();
  return executable.empty() ? std::wstring()
                            : L"\"" + executable + L"\" --minimized";
}

std::string ApplicationVersion() {
#ifdef FLUTTER_VERSION
  std::string version = FLUTTER_VERSION;
#else
  std::string version = "1.0.1";
#endif
  const auto build_separator = version.find('+');
  if (build_separator != std::string::npos) {
    version.erase(build_separator);
  }
  return version.empty() ? "1.0.1" : version;
}

std::string WindowsVersionLabel() {
  OSVERSIONINFOEXW version = {};
  version.dwOSVersionInfoSize = sizeof(version);
  using RtlGetVersion = LONG(WINAPI*)(OSVERSIONINFOEXW*);
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto get_version = ntdll == nullptr
      ? nullptr
      : reinterpret_cast<RtlGetVersion>(
            GetProcAddress(ntdll, "RtlGetVersion"));
  if (get_version != nullptr && get_version(&version) == 0 &&
      version.dwMajorVersion == 10) {
    return version.dwBuildNumber >= 22000 ? "Windows 11" : "Windows 10";
  }
  return "Windows";
}

std::string DeviceName() {
  return "FuzeVPN " + ApplicationVersion() + " -- " +
         WindowsVersionLabel();
}

bool IsLaunchAtStartupEnabled() {
  wchar_t stored[32768] = {};
  DWORD size = sizeof(stored);
  const LSTATUS status = RegGetValueW(
      HKEY_CURRENT_USER, kStartupRegistryPath, kStartupValueName,
      RRF_RT_REG_SZ, nullptr, stored, &size);
  return status == ERROR_SUCCESS && StartupCommand() == stored;
}

bool SetLaunchAtStartupEnabled(bool enabled) {
  HKEY key = nullptr;
  const LSTATUS open_status = RegCreateKeyExW(
      HKEY_CURRENT_USER, kStartupRegistryPath, 0, nullptr, 0,
      KEY_SET_VALUE, nullptr, &key, nullptr);
  if (open_status != ERROR_SUCCESS) return false;
  LSTATUS update_status = ERROR_SUCCESS;
  if (enabled) {
    const auto command = StartupCommand();
    if (command.empty()) {
      RegCloseKey(key);
      return false;
    }
    update_status = RegSetValueExW(
        key, kStartupValueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(command.c_str()),
        static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
  } else {
    update_status = RegDeleteValueW(key, kStartupValueName);
    if (update_status == ERROR_FILE_NOT_FOUND) update_status = ERROR_SUCCESS;
  }
  RegCloseKey(key);
  return update_status == ERROR_SUCCESS;
}

std::wstring Utf16FromUtf8(const std::string& value) {
  if (value.empty() || value.size() > 1024) return {};
  const int length = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
      static_cast<int>(value.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring result(length, L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), result.data(),
                          length) != length) {
    return {};
  }
  return result;
}

const std::string* StringArgument(const flutter::EncodableValue* arguments,
                                  const char* key) {
  if (arguments == nullptr) return nullptr;
  const auto* map = std::get_if<flutter::EncodableMap>(arguments);
  if (map == nullptr) return nullptr;
  const auto found = map->find(flutter::EncodableValue(key));
  return found == map->end() ? nullptr : std::get_if<std::string>(&found->second);
}

const bool* BoolArgument(const flutter::EncodableValue* arguments,
                         const char* key) {
  if (arguments == nullptr) return nullptr;
  const auto* map = std::get_if<flutter::EncodableMap>(arguments);
  if (map == nullptr) return nullptr;
  const auto found = map->find(flutter::EncodableValue(key));
  return found == map->end() ? nullptr : std::get_if<bool>(&found->second);
}

bool StartedMinimized() {
  const auto arguments = GetCommandLineArguments();
  return std::find(arguments.begin(), arguments.end(), "--minimized") !=
         arguments.end();
}

void CALLBACK ConnectivityHintChanged(
    PVOID context, NL_NETWORK_CONNECTIVITY_HINT hint) {
  if (hint.ConnectivityLevel != NetworkConnectivityLevelHintInternetAccess &&
      hint.ConnectivityLevel !=
          NetworkConnectivityLevelHintConstrainedInternetAccess) {
    return;
  }
  auto* window = static_cast<FlutterWindow*>(context);
  if (window != nullptr && window->GetHandle() != nullptr) {
    PostMessageW(window->GetHandle(), kConnectivityRestoredMessage, 0, 0);
  }
}

void CancelConnectivityNotification(HANDLE notification) {
  const HMODULE library = GetModuleHandleW(L"iphlpapi.dll");
  if (library == nullptr) {
    return;
  }
  using CancelNotification = NETIO_STATUS(WINAPI*)(HANDLE);
  const auto cancel = reinterpret_cast<CancelNotification>(
      GetProcAddress(library, "CancelMibChangeNotify2"));
  if (cancel != nullptr) {
    cancel(notification);
  }
}

void CALLBACK IpInterfaceChanged(PVOID context, PMIB_IPINTERFACE_ROW row,
                                 MIB_NOTIFICATION_TYPE type) {
  if (row == nullptr || type == MibDeleteInstance) return;
  MIB_IPINTERFACE_ROW current = {};
  InitializeIpInterfaceEntry(&current);
  current.Family = row->Family;
  current.InterfaceLuid = row->InterfaceLuid;
  current.InterfaceIndex = row->InterfaceIndex;
  if (GetIpInterfaceEntry(&current) != NO_ERROR || !current.Connected) return;
  auto* window = static_cast<FlutterWindow*>(context);
  if (window != nullptr && window->GetHandle() != nullptr) {
    PostMessageW(window->GetHandle(), kConnectivityRestoredMessage, 0, 0);
  }
}

HANDLE RegisterConnectivityNotification(FlutterWindow* window) {
  HANDLE notification = nullptr;
  // This export was introduced in Windows 10 2004. Do not add it to the
  // executable import table: older Windows 10 releases must still load.
  using NotifyHint = NETIO_STATUS(WINAPI*)(
      PNETWORK_CONNECTIVITY_HINT_CHANGE_CALLBACK, PVOID, BOOLEAN, PHANDLE);
  const HMODULE library = GetModuleHandleW(L"iphlpapi.dll");
  const auto notify_hint = library == nullptr ? nullptr :
      reinterpret_cast<NotifyHint>(
          GetProcAddress(library, "NotifyNetworkConnectivityHintChange"));
  if (notify_hint != nullptr &&
      notify_hint(ConnectivityHintChanged, window, FALSE, &notification) ==
          NO_ERROR) {
    return notification;
  }
  notification = nullptr;
  if (NotifyIpInterfaceChange(AF_UNSPEC, IpInterfaceChanged, window, FALSE,
                             &notification) != NO_ERROR) {
    return nullptr;
  }
  return notification;
}

}  // namespace

FlutterWindow::FlutterWindow(const flutter::DartProject& project)
    : project_(project) {}

FlutterWindow::~FlutterWindow() {}

bool FlutterWindow::OnCreate() {
  if (!Win32Window::OnCreate()) {
    return false;
  }

  RECT frame = GetClientArea();

  // The size here must match the window dimensions to avoid unnecessary surface
  // creation / destruction in the startup path.
  flutter_controller_ = std::make_unique<flutter::FlutterViewController>(
      frame.right - frame.left, frame.bottom - frame.top, project_);
  // Ensure that basic setup of the controller was successful.
  if (!flutter_controller_->engine() || !flutter_controller_->view()) {
    return false;
  }
  if (!InitializePrivilegedCallDispatcher(GetHandle())) return false;
  RegisterPlugins(flutter_controller_->engine());
  RegisterSecureStoreChannel(flutter_controller_->engine());
  RegisterOpenVpnChannel(flutter_controller_->engine());
  RegisterWireGuardChannel(flutter_controller_->engine());
  RegisterDiagnosticsChannel(flutter_controller_->engine());
  RegisterWindowChannel();
  update_channel_ = std::make_unique<UpdateChannel>(flutter_controller_->engine(), GetHandle());
  diagnostics_store_channel_ = std::make_unique<DiagnosticsStoreChannel>(
      flutter_controller_->engine(), GetHandle());
  tls_trust_channel_ = std::make_unique<TlsTrustChannel>(
      flutter_controller_->engine(), GetHandle());
  connectivity_notification_ = RegisterConnectivityNotification(this);
  SetChildContent(flutter_controller_->view()->GetNativeWindow());

  const bool started_minimized = StartedMinimized();
  flutter_controller_->engine()->SetNextFrameCallback([this, started_minimized]() {
    if (!started_minimized || !tray_available_) this->Show();
  });

  // Flutter can complete the first frame before the "show window" callback is
  // registered. The following call ensures a frame is pending to ensure the
  // window is shown. It is a no-op if the first frame hasn't completed yet.
  flutter_controller_->ForceRedraw();

  return true;
}

void FlutterWindow::RegisterWindowChannel() {
  window_channel_ =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          flutter_controller_->engine()->messenger(), "fuzevpn/window",
          &flutter::StandardMethodCodec::GetInstance());
  window_channel_->SetMethodCallHandler([this](const auto& call, auto result) {
    if (call.method_name() == "isLaunchAtStartupEnabled") {
      result->Success(flutter::EncodableValue(IsLaunchAtStartupEnabled()));
      return;
    }
    if (call.method_name() == "setLaunchAtStartup") {
      const bool* enabled = BoolArgument(call.arguments(), "enabled");
      if (enabled == nullptr) {
        result->Error("invalid_argument");
      } else if (!SetLaunchAtStartupEnabled(*enabled)) {
        result->Error("startup_update_failed");
      } else {
        result->Success();
      }
      return;
    }
    if (call.method_name() == "getDeviceName") {
      result->Success(flutter::EncodableValue(DeviceName()));
      return;
    }
    HWND window = GetHandle();
    if (window == nullptr) {
      result->Error("window_unavailable");
      return;
    }
    if (call.method_name() == "show") {
      ActivateFuzeVpnWindow(window);
      result->Success();
      return;
    }
    if (call.method_name() == "quit") {
      result->Success();
      PostMessage(window, WM_APP + 98, 0, 0);
      return;
    }
    if (call.method_name() == "setTrayAvailable") {
      const bool* available = BoolArgument(call.arguments(), "available");
      if (available == nullptr) {
        result->Error("invalid_argument");
        return;
      }
      tray_available_ = *available;
      if (!tray_available_) ActivateFuzeVpnWindow(window);
      result->Success();
      return;
    }
    if (call.method_name() == "showNotification") {
      const auto* title_value = StringArgument(call.arguments(), "title");
      const auto* message_value = StringArgument(call.arguments(), "message");
      if (title_value == nullptr || message_value == nullptr) {
        result->Error("invalid_argument");
        return;
      }
      const auto title = Utf16FromUtf8(*title_value);
      const auto message = Utf16FromUtf8(*message_value);
      if (title.empty() || message.empty()) {
        result->Error("invalid_argument");
        return;
      }
      NOTIFYICONDATAW notification = {};
      notification.cbSize = sizeof(notification);
      notification.hWnd = window;
      notification.uID = 1;
      notification.uFlags = NIF_INFO;
      notification.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
      wcsncpy_s(notification.szInfoTitle, title.c_str(), _TRUNCATE);
      wcsncpy_s(notification.szInfo, message.c_str(), _TRUNCATE);
      result->Success(flutter::EncodableValue(
          Shell_NotifyIconW(NIM_MODIFY, &notification) == TRUE));
      return;
    }
    result->NotImplemented();
  });
}

void FlutterWindow::NotifyDart(const char* method) {
  if (window_channel_ == nullptr) {
    return;
  }
  window_channel_->InvokeMethod(
      method, std::make_unique<flutter::EncodableValue>());
}

void FlutterWindow::OnDestroy() {
  fuzevpn_diagnostics::ShutdownLocalDiagnostics();
  tls_trust_channel_.reset();
  diagnostics_store_channel_.reset();
  update_channel_.reset();
  ShutdownPrivilegedCallDispatcher();
  if (connectivity_notification_ != nullptr) {
    CancelConnectivityNotification(connectivity_notification_);
    connectivity_notification_ = nullptr;
  }
  window_channel_ = nullptr;
  if (flutter_controller_) {
    flutter_controller_ = nullptr;
  }

  Win32Window::OnDestroy();
}

LRESULT
FlutterWindow::MessageHandler(HWND hwnd, UINT const message,
                              WPARAM const wparam,
                              LPARAM const lparam) noexcept {
  if (message == FuzeVpnSingleInstanceMessage()) {
    ActivateFuzeVpnWindow(hwnd);
    return 0;
  }

  // Give Flutter, including plugins, an opportunity to handle window messages.
  if (flutter_controller_) {
    std::optional<LRESULT> result =
        flutter_controller_->HandleTopLevelWindowProc(hwnd, message, wparam,
                                                      lparam);
    if (result) {
      return *result;
    }
  }

  switch (message) {
    case WM_APP + 98:
      DestroyWindow(hwnd);
      return 0;
    case kPrivilegedCallCompletedMessage:
      ProcessPrivilegedCallCompletions();
      return 0;
    case kUpdateCompletedMessage:
      if (update_channel_) update_channel_->ProcessCompletions();
      return 0;
    case kDiagnosticsStoreCompletedMessage:
      if (diagnostics_store_channel_) diagnostics_store_channel_->ProcessCompletions();
      return 0;
    case kTlsTrustCompletedMessage:
      if (tls_trust_channel_) tls_trust_channel_->ProcessCompletions();
      return 0;
    case WM_CLOSE:
      if (tray_available_) {
        ShowWindow(hwnd, SW_HIDE);
      } else {
        ActivateFuzeVpnWindow(hwnd);
      }
      return 0;
    case kConnectivityRestoredMessage:
      if (diagnostics_store_channel_) diagnostics_store_channel_->PurgeExpired();
      NotifyDart("networkAvailable");
      return 0;
    case WM_POWERBROADCAST:
      if (wparam == PBT_APMRESUMEAUTOMATIC ||
          wparam == PBT_APMRESUMESUSPEND ||
          wparam == PBT_APMRESUMECRITICAL) {
        if (diagnostics_store_channel_) diagnostics_store_channel_->PurgeExpired();
        NotifyDart("systemResumed");
      }
      return TRUE;
    case WM_FONTCHANGE:
      flutter_controller_->engine()->ReloadSystemFonts();
      break;
  }

  return Win32Window::MessageHandler(hwnd, message, wparam, lparam);
}
