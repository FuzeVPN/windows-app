// SPDX-License-Identifier: MPL-2.0
#include "maintenance_state.h"

#include <sddl.h>
#include <shlobj.h>
#include <winsvc.h>
#include <filesystem>
#include <vector>

#include "broker_security.h"
#include "installation_security.h"
#include "maintenance_service_config.h"
#include "maintenance_network_state.h"
#include "maintenance_process_wait.h"
#include "service_handoff_mutex.h"

namespace fuzevpn_maintenance {
namespace {
constexpr wchar_t kKey[] = L"SOFTWARE\\FuzeVPN\\Maintenance";
constexpr DWORD kDeadlineMs = 120000;
thread_local const wchar_t* maintenance_stage = L"not_started";
struct Key { HKEY value = nullptr; ~Key() { if (value) RegCloseKey(value); } };
struct Service { SC_HANDLE value = nullptr; ~Service() { if (value) CloseServiceHandle(value); } };
struct Handle { HANDLE value = nullptr; ~Handle() { if (value) CloseHandle(value); } };
bool Fail(DWORD value, DWORD* error) { if (error) *error = value; return false; }
bool ReadString(HKEY key, const wchar_t* name, std::wstring* result) {
  wchar_t value[32768]{};
  DWORD bytes = sizeof(value);
  if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, value, &bytes) != ERROR_SUCCESS)
    return false;
  *result = value;
  return true;
}
bool WriteString(HKEY key, const wchar_t* name, const std::wstring& value) {
  return RegSetValueExW(key, name, 0, REG_SZ,
      reinterpret_cast<const BYTE*>(value.c_str()),
      static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}
bool ProtectedKey(HKEY key) {
  DWORD bytes = 0;
  RegGetKeySecurity(key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, nullptr, &bytes);
  if (bytes == 0 || bytes > 65536) return false;
  std::vector<BYTE> storage(bytes);
  auto* descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(storage.data());
  if (RegGetKeySecurity(key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      descriptor, &bytes) != ERROR_SUCCESS) return false;
  PSID owner = nullptr; BOOL defaulted = FALSE, present = FALSE; PACL acl = nullptr;
  if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
      !fuzevpn_installation::IsTrustedOwner(owner) ||
      !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || !acl) return false;
  GENERIC_MAPPING mapping{KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};
  for (DWORD i = 0; i < acl->AceCount; ++i) {
    void* raw = nullptr;
    if (!GetAce(acl, i, &raw)) return false;
    const auto* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceFlags & INHERIT_ONLY_ACE) continue;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) return false;
    auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    DWORD rights = ace->Mask; MapGenericMask(&rights, &mapping);
    if ((rights & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER)) &&
        !fuzevpn_installation::IsTrustedOwner(&ace->SidStart)) return false;
  }
  return true;
}
bool RestoreGate(const std::wstring& transaction, const std::wstring& directory,
                 DWORD* error) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", SDDL_REVISION_1,
      &descriptor, nullptr)) return Fail(GetLastError(), error);
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  Key parent;
  LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\FuzeVPN", 0,
      KEY_READ | KEY_WOW64_64KEY, &parent.value);
  if (status != ERROR_SUCCESS || !ProtectedKey(parent.value)) {
    LocalFree(descriptor); return Fail(ERROR_ACCESS_DENIED, error);
  }
  Key key;
  DWORD disposition = 0;
  status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, nullptr, 0,
      KEY_ALL_ACCESS | KEY_WOW64_64KEY, &attributes, &key.value, &disposition);
  LocalFree(descriptor);
  if (status != ERROR_SUCCESS) return Fail(static_cast<DWORD>(status), error);
  if (!ProtectedKey(key.value)) return Fail(ERROR_ACCESS_DENIED, error);
  if (disposition != REG_CREATED_NEW_KEY) {
    std::wstring actual;
    // Never overwrite a gate acquired by another explicit installer attempt.
    if (!ReadString(key.value, L"Transaction", &actual) || actual != transaction)
      return Fail(ERROR_INSTALL_ALREADY_RUNNING, error);
  }
  const DWORD clean = 0;  // A failed/ambiguous start is not proof of clean stop.
  if (!WriteString(key.value, L"Transaction", transaction) ||
      !WriteString(key.value, L"Directory", directory) ||
      RegSetValueExW(key.value, L"CleanStopConfirmed", 0, REG_DWORD,
          reinterpret_cast<const BYTE*>(&clean), sizeof(clean)) != ERROR_SUCCESS ||
      RegFlushKey(key.value) != ERROR_SUCCESS) return Fail(ERROR_WRITE_FAULT, error);
  return true;
}
bool ValidToken(const std::wstring& token) {
  if (token.size() != 36) return false;
  for (size_t i = 0; i < token.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (token[i] != L'-') return false;
    } else if (!((token[i] >= L'0' && token[i] <= L'9') ||
                 (token[i] >= L'a' && token[i] <= L'f') ||
                 (token[i] >= L'A' && token[i] <= L'F'))) return false;
  }
  return true;
}
bool ValidDirectory(const std::wstring& directory) {
  return fuzevpn_installation::IsCanonicalLocalAbsolutePath(directory);
}
bool ProtectedInstallationPath(const std::wstring& directory) {
  return fuzevpn_installation::ValidateInstallationTarget(directory);
}
bool ExpectedService(SC_HANDLE service, const std::wstring& directory) {
  DWORD bytes = 0;
  QueryServiceConfigW(service, nullptr, 0, &bytes);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes > 65536) return false;
  std::vector<BYTE> storage(bytes);
  auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
  if (!QueryServiceConfigW(service, config, bytes, &bytes)) return false;
  const std::wstring command = L"\"" +
      (std::filesystem::path(directory) / L"fuzevpn-service.exe").wstring() +
      L"\" --fuzevpn-vpn-service";
  return config->dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
      fuzevpn_installation::SamePath(config->lpBinaryPathName, command) &&
      fuzevpn_installation::SamePath(config->lpServiceStartName, L"LocalSystem");
}
bool StopConfirmed(const std::wstring& directory, bool previously_clean, DWORD* error) {
  bool historical_failure = false;
  DWORD snapshot_pid = 0;
  maintenance_stage = L"scm_manager_open";
  Service manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
  if (!manager.value) return Fail(GetLastError(), error);
  maintenance_stage = L"service_open";
  Service service{OpenServiceW(manager.value, kServiceName,
      SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_CHANGE_CONFIG)};
  if (!service.value) {
    const DWORD status = GetLastError();
    if (status != ERROR_SERVICE_DOES_NOT_EXIST) return Fail(status, error);
  } else {
    maintenance_stage = L"service_configuration";
    if (!ExpectedService(service.value, directory)) return Fail(ERROR_BAD_CONFIGURATION, error);
    // Gate checks happen after the executable/DLL loader. Temporarily disabling
    // SCM startup also prevents recovery timers from loading files while MSI
    // replaces them. Commit/rollback restores automatic startup explicitly.
    maintenance_stage = L"service_disable";
    if (!ChangeServiceConfigW(service.value, SERVICE_NO_CHANGE, SERVICE_DISABLED,
        SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr)) return Fail(GetLastError(), error);
    SERVICE_STATUS_PROCESS state{};
    DWORD size = 0;
    maintenance_stage = L"service_state";
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&state), sizeof(state), &size)) return Fail(GetLastError(), error);
    // SCM retains a failed startup's exit code indefinitely, even after its
    // process is gone. A legacy unsigned service can fail before tunnel workers
    // exist. Such an old error requires an independent read-only network proof.
    const bool initially_stopped = state.dwCurrentState == SERVICE_STOPPED && state.dwProcessId == 0;
    Handle process;
    if (state.dwProcessId != 0) {
      maintenance_stage = L"service_process_open";
      process.value = OpenProcess(SYNCHRONIZE, FALSE, state.dwProcessId);
      if (!process.value) {
        const DWORD status = GetLastError();
        if (status != ERROR_ACCESS_DENIED && status != ERROR_INVALID_PARAMETER) return Fail(status, error);
        snapshot_pid = state.dwProcessId;
      }
    }
    if (state.dwCurrentState != SERVICE_STOPPED && state.dwCurrentState != SERVICE_STOP_PENDING) {
      maintenance_stage = L"service_stop_control";
      SERVICE_STATUS ignored{};
      if (!ControlService(service.value, SERVICE_CONTROL_STOP, &ignored) &&
          GetLastError() != ERROR_SERVICE_NOT_ACTIVE) return Fail(GetLastError(), error);
    }
    const ULONGLONG deadline = GetTickCount64() + kDeadlineMs;
    for (;;) {
      maintenance_stage = L"service_stop_confirmation";
      if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
          reinterpret_cast<BYTE*>(&state), sizeof(state), &size)) return Fail(GetLastError(), error);
      if (state.dwCurrentState == SERVICE_STOPPED) {
        // The current service reaches STOPPED with exit zero only after its
        // tunnel workers and network cleanup finish. Crash/error is not proof.
        const bool failed_stop = (state.dwWin32ExitCode != NO_ERROR &&
             !(previously_clean && state.dwWin32ExitCode == ERROR_INSTALL_ALREADY_RUNNING)) ||
            state.dwServiceSpecificExitCode != 0;
        if (failed_stop && !initially_stopped) return Fail(ERROR_SERVICE_SPECIFIC_ERROR, error);
        historical_failure = failed_stop;
        if (snapshot_pid && state.dwProcessId == 0) {
          maintenance_stage = L"service_process_snapshot";
          const auto exited = ServiceProcessExitedBySnapshot(snapshot_pid, error);
          if (!exited.has_value()) return false;
          if (*exited) break;
        } else if (!snapshot_pid && state.dwProcessId == 0 &&
            (!process.value || WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0)) break;
      }
      if (GetTickCount64() >= deadline) return Fail(ERROR_TIMEOUT, error);
      Sleep(100);
    }
  }
  // A separately surviving WireGuard tunnel must never be treated as stopped.
  maintenance_stage = L"wireguard_state";
  Service wireguard{OpenServiceW(manager.value, L"WireGuardTunnel$FuzeVPN", SERVICE_QUERY_STATUS)};
  if (wireguard.value) {
    SERVICE_STATUS state{};
    if (!QueryServiceStatus(wireguard.value, &state)) return Fail(GetLastError(), error);
    if (state.dwCurrentState != SERVICE_STOPPED) return Fail(ERROR_BUSY, error);
  } else if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) return Fail(GetLastError(), error);
  // This also detects a running broker. The registry gate prevents a new
  // runtime acquiring this mutex after the check; runtime checks it again
  // after acquisition to close the startup race.
  fuzevpn_handoff::Reservation lock;
  maintenance_stage = L"runtime_mutex";
  if (!lock.Acquire(L"Global\\FuzeVPN-ExclusiveRuntime-v1")) return Fail(GetLastError(), error);
  maintenance_stage = L"network_quiescence";
  if ((historical_failure || snapshot_pid) && !ConfirmStoppedNetworkState(directory, error)) return false;
  return true;
}
}  // namespace

bool IsBlocked() {
  Key key;
  const LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0,
      KEY_READ | KEY_WOW64_64KEY, &key.value);
  return status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND;
}

bool BeginInstallerMaintenance(const std::wstring& transaction,
                               const std::wstring& directory, DWORD* error) {
  maintenance_stage = L"request_validation";
  if (!ValidToken(transaction) || !ValidDirectory(directory)) return Fail(ERROR_INVALID_PARAMETER, error);
  maintenance_stage = L"target_security";
  if (!ProtectedInstallationPath(directory)) return Fail(ERROR_ACCESS_DENIED, error);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", SDDL_REVISION_1,
      &descriptor, nullptr)) return Fail(GetLastError(), error);
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  Key parent;
  maintenance_stage = L"parent_key_open";
  const LSTATUS parent_status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\FuzeVPN", 0, nullptr, 0,
      KEY_ALL_ACCESS | KEY_WOW64_64KEY, &attributes, &parent.value, nullptr);
  if (parent_status != ERROR_SUCCESS) {
    LocalFree(descriptor); return Fail(static_cast<DWORD>(parent_status), error);
  }
  maintenance_stage = L"parent_key_security";
  if (!ProtectedKey(parent.value)) {
    LocalFree(descriptor); return Fail(ERROR_ACCESS_DENIED, error);
  }
  Key key;
  maintenance_stage = L"gate_key_open";
  const LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, nullptr, 0,
      KEY_ALL_ACCESS | KEY_WOW64_64KEY, &attributes, &key.value, nullptr);
  LocalFree(descriptor);
  if (status != ERROR_SUCCESS) return Fail(static_cast<DWORD>(status), error);
  maintenance_stage = L"gate_key_security";
  if (!ProtectedKey(key.value)) return Fail(ERROR_ACCESS_DENIED, error);
  DWORD clean = 0, clean_size = sizeof(clean);
  const bool previously_clean = RegGetValueW(key.value, nullptr, L"CleanStopConfirmed",
      RRF_RT_REG_DWORD, nullptr, &clean, &clean_size) == ERROR_SUCCESS && clean == 1;
  // An interrupted earlier transaction intentionally leaves the gate in
  // place. The next explicit installer attempt retries the stop checks.
  maintenance_stage = L"gate_write";
  if (!WriteString(key.value, L"Transaction", transaction) ||
      !WriteString(key.value, L"Directory", directory)) return Fail(ERROR_WRITE_FAULT, error);
  maintenance_stage = L"gate_flush";
  if (RegFlushKey(key.value) != ERROR_SUCCESS) return Fail(ERROR_WRITE_FAULT, error);
  if (!StopConfirmed(directory, previously_clean, error)) return false;
  clean = 1;
  maintenance_stage = L"gate_clean_write";
  if (RegSetValueExW(key.value, L"CleanStopConfirmed", 0, REG_DWORD,
      reinterpret_cast<const BYTE*>(&clean), sizeof(clean)) != ERROR_SUCCESS ||
      RegFlushKey(key.value) != ERROR_SUCCESS) return Fail(ERROR_WRITE_FAULT, error);
  if (error) *error = ERROR_SUCCESS;
  maintenance_stage = L"complete";
  return true;
}

const wchar_t* LastInstallerMaintenanceStage() { return maintenance_stage; }

bool EndInstallerMaintenance(const std::wstring& transaction,
                             bool restart_service, DWORD* error,
                             bool* restart_attempted) {
  if (restart_attempted) *restart_attempted = false;
  if (!ValidToken(transaction)) return Fail(ERROR_INVALID_PARAMETER, error);
  Key key;
  LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0,
      KEY_READ | KEY_WOW64_64KEY, &key.value);
  if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
    if (error) *error = ERROR_SUCCESS;
    return true;
  }
  if (status != ERROR_SUCCESS) return Fail(static_cast<DWORD>(status), error);
  if (!ProtectedKey(key.value)) return Fail(ERROR_ACCESS_DENIED, error);
  std::wstring actual, directory;
  if (!ReadString(key.value, L"Transaction", &actual) || actual != transaction ||
      !ReadString(key.value, L"Directory", &directory) || !ValidDirectory(directory))
    return Fail(ERROR_ACCESS_DENIED, error);
  RegCloseKey(key.value); key.value = nullptr;
  const auto clear_gate = [&]() {
    const LSTATUS deleted = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, kKey, KEY_WOW64_64KEY, 0);
    return deleted == ERROR_SUCCESS || Fail(static_cast<DWORD>(deleted), error);
  };
  if (restart_service) {
    Service manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!manager.value) return Fail(GetLastError(), error);
    Service service{OpenServiceW(manager.value, kServiceName,
        SERVICE_START | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG)};
    if (!service.value) {
      if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) return Fail(GetLastError(), error);
      if (!clear_gate()) return false;
    } else {
      if (!ExpectedService(service.value, directory)) return Fail(ERROR_BAD_CONFIGURATION, error);
      if (!ConfigureServiceRuntime(service.value, ChangeServiceConfig2W)) return Fail(GetLastError(), error);
      if (!ChangeServiceConfigW(service.value, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
          SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
          nullptr)) return Fail(GetLastError(), error);
      const auto disable_service = [&]() {
        return ChangeServiceConfigW(service.value, SERVICE_NO_CHANGE, SERVICE_DISABLED,
            SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
      };
      if (!clear_gate()) {
        const DWORD clear_error = error ? *error : ERROR_WRITE_FAULT;
        return Fail(disable_service() ? clear_error : GetLastError(), error);
      }
      // A commit caller must not roll files back after this point: a timeout
      // does not prove SCM never created the service process. Report the
      // failure while preserving the installed files for an explicit repair.
      if (restart_attempted) *restart_attempted = true;
      if (!StartServiceW(service.value, 0, nullptr)) {
        const DWORD start_error = GetLastError();
        if (start_error != ERROR_SERVICE_ALREADY_RUNNING) {
          DWORD gate_error = ERROR_SUCCESS;
          const bool restored = RestoreGate(transaction, directory, &gate_error);
          const bool disabled = disable_service() != FALSE;
          const DWORD disable_error = disabled ? ERROR_SUCCESS : GetLastError();
          return Fail(!restored ? gate_error : !disabled ? disable_error : start_error, error);
        }
      }
    }
  } else if (!clear_gate()) return false;
  if (error) *error = ERROR_SUCCESS;
  return true;
}
}  // namespace fuzevpn_maintenance
