// SPDX-License-Identifier: MPL-2.0
#include "openvpn_dco_driver.h"
#include "retryable_installation.h"
#include "openvpn_driver_version.h"

#include <windows.h>
#include <devguid.h>
#include <newdev.h>
#include <setupapi.h>
#include <cfgmgr32.h>

#include <atomic>
#include <mutex>
#include <string>

namespace {

fuzevpn::RetryableInstallation installation;
std::atomic<bool> driver_restart_required{false};
constexpr wchar_t kPendingRestartKey[] = L"SOFTWARE\\FuzeVPN\\PendingDcoRestart";

bool DriverRestartPending() {
  if (driver_restart_required.load()) return true;
  HKEY key = nullptr;
  const auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPendingRestartKey, 0, KEY_QUERY_VALUE, &key);
  if (key) RegCloseKey(key);
  return status != ERROR_FILE_NOT_FOUND;
}
void MarkDriverRestartPending() {
  // Do not lose the OS result on a retry in this runtime if the registry
  // marker cannot be written. The volatile marker also covers later runtimes.
  driver_restart_required.store(true);
  HKEY key = nullptr;
  // This marker survives a service restart but disappears on Windows reboot.
  if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kPendingRestartKey, 0, nullptr,
      REG_OPTION_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) RegCloseKey(key);
}

std::uint64_t BundledDriverVersion(const std::wstring& inf) {
  const auto file = SetupOpenInfFileW(inf.c_str(), nullptr, INF_STYLE_WIN4, nullptr);
  if (file == INVALID_HANDLE_VALUE) return 0;
  INFCONTEXT context{};
  wchar_t text[64]{};
  const bool read = SetupFindFirstLineW(file, L"Version", L"DriverVer", &context) &&
      SetupGetStringFieldW(&context, 2, text, static_cast<DWORD>(std::size(text)), nullptr);
  SetupCloseInfFile(file);
  std::uint64_t version = 0;
  return read && fuzevpn::ParseOpenVpnDriverVersion(text, &version) ? version : 0;
}

bool InstalledDriverVersion(HDEVINFO devices, SP_DEVINFO_DATA* device, std::uint64_t* installed) {
  const HKEY key = SetupDiOpenDevRegKey(devices, device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
  if (key == INVALID_HANDLE_VALUE) return false;
  wchar_t text[64]{}; DWORD bytes = sizeof(text);
  const auto status = RegGetValueW(key, nullptr, L"DriverVersion", RRF_RT_REG_SZ,
                                   nullptr, text, &bytes);
  RegCloseKey(key);
  return status == ERROR_SUCCESS && fuzevpn::ParseOpenVpnDriverVersion(text, installed);
}

std::wstring ExecutableDirectory() {
  std::wstring path(MAX_PATH, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0 || length >= path.size()) return {};
  path.resize(length);
  const size_t separator = path.find_last_of(L"\\/");
  return separator == std::wstring::npos ? std::wstring{} : path.substr(0, separator);
}

bool IsWindows11OrNewer() {
  OSVERSIONINFOEXW version{};
  version.dwOSVersionInfoSize = sizeof(version);
  version.dwMajorVersion = 10;
  version.dwMinorVersion = 0;
  version.dwBuildNumber = 22000;
  DWORDLONG mask = VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL);
  mask = VerSetConditionMask(mask, VER_MINORVERSION, VER_GREATER_EQUAL);
  mask = VerSetConditionMask(mask, VER_BUILDNUMBER, VER_GREATER_EQUAL);
  return VerifyVersionInfoW(&version, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, mask) != FALSE;
}

bool Exists(const std::wstring& path) {
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

bool IsDcoHardwareId(const wchar_t* ids, DWORD byte_count) {
  if (!ids || byte_count < sizeof(wchar_t)) return false;
  const size_t characters = byte_count / sizeof(wchar_t);
  for (size_t offset = 0; offset < characters && ids[offset] != L'\0';) {
    const wchar_t* id = ids + offset;
    const size_t remaining = characters - offset;
    const size_t length = wcsnlen_s(id, remaining);
    if (length == remaining) return false;
    if (_wcsicmp(id, L"ovpn-dco") == 0 || _wcsicmp(id, L"root\\ovpn-dco") == 0)
      return true;
    offset += length + 1;
  }
  return false;
}

bool DcoAdapterExists(bool require_started = true, std::uint64_t minimum_version = 0,
                      bool* may_update = nullptr) {
  if (may_update) *may_update = true;
  HDEVINFO devices = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr,
                                           DIGCF_PRESENT);
  if (devices == INVALID_HANDLE_VALUE) { if (may_update) *may_update = false; return false; }
  bool found = false;
  bool incompatible = false;
  for (DWORD index = 0;; ++index) {
    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    if (!SetupDiEnumDeviceInfo(devices, index, &device)) {
      if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        incompatible = true;
        if (may_update) *may_update = false;
      }
      break;
    }
    wchar_t ids[4096]{};
    DWORD type = 0;
    DWORD required = 0;
    if (SetupDiGetDeviceRegistryPropertyW(
            devices, &device, SPDRP_HARDWAREID, &type,
            reinterpret_cast<PBYTE>(ids), sizeof(ids), &required) &&
        (type == REG_MULTI_SZ || type == REG_SZ) &&
        IsDcoHardwareId(ids, required)) {
      ULONG status = 0, problem = 0;
      const bool usable = !require_started ||
          (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) == CR_SUCCESS &&
           (status & DN_STARTED) != 0 && (status & DN_HAS_PROBLEM) == 0 && problem == 0);
      if (usable) {
        found = true;
      }
      if (minimum_version) {
        std::uint64_t installed = 0;
        const bool known = InstalledDriverVersion(devices, &device, &installed);
        if (usable && (!known || !fuzevpn::OpenVpnDriverVersionCompatible(installed, minimum_version))) incompatible = true;
        // Windows ranks date before version in some cases. Do not stage our
        // package if doing so could replace any newer bound package.
        if (may_update && ((!known && usable) || (known && installed > minimum_version))) *may_update = false;
      }
    }
  }
  SetupDiDestroyDeviceInfoList(devices);
  return found && !incompatible;
}

void RemoveRegisteredDevice(HDEVINFO devices, SP_DEVINFO_DATA* device) {
  SP_REMOVEDEVICE_PARAMS remove{};
  remove.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
  remove.ClassInstallHeader.InstallFunction = DIF_REMOVE;
  remove.Scope = DI_REMOVEDEVICE_GLOBAL;
  remove.HwProfile = 0;
  if (SetupDiSetClassInstallParamsW(
          devices, device, &remove.ClassInstallHeader, sizeof(remove))) {
    SetupDiCallClassInstaller(DIF_REMOVE, devices, device);
  }
}

bool CreateDcoAdapter(const std::wstring& inf, std::uint64_t minimum_version) {
  GUID class_guid{};
  wchar_t class_name[256]{};
  if (!SetupDiGetINFClassW(inf.c_str(), &class_guid, class_name,
                           static_cast<DWORD>(sizeof(class_name) / sizeof(*class_name)), nullptr))
    return false;

  HDEVINFO devices = SetupDiCreateDeviceInfoList(&class_guid, nullptr);
  if (devices == INVALID_HANDLE_VALUE) return false;
  SP_DEVINFO_DATA device{};
  device.cbSize = sizeof(device);
  bool registered = false;
  bool installed_device = false;
  do {
    if (!SetupDiCreateDeviceInfoW(
            devices, class_name, &class_guid, nullptr, nullptr,
            DICD_GENERATE_ID, &device))
      break;
    // REG_MULTI_SZ requires two terminating NUL characters. The explicit NUL
    // below plus the string literal terminator provide exactly that.
    const wchar_t hardware_id[] = L"ovpn-dco\0";
    if (!SetupDiSetDeviceRegistryPropertyW(
            devices, &device, SPDRP_HARDWAREID,
            reinterpret_cast<const BYTE*>(hardware_id), sizeof(hardware_id)))
      break;
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devices, &device))
      break;
    registered = true;

    BOOL reboot_required = FALSE;
    if (!UpdateDriverForPlugAndPlayDevicesW(
            nullptr, L"ovpn-dco", inf.c_str(), INSTALLFLAG_NONINTERACTIVE,
            &reboot_required))
      break;
    installed_device = true;
    if (reboot_required) { MarkDriverRestartPending(); break; }
  } while (false);

  if (registered && !installed_device) RemoveRegisteredDevice(devices, &device);
  SetupDiDestroyDeviceInfoList(devices);
  return installed_device && !DriverRestartPending() && DcoAdapterExists(true, minimum_version);
}

bool Install() {
  const std::wstring base = ExecutableDirectory();
  if (base.empty()) return false;
  const std::wstring directory = base + L"\\openvpn-dco\\" +
      (IsWindows11OrNewer() ? L"win11" : L"win10");
  const std::wstring inf = directory + L"\\ovpn-dco.inf";
  // The catalog and driver must be adjacent to the INF. Windows verifies the
  // signed catalog while adding the package to its driver store.
  if (!Exists(inf) || !Exists(directory + L"\\ovpn-dco.cat") ||
      !Exists(directory + L"\\ovpn-dco.sys")) return false;
  const auto minimum_version = BundledDriverVersion(inf);
  if (!minimum_version || DriverRestartPending()) return false;
  // A started adapter without a PnP problem can be reused. Re-running DiInstallDriver for an
  // installed package may legitimately report that there is no applicable
  // installation work; that must not make the OpenVPN runtime unavailable.
  bool may_update = false;
  if (DcoAdapterExists(true, minimum_version, &may_update)) return true;
  if (!may_update) return false;

  BOOL reboot_required = FALSE;
  // Stage/update the signed package first. DiInstallDriver does not create a
  // root-enumerated virtual adapter when none exists, so explicitly register
  // one below before binding the package to it.
  //
  // CreateDcoAdapter also binds this exact signed INF and reports the final
  // result. Continue when staging alone reports no applicable device.
  (void)DiInstallDriverW(nullptr, inf.c_str(), 0, &reboot_required);
  if (reboot_required) { MarkDriverRestartPending(); return false; }
  if (DcoAdapterExists(true, minimum_version)) return true;
  if (DcoAdapterExists(false)) {
    // Repair binding of an existing unhealthy device instead of creating an
    // additional root adapter on every failed attempt. Disabled/reboot-pending
    // devices remain unavailable and are not advertised as a working driver.
    (void)UpdateDriverForPlugAndPlayDevicesW(nullptr, L"ovpn-dco", inf.c_str(),
        INSTALLFLAG_NONINTERACTIVE, &reboot_required);
    if (reboot_required) { MarkDriverRestartPending(); return false; }
    return DcoAdapterExists(true, minimum_version);
  }
  return CreateDcoAdapter(inf, minimum_version);
}

}  // namespace

bool EnsureBundledOpenVpnDcoDriver() {
  // Failed staging is retryable (PnP may be busy). Also recover if an adapter
  // that existed earlier has since been removed.
  // Validate the actual bound package on every use, not only hardware presence.
  // Install uses Windows' normal ranking; it never forces a downgrade.
  const auto directory = ExecutableDirectory() + L"\\openvpn-dco\\" +
      (IsWindows11OrNewer() ? L"win11" : L"win10");
  const auto minimum_version = BundledDriverVersion(directory + L"\\ovpn-dco.inf");
  if (!minimum_version || DriverRestartPending()) return false;
  return installation.Ensure([minimum_version] { return DcoAdapterExists(true, minimum_version); }, Install);
}

bool BundledOpenVpnDcoDriverAvailable() {
  const std::wstring base = ExecutableDirectory();
  if (base.empty()) return false;
  const std::wstring directory = base + L"\\openvpn-dco\\" +
      (IsWindows11OrNewer() ? L"win11" : L"win10");
  return Exists(directory + L"\\ovpn-dco.inf") &&
         Exists(directory + L"\\ovpn-dco.cat") &&
         Exists(directory + L"\\ovpn-dco.sys");
}

bool OpenVpnDcoDriverRestartRequired() { return DriverRestartPending(); }

fuzevpn_diagnostics::DriverObservation ObserveOpenVpnDcoDriver() {
  using namespace fuzevpn_diagnostics;
  DriverObservation out;
  HKEY pending = nullptr;
  const auto restart_status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPendingRestartKey, 0, KEY_QUERY_VALUE, &pending);
  if (pending) RegCloseKey(pending);
  const bool restart_pending = driver_restart_required.load() || restart_status == ERROR_SUCCESS;
  const bool restart_unknown = restart_status != ERROR_SUCCESS && restart_status != ERROR_FILE_NOT_FOUND;
  HDEVINFO devices = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
  if (devices == INVALID_HANDLE_VALUE) return out;
  bool usable = false, unknown = false;
  std::optional<std::uint64_t> version;
  bool version_conflict = false;
  for (DWORD index = 0; index < 4096; ++index) {
    SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
    if (!SetupDiEnumDeviceInfo(devices, index, &device)) {
      if (GetLastError() != ERROR_NO_MORE_ITEMS) unknown = true;
      break;
    }
    if (index == 4095) unknown = true;
    wchar_t ids[4096]{}; DWORD type = 0, required = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(devices, &device, SPDRP_HARDWAREID, &type,
        reinterpret_cast<PBYTE>(ids), sizeof(ids), &required)) {
      if (GetLastError() != ERROR_INVALID_DATA) unknown = true;
      continue;
    }
    if ((type != REG_MULTI_SZ && type != REG_SZ) || !IsDcoHardwareId(ids, required)) continue;
    ULONG state = 0, problem = 0;
    if (CM_Get_DevNode_Status(&state, &problem, device.DevInst, 0) != CR_SUCCESS) { unknown = true; continue; }
    usable |= (state & DN_STARTED) && !(state & DN_HAS_PROBLEM) && problem == 0;
    std::uint64_t current = 0;
    if (!InstalledDriverVersion(devices, &device, &current)) version_conflict = true;
    else if (version && *version != current) version_conflict = true;
    else version = current;
  }
  SetupDiDestroyDeviceInfoList(devices);
  out.available = restart_pending ? CheckResult::failed : restart_unknown ? CheckResult::unknown :
      usable ? CheckResult::passed : unknown ? CheckResult::unknown : CheckResult::failed;
  if (version && !version_conflict) out.version = std::to_string((*version >> 48) & 65535) + "." +
      std::to_string((*version >> 32) & 65535) + "." + std::to_string((*version >> 16) & 65535) + "." +
      std::to_string(*version & 65535);
  return out;
}
