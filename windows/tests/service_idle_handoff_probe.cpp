// SPDX-License-Identifier: MPL-2.0
// Explicitly manual, elevated integration probe. This is never run by CTest
// and never shipped. It yields an idle signed service and restores it; no
// tunnel, GUI, packet filtering or portable engine is started.
#include <windows.h>
#include <winsvc.h>
#include <iostream>
#include "../runner/portable_service_lease.h"

int wmain(int count, wchar_t** arguments) {
  if (count != 2) { std::cerr << "Usage: service_idle_handoff_probe signed-helper.exe\n"; return 87; }
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  SC_HANDLE service = manager ? OpenServiceW(manager, L"FuzeVPNService", SERVICE_QUERY_STATUS) : nullptr;
  DWORD error = service ? ERROR_SUCCESS : GetLastError();
  const auto query = [&](SERVICE_STATUS_PROCESS* state) {
    DWORD bytes = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(state), sizeof(*state), &bytes)) return true;
    error = GetLastError(); return false;
  };
  SERVICE_STATUS_PROCESS state{};
  if (service && query(&state) && state.dwCurrentState == SERVICE_RUNNING && state.dwProcessId != 0) {
    fuzevpn_update::PinnedFile helper;
    if (!helper.Open(arguments[1])) error = ERROR_ACCESS_DENIED;
    else {
      fuzevpn_handoff::InstalledServiceLease lease;
      if (lease.Acquire(helper, GetCurrentProcess(), &error)) {
        if (!query(&state) || state.dwCurrentState != SERVICE_STOPPED || state.dwProcessId != 0)
          error = error ? error : ERROR_BUSY;
        else {
          std::cout << "PASS: production lease accepted; service STOPPED, PID0\n";
          if (lease.Restore(&error)) {
            const ULONGLONG deadline = GetTickCount64() + 12000;
            do {
              if (!query(&state)) break;
              if (state.dwCurrentState == SERVICE_RUNNING && state.dwProcessId != 0) {
                std::cout << "PASS: production restoration; service RUNNING\n"; break;
              }
              Sleep(50);
            } while (GetTickCount64() < deadline);
            if (state.dwCurrentState != SERVICE_RUNNING || state.dwProcessId == 0)
              error = error ? error : ERROR_BUSY;
          }
        }
      }
    }
  } else if (error == ERROR_SUCCESS) error = ERROR_SERVICE_NOT_ACTIVE;
  if (service) CloseServiceHandle(service);
  if (manager) CloseServiceHandle(manager);
  if (error) std::cerr << "FAIL: Windows code " << error << '\n';
  return static_cast<int>(error);
}
