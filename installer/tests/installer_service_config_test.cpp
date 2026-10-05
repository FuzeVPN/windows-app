#include "../../windows/runner/maintenance_service_config.h"
#include "../l10n/generated/installer_catalogs.h"
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
struct ServiceFixture {
  std::wstring description;
  std::vector<DWORD> changes;
  DWORD fail_on = 0;
  BOOL Configure(SC_HANDLE service, DWORD level, LPVOID data) {
    Require(service == reinterpret_cast<SC_HANDLE>(this), "fixture service handle");
    changes.push_back(level);
    if (level == fail_on) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    switch (level) {
      case SERVICE_CONFIG_DESCRIPTION:
        description = static_cast<SERVICE_DESCRIPTIONW*>(data)->lpDescription;
        break;
      case SERVICE_CONFIG_SERVICE_SID_INFO:
        Require(static_cast<SERVICE_SID_INFO*>(data)->dwServiceSidType == SERVICE_SID_TYPE_UNRESTRICTED, "service SID");
        break;
      case SERVICE_CONFIG_DELAYED_AUTO_START_INFO:
        Require(static_cast<SERVICE_DELAYED_AUTO_START_INFO*>(data)->fDelayedAutostart, "delayed start");
        break;
      case SERVICE_CONFIG_FAILURE_ACTIONS: {
        const auto* recovery = static_cast<SERVICE_FAILURE_ACTIONSW*>(data);
        Require(recovery->dwResetPeriod == 86400 && recovery->cActions == 3, "recovery policy");
        const std::array<DWORD, 3> delays{1000, 5000, 30000};
        for (size_t i = 0; i < delays.size(); ++i)
          Require(recovery->lpsaActions[i].Type == SC_ACTION_RESTART && recovery->lpsaActions[i].Delay == delays[i], "recovery actions");
        break;
      }
      case SERVICE_CONFIG_FAILURE_ACTIONS_FLAG:
        Require(static_cast<SERVICE_FAILURE_ACTIONS_FLAG*>(data)->fFailureActionsOnNonCrashFailures, "recovery failure flag");
        break;
      default: throw std::runtime_error("unexpected service configuration");
    }
    return TRUE;
  }
  bool Run() {
    return fuzevpn_maintenance::ConfigureServiceRuntime(reinterpret_cast<SC_HANDLE>(this),
        [this](SC_HANDLE service, DWORD level, LPVOID data) { return Configure(service, level, data); });
  }
};
}  // namespace

int main() {
  try {
    namespace loc = fuzevpn::installer::l10n;
    for (const auto& catalog : loc::catalogs) {
      const std::wstring localized = loc::Text(catalog, loc::Message::ServiceDescription);
      ServiceFixture fixture{localized, {}, 0};
      Require(fixture.Run(), "configure runtime");
      Require(fixture.description == localized, "maintenance must retain the MSI service description");
      Require(fixture.changes.size() == 4, "operational settings are restored");
    }
    const std::array<DWORD, 4> levels{SERVICE_CONFIG_SERVICE_SID_INFO,
        SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_FAILURE_ACTIONS,
        SERVICE_CONFIG_FAILURE_ACTIONS_FLAG};
    for (size_t i = 0; i < levels.size(); ++i) {
      ServiceFixture fixture{L"Existing service description", {}, levels[i]};
      Require(!fixture.Run() && GetLastError() == ERROR_ACCESS_DENIED, "configuration failure propagates");
      Require(fixture.changes.size() == i + 1 && fixture.description == L"Existing service description", "failure stops further changes");
    }
    std::cout << "Service operational settings preserve all 30 localized descriptions; no real service was accessed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n'; return 1;
  }
}
