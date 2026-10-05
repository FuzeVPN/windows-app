#pragma once
#include <winsock2.h>
#include <windows.h>

namespace openvpn::Win {
// Creation is atomic in IP Helper. An existing tuple is usable but remains
// owned by its creator, including when it appeared concurrently with our call.
class OwnedRouteState {
public:
    template<typename Create> DWORD CreateRoute(Create create) {
        if (owned_) return ERROR_SUCCESS;
        const DWORD status = create();
        if (status == ERROR_SUCCESS) owned_ = true;
        return status == ERROR_OBJECT_ALREADY_EXISTS ? ERROR_SUCCESS : status;
    }
    template<typename Remove> DWORD RemoveRoute(Remove remove) {
        if (!owned_) return ERROR_SUCCESS;
        const DWORD status = remove();
        if (status == ERROR_SUCCESS || status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND) {
            owned_ = false;
            return ERROR_SUCCESS;
        }
        return status;
    }
    bool owned() const { return owned_; }
    void MarkCreated() { owned_ = true; uncertain_ = false; }
    void MarkUncertain() { uncertain_ = true; }
    bool uncertain() const { return uncertain_; }
    DWORD ReconcileUncertain(DWORD lookup_status) {
        if (!uncertain_) return ERROR_SUCCESS;
        if (lookup_status == ERROR_NOT_FOUND || lookup_status == ERROR_FILE_NOT_FOUND) {
            uncertain_ = false;
            return ERROR_SUCCESS;
        }
        // A timed-out CLI does not prove who created a now-present tuple.
        // Preserve it and expose incomplete cleanup instead of deleting it.
        return lookup_status == ERROR_SUCCESS ? ERROR_RETRY : lookup_status;
    }
private:
    bool owned_ = false;
    bool uncertain_ = false;
};
} // namespace openvpn::Win
