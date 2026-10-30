// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_PROTECTED_STORE_H_
#define RUNNER_PROTECTED_STORE_H_

#include <string>

// A LocalSystem VPN service must open the signed-in user's CurrentUser DPAPI
// store without running the privileged tunnel operation under that user's
// token. This scope only selects the token used by the protected-store helper;
// every filesystem/DPAPI call impersonates for the shortest possible time.
class ScopedProtectedStoreUser final {
 public:
  explicit ScopedProtectedStoreUser(void* impersonation_token);
  ~ScopedProtectedStoreUser();

  ScopedProtectedStoreUser(const ScopedProtectedStoreUser&) = delete;
  ScopedProtectedStoreUser& operator=(const ScopedProtectedStoreUser&) = delete;

 private:
  void* previous_token_ = nullptr;
};

// Native-only DPAPI values. This header deliberately has no Flutter dependency
// so VPN engines can be compiled in isolated native modules.
bool ReadProtectedValue(const std::string& key, std::string* value);
enum class ProtectedValueReadStatus {
  found, not_found, access_denied, corrupt, decryption_failed, io_error
};
ProtectedValueReadStatus ReadProtectedValueStatus(const std::string& key,
                                                std::string* value);
bool WriteProtectedValue(const std::string& key, const std::string& value);
bool DeleteProtectedValue(const std::string& key);

// Non-sensitive outcome of a mutation. On failure `stage` is one of the fixed
// secure_store_* names and `win32_error` that step's Windows error; neither
// ever names a path or a value. `attempts` counts tries of the reported step,
// including retried replacements/deletions that eventually succeeded.
struct ProtectedStoreFailure {
  const char* stage = nullptr;
  unsigned long win32_error = 0;
  int attempts = 0;
};
bool WriteProtectedValueDetailed(const std::string& key,
                                 const std::string& value,
                                 ProtectedStoreFailure* failure);
bool DeleteProtectedValueDetailed(const std::string& key,
                                  ProtectedStoreFailure* failure);

// Stable Windows account identifier for isolating native reconnect state.
// Empty means the account could not be established; callers must fail closed.
std::string ProtectedStoreUserId();

// Fixed-name, non-sensitive diagnostics use the same short user impersonation
// as DPAPI files. A service without a selected client never writes a profile.
bool WriteUserDiagnostic(const std::string& filename, const std::string& text,
                         bool append);

#endif  // RUNNER_PROTECTED_STORE_H_
