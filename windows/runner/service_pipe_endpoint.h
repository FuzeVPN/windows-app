// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_SERVICE_PIPE_ENDPOINT_H_
#define RUNNER_SERVICE_PIPE_ENDPOINT_H_

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace fuzevpn_ipc {
namespace endpoint_detail {

constexpr wchar_t kApplicationKey[] = L"FuzeVPN";
constexpr wchar_t kEndpointKey[] = L"ServiceEndpointV2";
constexpr wchar_t kEndpointValue[] = L"Endpoint";
constexpr wchar_t kPipePrefix[] = L"\\\\.\\pipe\\FuzeVPN-Service-v2-";
constexpr wchar_t kRegistrySecurity[] =
    L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";

struct Record {
  uint32_t magic = 0x32455056;  // VPE2
  uint32_t version = 2;
  uint32_t process_id = 0;
  std::array<BYTE, 32> nonce{};
};
static_assert(sizeof(Record) == 44);

inline bool ValidRecord(const Record& record) {
  return record.magic == 0x32455056 && record.version == 2 && record.process_id != 0;
}
inline std::wstring PipeName(const Record& record) {
  if (!ValidRecord(record)) return {};
  constexpr wchar_t hex[] = L"0123456789abcdef";
  std::wstring result(kPipePrefix);
  for (BYTE value : record.nonce) {
    result.push_back(hex[value >> 4]);
    result.push_back(hex[value & 15]);
  }
  return result;
}
inline bool Fail(DWORD code, DWORD* error) {
  if (error != nullptr) *error = code;
  return false;
}
inline bool TrustedSid(PSID sid, bool system_software) {
  if (sid == nullptr || !IsValidSid(sid)) return false;
  if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
      IsWellKnownSid(sid, WinLocalSystemSid)) return true;
  // The Windows-owned SOFTWARE ancestor may belong to TrustedInstaller.
  if (!system_software) return false;
  PSID installer = nullptr;
  if (!ConvertStringSidToSidW(
      L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
      &installer)) return false;
  const bool same = EqualSid(sid, installer) != FALSE;
  LocalFree(installer);
  return same;
}

struct Win32Api {
  static LSTATUS Open(HKEY parent, const wchar_t* name, REGSAM access, HKEY* key) {
    return RegOpenKeyExW(parent, name, REG_OPTION_OPEN_LINK,
                         access | KEY_WOW64_64KEY, key);
  }
  static LSTATUS Create(HKEY parent, const wchar_t* name, REGSAM access,
                        SECURITY_ATTRIBUTES* security, HKEY* key) {
    return RegCreateKeyExW(parent, name, 0, nullptr, REG_OPTION_NON_VOLATILE,
        access | KEY_WOW64_64KEY, security, key, nullptr);
  }
  static LSTATUS Security(HKEY key, PSECURITY_DESCRIPTOR descriptor, DWORD* size) {
    return RegGetKeySecurity(key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                             descriptor, size);
  }
  static LSTATUS Query(HKEY key, const wchar_t* name, DWORD* type, BYTE* data, DWORD* size) {
    return RegQueryValueExW(key, name, nullptr, type, data, size);
  }
  static LSTATUS Write(HKEY key, const Record& record) {
    return RegSetValueExW(key, kEndpointValue, 0, REG_BINARY,
        reinterpret_cast<const BYTE*>(&record), sizeof(record));
  }
  static LSTATUS Delete(HKEY key) { return RegDeleteValueW(key, kEndpointValue); }
  static void CloseKey(HKEY key) { RegCloseKey(key); }
  static bool Random(std::array<BYTE, 32>* nonce) {
    return BCryptGenRandom(nullptr, nonce->data(), static_cast<ULONG>(nonce->size()),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
  }
  static DWORD ProcessId() { return GetCurrentProcessId(); }
  static HANDLE CreatePipe(const wchar_t* name, DWORD buffer_size,
                           SECURITY_ATTRIBUTES* security) {
    return CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
        FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, buffer_size, buffer_size, 0, security);
  }
  static void ClosePipe(HANDLE pipe) { CloseHandle(pipe); }
};

template <typename Api>
struct Key {
  HKEY value = nullptr;
  ~Key() { if (value != nullptr) Api::CloseKey(value); }
  Key() = default;
  Key(const Key&) = delete;
  Key& operator=(const Key&) = delete;
};

template <typename Api = Win32Api>
class Store final {
 public:
  static bool Read(DWORD expected_process, Record* record, DWORD* error) {
    if (expected_process == 0) return Fail(ERROR_FILE_NOT_FOUND, error);
    Key<Api> software, application, endpoint;
    if (!OpenKeys(false, &software, &application, &endpoint, error) ||
        !ReadRecord(endpoint.value, record, error)) return false;
    // A crash leaves a stale record. It is never an instruction to connect to
    // an old name while the current SCM process is absent or has changed.
    if (record->process_id != expected_process) return Fail(ERROR_FILE_NOT_FOUND, error);
    return true;
  }
  static bool Publish(const Record& record, DWORD* error) {
    if (!ValidRecord(record)) return Fail(ERROR_INVALID_DATA, error);
    Key<Api> software, application, endpoint;
    if (!OpenKeys(true, &software, &application, &endpoint, error)) return false;
    const LSTATUS result = Api::Write(endpoint.value, record);
    return result == ERROR_SUCCESS || Fail(static_cast<DWORD>(result), error);
  }
  static void ClearOwn(const Record& own) {
    Key<Api> software, application, endpoint;
    DWORD error = ERROR_SUCCESS;
    if (!OpenKeys(false, &software, &application, &endpoint, &error, true)) return;
    Record current;
    if (!ReadRecord(endpoint.value, &current, &error) ||
        std::memcmp(&current, &own, sizeof(own)) != 0) return;
    // Callers retain the exclusive machine runtime lock through this cleanup.
    // Never remove a replacement service's record or delete a registry tree.
    Api::Delete(endpoint.value);
  }

 private:
  static bool ProtectedKey(HKEY key, bool system_software, bool endpoint, DWORD* error) {
    DWORD bytes = 0;
    const LSTATUS initial = Api::Security(key, nullptr, &bytes);
    if (initial != ERROR_INSUFFICIENT_BUFFER || bytes == 0 || bytes > 65536)
      return Fail(initial == ERROR_INSUFFICIENT_BUFFER ? ERROR_INVALID_DATA :
          static_cast<DWORD>(initial == ERROR_SUCCESS ? ERROR_INVALID_DATA : initial), error);
    std::vector<BYTE> storage(bytes);
    auto* descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(storage.data());
    const DWORD capacity = bytes;
    const LSTATUS status = Api::Security(key, descriptor, &bytes);
    if (status != ERROR_SUCCESS || bytes > capacity)
      return Fail(status == ERROR_SUCCESS ? ERROR_INVALID_DATA : static_cast<DWORD>(status), error);
    PSID owner = nullptr;
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (!IsValidSecurityDescriptor(descriptor) ||
        !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) ||
        !TrustedSid(owner, system_software) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) ||
        !present || acl == nullptr || !IsValidAcl(acl) ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        (endpoint && (control & SE_DACL_PROTECTED) == 0))
      return Fail(ERROR_ACCESS_DENIED, error);
    GENERIC_MAPPING mapping{KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};
    constexpr DWORD dangerous = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
        DELETE | WRITE_DAC | WRITE_OWNER;
    for (DWORD index = 0; index < acl->AceCount; ++index) {
      void* raw = nullptr;
      if (!GetAce(acl, index, &raw)) return Fail(ERROR_ACCESS_DENIED, error);
      const auto* header = static_cast<ACE_HEADER*>(raw);
      if (header->AceFlags & INHERIT_ONLY_ACE) continue;
      if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
      if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
          header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) return Fail(ERROR_ACCESS_DENIED, error);
      const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      DWORD access = ace->Mask;
      MapGenericMask(&access, &mapping);
      PSID trustee = const_cast<DWORD*>(&ace->SidStart);
      // Windows SOFTWARE includes this CREATOR_OWNER inheritance template
      // without INHERIT_ONLY. It is a placeholder for future child owners,
      // not a current unprivileged writer. Never admit it on our own keys.
      const bool software_owner_template = system_software &&
          header->AceFlags == CONTAINER_INHERIT_ACE && IsValidSid(trustee) &&
          IsWellKnownSid(trustee, WinCreatorOwnerSid);
      if ((access & dangerous) != 0 &&
          !TrustedSid(trustee, system_software) && !software_owner_template)
        return Fail(ERROR_ACCESS_DENIED, error);
    }
    // Registry links are never endpoints or ancestors in this protocol. OPEN_LINK
    // above lets us inspect their own security instead of following a redirection.
    DWORD type = 0, size = 0;
    const LSTATUS link = Api::Query(key, L"SymbolicLinkValue", &type, nullptr, &size);
    if ((link == ERROR_SUCCESS || link == ERROR_MORE_DATA) && type == REG_LINK)
      return Fail(ERROR_ACCESS_DENIED, error);
    if (link != ERROR_FILE_NOT_FOUND && link != ERROR_SUCCESS && link != ERROR_MORE_DATA)
      return Fail(static_cast<DWORD>(link), error);
    return true;
  }
  static bool OpenKeys(bool create, Key<Api>* software, Key<Api>* application,
                       Key<Api>* endpoint, DWORD* error, bool clearing = false) {
    const REGSAM software_access = READ_CONTROL | KEY_QUERY_VALUE | KEY_WOW64_64KEY |
        (create ? KEY_CREATE_SUB_KEY : 0);
    LSTATUS status = Api::Open(HKEY_LOCAL_MACHINE, L"SOFTWARE", software_access,
                               &software->value);
    if (status != ERROR_SUCCESS) return Fail(static_cast<DWORD>(status), error);
    if (!ProtectedKey(software->value, true, false, error)) return false;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (create && !ConvertStringSecurityDescriptorToSecurityDescriptorW(
        kRegistrySecurity, SDDL_REVISION_1, &descriptor, nullptr))
      return Fail(GetLastError(), error);
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    status = create ? Api::Create(software->value, kApplicationKey,
        KEY_ALL_ACCESS | KEY_WOW64_64KEY, &security, &application->value) :
        Api::Open(software->value, kApplicationKey,
            READ_CONTROL | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &application->value);
    if (status == ERROR_SUCCESS && !ProtectedKey(application->value, false, false, error)) {
      if (descriptor != nullptr) LocalFree(descriptor);
      return false;
    }
    if (status == ERROR_SUCCESS) {
      status = create ? Api::Create(application->value, kEndpointKey,
          KEY_ALL_ACCESS | KEY_WOW64_64KEY, &security, &endpoint->value) :
          Api::Open(application->value, kEndpointKey,
              READ_CONTROL | KEY_QUERY_VALUE | KEY_WOW64_64KEY |
                  (clearing ? KEY_SET_VALUE : 0), &endpoint->value);
    }
    if (descriptor != nullptr) LocalFree(descriptor);
    if (status != ERROR_SUCCESS) return Fail(static_cast<DWORD>(status), error);
    return ProtectedKey(endpoint->value, false, true, error);
  }
  static bool ReadRecord(HKEY key, Record* record, DWORD* error) {
    DWORD type = 0, bytes = sizeof(*record);
    const LSTATUS status = Api::Query(key, kEndpointValue, &type,
        reinterpret_cast<BYTE*>(record), &bytes);
    if (status != ERROR_SUCCESS) return Fail(static_cast<DWORD>(status), error);
    if (type != REG_BINARY || bytes != sizeof(*record) || !ValidRecord(*record))
      return Fail(ERROR_INVALID_DATA, error);
    return true;
  }
};

template <typename Api = Win32Api>
class PublishedPipe final {
 public:
  ~PublishedPipe() { Reset(); }
  PublishedPipe() = default;
  PublishedPipe(const PublishedPipe&) = delete;
  PublishedPipe& operator=(const PublishedPipe&) = delete;
  HANDLE pipe() const { return pipe_; }
  bool Create(DWORD maximum_payload, SECURITY_ATTRIBUTES* security) {
    if (pipe_ != INVALID_HANDLE_VALUE || maximum_payload == 0 || maximum_payload > 1024 * 1024) {
      SetLastError(ERROR_INVALID_PARAMETER); return false;
    }
    record_.process_id = Api::ProcessId();
    if (record_.process_id == 0) { SetLastError(ERROR_INVALID_DATA); return false; }
    DWORD error = ERROR_GEN_FAILURE;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
      if (!Api::Random(&record_.nonce)) { SetLastError(ERROR_GEN_FAILURE); return false; }
      const std::wstring name = PipeName(record_);
      pipe_ = Api::CreatePipe(name.c_str(), maximum_payload, security);
      if (pipe_ != INVALID_HANDLE_VALUE) break;
      error = GetLastError();
      if (error != ERROR_ACCESS_DENIED && error != ERROR_PIPE_BUSY) break;
    }
    if (pipe_ == INVALID_HANDLE_VALUE) { SetLastError(error); return false; }
    if (!Store<Api>::Publish(record_, &error)) {
      Api::ClosePipe(pipe_); pipe_ = INVALID_HANDLE_VALUE;
      SetLastError(error); return false;
    }
    published_ = true;
    return true;
  }
  void Reset() {
    const DWORD previous = GetLastError();
    if (published_) Store<Api>::ClearOwn(record_);
    published_ = false;
    if (pipe_ != INVALID_HANDLE_VALUE) Api::ClosePipe(pipe_);
    pipe_ = INVALID_HANDLE_VALUE;
    SetLastError(previous);
  }

 private:
  HANDLE pipe_ = INVALID_HANDLE_VALUE;
  Record record_;
  bool published_ = false;
};

}  // namespace endpoint_detail

using ServicePipeEndpoint = endpoint_detail::PublishedPipe<>;

inline bool ReadServicePipeName(DWORD expected_process, std::wstring* name) {
  endpoint_detail::Record record;
  DWORD error = ERROR_SUCCESS;
  const bool read = endpoint_detail::Store<>::Read(expected_process, &record, &error);
  if (read) *name = endpoint_detail::PipeName(record);
  SetLastError(read ? ERROR_SUCCESS : error);
  return read;
}

}  // namespace fuzevpn_ipc
#endif  // RUNNER_SERVICE_PIPE_ENDPOINT_H_
