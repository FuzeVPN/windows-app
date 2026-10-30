// SPDX-License-Identifier: MPL-2.0
#ifndef RUNNER_TESTS_SERVICE_PIPE_ENDPOINT_TEST_H_
#define RUNNER_TESTS_SERVICE_PIPE_ENDPOINT_TEST_H_

#include "../service_pipe_endpoint.h"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace fuzevpn_service_endpoint_test {
using fuzevpn_ipc::endpoint_detail::Record;

inline bool Check(bool condition, const char* description) {
  if (!condition) std::cerr << "Service endpoint: " << description << '\n';
  return condition;
}

struct FixtureApi {
  static inline std::wstring descriptors[3];
  static inline std::optional<Record> stored;
  static inline std::vector<std::wstring> pipe_names;
  static inline std::string order;
  static inline unsigned opens = 0, creates = 0, writes = 0, deletes = 0;
  static inline unsigned randoms = 0, pipe_creates = 0, pipe_closes = 0;
  static inline bool all_64 = true, all_readonly = true, protected_creation = true;
  static inline bool random_failure = false, oversized_security = false;
  static inline DWORD open_error = ERROR_SUCCESS, write_error = ERROR_SUCCESS;
  static inline DWORD pipe_error = ERROR_SUCCESS, value_type = REG_BINARY;
  static inline DWORD value_bytes = sizeof(Record);
  static inline unsigned pipe_collisions = 0;
  static inline int link_level = -1;
  static HKEY Key(unsigned index) { return reinterpret_cast<HKEY>(static_cast<ULONG_PTR>(701 + index)); }
  static int Level(HKEY key) {
    for (int index = 0; index < 3; ++index)
      if (key == Key(static_cast<unsigned>(index))) return index;
    return -1;
  }
  static void Reset() {
    for (auto& descriptor : descriptors)
      descriptor = L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
    stored.reset(); pipe_names.clear(); order.clear();
    opens = creates = writes = deletes = randoms = pipe_creates = pipe_closes = 0;
    all_64 = all_readonly = protected_creation = true;
    random_failure = oversized_security = false;
    open_error = write_error = pipe_error = ERROR_SUCCESS;
    value_type = REG_BINARY; value_bytes = sizeof(Record); pipe_collisions = 0; link_level = -1;
  }
  static LSTATUS Open(HKEY parent, const wchar_t* name, REGSAM access, HKEY* key) {
    ++opens; order += 'O';
    all_64 &= (access & KEY_WOW64_64KEY) != 0;
    all_readonly &= (access & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE | WRITE_DAC | WRITE_OWNER)) == 0;
    if (open_error != ERROR_SUCCESS) return static_cast<LSTATUS>(open_error);
    if (parent == HKEY_LOCAL_MACHINE && std::wstring(name) == L"SOFTWARE") *key = Key(0);
    else if (parent == Key(0) && std::wstring(name) == L"FuzeVPN") *key = Key(1);
    else if (parent == Key(1) && std::wstring(name) == L"ServiceEndpointV2") *key = Key(2);
    else return ERROR_FILE_NOT_FOUND;
    return ERROR_SUCCESS;
  }
  static LSTATUS Create(HKEY parent, const wchar_t* name, REGSAM access,
                        SECURITY_ATTRIBUTES* security, HKEY* key) {
    ++creates; order += 'K';
    all_64 &= (access & KEY_WOW64_64KEY) != 0;
    LPWSTR sddl = nullptr;
    const bool converted = ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security->lpSecurityDescriptor, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &sddl, nullptr) != FALSE;
    protected_creation &= converted && security->bInheritHandle == FALSE &&
        std::wstring(sddl) == fuzevpn_ipc::endpoint_detail::kRegistrySecurity;
    if (sddl != nullptr) LocalFree(sddl);
    if (parent == Key(0) && std::wstring(name) == L"FuzeVPN") *key = Key(1);
    else if (parent == Key(1) && std::wstring(name) == L"ServiceEndpointV2") *key = Key(2);
    else return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
  }
  static LSTATUS Security(HKEY key, PSECURITY_DESCRIPTOR target, DWORD* bytes) {
    const int level = Level(key);
    if (level < 0) return ERROR_INVALID_HANDLE;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptors[level].c_str(),
        SDDL_REVISION_1, &descriptor, nullptr)) return ERROR_INVALID_SECURITY_DESCR;
    const DWORD needed = GetSecurityDescriptorLength(descriptor);
    if (target == nullptr) {
      *bytes = oversized_security ? 65537 : needed;
      LocalFree(descriptor); return ERROR_INSUFFICIENT_BUFFER;
    }
    if (*bytes < needed) { *bytes = needed; LocalFree(descriptor); return ERROR_INSUFFICIENT_BUFFER; }
    std::memcpy(target, descriptor, needed); *bytes = needed;
    LocalFree(descriptor); return ERROR_SUCCESS;
  }
  static LSTATUS Query(HKEY key, const wchar_t* name, DWORD* type, BYTE* data, DWORD* bytes) {
    if (std::wstring(name) == L"SymbolicLinkValue") {
      if (Level(key) != link_level) return ERROR_FILE_NOT_FOUND;
      *type = REG_LINK; *bytes = 80; return ERROR_SUCCESS;
    }
    if (key != Key(2) || std::wstring(name) != L"Endpoint" || !stored)
      return ERROR_FILE_NOT_FOUND;
    *type = value_type;
    const DWORD capacity = *bytes; *bytes = value_bytes;
    if (capacity < value_bytes) return ERROR_MORE_DATA;
    if (data != nullptr) std::memcpy(data, &*stored, (std::min)(value_bytes, static_cast<DWORD>(sizeof(Record))));
    return ERROR_SUCCESS;
  }
  static LSTATUS Write(HKEY key, const Record& record) {
    ++writes; order += 'W';
    if (key != Key(2)) return ERROR_INVALID_HANDLE;
    if (write_error != ERROR_SUCCESS) return static_cast<LSTATUS>(write_error);
    stored = record; return ERROR_SUCCESS;
  }
  static LSTATUS Delete(HKEY key) {
    ++deletes; order += 'D';
    if (key != Key(2)) return ERROR_INVALID_HANDLE;
    stored.reset(); return ERROR_SUCCESS;
  }
  static void CloseKey(HKEY) { SetLastError(ERROR_INVALID_HANDLE); }
  static bool Random(std::array<BYTE, 32>* nonce) {
    ++randoms; order += 'R';
    if (random_failure) return false;
    nonce->fill(static_cast<BYTE>(randoms)); return true;
  }
  static DWORD ProcessId() { return 4242; }
  static HANDLE CreatePipe(const wchar_t* name, DWORD, SECURITY_ATTRIBUTES*) {
    ++pipe_creates; order += 'P'; pipe_names.emplace_back(name);
    if (pipe_creates <= pipe_collisions || pipe_error != ERROR_SUCCESS) {
      SetLastError(pipe_error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : pipe_error);
      return INVALID_HANDLE_VALUE;
    }
    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(704));
  }
  static void ClosePipe(HANDLE) { ++pipe_closes; order += 'C'; SetLastError(ERROR_INVALID_HANDLE); }
};

inline bool TestServicePipeEndpoint() {
  using Store = fuzevpn_ipc::endpoint_detail::Store<FixtureApi>;
  using Server = fuzevpn_ipc::endpoint_detail::PublishedPipe<FixtureApi>;
  bool passed = true;
  DWORD error = ERROR_SUCCESS;
  FixtureApi::Reset();
  FixtureApi::descriptors[0] =
      L"O:SYG:SYD:PAI(A;CI;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)";
  {
    Server server;
    Record result;
    passed &= Check(server.Create(1024, nullptr) &&
        Store::Read(4242, &result, &error) && FixtureApi::writes == 1,
        "the Windows SOFTWARE creator-owner inheritance template permits protected publication and reads");
  }
  for (int level = 1; level < 3; ++level) {
    FixtureApi::Reset();
    FixtureApi::descriptors[level] =
        L"O:BAG:BAD:P(A;CI;KA;;;CO)(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
    Server server;
    passed &= Check(!server.Create(1024, nullptr) &&
        GetLastError() == ERROR_ACCESS_DENIED && FixtureApi::writes == 0,
        "creator-owner remains forbidden on the application and endpoint keys");
  }
  for (const auto* flags : {L"", L"OI", L"CINP", L"CIID"}) {
    FixtureApi::Reset();
    FixtureApi::descriptors[0] = std::wstring(L"O:SYG:SYD:P(A;") + flags +
        L";KA;;;CO)(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
    Server server;
    passed &= Check(!server.Create(1024, nullptr) &&
        GetLastError() == ERROR_ACCESS_DENIED && FixtureApi::writes == 0,
        "only the exact SOFTWARE container-inherit creator-owner template is accepted");
  }
  for (const auto* trustee : {L"BU", L"WD", L"CG"}) {
    FixtureApi::Reset();
    FixtureApi::descriptors[0] = std::wstring(L"O:SYG:SYD:P(A;CI;KA;;;") + trustee +
        L")(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
    Server server;
    passed &= Check(!server.Create(1024, nullptr) &&
        GetLastError() == ERROR_ACCESS_DENIED && FixtureApi::writes == 0,
        "SOFTWARE users, everyone and creator-group never receive trusted write rights");
  }
  FixtureApi::Reset();
  FixtureApi::descriptors[0] =
      L"O:BUG:BAD:P(A;CI;KA;;;CO)(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
  {
    Server server;
    passed &= Check(!server.Create(1024, nullptr) &&
        GetLastError() == ERROR_ACCESS_DENIED && FixtureApi::writes == 0,
        "a creator-owner template cannot authorize an untrusted SOFTWARE owner");
  }
  FixtureApi::Reset();
  Record stale;
  stale.process_id = 99;
  FixtureApi::stored = stale;
  {
    Server server;
    passed &= Check(server.Create(1024 * 1024, nullptr) && FixtureApi::stored &&
        FixtureApi::stored->process_id == 4242 && FixtureApi::deletes == 0 &&
        FixtureApi::protected_creation && FixtureApi::all_64 &&
        FixtureApi::order.find('P') < FixtureApi::order.find('K') &&
        FixtureApi::order.find('P') < FixtureApi::order.find('W'),
        "a live random pipe precedes protected 64-bit publication and replacement of a stale crash record");
    Record record;
    FixtureApi::all_readonly = true;
    passed &= Check(Store::Read(4242, &record, &error) && FixtureApi::all_readonly && FixtureApi::all_64,
        "clients only read protected ancestors and the exact binary record in the 64-bit view");
    const std::wstring name = fuzevpn_ipc::endpoint_detail::PipeName(record);
    const size_t prefix = std::size(fuzevpn_ipc::endpoint_detail::kPipePrefix) - 1;
    bool format = name.size() == prefix + 64 && name.rfind(fuzevpn_ipc::endpoint_detail::kPipePrefix, 0) == 0;
    for (size_t index = prefix; index < name.size(); ++index)
      format &= (name[index] >= L'0' && name[index] <= L'9') || (name[index] >= L'a' && name[index] <= L'f');
    passed &= Check(format && FixtureApi::pipe_names.front() == name,
        "the client name is derived from exactly 256 nonce bits with a fixed local-pipe prefix");
    passed &= Check(!Store::Read(4243, &record, &error) && error == ERROR_FILE_NOT_FOUND,
        "a stale process record cannot select an old endpoint");
    const unsigned opened = FixtureApi::opens;
    passed &= Check(!Store::Read(0, &record, &error) && FixtureApi::opens == opened,
        "an absent SCM process never reads or uses a stale endpoint");
    server.Reset();
    passed &= Check(!FixtureApi::stored && FixtureApi::deletes == 1 && FixtureApi::pipe_closes == 1 &&
        FixtureApi::order.find('D') < FixtureApi::order.find('C'),
        "clean stop removes only its record before closing its pipe");
  }
  passed &= Check(FixtureApi::pipe_closes == 1, "reset followed by destruction closes exactly once");

  FixtureApi::Reset();
  {
    Server server;
    passed &= Check(server.Create(1024, nullptr), "replacement-record fixture starts");
    FixtureApi::stored->nonce[0] ^= 1;
    server.Reset();
    passed &= Check(FixtureApi::stored.has_value() && FixtureApi::deletes == 0,
        "shutdown never deletes a different publisher's record");
  }
  FixtureApi::Reset(); FixtureApi::random_failure = true;
  {
    Server server;
    passed &= Check(!server.Create(1024, nullptr) && GetLastError() == ERROR_GEN_FAILURE &&
        FixtureApi::pipe_creates == 0 && FixtureApi::opens == 0 && FixtureApi::writes == 0,
        "RNG failure cannot create or publish a predictable endpoint");
  }
  FixtureApi::Reset(); FixtureApi::pipe_collisions = 2;
  {
    Server server;
    passed &= Check(server.Create(1024, nullptr) && FixtureApi::randoms == 3 &&
        FixtureApi::pipe_names[0] != FixtureApi::pipe_names[1] &&
        FixtureApi::pipe_names[1] != FixtureApi::pipe_names[2] && FixtureApi::writes == 1,
        "a pipe collision retries with a fresh nonce and only publishes a successfully created pipe");
  }
  FixtureApi::Reset(); FixtureApi::pipe_collisions = 4;
  {
    Server server;
    passed &= Check(!server.Create(1024, nullptr) && GetLastError() == ERROR_ACCESS_DENIED &&
        FixtureApi::pipe_creates == 3 && FixtureApi::opens == 0 && FixtureApi::writes == 0,
        "persistent collisions have a finite budget and never publish or fall back");
  }
  FixtureApi::Reset(); FixtureApi::write_error = ERROR_ACCESS_DENIED;
  FixtureApi::stored = stale;
  {
    Server server;
    passed &= Check(!server.Create(1024, nullptr) && GetLastError() == ERROR_ACCESS_DENIED &&
        FixtureApi::pipe_closes == 1 && FixtureApi::stored && FixtureApi::stored->process_id == 99,
        "publication failure closes its pipe, preserves the prior record and retains the registry error");
  }
  for (unsigned level = 0; level < 3; ++level) {
    for (const wchar_t* insecure : {
        L"O:S-1-5-21-1-2-3-1001G:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)",
        L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KW;;;BU)",
        L"O:BAG:BAD:NO_ACCESS_CONTROL"}) {
      FixtureApi::Reset(); FixtureApi::descriptors[level] = insecure;
      Server server;
      passed &= Check(!server.Create(1024, nullptr) && GetLastError() == ERROR_ACCESS_DENIED &&
          FixtureApi::writes == 0 && FixtureApi::pipe_closes == 1,
          "untrusted ownership, ordinary writes and a null DACL fail before publication at every ancestor");
    }
  }
  FixtureApi::Reset();
  FixtureApi::descriptors[2] = L"O:BAG:BAD:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
  {
    Server server;
    passed &= Check(!server.Create(1024, nullptr) && FixtureApi::writes == 0,
        "the endpoint key must protect its DACL from inheritance");
  }
  for (int level = 0; level < 3; ++level) {
    FixtureApi::Reset(); FixtureApi::link_level = level;
    Server server;
    passed &= Check(!server.Create(1024, nullptr) && FixtureApi::writes == 0,
        "registry symbolic links cannot redirect the endpoint or its ancestors");
  }
  FixtureApi::Reset(); FixtureApi::oversized_security = true;
  {
    Server server;
    passed &= Check(!server.Create(1024, nullptr) && GetLastError() == ERROR_INVALID_DATA && FixtureApi::writes == 0,
        "descriptor lengths are bounded before allocation");
  }
  for (unsigned mutation = 0; mutation < 6; ++mutation) {
    FixtureApi::Reset(); Record malformed; malformed.process_id = 4242;
    if (mutation == 0) malformed.magic = 0;
    if (mutation == 1) malformed.version = 1;
    if (mutation == 2) malformed.process_id = 0;
    if (mutation == 3) FixtureApi::value_type = REG_SZ;
    if (mutation == 4) FixtureApi::value_bytes = sizeof(Record) - 1;
    if (mutation == 5) FixtureApi::value_bytes = sizeof(Record) + 1;
    FixtureApi::stored = malformed;
    Record result;
    passed &= Check(!Store::Read(4242, &result, &error) && FixtureApi::writes == 0,
        "wrong record magic, version, PID, type, truncation and oversized values are rejected without mutation");
  }
  FixtureApi::Reset(); FixtureApi::open_error = ERROR_FILE_NOT_FOUND;
  Record result;
  passed &= Check(!Store::Read(4242, &result, &error) && error == ERROR_FILE_NOT_FOUND &&
      FixtureApi::creates == 0 && FixtureApi::writes == 0,
      "legacy or absent publication remains missing without creating keys or selecting a static pipe");

  std::array<BYTE, 32> first{}, second{};
  passed &= Check(fuzevpn_ipc::endpoint_detail::Win32Api::Random(&first) &&
      fuzevpn_ipc::endpoint_detail::Win32Api::Random(&second) && first != second,
      "the production nonce generator obtains distinct system BCrypt samples without logging them");
  return passed;
}

}  // namespace fuzevpn_service_endpoint_test
#endif  // RUNNER_TESTS_SERVICE_PIPE_ENDPOINT_TEST_H_
