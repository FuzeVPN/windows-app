// SPDX-License-Identifier: MPL-2.0
#include "portable_update.h"
#include "portable_runtime.h"
#include "installation_security.h"
#include "runtime_architecture.h"
#include "../../third_party/miniz/miniz_tinfl.h"
#include <algorithm>
#include <array>
#include <set>
#include <memory>

namespace fuzevpn_portable_update {
namespace {
using fuzevpn_update::Failure;
using fuzevpn_update::PinnedFile;
bool Fail(Failure* failure, const char* code, const char* stage,
          DWORD error = ERROR_SUCCESS, LONG trust = ERROR_SUCCESS) {
  if (failure) *failure = {code, stage, error, 0, trust};
  return false;
}
uint16_t U16(const BYTE* p) { return p[0] | static_cast<uint16_t>(p[1]) << 8; }
uint32_t U32(const BYTE* p) { return U16(p) | static_cast<uint32_t>(U16(p + 2)) << 16; }
bool Read(HANDLE file, uint64_t offset, void* data, DWORD count) {
  LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset);
  DWORD read = 0;
  return SetFilePointerEx(file, position, nullptr, FILE_BEGIN) &&
      ReadFile(file, data, count, &read, nullptr) && read == count;
}
std::string Lower(std::string value) {
  for (char& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  return value;
}
bool SafeName(const std::string& name, bool directory, std::string* relative) {
  if (name.empty() || name.size() > 240 || name.rfind("FuzeVPN/", 0) != 0 ||
      name.find('\0') != std::string::npos || name.find('\\') != std::string::npos) return false;
  std::string path = name.substr(8);
  if (directory) {
    if (name.back() != '/') return false;
    if (!path.empty()) path.pop_back();
    if (path.empty()) { *relative = {}; return true; }
  } else if (path.empty() || path.back() == '/') return false;
  unsigned depth = 0;
  for (size_t start = 0; start < path.size();) {
    const auto slash = path.find('/', start);
    const auto part = path.substr(start, slash == std::string::npos ? slash : slash - start);
    if (++depth > 16 || part.empty() || part == "." || part == ".." || part.back() == '.') return false;
    for (char c : part) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return false;
    const auto base = Lower(part.substr(0, part.find('.')));
    if (base == "con" || base == "prn" || base == "aux" || base == "nul" ||
        (base.size() == 4 && (base.rfind("com", 0) == 0 || base.rfind("lpt", 0) == 0) &&
         base[3] >= '0' && base[3] <= '9')) return false;
    if (slash == std::string::npos) break;
    start = slash + 1;
  }
  *relative = path;
  return true;
}
bool ExtraSafe(const BYTE* extra, size_t size) {
  for (size_t offset = 0; offset < size;) {
    if (size - offset < 4) return false;
    const auto type = U16(extra + offset), length = U16(extra + offset + 2);
    offset += 4;
    if (length > size - offset || type == 0x0001 || type == 0x7075 || type == 0x6375)
      return false; // ZIP64 and alternate Unicode names are not used by packaging.
    offset += length;
  }
  return true;
}
struct Entry {
  std::string name, relative;
  uint32_t compressed = 0, expanded = 0, crc = 0, offset = 0;
  uint16_t flags = 0, method = 0;
  bool directory = false;
  uint64_t data_offset = 0, end_offset = 0;
};
uint32_t Crc(uint32_t crc, const BYTE* data, size_t size) {
  static const std::array<uint32_t, 256> table = [] {
    std::array<uint32_t, 256> result{};
    for (unsigned i = 0; i < result.size(); ++i) {
      uint32_t value = i;
      for (unsigned bit = 0; bit < 8; ++bit) value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1)));
      result[i] = value;
    }
    return result;
  }();
  for (size_t i = 0; i < size; ++i) crc = table[(crc ^ data[i]) & 255] ^ (crc >> 8);
  return crc;
}
bool Directory(const std::filesystem::path& path) {
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
      (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}
bool EmptyDirectory(const std::filesystem::path& path) {
  if (!Directory(path)) return false;
  WIN32_FIND_DATAW item{};
  HANDLE find = FindFirstFileW((path / L"*").c_str(), &item);
  if (find == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
  bool empty = true;
  do {
    if (wcscmp(item.cFileName, L".") && wcscmp(item.cFileName, L"..")) { empty = false; break; }
  } while (FindNextFileW(find, &item));
  if (empty && GetLastError() != ERROR_NO_MORE_FILES) empty = false;
  FindClose(find);
  return empty;
}
bool Rename(const std::filesystem::path& source, const std::filesystem::path& destination) {
  const ULONGLONG deadline = GetTickCount64() + 5000;
  for (;;) {
    if (MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) return true;
    const DWORD error = GetLastError();
    if ((error != ERROR_SHARING_VIOLATION && error != ERROR_LOCK_VIOLATION && error != ERROR_ACCESS_DENIED) ||
        GetTickCount64() >= deadline) { SetLastError(error); return false; }
    Sleep(100);
  }
}
bool DeleteTree(const std::filesystem::path& path, unsigned depth, unsigned* count) {
  if (depth > 16 || ++*count > kMaximumArchiveEntries * 2) return false;
  HANDLE handle = CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  bool ok = GetFileInformationByHandle(handle, &info) &&
      !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && info.nNumberOfLinks == 1;
  if (ok && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
    WIN32_FIND_DATAW child{};
    HANDLE find = FindFirstFileW((path / L"*").c_str(), &child);
    if (find == INVALID_HANDLE_VALUE) ok = GetLastError() == ERROR_FILE_NOT_FOUND;
    else {
      do {
        if (!wcscmp(child.cFileName, L".") || !wcscmp(child.cFileName, L"..")) continue;
        if (!DeleteTree(path / child.cFileName, depth + 1, count)) { ok = false; break; }
      } while (FindNextFileW(find, &child));
      if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = false;
      FindClose(find);
    }
  }
  // The open parent stays pinned against rename while children are traversed.
  if (ok) {
    FILE_DISPOSITION_INFO disposition{TRUE};
    ok = SetFileInformationByHandle(handle, FileDispositionInfo, &disposition, sizeof(disposition)) != FALSE;
  }
  CloseHandle(handle);
  return ok;
}
bool MakeDirectories(const std::filesystem::path& root, const std::string& relative) {
  auto current = root;
  if (!Directory(current)) return false;
  for (size_t start = 0; start < relative.size();) {
    const auto slash = relative.find('/', start);
    current /= fuzevpn_update::Wide(relative.substr(start, slash == std::string::npos ? slash : slash - start));
    if (!CreateDirectoryW(current.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
    if (!Directory(current)) return false;
    if (slash == std::string::npos) break;
    start = slash + 1;
  }
  return true;
}
bool Enumerate(const std::filesystem::path& root, const std::filesystem::path& directory,
               std::vector<std::filesystem::path>* files, unsigned depth = 0) {
  if (depth > 16 || !Directory(directory)) return false;
  WIN32_FIND_DATAW item{};
  HANDLE find = FindFirstFileW((directory / L"*").c_str(), &item);
  if (find == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
  bool ok = true;
  do {
    if (!wcscmp(item.cFileName, L".") || !wcscmp(item.cFileName, L"..")) continue;
    if ((item.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) { ok = false; break; }
    const auto path = directory / item.cFileName;
    std::string relative;
    const bool is_directory = (item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (!SafeName("FuzeVPN/" + path.lexically_relative(root).generic_string() + (is_directory ? "/" : ""),
                  is_directory, &relative)) { ok = false; break; }
    if (is_directory) { if (!Enumerate(root, path, files, depth + 1)) { ok = false; break; } }
    else {
      if (files->size() >= kMaximumArchiveEntries) { ok = false; break; }
      files->push_back(path);
    }
  } while (FindNextFileW(find, &item));
  if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = false;
  FindClose(find);
  return ok;
}
struct Output {
  HANDLE handle = INVALID_HANDLE_VALUE;
  uint64_t written = 0, limit = 0;
  uint32_t crc = 0xffffffffu;
  ~Output() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
  bool Write(const BYTE* bytes, size_t length) {
    if (length > limit - written || length > MAXDWORD) return false;
    DWORD actual = 0;
    if (!WriteFile(handle, bytes, static_cast<DWORD>(length), &actual, nullptr) || actual != length) return false;
    written += length; crc = Crc(crc, bytes, length);
    return true;
  }
};
int InflateOutput(const void* data, int length, void* context) {
  return length >= 0 && static_cast<Output*>(context)->Write(static_cast<const BYTE*>(data), length);
}
}  // namespace

bool ExtractArchive(const PinnedFile& archive, const std::string& sha256,
                    const std::filesystem::path& destination, Failure* failure) {
  if (failure) *failure = {};
  if (!fuzevpn_update::MatchesHash(archive.get(), sha256))
    return Fail(failure, "update_hash_mismatch", "portable_hash");
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(archive.get(), &size) || size.QuadPart < 22 ||
      static_cast<uint64_t>(size.QuadPart) > fuzevpn_update::kMaximumDownloadBytes)
    return Fail(failure, "update_archive_invalid", "portable_archive");
  const uint64_t length = static_cast<uint64_t>(size.QuadPart);
  const auto tail_size = static_cast<DWORD>(std::min<uint64_t>(length, 65557));
  std::vector<BYTE> tail(tail_size);
  if (!Read(archive.get(), length - tail_size, tail.data(), tail_size))
    return Fail(failure, "update_archive_invalid", "portable_archive", GetLastError());
  size_t end = tail.size();
  for (size_t i = tail.size() - 22;; --i) {
    if (U32(tail.data() + i) == 0x06054b50 && i + 22 + U16(tail.data() + i + 20) == tail.size()) { end = i; break; }
    if (i == 0) break;
  }
  if (end == tail.size()) return Fail(failure, "update_archive_invalid", "portable_archive");
  const BYTE* eocd = tail.data() + end;
  const unsigned count = U16(eocd + 10);
  const uint32_t central_size = U32(eocd + 12), central_offset = U32(eocd + 16);
  if (U16(eocd + 4) || U16(eocd + 6) || U16(eocd + 8) != count || !count ||
      count == 65535 || count > kMaximumArchiveEntries || central_size > 1024 * 1024 ||
      static_cast<uint64_t>(central_offset) + central_size != length - tail_size + end)
    return Fail(failure, count > kMaximumArchiveEntries ? "update_archive_too_large" :
        "update_archive_invalid", "portable_archive");
  std::vector<BYTE> central(central_size);
  if (!Read(archive.get(), central_offset, central.data(), central_size))
    return Fail(failure, "update_archive_invalid", "portable_archive", GetLastError());
  std::vector<Entry> entries;
  std::set<std::string> names, file_names;
  size_t position = 0;
  uint64_t expanded = 0;
  for (unsigned i = 0; i < count; ++i) {
    if (central.size() - position < 46 || U32(central.data() + position) != 0x02014b50)
      return Fail(failure, "update_archive_invalid", "portable_archive");
    const BYTE* header = central.data() + position;
    const unsigned name_size = U16(header + 28), extra_size = U16(header + 30), comment_size = U16(header + 32);
    const size_t record_size = 46ull + name_size + extra_size + comment_size;
    if (!name_size || record_size > central.size() - position || U16(header + 34))
      return Fail(failure, "update_archive_invalid", "portable_archive");
    Entry entry;
    entry.name.assign(reinterpret_cast<const char*>(header + 46), name_size);
    entry.flags = U16(header + 8); entry.method = U16(header + 10);
    entry.crc = U32(header + 16); entry.compressed = U32(header + 20);
    entry.expanded = U32(header + 24); entry.offset = U32(header + 42);
    entry.directory = entry.name.back() == '/';
    const uint32_t attributes = U32(header + 38), unix_type = (attributes >> 16) & 0170000;
    if ((entry.flags & ~0x080e) != 0 || (entry.method != 0 && entry.method != 8) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (unix_type && unix_type != 0100000 && unix_type != 0040000) ||
        (unix_type == 0040000 && !entry.directory) ||
        !SafeName(entry.name, entry.directory, &entry.relative) ||
        !ExtraSafe(header + 46 + name_size, extra_size) ||
        !names.insert(Lower(entry.relative)).second)
      return Fail(failure, "update_archive_unsafe", "portable_archive");
    if ((entry.directory && (entry.expanded || entry.compressed || entry.crc)) ||
        entry.expanded > kMaximumEntryBytes || entry.compressed > fuzevpn_update::kMaximumDownloadBytes ||
        entry.expanded > kMaximumExpandedBytes - expanded ||
        (entry.method == 0 && entry.compressed != entry.expanded))
      return Fail(failure, "update_archive_too_large", "portable_archive");
    expanded += entry.expanded;
    if (!entry.directory) file_names.insert(Lower(entry.relative));
    entries.push_back(std::move(entry));
    position += record_size;
  }
  if (position != central.size()) return Fail(failure, "update_archive_invalid", "portable_archive");
  for (const auto& name : names) {
    for (auto slash = name.find('/'); slash != std::string::npos; slash = name.find('/', slash + 1))
      if (file_names.count(name.substr(0, slash))) return Fail(failure, "update_archive_unsafe", "portable_archive");
  }
  // Local records must agree with central metadata and may not overlap.
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  for (auto& entry : entries) {
    std::array<BYTE, 30> local{};
    if (entry.offset > central_offset || central_offset - entry.offset < local.size() ||
        !Read(archive.get(), entry.offset, local.data(), static_cast<DWORD>(local.size())) ||
        U32(local.data()) != 0x04034b50 || U16(local.data() + 6) != entry.flags ||
        U16(local.data() + 8) != entry.method || U16(local.data() + 26) != entry.name.size())
      return Fail(failure, "update_archive_invalid", "portable_archive");
    const unsigned extra_size = U16(local.data() + 28);
    std::vector<BYTE> extra(entry.name.size() + extra_size);
    entry.data_offset = static_cast<uint64_t>(entry.offset) + local.size() + extra.size();
    if (entry.data_offset > central_offset || entry.compressed > central_offset - entry.data_offset ||
        !Read(archive.get(), entry.offset + local.size(), extra.data(), static_cast<DWORD>(extra.size())) ||
        !std::equal(entry.name.begin(), entry.name.end(), extra.begin()) ||
        !ExtraSafe(extra.data() + entry.name.size(), extra_size))
      return Fail(failure, "update_archive_invalid", "portable_archive");
    entry.end_offset = entry.data_offset + entry.compressed;
    if ((entry.flags & 8) == 0) {
      if (U32(local.data() + 14) != entry.crc || U32(local.data() + 18) != entry.compressed ||
          U32(local.data() + 22) != entry.expanded)
        return Fail(failure, "update_archive_invalid", "portable_archive");
    } else {
      std::array<BYTE, 16> descriptor{};
      if (entry.end_offset > central_offset || central_offset - entry.end_offset < 12 ||
          !Read(archive.get(), entry.end_offset, descriptor.data(), 12))
        return Fail(failure, "update_archive_invalid", "portable_archive");
      unsigned offset = 0;
      if (U32(descriptor.data()) == 0x08074b50) {
        if (central_offset - entry.end_offset < 16 || !Read(archive.get(), entry.end_offset, descriptor.data(), 16))
          return Fail(failure, "update_archive_invalid", "portable_archive");
        offset = 4;
      }
      if (U32(descriptor.data() + offset) != entry.crc || U32(descriptor.data() + offset + 4) != entry.compressed ||
          U32(descriptor.data() + offset + 8) != entry.expanded)
        return Fail(failure, "update_archive_invalid", "portable_archive");
      entry.end_offset += offset + 12;
    }
    ranges.emplace_back(entry.offset, entry.end_offset);
  }
  std::sort(ranges.begin(), ranges.end());
  uint64_t last = 0;
  for (const auto& range : ranges) {
    if (range.first != last) return Fail(failure, "update_archive_invalid", "portable_archive");
    last = range.second;
  }
  if (last != central_offset) return Fail(failure, "update_archive_invalid", "portable_archive");
  if (!destination.is_absolute() || !EmptyDirectory(destination))
    return Fail(failure, "update_archive_extract_failed", "portable_extract", ERROR_ACCESS_DENIED);
  for (const auto& entry : entries) {
    if (entry.directory) {
      if (!MakeDirectories(destination, entry.relative))
        return Fail(failure, "update_archive_extract_failed", "portable_extract", GetLastError());
      continue;
    }
    const auto slash = entry.relative.rfind('/');
    if (slash != std::string::npos && !MakeDirectories(destination, entry.relative.substr(0, slash)))
      return Fail(failure, "update_archive_extract_failed", "portable_extract", GetLastError());
    const auto path = destination / fuzevpn_update::Wide(entry.relative);
    Output output;
    output.limit = entry.expanded;
    output.handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (output.handle == INVALID_HANDLE_VALUE)
      return Fail(failure, "update_archive_extract_failed", "portable_extract", GetLastError());
    std::vector<BYTE> compressed(entry.compressed);
    if (!Read(archive.get(), entry.data_offset, compressed.data(), entry.compressed))
      return Fail(failure, "update_archive_extract_failed", "portable_extract", GetLastError());
    bool copied = false;
    if (entry.method == 0) copied = output.Write(compressed.data(), compressed.size());
    else {
      size_t consumed = compressed.size();
      copied = tinfl_decompress_mem_to_callback(compressed.data(), &consumed,
          InflateOutput, &output, 0) != 0 && consumed == compressed.size();
    }
    if (!copied || output.written != entry.expanded || (output.crc ^ 0xffffffffu) != entry.crc)
      return Fail(failure, "update_archive_invalid", "portable_extract");
    if (!FlushFileBuffers(output.handle))
      return Fail(failure, "update_archive_extract_failed", "portable_extract", GetLastError());
  }
  return true;
}

bool IsPortableTarget(const std::filesystem::path& root) {
  if (!root.is_absolute() || root == root.root_path() || !Directory(root) ||
      !fuzevpn_installation::IsCanonicalLocalAbsolutePath(root.wstring())) return false;
  std::array<wchar_t, MAX_PATH> volume{};
  DWORD filesystem_flags = 0;
  if (!GetVolumePathNameW(root.c_str(), volume.data(), static_cast<DWORD>(volume.size())) ||
      !GetVolumeInformationW(volume.data(), nullptr, 0, nullptr, nullptr, &filesystem_flags, nullptr, 0) ||
      !(filesystem_flags & FILE_PERSISTENT_ACLS)) return false;
  PinnedFile marker;
  if (!marker.Open(root / L"fuzevpn.portable", true)) return false;
  constexpr char contents[] = "FuzeVPN portable v1\n";
  LARGE_INTEGER size{};
  std::array<char, sizeof(contents) - 1> bytes{};
  return GetFileSizeEx(marker.get(), &size) && size.QuadPart == static_cast<LONGLONG>(bytes.size()) &&
      Read(marker.get(), 0, bytes.data(), static_cast<DWORD>(bytes.size())) &&
      std::equal(bytes.begin(), bytes.end(), contents);
}
bool ValidateBundle(const std::filesystem::path& root, const fuzevpn_update::Version& target,
                    const std::vector<BYTE>& publisher, Failure* failure) {
  if (failure) *failure = {};
  if (!IsPortableTarget(root)) return Fail(failure, "update_portable_target_invalid", "portable_bundle");
  std::vector<std::filesystem::path> paths;
  if (!Enumerate(root, root, &paths)) return Fail(failure, "update_archive_unsafe", "portable_bundle");
  std::vector<std::unique_ptr<PinnedFile>> pins;
  uint64_t total = 0;
  std::set<std::string> names;
  for (const auto& path : paths) {
    auto file = std::make_unique<PinnedFile>();
    LARGE_INTEGER size{};
    if (!file->Open(path, true) || !GetFileSizeEx(file->get(), &size) || size.QuadPart <= 0 ||
        static_cast<uint64_t>(size.QuadPart) > kMaximumExpandedBytes - total)
      return Fail(failure, "update_archive_unsafe", "portable_bundle");
    total += static_cast<uint64_t>(size.QuadPart);
    const auto name = Lower(path.lexically_relative(root).generic_string());
    if (!names.insert(name).second) return Fail(failure, "update_archive_unsafe", "portable_bundle");
    const auto extension = Lower(path.extension().string());
    std::array<BYTE, 2> magic{};
    const bool pe = Read(file->get(), 0, magic.data(), 2) && magic[0] == 'M' && magic[1] == 'Z';
    if (pe || extension == ".exe" || extension == ".dll" || extension == ".sys") {
      if (!fuzevpn_update::MatchesBuildArchitecture(file->get()))
        return Fail(failure, "update_package_architecture_mismatch", "portable_bundle");
      std::vector<BYTE> subject;
      LONG status = ERROR_SUCCESS;
      if (!fuzevpn_update::TrustedPublisher(*file, &subject, &status))
        return Fail(failure, "update_signature_invalid", "portable_bundle", 0, status);
      if (name == "fuzevpn_windows.exe" || name == "fuzevpn-service.exe" ||
          name == "fuzevpn-runtime.exe" || name == "fuzevpn-update.exe") {
        fuzevpn_update::Version version;
        if (!fuzevpn_update::SamePublisher(subject, publisher))
          return Fail(failure, "update_publisher_mismatch", "portable_bundle");
        if (!fuzevpn_update::ReadVersion(path, &version, true) || !(version == target))
          return Fail(failure, "update_package_version_mismatch", "portable_bundle");
      }
    }
    if (name == "data/app.so") {
      // Flutter AOT snapshots use ELF64 on Windows, authenticated by the ZIP
      // hash rather than Authenticode. Check their target without loading it.
      std::array<BYTE, 64> elf{};
      const unsigned machine = fuzevpn_architecture::kBuildMachine ==
          fuzevpn_architecture::kX64Machine ? 62 : 183;
      if (!Read(file->get(), 0, elf.data(), static_cast<DWORD>(elf.size())) ||
          elf[0] != 0x7f || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F' ||
          elf[4] != 2 || elf[5] != 1 || elf[6] != 1 || U16(elf.data() + 18) != machine)
        return Fail(failure, "update_package_architecture_mismatch", "portable_bundle");
    }
    pins.push_back(std::move(file));
  }
  for (const char* required : {"fuzevpn_windows.exe", "fuzevpn-service.exe", "fuzevpn-runtime.exe",
      "fuzevpn-update.exe", "flutter_windows.dll", "data/app.so", "data/icudtl.dat",
      "data/flutter_assets/assetmanifest.bin", "portable-runtime.manifest", "fuzevpn_tray.ico"})
    if (!names.count(required)) return Fail(failure, "update_portable_manifest_invalid", "portable_manifest");
  fuzevpn_portable::Manifest manifest;
  DWORD error = ERROR_SUCCESS;
  if (!fuzevpn_portable::ReadEmbeddedManifest(root / L"fuzevpn-runtime.exe", &manifest, &error) ||
      !(manifest.version == target) || !fuzevpn_portable::VerifyManifestFiles(root, manifest, &error))
    return Fail(failure, "update_portable_manifest_invalid", "portable_manifest", error);
  PinnedFile manifest_file;
  if (!manifest_file.Open(root / L"portable-runtime.manifest", true) ||
      !fuzevpn_update::MatchesHash(manifest_file.get(), manifest.sha256))
    return Fail(failure, "update_portable_manifest_invalid", "portable_manifest");
  return true;
}
bool RemoveStaging(const std::filesystem::path& root) {
  if (!root.is_absolute() || root == root.root_path()) return false;
  unsigned count = 0;
  return DeleteTree(root, 0, &count);
}
bool ReplaceDirectory(const std::filesystem::path& target, const std::filesystem::path& candidate,
                      const std::filesystem::path& backup, Failure* failure) {
  if (failure) *failure = {};
  if (!target.is_absolute() || !candidate.is_absolute() || !backup.is_absolute() ||
      target.parent_path() != candidate.parent_path() || target.parent_path() != backup.parent_path() ||
      target == candidate || target == backup || candidate == backup ||
      !IsPortableTarget(target) || !IsPortableTarget(candidate) ||
      GetFileAttributesW(backup.c_str()) != INVALID_FILE_ATTRIBUTES)
    return Fail(failure, "update_portable_target_invalid", "portable_target", ERROR_ACCESS_DENIED);
  if (!Rename(target, backup))
    return Fail(failure, "update_portable_replace_failed", "portable_replace", GetLastError());
  if (Rename(candidate, target)) return true;
  const DWORD error = GetLastError();
  if (!Rename(backup, target))
    return Fail(failure, "update_portable_replace_failed", "portable_rollback", GetLastError());
  return Fail(failure, "update_portable_replace_failed", "portable_replace", error);
}
}  // namespace fuzevpn_portable_update
