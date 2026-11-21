// Windows helpers shared by the detectors.
#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace aegis::win {

// ---- Errors / privileges ----
bool IsElevated();
bool EnablePrivilege(const wchar_t* name);
// Best-effort process mitigations from roadmap section 6. Returns a list of failures.
std::vector<std::string> HardenSelf();

// ---- Environment and paths ----
std::wstring GetEnv(const wchar_t* name);
std::wstring KnownFolder(const GUID& id);
std::wstring WindowsDir();
// Converts \Device\HarddiskVolumeN\..., \SystemRoot\..., \??\C:\... and
// "System32\drivers\x.sys" style paths to Win32 paths.
std::wstring ToWin32Path(const std::wstring& native);
bool FileExists(const std::wstring& path);
std::optional<FILETIME> LastWriteTime(const std::wstring& path);
std::wstring ExpandEnv(const std::wstring& s);

// ---- Files ----
// Lowercase hex SHA-256, empty on failure. Files over max_bytes are skipped.
std::string Sha256File(const std::wstring& path, uint64_t max_bytes = 256ull << 20);
std::string Sha256Bytes(const void* data, size_t len);
std::optional<std::string> ReadFileBytes(const std::wstring& path, size_t max_bytes);

struct DirEntry {
  std::wstring name;
  bool is_dir = false;
  bool is_reparse = false;
  uint64_t size = 0;
  FILETIME write_time{};
};
std::vector<DirEntry> ListDir(const std::wstring& dir);

// ---- Registry ----
std::optional<DWORD> RegDword(HKEY root, const wchar_t* subkey, const wchar_t* value);
std::optional<std::wstring> RegString(HKEY root, const wchar_t* subkey, const wchar_t* value);
std::optional<std::vector<uint8_t>> RegBinary(HKEY root, const wchar_t* subkey, const wchar_t* value);
std::vector<std::wstring> RegSubkeys(HKEY root, const wchar_t* subkey);
std::vector<std::wstring> RegValueNames(HKEY root, const wchar_t* subkey);

// ---- Processes ----
struct ProcEntry {
  DWORD pid = 0;
  DWORD ppid = 0;
  std::wstring name;
};
std::vector<ProcEntry> SnapshotProcesses();
std::map<DWORD, ProcEntry> SnapshotProcessMap();
std::wstring ProcessImagePath(DWORD pid);  // Win32 path, empty if not accessible
std::optional<std::wstring> ProcessCommandLine(DWORD pid);
std::optional<bool> ProcessElevated(DWORD pid);
uint64_t ProcessCreateTime(DWORD pid);  // FILETIME as integer, 0 if unknown

// ---- Authenticode ----
struct SignerInfo {
  bool signed_ok = false;  // embedded or catalog signature verified
  std::wstring signer;     // leaf certificate simple display name, empty if unsigned
  bool catalog = false;
};
// Cached by lowercase path.
SignerInfo GetSigner(const std::wstring& path);

// ---- Time ----
int64_t NowUnix();
std::string UnixToIso(int64_t t);
std::string FileTimeToIso(const FILETIME& ft);

// ---- Logging to stderr (never findings) ----
void Log(const char* fmt, ...);

}  // namespace aegis::win
