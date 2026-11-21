// Pure matching logic behind the behaviour rules. Everything here is portable and
// unit-tested; the Windows layer gathers the data and calls these.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace aegis {

// ---- Process access rights (winnt.h values, repeated so this builds anywhere) ----
namespace access {
constexpr uint32_t kTerminate = 0x0001;
constexpr uint32_t kCreateThread = 0x0002;
constexpr uint32_t kVmOperation = 0x0008;
constexpr uint32_t kVmRead = 0x0010;
constexpr uint32_t kVmWrite = 0x0020;
constexpr uint32_t kDupHandle = 0x0040;
constexpr uint32_t kCreateProcess = 0x0080;
constexpr uint32_t kSetInformation = 0x0200;
constexpr uint32_t kQueryInformation = 0x0400;
constexpr uint32_t kSuspendResume = 0x0800;
constexpr uint32_t kQueryLimited = 0x1000;
constexpr uint32_t kInjectMask = kCreateThread | kVmOperation | kVmWrite;
constexpr uint32_t kVmMask = kVmOperation | kVmRead | kVmWrite;
}  // namespace access

// "VM_READ|VM_WRITE|..." for the bits that matter to the rules.
std::string DecodeProcessAccess(uint32_t mask);

// ---- A1: handle holders ----
bool IsScriptHost(const std::wstring& image_name);

enum class HandleRule { kNone, kGen001, kGen002, kGen003 };
// GEN-002 (script host with any VM right) wins over the allowlist; GEN-001 is write or
// thread rights from a non-allowlisted holder; GEN-003 is read-only VM from one.
HandleRule ClassifyRobloxHandle(uint32_t granted, const std::wstring& holder_name, bool holder_allowlisted);
const char* HandleRuleId(HandleRule r);

// ---- Signer + path allowlist (data/handle_allowlist.tsv) ----
struct AllowEntry {
  std::wstring name;           // image file name, or "*"
  std::wstring signer_prefix;  // required signer prefix; "-" means unsigned is accepted
  std::wstring path_prefix;    // normalised path prefix (tokens such as %ProgramFiles%), or "*"
};
std::vector<AllowEntry> ParseAllowlist(const std::string& tsv);
// `normalised_path` uses the same tokens as the entries. `signer` is empty when unsigned.
bool IsAllowlisted(const std::vector<AllowEntry>& list, const std::wstring& image_name,
                   const std::wstring& normalised_path, const std::wstring& signer);

// ---- A3: vulnerable / malicious driver hashes (data/vulnerable_drivers.tsv) ----
struct DriverListEntry {
  std::string category;  // "vulnerable driver" | "malicious"
  std::string name;
};
std::unordered_map<std::string, DriverListEntry> ParseDriverList(const std::string& tsv);

// ---- Domain list (data/cheat_domains.tsv): domain <tab> family ----
std::unordered_map<std::string, std::string> ParseDomainList(const std::string& tsv);
// Returns the matched list entry (exact or subdomain), or empty.
std::string MatchDomain(const std::unordered_map<std::string, std::string>& list, std::string host);

// ---- Command lines (B5) ----
// AEGIS-DESTINY-008 / sigma destiny_hidden_worker: hidden encoded PowerShell child of PowerShell.
bool MatchHiddenEncodedWorker(const std::wstring& image_name, const std::wstring& parent_name,
                              const std::wstring& command_line);
// AEGIS-DESTINY-011 (also): "adb reverse tcp:N tcp:N".
bool MatchAdbReverse(const std::wstring& image_name, const std::wstring& command_line);

// ---- A6: named objects, files, executor layout, scripts ----
// AEGIS-DESTINY-001. `full_name` is the object path, e.g. \Sessions\1\BaseNamedObjects\DestinyMem_<hex>.
bool MatchDestinyNamedObject(const std::wstring& full_name);
// AEGIS-DESTINY-002 on the file name only.
bool MatchDestinyTempDll(const std::wstring& file_name);

struct DirListing {
  std::vector<std::wstring> dirs;   // child directory names
  std::vector<std::wstring> files;  // child file names
};
// AEGIS-EXEC-001: an executable next to an `autoexec` folder plus `workspace`, `scripts` or `bin`.
bool LooksLikeExecutorFolder(const DirListing& d);
// AEGIS-EXEC-002: executor-only Luau calls in a script. Returns the distinct tokens found;
// the rule fires on loadstring(game:HttpGet( alone or on two or more tokens.
std::vector<std::string> ExecutorScriptTokens(const std::string& script);
bool ExecutorScriptHit(const std::vector<std::string>& tokens);

// sigma destiny_powershell_reflective_loader, on a 4104 ScriptBlockText.
bool MatchReflectiveLoaderScript(const std::wstring& text);

// ---- A5 ----
// AEGIS-TAMP-003: clock set back by more than `threshold_s` seconds.
bool IsBackwardClockChange(int64_t previous_unix, int64_t new_unix, int64_t threshold_s = 600);
// Parses an ISO-8601 UTC time as written in event XML ("2026-11-21T19:06:14.1234567Z").
// Returns false if it cannot be parsed.
bool ParseIsoUtc(const std::wstring& s, int64_t& unix_seconds);

// Converts a Windows FILETIME value (100 ns since 1601) to Unix seconds.
inline int64_t FileTimeToUnix(uint64_t ft) { return static_cast<int64_t>(ft / 10000000ULL) - 11644473600LL; }

// Pulls <Data Name='X'>value</Data> out of rendered event XML.
std::wstring EventXmlData(const std::wstring& xml, const std::wstring& name);

}  // namespace aegis
