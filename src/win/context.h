// Shared state passed to every detector.
#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "../logic/match.h"
#include "../logic/privacy.h"
#include "../logic/report.h"
#include "../logic/rulemeta.h"

namespace aegis {

class YaraEngine;

struct Options {
  bool open_roblox = true;  // A1 needs one brief PROCESS_QUERY_LIMITED_INFORMATION open per Roblox instance
  bool harden = true;
  int history_days = 30;
  std::set<std::string> skip;  // check names to skip
};

struct Context {
  Options opts;
  RuleCatalog catalog;
  std::unique_ptr<Reporter> reporter;
  PathNormaliser paths;
  std::vector<AllowEntry> allowlist;
  std::unordered_map<std::string, DriverListEntry> drivers;
  std::unordered_map<std::string, std::string> domains;
  YaraEngine* yara = nullptr;  // null when built without YARA or rules failed to compile

  // Memory scans queued by live rules (pid -> due tick). Drained by the monitor loop.
  std::mutex scan_mu;
  std::map<uint32_t, uint64_t> pending_mem_scans;
  std::set<uint32_t> mem_scanned;
  std::atomic<bool> sweep_named_objects_now{false};

  std::mutex checks_mu;
  std::vector<std::string> checks_run, checks_skipped;

  bool Skip(const std::string& check) const { return opts.skip.count(check) > 0; }
  void Ran(const std::string& check);
  void Skipped(const std::string& check, const std::string& why);
  void QueueMemoryScan(uint32_t pid, uint64_t delay_ms);

  // Normalised path for evidence.
  std::string Ev(const std::wstring& path) const;
  // True if the holder at `path` (Win32) with `name` is allowlisted for handle rules.
  bool Allowlisted(const std::wstring& name, const std::wstring& path) const;
};

// Builds the catalog, allowlists and path tokens. `data_dir` overrides embedded data.
bool InitContext(Context& ctx, const std::wstring& data_dir);

// ---- Detectors (one file each) ----
namespace detect {
// A1. Returns false if the handle table could not be used (e.g. no SeDebugPrivilege).
class HandleSampler {
 public:
  explicit HandleSampler(Context& ctx) : ctx_(ctx) {}
  bool Sample();
  // PIDs that hit a handle rule this session.
  std::set<uint32_t> Holders() const;

 private:
  struct Target {
    uint32_t pid;
    void* object;
    unsigned short type_index;
  };
  Context& ctx_;
  std::vector<Target> targets_;
  std::set<uint32_t> holders_;
  std::set<uint32_t> listener_checked_;
  bool warned_ = false;
  bool disabled_ = false;
};

// A2. Live ETW session.
class EtwMonitor {
 public:
  explicit EtwMonitor(Context& ctx);
  ~EtwMonitor();
  bool Start();
  void Stop();
  // Session health check for AEGIS-SELF-001; call every few seconds.
  void CheckHealth();
  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

void CheckIntegrity(Context& ctx);   // A4
void CheckDrivers(Context& ctx);     // A3
void CheckTamper(Context& ctx);      // A5 + DESTINY-006
void CheckScriptLogs(Context& ctx);  // Sigma rules over PowerShell 4104 and Security 4688
void CheckArtifacts(Context& ctx);   // A6 static: files, execution records, executor folders, Zone.Identifier
void SweepNamedObjects(Context& ctx);  // DESTINY-001
void CheckDnsCache(Context& ctx);      // DESTINY-007
void SweepWindows(Context& ctx);       // GEN-010, GEN-011, FORSAKEN-001
void ScanProcessMemory(Context& ctx, uint32_t pid);  // DESTINY-010, YARA-002
void YaraScanFileReport(Context& ctx, const std::wstring& path, uint32_t pid, const std::string& why);

constexpr const wchar_t* kRobloxImage = L"RobloxPlayerBeta.exe";
}  // namespace detect

}  // namespace aegis
