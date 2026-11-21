// AEGIS: usermode anticheat for Roblox. Tier 1 of docs/ROADMAP.md.
//
//   aegis scan     one-shot: integrity, drivers, tamper, script logs, artifacts, and a
//                  handle + window check if Roblox is open
//   aegis monitor  scan, then live checks (ETW, handle sampling, windows, named objects)
//                  until --duration elapses, Roblox exits (--until-roblox-exits) or Ctrl+C
//   aegis yara <path>     run the embedded YARA rules over a file or folder
//   aegis rules           list the loaded rules
//   aegis signer <file>   print a file's Authenticode signer (for allowlist tuning)
//
// Output: one JSON object per line on stdout (or --out <file>): findings, then a summary.
// Diagnostics go to stderr. Only rule hits are reported (roadmap section 7).

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include "logic/strutil.h"
#include "win/context.h"
#include "win/winutil.h"
#include "win/yara_engine.h"

using namespace aegis;

namespace {

std::atomic<bool> g_stop{false};

BOOL WINAPI OnCtrl(DWORD) {
  g_stop = true;
  return TRUE;
}

void Usage() {
  std::fputs(
      "usage: aegis <scan|monitor|yara|rules|signer> [options]\n"
      "  --out <file>            write JSON lines to a file instead of stdout\n"
      "  --data-dir <dir>        load rules/ and data/ from this folder instead of the embedded copies\n"
      "  --duration <seconds>    monitor: stop after this long (default: until Ctrl+C)\n"
      "  --until-roblox-exits    monitor: stop once Roblox has been seen and then closes\n"
      "  --no-scan               monitor: skip the one-shot scan\n"
      "  --no-roblox-open        never open the Roblox process (disables the A1 handle sampler)\n"
      "  --history-days <n>      look-back for event logs (default 30)\n"
      "  --skip <a,b,...>        skip checks: handles integrity drivers tamper script_logs artifacts\n"
      "                          named_objects dns_cache windows memory etw\n"
      "  --no-harden             do not apply process mitigation policies to AEGIS itself\n",
      stderr);
}

bool RobloxRunning() {
  for (const auto& p : win::SnapshotProcesses())
    if (IEquals(p.name, detect::kRobloxImage)) return true;
  return false;
}

void RunScan(Context& ctx, detect::HandleSampler& handles) {
  detect::CheckIntegrity(ctx);
  detect::CheckDrivers(ctx);
  detect::CheckTamper(ctx);
  detect::CheckScriptLogs(ctx);
  detect::CheckArtifacts(ctx);
  if (!ctx.Skip("named_objects")) {
    detect::SweepNamedObjects(ctx);
    ctx.Ran("named_objects");
  }
  if (!ctx.Skip("dns_cache")) {
    detect::CheckDnsCache(ctx);
    ctx.Ran("dns_cache");
  }
  if (RobloxRunning()) {
    if (handles.Sample()) ctx.Ran("handles");
    else ctx.Skipped("handles", ctx.opts.open_roblox ? "handle table unavailable" : "--no-roblox-open");
    detect::SweepWindows(ctx);
    ctx.Ran("windows");
  } else {
    ctx.Skipped("handles", "Roblox not running");
    ctx.Skipped("windows", "Roblox not running");
  }
}

void DrainMemoryScans(Context& ctx, std::map<uint32_t, int>& attempts) {
  std::vector<uint32_t> due;
  {
    std::lock_guard<std::mutex> lock(ctx.scan_mu);
    uint64_t now = GetTickCount64();
    for (auto it = ctx.pending_mem_scans.begin(); it != ctx.pending_mem_scans.end();) {
      if (it->second <= now) {
        due.push_back(it->first);
        it = ctx.pending_mem_scans.erase(it);
      } else {
        ++it;
      }
    }
  }
  for (uint32_t pid : due) {
    detect::ScanProcessMemory(ctx, pid);
    // The loader maps the PE some seconds after the process starts; look a few times.
    if (++attempts[pid] < 3) ctx.QueueMemoryScan(pid, 10000);
  }
}

int RunMonitor(Context& ctx, detect::HandleSampler& handles, int duration_s, bool until_exit) {
  detect::EtwMonitor etw(ctx);
  bool etw_ok = !ctx.Skip("etw") && etw.Start();
  if (!etw_ok) ctx.Skipped("etw", ctx.Skip("etw") ? "--skip" : "could not start session (needs elevation)");

  SetConsoleCtrlHandler(OnCtrl, TRUE);
  const uint64_t start = GetTickCount64();
  uint64_t next_handles = 0, next_objects = 0, next_windows = 0, next_dns = 0, next_health = 0;
  bool seen_roblox = false;
  std::map<uint32_t, int> attempts;
  win::Log("monitoring%s; Ctrl+C to stop", etw_ok ? " with ETW" : " without ETW");

  while (!g_stop) {
    uint64_t now = GetTickCount64();
    if (duration_s > 0 && now - start >= static_cast<uint64_t>(duration_s) * 1000) break;
    bool roblox = RobloxRunning();
    if (roblox) seen_roblox = true;
    if (until_exit && seen_roblox && !roblox) {
      win::Log("Roblox exited; stopping");
      break;
    }
    if (roblox && now >= next_handles) {
      handles.Sample();  // roadmap A1: sample at least every 2 s
      next_handles = now + 2000;
    }
    if (now >= next_objects || ctx.sweep_named_objects_now.exchange(false)) {
      detect::SweepNamedObjects(ctx);
      next_objects = now + 2000;
    }
    if (roblox && now >= next_windows) {
      detect::SweepWindows(ctx);
      next_windows = now + 5000;
    }
    if (now >= next_dns) {
      detect::CheckDnsCache(ctx);
      next_dns = now + 30000;
    }
    if (etw_ok && now >= next_health) {
      etw.CheckHealth();
      next_health = now + 5000;
    }
    DrainMemoryScans(ctx, attempts);
    Sleep(250);
  }
  etw.Stop();
  ctx.Ran("monitor.live");
  return 0;
}

int CmdYara(Context& ctx, const std::wstring& target) {
  if (!ctx.yara) {
    win::Log("YARA is not available in this build");
    return 2;
  }
  DWORD attr = GetFileAttributesW(target.c_str());
  if (attr == INVALID_FILE_ATTRIBUTES) {
    win::Log("not found");
    return 2;
  }
  std::vector<std::wstring> stack{target};
  size_t files = 0;
  while (!stack.empty()) {
    std::wstring p = stack.back();
    stack.pop_back();
    DWORD a = GetFileAttributesW(p.c_str());
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
      for (const auto& e : win::ListDir(p))
        if (!e.is_reparse) stack.push_back(p + L"\\" + e.name);
      continue;
    }
    ++files;
    detect::YaraScanFileReport(ctx, p, 0, "aegis yara");
  }
  win::Log("scanned %zu files", files);
  ctx.Ran("yara");
  return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc < 2) {
    Usage();
    return 2;
  }
  std::wstring cmd = argv[1];
  std::wstring out_path, data_dir, positional;
  int duration = 0;
  bool until_exit = false, no_scan = false;
  Options opts;
  for (int i = 2; i < argc; ++i) {
    std::wstring a = argv[i];
    auto next = [&]() -> std::wstring { return i + 1 < argc ? argv[++i] : L""; };
    if (a == L"--out") out_path = next();
    else if (a == L"--data-dir") data_dir = next();
    else if (a == L"--duration") duration = _wtoi(next().c_str());
    else if (a == L"--until-roblox-exits") until_exit = true;
    else if (a == L"--no-scan") no_scan = true;
    else if (a == L"--no-roblox-open") opts.open_roblox = false;
    else if (a == L"--no-harden") opts.harden = false;
    else if (a == L"--history-days") opts.history_days = std::max(1, _wtoi(next().c_str()));
    else if (a == L"--skip") {
      std::string list = WideToUtf8(next());
      size_t s = 0;
      for (size_t k = 0; k <= list.size(); ++k)
        if (k == list.size() || list[k] == ',') {
          if (k > s) opts.skip.insert(list.substr(s, k - s));
          s = k + 1;
        }
    } else if (a == L"-h" || a == L"--help") {
      Usage();
      return 0;
    } else if (positional.empty() && a.rfind(L"--", 0) != 0) positional = a;
    else {
      Usage();
      return 2;
    }
  }
  if (!opts.open_roblox) opts.skip.insert("handles");

  if (cmd == L"signer") {
    auto s = win::GetSigner(positional);
    std::printf("%s\t%s\n", s.signed_ok ? (s.catalog ? "catalog" : "embedded") : "unsigned", WideToUtf8(s.signer).c_str());
    return 0;
  }

  if (opts.harden) {
    for (const auto& f : win::HardenSelf()) win::Log("mitigation not applied: %s", f.c_str());
  }
  if (!win::IsElevated()) win::Log("not elevated: handle, ETW, Security log and driver checks will be limited");
  if (!win::EnablePrivilege(L"SeDebugPrivilege")) win::Log("SeDebugPrivilege not enabled");

  Context ctx;
  ctx.opts = opts;
  std::ofstream file;
  std::ostream* out = &std::cout;
  if (!out_path.empty()) {
    file.open(std::filesystem::path(out_path), std::ios::out | std::ios::trunc | std::ios::binary);
    if (!file) {
      win::Log("cannot open --out file");
      return 2;
    }
    out = &file;
  }
  InitContext(ctx, data_dir);
  ctx.reporter = std::make_unique<Reporter>(ctx.catalog, *out);

  if (cmd == L"rules") {
    for (const auto& [id, m] : ctx.catalog.All())
      std::printf("%-46s %-8s %-6s %s\n", id.c_str(), m.severity.c_str(), m.confidence.c_str(), m.title.c_str());
    return 0;
  }

  detect::HandleSampler handles(ctx);
  int rc = 0;
  std::string mode = WideToUtf8(cmd);
  if (cmd == L"scan") {
    RunScan(ctx, handles);
  } else if (cmd == L"monitor") {
    if (!no_scan) RunScan(ctx, handles);
    rc = RunMonitor(ctx, handles, duration, until_exit);
  } else if (cmd == L"yara") {
    if (positional.empty()) {
      Usage();
      return 2;
    }
    rc = CmdYara(ctx, positional);
  } else {
    Usage();
    return 2;
  }
  ctx.reporter->Summary(mode, ctx.checks_run, ctx.checks_skipped);
  return rc != 0 ? rc : (ctx.reporter->HitCount() ? 1 : 0);
}
