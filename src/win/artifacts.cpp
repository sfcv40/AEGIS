// A6 executor and family artifacts, plus the window sweep (GEN-010/011, FORSAKEN-001)
// and the targeted memory scan of flagged script hosts (DESTINY-010, YARA-002).
//
// Scope is deliberately narrow (roadmap section 7, point 4): only named locations are
// walked, scripts are read only inside folders that already look like an executor, and
// only matches leave the machine.

#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <functional>

#include "../logic/strutil.h"
#include "context.h"
#include "nt.h"
#include "winutil.h"
#include "yara_engine.h"

namespace aegis::detect {

namespace {

void ReportFile(Context& ctx, const char* rule, const std::wstring& path) {
  Finding f;
  f.rule = rule;
  f.dedupe = WideToUtf8(ToLower(path));
  f.Add("file", ctx.Ev(path)).Add("sha256", win::Sha256File(path));
  if (auto t = win::LastWriteTime(path)) f.Add("last_write", win::FileTimeToIso(*t));
  ctx.reporter->Report(std::move(f));
}

void CheckFamilyFiles(Context& ctx) {
  // DESTINY-002: staged nv_biosmeth DLL in Windows Temp or the user's Temp.
  for (const std::wstring& dir : {win::WindowsDir() + L"\\Temp", ctx.paths.Expand(L"%TEMP%")}) {
    for (const auto& e : win::ListDir(dir)) {
      if (e.is_dir || !MatchDestinyTempDll(e.name)) continue;
      std::wstring path = dir + L"\\" + e.name;
      ReportFile(ctx, "AEGIS-DESTINY-002", path);
      YaraScanFileReport(ctx, path, 0, "Destiny staging path");
    }
  }
  // FORSAKEN-002: license and config files.
  std::wstring kw = ctx.paths.Expand(L"%LOCALAPPDATA%") + L"\\KILLYWARE\\";
  for (const wchar_t* name : {L"license.dat", L"config_last.bin"})
    if (win::FileExists(kw + name)) ReportFile(ctx, "AEGIS-FORSAKEN-002", kw + name);
  ctx.Ran("artifacts.family_files");
}

void CheckExecutionRecords(Context& ctx) {
  struct Known {
    const wchar_t* exe;
    const char* rule;
  } known[] = {{L"FORSAKEN.EXE", "AEGIS-FORSAKEN-003"},
               {L"KILLYWARE.EXE", "AEGIS-FORSAKEN-003"},
               {L"DESTINY.EXE", "AEGIS-DESTINY-012"},
               {L"DESTINYSCRIPTS.EXE", "AEGIS-DESTINY-012"}};
  auto match = [&](const std::wstring& exe) -> const char* {
    for (const auto& k : known)
      if (IEquals(exe, k.exe)) return k.rule;
    return nullptr;
  };

  // Prefetch: <EXE>-<HASH>.pf
  std::wstring pfdir = win::WindowsDir() + L"\\Prefetch";
  for (const auto& e : win::ListDir(pfdir)) {
    if (e.is_dir || !IEndsWith(e.name, L".pf")) continue;
    auto dash = e.name.rfind(L'-');
    if (dash == std::wstring::npos) continue;
    std::wstring exe = e.name.substr(0, dash);
    if (const char* rule = match(exe)) {
      Finding f;
      f.rule = rule;
      f.dedupe = "prefetch|" + WideToUtf8(e.name);
      f.Add("source", "prefetch").Add("executable", WideToUtf8(exe)).Add("last_run", win::FileTimeToIso(e.write_time));
      ctx.reporter->Report(std::move(f));
    }
  }

  // BAM: value names are device paths of executables, per user SID.
  const wchar_t* bam = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
  for (const auto& sid : win::RegSubkeys(HKEY_LOCAL_MACHINE, bam)) {
    std::wstring key = std::wstring(bam) + L"\\" + sid;
    for (const auto& v : win::RegValueNames(HKEY_LOCAL_MACHINE, key.c_str())) {
      std::wstring exe = BaseName(v);
      if (const char* rule = match(exe)) {
        std::wstring path = win::ToWin32Path(v);
        Finding f;
        f.rule = rule;
        f.dedupe = "bam|" + WideToUtf8(ToLower(path));
        f.Add("source", "bam").Add("executable", WideToUtf8(exe)).Add("path", ctx.Ev(path));
        f.Add("file_present", win::FileExists(path) ? "true" : "false");
        ctx.reporter->Report(std::move(f));
        if (win::FileExists(path)) YaraScanFileReport(ctx, path, 0, "named in execution records");
      }
    }
  }
  ctx.Ran("artifacts.execution_records");
}

// Depth-limited walk that skips reparse points. `visit` returns false to stop descending.
void Walk(const std::wstring& dir, int depth, size_t& budget,
          const std::function<bool(const std::wstring&, const std::vector<win::DirEntry>&)>& visit) {
  if (budget == 0) return;
  --budget;
  auto entries = win::ListDir(dir);
  if (!visit(dir, entries) || depth == 0) return;
  for (const auto& e : entries)
    if (e.is_dir && !e.is_reparse) Walk(dir + L"\\" + e.name, depth - 1, budget, visit);
}

void ScanExecutorScripts(Context& ctx, const std::wstring& folder) {
  size_t budget = 200;
  int reported = 0;
  for (const wchar_t* sub : {L"autoexec", L"scripts", L"workspace"}) {
    Walk(folder + L"\\" + sub, 2, budget, [&](const std::wstring& dir, const std::vector<win::DirEntry>& entries) {
      for (const auto& e : entries) {
        if (e.is_dir || e.size > (1u << 20) || reported >= 20) continue;
        if (!IEndsWith(e.name, L".lua") && !IEndsWith(e.name, L".luau") && !IEndsWith(e.name, L".txt")) continue;
        std::wstring path = dir + L"\\" + e.name;
        auto text = win::ReadFileBytes(path, 1u << 20);
        if (!text) continue;
        auto tokens = ExecutorScriptTokens(*text);
        if (!ExecutorScriptHit(tokens)) continue;
        std::string list;
        for (const auto& t : tokens) list += (list.empty() ? "" : ",") + t;
        Finding f;
        f.rule = "AEGIS-EXEC-002";
        f.dedupe = WideToUtf8(ToLower(path));
        f.Add("file", ctx.Ev(path)).Add("tokens", list).Add("sha256", win::Sha256File(path));
        ctx.reporter->Report(std::move(f));
        ++reported;
      }
      return true;
    });
  }
}

void CheckExecutorFolders(Context& ctx) {
  std::vector<std::wstring> roots = {win::KnownFolder(FOLDERID_Desktop),   win::KnownFolder(FOLDERID_Downloads),
                                     win::KnownFolder(FOLDERID_Documents), ctx.paths.Expand(L"%LOCALAPPDATA%"),
                                     ctx.paths.Expand(L"%APPDATA%"),       ctx.paths.Expand(L"%TEMP%")};
  size_t budget = 40000;  // directories visited, across all roots
  for (const auto& root : roots) {
    if (root.empty() || root[0] == L'%') continue;
    Walk(root, 3, budget, [&](const std::wstring& dir, const std::vector<win::DirEntry>& entries) {
      DirListing d;
      for (const auto& e : entries) (e.is_dir ? d.dirs : d.files).push_back(e.name);
      if (!LooksLikeExecutorFolder(d)) return true;
      std::string subdirs;
      for (const auto& s : d.dirs)
        if (IEquals(s, L"autoexec") || IEquals(s, L"workspace") || IEquals(s, L"scripts") || IEquals(s, L"bin"))
          subdirs += (subdirs.empty() ? "" : ",") + WideToUtf8(ToLower(s));
      Finding f;
      f.rule = "AEGIS-EXEC-001";
      f.dedupe = WideToUtf8(ToLower(dir));
      f.Add("folder", ctx.Ev(dir)).Add("subfolders", subdirs);
      ctx.reporter->Report(std::move(f));
      ScanExecutorScripts(ctx, dir);
      for (const auto& e : entries)
        if (!e.is_dir && (IEndsWith(e.name, L".exe") || IEndsWith(e.name, L".dll")))
          YaraScanFileReport(ctx, dir + L"\\" + e.name, 0, "executor folder");
      for (const auto& e : win::ListDir(dir + L"\\bin"))
        if (!e.is_dir && IEndsWith(e.name, L".dll")) YaraScanFileReport(ctx, dir + L"\\bin\\" + e.name, 0, "executor folder");
      return false;  // do not descend into the executor's own tree
    });
  }
  ctx.Ran("artifacts.executor_folders");
}

std::string HostOf(const std::wstring& url) {
  auto p = url.find(L"://");
  std::wstring rest = p == std::wstring::npos ? url : url.substr(p + 3);
  auto end = rest.find_first_of(L"/:?#");
  if (end != std::wstring::npos) rest = rest.substr(0, end);
  auto at = rest.rfind(L'@');
  if (at != std::wstring::npos) rest = rest.substr(at + 1);
  return WideToUtf8(rest);
}

void CheckDownloads(Context& ctx) {
  static const wchar_t* kExt[] = {L".exe", L".dll", L".zip", L".rar", L".7z", L".ps1", L".sys"};
  size_t budget = 2000;
  int scanned = 0;
  for (const auto& root : {win::KnownFolder(FOLDERID_Downloads), win::KnownFolder(FOLDERID_Desktop)}) {
    if (root.empty()) continue;
    Walk(root, 2, budget, [&](const std::wstring& dir, const std::vector<win::DirEntry>& entries) {
      for (const auto& e : entries) {
        if (e.is_dir) continue;
        bool want = std::any_of(std::begin(kExt), std::end(kExt), [&](const wchar_t* x) { return IEndsWith(e.name, x); });
        if (!want) continue;
        std::wstring path = dir + L"\\" + e.name;
        // EXEC-004: where the file came from.
        if (auto zone = win::ReadFileBytes(path + L":Zone.Identifier", 16384)) {
          for (const auto& line : SplitLines(Utf8ToWide(*zone))) {
            if (!IStartsWith(line, L"HostUrl=") && !IStartsWith(line, L"ReferrerUrl=")) continue;
            std::string host = HostOf(line.substr(line.find(L'=') + 1));
            std::string hit = MatchDomain(ctx.domains, host);
            if (hit.empty()) continue;
            Finding f;
            f.rule = "AEGIS-EXEC-004";
            f.dedupe = WideToUtf8(ToLower(path));
            f.Add("file", ctx.Ev(path)).Add("domain", hit).Add("list_family", ctx.domains.at(hit));
            f.Add("sha256", win::Sha256File(path));
            ctx.reporter->Report(std::move(f));
            break;
          }
        }
        // YARA over executables and DLLs only, capped.
        if ((IEndsWith(e.name, L".exe") || IEndsWith(e.name, L".dll")) && e.size < (64u << 20) && scanned < 500) {
          ++scanned;
          YaraScanFileReport(ctx, path, 0, "Downloads/Desktop executable");
        }
      }
      return true;
    });
  }
  ctx.Ran("artifacts.downloads");
}

}  // namespace

void CheckArtifacts(Context& ctx) {
  if (ctx.Skip("artifacts")) return;
  CheckFamilyFiles(ctx);
  CheckExecutionRecords(ctx);
  CheckExecutorFolders(ctx);
  CheckDownloads(ctx);
}

// ---------------- Named objects (DESTINY-001) ----------------

namespace {

std::vector<std::pair<std::wstring, std::wstring>> ListObjectDir(const std::wstring& path) {
  std::vector<std::pair<std::wstring, std::wstring>> out;  // (name, type)
  const auto& api = nt::Get();
  if (!api.OpenDirectoryObject || !api.QueryDirectoryObject) return out;
  UNICODE_STRING us;
  us.Buffer = const_cast<PWSTR>(path.c_str());
  us.Length = static_cast<USHORT>(path.size() * sizeof(wchar_t));
  us.MaximumLength = us.Length;
  OBJECT_ATTRIBUTES oa;
  InitializeObjectAttributes(&oa, &us, 0, nullptr, nullptr);
  HANDLE dir = nullptr;
  if (api.OpenDirectoryObject(&dir, 0x0001 /*DIRECTORY_QUERY*/, &oa) < 0) return out;
  std::vector<BYTE> buf(64 * 1024);
  ULONG ctxv = 0;
  for (int guard = 0; guard < 100000; ++guard) {
    ULONG ret = 0;
    NTSTATUS st = api.QueryDirectoryObject(dir, buf.data(), static_cast<ULONG>(buf.size()), TRUE, guard == 0, &ctxv, &ret);
    if (st < 0 || st == nt::kNoMoreEntries) break;
    auto* info = reinterpret_cast<nt::ObjectDirectoryInformation*>(buf.data());
    if (!info->Name.Buffer) break;
    out.emplace_back(std::wstring(info->Name.Buffer, info->Name.Length / sizeof(wchar_t)),
                     std::wstring(info->TypeName.Buffer, info->TypeName.Length / sizeof(wchar_t)));
  }
  CloseHandle(dir);
  return out;
}

}  // namespace

void SweepNamedObjects(Context& ctx) {
  if (ctx.Skip("named_objects")) return;
  std::vector<std::wstring> dirs = {L"\\BaseNamedObjects"};
  for (const auto& [name, type] : ListObjectDir(L"\\Sessions"))
    if (!name.empty() && iswdigit(name[0])) dirs.push_back(L"\\Sessions\\" + name + L"\\BaseNamedObjects");
  for (const auto& d : dirs) {
    for (const auto& [name, type] : ListObjectDir(d)) {
      std::wstring full = d + L"\\" + name;
      if (!MatchDestinyNamedObject(full)) continue;
      Finding f;
      f.rule = "AEGIS-DESTINY-001";
      f.dedupe = WideToUtf8(full);
      f.Add("object", WideToUtf8(full)).Add("type", WideToUtf8(type));
      ctx.reporter->Report(std::move(f));
    }
  }
}

// ---------------- DNS cache (DESTINY-007) ----------------

namespace {
struct DnsCacheEntry {
  DnsCacheEntry* next;
  PWSTR name;
  USHORT type;
  USHORT data_length;
  ULONG flags;
};
using DnsGetCacheDataTableFn = BOOL(WINAPI*)(DnsCacheEntry**);
using DnsFreeFn = void(WINAPI*)(PVOID, int);
}  // namespace

void CheckDnsCache(Context& ctx) {
  if (ctx.Skip("dns_cache")) return;
  static HMODULE dns = LoadLibraryExW(L"dnsapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!dns) return;
  static auto get = reinterpret_cast<DnsGetCacheDataTableFn>(GetProcAddress(dns, "DnsGetCacheDataTable"));
  static auto free_fn = reinterpret_cast<DnsFreeFn>(GetProcAddress(dns, "DnsFree"));
  if (!get) {
    ctx.Skipped("dns_cache", "DnsGetCacheDataTable unavailable");
    return;
  }
  DnsCacheEntry* head = nullptr;
  if (!get(&head)) return;
  for (DnsCacheEntry* e = head; e;) {
    if (e->name) {
      std::string hit = MatchDomain(ctx.domains, WideToUtf8(e->name));
      if (!hit.empty()) {
        Finding f;
        f.rule = "AEGIS-DESTINY-007";
        f.dedupe = hit;
        f.Add("domain", hit).Add("list_family", ctx.domains.at(hit)).Add("source", "dns_cache");
        ctx.reporter->Report(std::move(f));
      }
    }
    DnsCacheEntry* next = e->next;
    if (free_fn) {
      if (e->name) free_fn(e->name, 0 /*DnsFreeFlat*/);
      free_fn(e, 0);
    }
    e = next;
  }
}

// ---------------- Windows (GEN-010, GEN-011, FORSAKEN-001) ----------------

namespace {
struct Win {
  HWND hwnd;
  DWORD pid;
  std::wstring cls;
  std::wstring title;  // compared locally, never reported
  LONG_PTR ex;
  RECT rc;
};

BOOL CALLBACK CollectWindow(HWND h, LPARAM lp) {
  if (!IsWindowVisible(h) || IsIconic(h)) return TRUE;
  auto* v = reinterpret_cast<std::vector<Win>*>(lp);
  Win w{h, 0, {}, {}, GetWindowLongPtrW(h, GWL_EXSTYLE), {}};
  GetWindowThreadProcessId(h, &w.pid);
  wchar_t buf[256];
  if (GetClassNameW(h, buf, 256)) w.cls = buf;
  if (GetWindowTextW(h, buf, 256)) w.title = buf;
  GetWindowRect(h, &w.rc);
  v->push_back(std::move(w));
  return TRUE;
}

double Overlap(const RECT& a, const RECT& roblox) {
  RECT i;
  if (!IntersectRect(&i, &a, &roblox)) return 0;
  double area = double(roblox.right - roblox.left) * double(roblox.bottom - roblox.top);
  return area > 0 ? double(i.right - i.left) * double(i.bottom - i.top) / area : 0;
}
}  // namespace

void SweepWindows(Context& ctx) {
  if (ctx.Skip("windows")) return;
  std::vector<Win> wins;
  EnumWindows(CollectWindow, reinterpret_cast<LPARAM>(&wins));
  auto procs = win::SnapshotProcessMap();
  auto name_of = [&](DWORD pid) {
    auto it = procs.find(pid);
    return it == procs.end() ? std::wstring() : it->second.name;
  };

  std::vector<const Win*> roblox;
  for (const auto& w : wins)
    if (w.cls == L"WINDOWSCLIENT" && IEquals(name_of(w.pid), kRobloxImage)) roblox.push_back(&w);

  for (const auto& w : wins) {
    std::wstring owner = name_of(w.pid);
    if (w.cls == L"FORSAKEN_EXTERNAL_OVERLAY_HOST" || w.title == L"FORSAKEN External Overlay") {
      Finding f;
      f.rule = "AEGIS-FORSAKEN-001";
      f.pid = w.pid;
      f.Add("class", WideToUtf8(w.cls)).Add("owner", WideToUtf8(owner));
      ctx.reporter->Report(std::move(f));
    }
    if (roblox.empty() || IEquals(owner, kRobloxImage)) continue;

    double best = 0;
    for (const Win* r : roblox) best = std::max(best, Overlap(w.rc, r->rc));
    if (best < 0.5) continue;

    std::wstring path = win::ProcessImagePath(w.pid);
    if (ctx.Allowlisted(owner, path)) continue;
    DWORD affinity = 0;
    GetWindowDisplayAffinity(w.hwnd, &affinity);
    const char* family = w.cls == L"DestinyOverlayWindow" ? "Destiny"
                         : w.cls == L"FORSAKEN_EXTERNAL_OVERLAY_HOST" ? "FORSAKEN" : "";

    auto base = [&](const char* rule) {
      Finding f;
      f.rule = rule;
      f.pid = w.pid;
      f.dedupe = WideToUtf8(w.cls);
      auto signer = win::GetSigner(path);
      f.Add("owner", WideToUtf8(owner))
          .Add("owner_path", path.empty() ? "<inaccessible>" : ctx.Ev(path))
          .Add("owner_signer", signer.signed_ok ? WideToUtf8(signer.signer) : "unsigned")
          .Add("class", WideToUtf8(w.cls))
          .Add("ex_style", Hex32(static_cast<uint32_t>(w.ex)))
          .Add("display_affinity", Hex32(affinity))
          .Add("overlap", std::to_string(static_cast<int>(best * 100)) + "%");
      if (*family) f.Add("known_family_class", family);
      return f;
    };

    const LONG_PTR ex = w.ex;
    bool overlay = (ex & WS_EX_TOPMOST) && (ex & WS_EX_LAYERED) &&
                   (ex & (WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW));
    if (overlay && best >= 0.8) ctx.reporter->Report(base("AEGIS-GEN-010"));
    if (affinity == 0x11 /*WDA_EXCLUDEFROMCAPTURE*/ || affinity == 0x1 /*WDA_MONITOR*/)
      ctx.reporter->Report(base("AEGIS-GEN-011"));
  }
}

// ---------------- Memory scan of flagged script hosts ----------------

void ScanProcessMemory(Context& ctx, uint32_t pid) {
  if (ctx.Skip("memory")) return;
  // Never open Roblox for memory reads (Hyperion, roadmap section 1): check by snapshot name first.
  auto procs = win::SnapshotProcessMap();
  auto it = procs.find(pid);
  if (it == procs.end() || IEquals(it->second.name, kRobloxImage)) return;
  std::wstring name = it->second.name;
  HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!h) return;
  bool script_host = IsScriptHost(name);
  size_t total = 0;
  const size_t kMaxRegion = 64u << 20, kMaxTotal = 512u << 20;
  std::vector<BYTE> buf;
  MEMORY_BASIC_INFORMATION mbi;
  for (BYTE* addr = nullptr; VirtualQueryEx(h, addr, &mbi, sizeof(mbi)) == sizeof(mbi);
       addr = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize) {
    const DWORD exec = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || !(mbi.Protect & exec) || (mbi.Protect & PAGE_GUARD))
      continue;
    if (mbi.RegionSize > kMaxRegion || total + mbi.RegionSize > kMaxTotal) continue;
    buf.resize(mbi.RegionSize);
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, mbi.BaseAddress, buf.data(), buf.size(), &got) || got < 64) continue;
    total += got;
    bool pe = buf[0] == 'M' && buf[1] == 'Z';
    if (pe) {
      LONG lfanew = *reinterpret_cast<LONG*>(&buf[0x3C]);
      pe = lfanew > 0 && static_cast<SIZE_T>(lfanew) + 4 < got && memcmp(&buf[lfanew], "PE\0\0", 4) == 0;
    }
    std::vector<YaraMatch> matches = ctx.yara ? ctx.yara->ScanMemory(buf.data(), got) : std::vector<YaraMatch>{};
    char base[32];
    snprintf(base, sizeof(base), "0x%llx", static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(mbi.BaseAddress)));
    bool destiny = std::any_of(matches.begin(), matches.end(), [](const YaraMatch& m) { return m.rule == "AEGIS_Destiny_Client"; });
    if (script_host && pe && destiny) {
      Finding f;
      f.rule = "AEGIS-DESTINY-010";
      f.pid = pid;
      f.dedupe = base;
      f.Add("process", WideToUtf8(name)).Add("region_base", base).Add("region_size", std::to_string(got));
      f.Add("protect", Hex32(mbi.Protect)).Add("yara_rule", "AEGIS_Destiny_Client");
      f.Add("image_sha256", win::Sha256Bytes(buf.data(), got));
      ctx.reporter->Report(std::move(f));
    }
    for (const auto& m : matches) {
      if (destiny && script_host && pe && m.rule == "AEGIS_Destiny_Client") continue;
      Finding f;
      f.rule = "AEGIS-YARA-002";
      f.pid = pid;
      f.dedupe = std::string(base) + "|" + m.rule;
      f.title = "YARA " + m.rule + " in process memory";
      if (!m.severity.empty()) f.severity = m.severity;
      f.family = m.family;
      f.Add("process", WideToUtf8(name)).Add("yara_rule", m.rule).Add("region_base", base);
      f.Add("region_has_pe_header", pe ? "true" : "false").Add("protect", Hex32(mbi.Protect));
      ctx.reporter->Report(std::move(f));
    }
  }
  CloseHandle(h);
}

}  // namespace aegis::detect
