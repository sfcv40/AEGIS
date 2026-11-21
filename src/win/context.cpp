#include "context.h"

#include <windows.h>
#include <shlobj.h>

#include "../logic/strutil.h"
#include "embedded.h"
#include "winutil.h"
#include "yara_engine.h"

namespace aegis {

void Context::Ran(const std::string& check) {
  std::lock_guard<std::mutex> lock(checks_mu);
  checks_run.push_back(check);
}

void Context::Skipped(const std::string& check, const std::string& why) {
  std::lock_guard<std::mutex> lock(checks_mu);
  checks_skipped.push_back(check + ": " + why);
}

void Context::QueueMemoryScan(uint32_t pid, uint64_t delay_ms) {
  std::lock_guard<std::mutex> lock(scan_mu);
  uint64_t due = GetTickCount64() + delay_ms;
  auto it = pending_mem_scans.find(pid);
  if (it == pending_mem_scans.end() || it->second > due) pending_mem_scans[pid] = due;
}

std::string Context::Ev(const std::wstring& path) const { return WideToUtf8(paths.Normalise(path)); }

bool Context::Allowlisted(const std::wstring& name, const std::wstring& path) const {
  if (path.empty()) return false;
  auto signer = win::GetSigner(path);
  return IsAllowlisted(allowlist, name, paths.Normalise(path), signer.signed_ok ? signer.signer : L"");
}

namespace {

struct Loaded {
  std::string path;  // forward-slash relative path, e.g. "rules/yara/destiny.yar"
  std::string text;
};

std::vector<Loaded> LoadFiles(const std::wstring& data_dir) {
  std::vector<Loaded> out;
  for (size_t i = 0; i < kEmbeddedFileCount; ++i) {
    const auto& f = kEmbeddedFiles[i];
    Loaded l{f.path, std::string(reinterpret_cast<const char*>(f.data), f.size)};
    if (!data_dir.empty()) {
      std::wstring rel = Utf8ToWide(f.path);
      for (auto& c : rel)
        if (c == L'/') c = L'\\';
      if (auto disk = win::ReadFileBytes(data_dir + L"\\" + rel, 64u << 20)) {
        l.text = *disk;
        win::Log("using %s from --data-dir", f.path);
      }
    }
    out.push_back(std::move(l));
  }
  return out;
}

bool StartsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

}  // namespace

bool InitContext(Context& ctx, const std::wstring& data_dir) {
  auto files = LoadFiles(data_dir);
  std::vector<std::pair<std::string, std::string>> yara_sources;
  for (const auto& f : files) {
    if (StartsWith(f.path, "rules/behavior/")) {
      for (const auto& m : ParseBehaviorYaml(f.text)) ctx.catalog.Add(m);
    } else if (StartsWith(f.path, "rules/sigma/")) {
      ctx.catalog.Add(ParseSigmaYaml(f.text));
    } else if (StartsWith(f.path, "rules/yara/")) {
      std::string ns = f.path.substr(11);
      ns = ns.substr(0, ns.find('.'));
      yara_sources.emplace_back(ns, f.text);
    } else if (f.path == "data/handle_allowlist.tsv") {
      ctx.allowlist = ParseAllowlist(f.text);
    } else if (f.path == "data/vulnerable_drivers.tsv") {
      ctx.drivers = ParseDriverList(f.text);
    } else if (f.path == "data/cheat_domains.tsv") {
      ctx.domains = ParseDomainList(f.text);
    }
  }

  // Path tokens, most specific first (PathNormaliser sorts by length).
  wchar_t tmp[MAX_PATH + 1];
  DWORD n = GetTempPathW(MAX_PATH + 1, tmp);
  if (n) ctx.paths.AddPrefix(std::wstring(tmp, n), L"%TEMP%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_LocalAppData), L"%LOCALAPPDATA%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_RoamingAppData), L"%APPDATA%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_Profile), L"%USERPROFILE%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_Public), L"%PUBLIC%");
  ctx.paths.AddPrefix(win::WindowsDir(), L"%SystemRoot%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_ProgramFilesX64), L"%ProgramFiles%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_ProgramFilesX86), L"%ProgramFiles(x86)%");
  ctx.paths.AddPrefix(win::KnownFolder(FOLDERID_ProgramData), L"%ProgramData%");

  static YaraEngine engine;
  if (YaraEngine::Available()) {
    std::string err;
    if (engine.Compile(yara_sources, err)) {
      ctx.yara = &engine;
    } else {
      win::Log("YARA rules failed to compile:\n%s", err.c_str());
    }
  }
  win::Log("loaded %zu rules, %zu allowlist entries, %zu driver hashes, %zu domains, YARA %s",
           ctx.catalog.All().size(), ctx.allowlist.size(), ctx.drivers.size(), ctx.domains.size(),
           ctx.yara ? "ready" : "off");
  return true;
}

namespace detect {

void YaraScanFileReport(Context& ctx, const std::wstring& path, uint32_t pid, const std::string& why) {
  if (!ctx.yara) return;
  for (const auto& m : ctx.yara->ScanFile(path)) {
    Finding f;
    f.rule = "AEGIS-YARA-001";
    f.pid = pid;
    f.dedupe = WideToUtf8(ToLower(path)) + "|" + m.rule;
    f.title = "YARA " + m.rule + (m.description.empty() ? "" : ": " + m.description);
    if (!m.severity.empty()) f.severity = m.severity;
    f.family = m.family;
    f.Add("yara_rule", m.rule).Add("file", ctx.Ev(path)).Add("sha256", win::Sha256File(path)).Add("scanned_because", why);
    ctx.reporter->Report(std::move(f));
  }
}

}  // namespace detect
}  // namespace aegis
