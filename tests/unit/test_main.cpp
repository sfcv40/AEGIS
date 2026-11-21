// Unit tests for the portable logic layer. No framework: each CHECK prints on failure
// and the process exits non-zero if any failed.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>

#include "logic/match.h"
#include "logic/privacy.h"
#include "logic/report.h"
#include "logic/rulemeta.h"
#include "logic/strutil.h"

using namespace aegis;

static int g_failed = 0, g_checks = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    ++g_checks;                                                        \
    if (!(cond)) {                                                     \
      ++g_failed;                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                  \
  } while (0)

namespace fs = std::filesystem;

static std::string ReadAll(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

static RuleCatalog LoadCatalog() {
  RuleCatalog cat;
  fs::path root = AEGIS_SOURCE_DIR;
  for (auto& e : fs::directory_iterator(root / "rules" / "behavior"))
    for (auto& m : ParseBehaviorYaml(ReadAll(e.path()))) cat.Add(m);
  for (auto& e : fs::directory_iterator(root / "rules" / "sigma")) cat.Add(ParseSigmaYaml(ReadAll(e.path())));
  return cat;
}

static void TestStrings() {
  CHECK(IEquals(L"RobloxPlayerBeta.EXE", L"robloxplayerbeta.exe"));
  CHECK(BaseName(L"C:\\a\\b\\c.exe") == L"c.exe");
  CHECK(DirName(L"C:\\a\\b\\c.exe") == L"C:\\a\\b");
  CHECK(WideToUtf8(L"caf\u00e9") == "caf\xc3\xa9");
  CHECK(Utf8ToWide("caf\xc3\xa9") == L"caf\u00e9");
  CHECK(Hex32(0x438) == "0x00000438");
}

static void TestRuleMeta() {
  RuleCatalog cat = LoadCatalog();
  const RuleMeta* g2 = cat.Find("AEGIS-GEN-002");
  CHECK(g2 != nullptr);
  if (g2) {
    CHECK(g2->severity == "critical");
    CHECK(g2->confidence == "high");
    CHECK(g2->roadmap.size() == 2 && g2->roadmap[0] == "A1" && g2->roadmap[1] == "B5");
  }
  const RuleMeta* d8 = cat.Find("AEGIS-DESTINY-008");
  CHECK(d8 && d8->correlate.size() == 2 && d8->correlate[0] == "AEGIS-GEN-002");
  const RuleMeta* sg = cat.Find("SIGMA-7f3a2c1e-5b8d-4e0a-9c61-2d4f8a9e1b70");
  CHECK(sg && sg->severity == "high" && sg->title == "Destiny PowerShell Reflective PE Loader");

  // Every rule id the detectors emit must exist in rules/ so the report has metadata.
  std::set<std::string> used;
  std::regex id(R"((AEGIS-[A-Z]+-\d{3}|SIGMA-[0-9a-f-]{36}))");
  for (auto& e : fs::directory_iterator(fs::path(AEGIS_SOURCE_DIR) / "src" / "win")) {
    std::string text = ReadAll(e.path());
    for (std::sregex_iterator it(text.begin(), text.end(), id), end; it != end; ++it) used.insert(it->str());
  }
  CHECK(used.size() > 30);
  for (const auto& u : used) {
    if (!cat.Find(u)) std::fprintf(stderr, "rule used in src/win but missing from rules/: %s\n", u.c_str());
    CHECK(cat.Find(u) != nullptr);
  }
}

static void TestPrivacy() {
  PathNormaliser n;
  n.AddPrefix(L"C:\\Users\\Jack", L"%USERPROFILE%");
  n.AddPrefix(L"C:\\Users\\Jack\\AppData\\Local", L"%LOCALAPPDATA%");
  n.AddPrefix(L"C:\\Users\\Jack\\AppData\\Local\\Temp\\", L"%TEMP%");
  n.AddPrefix(L"C:\\Windows", L"%SystemRoot%");
  CHECK(n.Normalise(L"C:\\Users\\Jack\\Downloads\\x.exe") == L"%USERPROFILE%\\Downloads\\x.exe");
  CHECK(n.Normalise(L"c:\\users\\jack\\appdata\\local\\Temp\\a.dll") == L"%TEMP%\\a.dll");
  CHECK(n.Normalise(L"C:\\Users\\Jack\\AppData\\Local\\Roblox\\x") == L"%LOCALAPPDATA%\\Roblox\\x");
  CHECK(n.Normalise(L"\\\\?\\C:\\Windows\\System32\\ntdll.dll") == L"%SystemRoot%\\System32\\ntdll.dll");
  // Another account's name must not leak either.
  CHECK(n.Normalise(L"D:\\Users\\SomeoneElse\\Desktop\\c.exe") == L"%USERPROFILE%\\Desktop\\c.exe");
  CHECK(n.Normalise(L"C:\\Users\\Public\\x.exe") == L"%PUBLIC%\\x.exe");
  CHECK(n.Normalise(L"C:\\Users\\Jackson\\x") == L"%USERPROFILE%\\x");  // prefix boundary, then catch-all
  CHECK(n.Expand(L"%TEMP%\\a.dll") == L"C:\\Users\\Jack\\AppData\\Local\\Temp\\a.dll");

  CHECK(IsUserWritable(L"%TEMP%\\x.dll"));
  CHECK(IsUserWritable(L"%SystemRoot%\\Temp\\nv_biosmeth_v5.dll"));
  CHECK(!IsUserWritable(L"%SystemRoot%\\System32\\x.dll"));
  CHECK(IsRobloxInstallPath(L"%LOCALAPPDATA%\\Roblox\\Versions\\version-abc\\x.dll"));
  CHECK(IsRobloxInstallPath(L"%LOCALAPPDATA%\\Bloxstrap\\Versions\\version-abc\\x.dll"));
  CHECK(!IsRobloxInstallPath(L"%LOCALAPPDATA%\\Roblox\\x.dll"));
}

static void TestHandles() {
  using namespace access;
  // Destiny and FORSAKEN: 0x438 from an unsigned exe.
  CHECK(ClassifyRobloxHandle(0x438, L"FORSAKEN.exe", false) == HandleRule::kGen001);
  // Fallback 0x410 read-only.
  CHECK(ClassifyRobloxHandle(0x410, L"Destiny.exe", false) == HandleRule::kGen003);
  // In-memory Destiny: powershell, even if someone allowlisted it.
  CHECK(ClassifyRobloxHandle(0x438, L"powershell.exe", true) == HandleRule::kGen002);
  CHECK(ClassifyRobloxHandle(0x410, L"PowerShell.exe", false) == HandleRule::kGen002);
  // Query-only and allowlisted holders are quiet.
  CHECK(ClassifyRobloxHandle(0x1000, L"x.exe", false) == HandleRule::kNone);
  CHECK(ClassifyRobloxHandle(0x1FFFFF, L"csrss.exe", true) == HandleRule::kNone);
  CHECK(ClassifyRobloxHandle(0x1000, L"pwsh.exe", false) == HandleRule::kNone);
  CHECK(DecodeProcessAccess(0x438) == "VM_OPERATION|VM_READ|VM_WRITE|QUERY_INFORMATION");
  CHECK(DecodeProcessAccess(0x1FFFFF) == "PROCESS_ALL_ACCESS");
}

static void TestAllowlist() {
  fs::path root = AEGIS_SOURCE_DIR;
  auto list = ParseAllowlist(ReadAll(root / "data" / "handle_allowlist.tsv"));
  CHECK(list.size() > 10);
  CHECK(IsAllowlisted(list, L"csrss.exe", L"%SystemRoot%\\System32\\csrss.exe", L"Microsoft Windows Publisher"));
  CHECK(!IsAllowlisted(list, L"csrss.exe", L"%TEMP%\\csrss.exe", L"Microsoft Windows"));  // wrong path
  CHECK(!IsAllowlisted(list, L"csrss.exe", L"%SystemRoot%\\System32\\csrss.exe", L""));    // unsigned
  CHECK(IsAllowlisted(list, L"RobloxCrashHandler.exe", L"%LOCALAPPDATA%\\Roblox\\Versions\\v\\RobloxCrashHandler.exe",
                      L"Roblox Corporation"));
  CHECK(IsAllowlisted(list, L"Bloxstrap.exe", L"%LOCALAPPDATA%\\Bloxstrap\\Bloxstrap.exe", L""));
  CHECK(!IsAllowlisted(list, L"Bloxstrap.exe", L"%USERPROFILE%\\Downloads\\Bloxstrap.exe", L""));
  // Script hosts never pass, whatever the signer or path.
  CHECK(!IsAllowlisted(list, L"powershell.exe", L"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       L"Microsoft Windows"));
  CHECK(!IsAllowlisted(list, L"FORSAKEN.exe", L"%USERPROFILE%\\Desktop\\FORSAKEN.exe", L""));
}

static void TestDriverAndDomains() {
  fs::path root = AEGIS_SOURCE_DIR;
  auto drivers = ParseDriverList(ReadAll(root / "data" / "vulnerable_drivers.tsv"));
  CHECK(drivers.size() > 1000);
  auto it = drivers.find("000547560fea0dd4b477eb28bf781ea67bf83c748945ce8923f90fdd14eb7a4b");
  CHECK(it != drivers.end() && it->second.category == "vulnerable driver");

  auto domains = ParseDomainList(ReadAll(root / "data" / "cheat_domains.tsv"));
  CHECK(MatchDomain(domains, "frappe.win") == "frappe.win");
  CHECK(MatchDomain(domains, "API.Frappe.Win.") == "frappe.win");
  CHECK(MatchDomain(domains, "offsets.imtheo.lol") == "offsets.imtheo.lol");
  CHECK(MatchDomain(domains, "notfrappe.win").empty());
  CHECK(MatchDomain(domains, "roblox.com").empty());
}

static void TestCommandLines() {
  // Destiny's hidden worker (launch-memory.ps1 hand-off).
  std::wstring cmd =
      L"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive "
      L"-ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgA";
  CHECK(MatchHiddenEncodedWorker(L"powershell.exe", L"powershell.exe", cmd));
  CHECK(!MatchHiddenEncodedWorker(L"powershell.exe", L"explorer.exe", cmd));  // parent must be PowerShell
  CHECK(!MatchHiddenEncodedWorker(L"powershell.exe", L"powershell.exe", L"powershell.exe -EncodedCommand abc"));
  // Short aliases are matched too.
  CHECK(MatchHiddenEncodedWorker(L"pwsh.exe", L"pwsh.exe", L"pwsh -noni -ep bypass -w hidden -enc abc"));
  CHECK(MatchAdbReverse(L"adb.exe", L"adb reverse tcp:8080 tcp:8080"));
  CHECK(!MatchAdbReverse(L"adb.exe", L"adb devices"));
}

static void TestArtifacts() {
  CHECK(MatchDestinyNamedObject(L"\\Sessions\\1\\BaseNamedObjects\\Destiny_Instance_Shutdown"));
  CHECK(MatchDestinyNamedObject(L"\\Sessions\\1\\BaseNamedObjects\\DestinyMem_0123456789abcdef0123456789abcdef"));
  CHECK(MatchDestinyNamedObject(L"\\BaseNamedObjects\\FRAPPE_NV_BLOCK_FBC"));
  CHECK(MatchDestinyNamedObject(L"\\Sessions\\1\\BaseNamedObjects\\NV_BIOSMETH_STATUS_1234"));
  CHECK(!MatchDestinyNamedObject(L"\\Sessions\\1\\BaseNamedObjects\\DestinyMem_short"));
  CHECK(!MatchDestinyNamedObject(L"\\BaseNamedObjects\\Destiny_Instance_Shutdown"));  // Local\ only

  CHECK(MatchDestinyTempDll(L"nv_biosmeth_v5.dll"));
  CHECK(MatchDestinyTempDll(L"nv_biosmeth_v5_123456.dll"));
  CHECK(MatchDestinyTempDll(L"NV_BIOSMETH.DLL"));
  CHECK(!MatchDestinyTempDll(L"nvapi64.dll"));

  CHECK(LooksLikeExecutorFolder({{L"autoexec", L"workspace", L"bin"}, {L"Executor.exe"}}));
  CHECK(LooksLikeExecutorFolder({{L"AutoExec", L"scripts"}, {L"x.exe", L"readme.txt"}}));
  CHECK(!LooksLikeExecutorFolder({{L"workspace", L"scripts", L"bin"}, {L"x.exe"}}));  // no autoexec
  CHECK(!LooksLikeExecutorFolder({{L"autoexec", L"workspace"}, {L"readme.txt"}}));    // no exe

  auto t1 = ExecutorScriptTokens("loadstring(game:HttpGet(\"https://x\"))()");
  CHECK(ExecutorScriptHit(t1));
  auto t2 = ExecutorScriptTokens("local mt = getrawmetatable(game)\nsetreadonly(mt, false)");
  CHECK(t2.size() == 2 && ExecutorScriptHit(t2));
  auto t3 = ExecutorScriptTokens("local env = getgenv()\nprint('hi')");
  CHECK(t3.size() == 1 && !ExecutorScriptHit(t3));
  auto t4 = ExecutorScriptTokens("game.Players.LocalPlayer.Character.Humanoid.WalkSpeed = 16");
  CHECK(t4.empty());

  CHECK(MatchReflectiveLoaderScript(L"$asm = 'DestinyMemDynamicAsm'"));
  CHECK(MatchReflectiveLoaderScript(
      L"DefinePInvokeMethod VirtualAlloc ... RtlAddFunctionTable ... GetDelegateForFunctionPointer"));
  CHECK(!MatchReflectiveLoaderScript(L"DefinePInvokeMethod VirtualAlloc"));
}

static void TestTime() {
  int64_t t = 0;
  CHECK(ParseIsoUtc(L"1970-01-02T00:00:00.000Z", t) && t == 86400);
  CHECK(ParseIsoUtc(L"2026-11-21T19:06:14.1234567Z", t) && t == 1795287974);
  CHECK(!ParseIsoUtc(L"garbage", t));
  CHECK(IsBackwardClockChange(2000, 1000));
  CHECK(!IsBackwardClockChange(1000, 900));  // under 10 minutes
  CHECK(!IsBackwardClockChange(1000, 5000));
  CHECK(FileTimeToUnix(116444736000000000ULL) == 0);
  std::wstring xml = L"<EventData><Data Name=\"PreviousTime\">2026-01-01T00:00:00Z</Data><Data Name='NewTime'>x</Data>";
  CHECK(EventXmlData(xml, L"PreviousTime") == L"2026-01-01T00:00:00Z");
  CHECK(EventXmlData(xml, L"NewTime") == L"x");
  CHECK(EventXmlData(xml, L"Missing").empty());
}

static void TestReporter() {
  RuleCatalog cat = LoadCatalog();
  std::ostringstream out;
  Reporter r(cat, out);
  Finding a;
  a.rule = "AEGIS-DESTINY-008";
  a.pid = 42;
  a.Add("image", "powershell.exe");
  CHECK(r.Report(a));
  CHECK(!r.Report(a));  // deduplicated
  Finding b;
  b.rule = "AEGIS-GEN-002";
  b.pid = 42;
  b.Add("holder", "powershell.exe").Add("quote", "a\"b\\c");
  CHECK(r.Report(b));
  std::string s = out.str();
  CHECK(s.find("\"rule\":\"AEGIS-GEN-002\"") != std::string::npos);
  CHECK(s.find("\"severity\":\"critical\"") != std::string::npos);
  CHECK(s.find("\"correlated_with\":[\"AEGIS-DESTINY-008\"]") != std::string::npos);
  CHECK(s.find("a\\\"b\\\\c") != std::string::npos);
  CHECK(r.HitCount() == 2);
  CHECK(r.Fired("AEGIS-GEN-002", 42));
  r.Summary("scan", {"a"}, {"b: why"});
  CHECK(out.str().find("\"type\":\"summary\"") != std::string::npos);
}

int main() {
  TestStrings();
  TestRuleMeta();
  TestPrivacy();
  TestHandles();
  TestAllowlist();
  TestDriverAndDomains();
  TestCommandLines();
  TestArtifacts();
  TestTime();
  TestReporter();
  std::printf("%d checks, %d failed\n", g_checks, g_failed);
  return g_failed ? 1 : 0;
}
