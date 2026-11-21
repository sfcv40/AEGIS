#include "match.h"

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <regex>
#include <set>

#include "strutil.h"

namespace aegis {

std::string DecodeProcessAccess(uint32_t m) {
  if ((m & 0x1FFFFF) == 0x1FFFFF) return "PROCESS_ALL_ACCESS";
  static const std::pair<uint32_t, const char*> kBits[] = {
      {access::kTerminate, "TERMINATE"},          {access::kCreateThread, "CREATE_THREAD"},
      {access::kVmOperation, "VM_OPERATION"},     {access::kVmRead, "VM_READ"},
      {access::kVmWrite, "VM_WRITE"},             {access::kDupHandle, "DUP_HANDLE"},
      {access::kCreateProcess, "CREATE_PROCESS"}, {access::kSetInformation, "SET_INFORMATION"},
      {access::kQueryInformation, "QUERY_INFORMATION"}, {access::kSuspendResume, "SUSPEND_RESUME"},
      {access::kQueryLimited, "QUERY_LIMITED_INFORMATION"}};
  std::string s;
  for (auto& [bit, name] : kBits) {
    if (m & bit) {
      if (!s.empty()) s += "|";
      s += name;
    }
  }
  return s.empty() ? "NONE" : s;
}

bool IsScriptHost(const std::wstring& image_name) {
  // AEGIS-GEN-002 holder_image_any. Never allowlisted, whatever the signer.
  static const wchar_t* kHosts[] = {L"powershell.exe", L"pwsh.exe",     L"powershell_ise.exe", L"wscript.exe",
                                    L"cscript.exe",    L"mshta.exe",    L"rundll32.exe",       L"regsvr32.exe",
                                    L"msbuild.exe",    L"InstallUtil.exe", L"dotnet.exe"};
  for (auto h : kHosts)
    if (IEquals(image_name, h)) return true;
  return false;
}

HandleRule ClassifyRobloxHandle(uint32_t granted, const std::wstring& holder_name, bool holder_allowlisted) {
  if (IsScriptHost(holder_name) && (granted & access::kVmMask)) return HandleRule::kGen002;
  if (holder_allowlisted) return HandleRule::kNone;
  if (granted & access::kInjectMask) return HandleRule::kGen001;
  if (granted & access::kVmRead) return HandleRule::kGen003;
  return HandleRule::kNone;
}

const char* HandleRuleId(HandleRule r) {
  switch (r) {
    case HandleRule::kGen001: return "AEGIS-GEN-001";
    case HandleRule::kGen002: return "AEGIS-GEN-002";
    case HandleRule::kGen003: return "AEGIS-GEN-003";
    default: return "";
  }
}

std::vector<AllowEntry> ParseAllowlist(const std::string& tsv) {
  std::vector<AllowEntry> out;
  for (const auto& raw : SplitLines(tsv)) {
    std::string line = Trim(raw);
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> cols;
    size_t start = 0;
    for (size_t i = 0; i <= line.size(); ++i) {
      if (i == line.size() || line[i] == '\t') {
        cols.push_back(Trim(std::string_view(line).substr(start, i - start)));
        start = i + 1;
      }
    }
    if (cols.size() < 3) continue;
    out.push_back({Utf8ToWide(cols[0]), Utf8ToWide(cols[1]), Utf8ToWide(cols[2])});
  }
  return out;
}

bool IsAllowlisted(const std::vector<AllowEntry>& list, const std::wstring& image_name,
                   const std::wstring& normalised_path, const std::wstring& signer) {
  if (IsScriptHost(image_name)) return false;
  for (const auto& e : list) {
    if (e.name != L"*" && !IEquals(e.name, image_name)) continue;
    if (e.path_prefix != L"*" && !IStartsWith(normalised_path, e.path_prefix)) continue;
    if (e.signer_prefix == L"-") return true;  // unsigned accepted (path + name only)
    if (signer.empty()) continue;
    if (e.signer_prefix == L"*" || IStartsWith(signer, e.signer_prefix)) return true;
  }
  return false;
}

std::unordered_map<std::string, DriverListEntry> ParseDriverList(const std::string& tsv) {
  std::unordered_map<std::string, DriverListEntry> out;
  for (const auto& raw : SplitLines(tsv)) {
    if (raw.empty() || raw[0] == '#') continue;
    auto t1 = raw.find('\t');
    if (t1 == std::string::npos) continue;
    auto t2 = raw.find('\t', t1 + 1);
    std::string hash = raw.substr(0, t1);
    std::transform(hash.begin(), hash.end(), hash.begin(), [](unsigned char c) { return std::tolower(c); });
    DriverListEntry e;
    e.category = raw.substr(t1 + 1, t2 == std::string::npos ? std::string::npos : t2 - t1 - 1);
    if (t2 != std::string::npos) e.name = Trim(std::string_view(raw).substr(t2 + 1));
    if (hash.size() == 64) out[hash] = e;
  }
  return out;
}

std::unordered_map<std::string, std::string> ParseDomainList(const std::string& tsv) {
  std::unordered_map<std::string, std::string> out;
  for (const auto& raw : SplitLines(tsv)) {
    std::string line = Trim(raw);
    if (line.empty() || line[0] == '#') continue;
    auto tab = line.find('\t');
    std::string d = Trim(std::string_view(line).substr(0, tab));
    std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return std::tolower(c); });
    out[d] = tab == std::string::npos ? "generic" : Trim(std::string_view(line).substr(tab + 1));
  }
  return out;
}

std::string MatchDomain(const std::unordered_map<std::string, std::string>& list, std::string host) {
  std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return std::tolower(c); });
  while (!host.empty() && host.back() == '.') host.pop_back();
  for (;;) {
    if (list.count(host)) return host;
    auto dot = host.find('.');
    if (dot == std::string::npos) return {};
    host = host.substr(dot + 1);
  }
}

bool MatchHiddenEncodedWorker(const std::wstring& image_name, const std::wstring& parent_name,
                              const std::wstring& cmd) {
  auto is_ps = [](const std::wstring& n) { return IEquals(n, L"powershell.exe") || IEquals(n, L"pwsh.exe"); };
  if (!is_ps(image_name) || !is_ps(parent_name)) return false;
  static const std::wregex kNeed[] = {
      std::wregex(LR"((^|\s)-(e|ec|enc|encodedcommand)\s)", std::regex::icase),
      std::wregex(LR"((^|\s)-(w|win|windowstyle)\s+hidden)", std::regex::icase),
      std::wregex(LR"((^|\s)-(noni|noninteractive)(\s|$))", std::regex::icase),
      std::wregex(LR"((^|\s)-(ep|ex|exec|executionpolicy)\s+bypass)", std::regex::icase)};
  for (const auto& re : kNeed)
    if (!std::regex_search(cmd, re)) return false;
  return true;
}

bool MatchAdbReverse(const std::wstring& image_name, const std::wstring& cmd) {
  static const std::wregex kRe(LR"(\breverse\s+tcp:\d+\s+tcp:\d+)", std::regex::icase);
  return IEquals(image_name, L"adb.exe") && std::regex_search(cmd, kRe);
}

bool MatchDestinyNamedObject(const std::wstring& full_name) {
  static const std::wregex kRes[] = {
      std::wregex(LR"(^\\Sessions\\\d+\\BaseNamedObjects\\Destiny_Instance_Shutdown$)"),
      std::wregex(LR"(\\BaseNamedObjects\\DestinyMem_[0-9a-f]{32}$)"),
      std::wregex(LR"(\\BaseNamedObjects\\DestinyEvt_[0-9a-f]{32}$)"),
      std::wregex(LR"(\\BaseNamedObjects\\NV_BIOSMETH_(STATUS|UNLOAD)_\d+$)"),
      std::wregex(LR"(\\BaseNamedObjects\\FRAPPE_NV_BLOCK_FBC$)")};
  for (const auto& re : kRes)
    if (std::regex_search(full_name, re)) return true;
  return false;
}

bool MatchDestinyTempDll(const std::wstring& file_name) {
  static const std::wregex kRe(LR"(^nv_biosmeth(_v5)?(_\d+)?\.dll$)", std::regex::icase);
  return std::regex_match(file_name, kRe);
}

bool LooksLikeExecutorFolder(const DirListing& d) {
  bool exe = false, autoexec = false, other = false;
  for (const auto& f : d.files)
    if (IEndsWith(f, L".exe")) exe = true;
  for (const auto& dir : d.dirs) {
    if (IEquals(dir, L"autoexec")) autoexec = true;
    if (IEquals(dir, L"workspace") || IEquals(dir, L"scripts") || IEquals(dir, L"bin")) other = true;
  }
  return exe && autoexec && other;
}

std::vector<std::string> ExecutorScriptTokens(const std::string& script) {
  // Calls that only exist in executor environments, never in Roblox's own Luau.
  static const char* kTokens[] = {"loadstring(game:HttpGet(", "getgenv(",          "hookfunction(",
                                  "getrawmetatable(",         "setreadonly(",       "firetouchinterest(",
                                  "hookmetamethod(",          "getnamecallmethod(", "newcclosure(",
                                  "checkcaller(",             "fireclickdetector(", "getconnections("};
  std::string lower = script;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
  lower.erase(std::remove_if(lower.begin(), lower.end(), [](unsigned char c) { return c == ' ' || c == '\t'; }),
              lower.end());
  std::vector<std::string> found;
  for (auto t : kTokens) {
    std::string lt = t;
    std::transform(lt.begin(), lt.end(), lt.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower.find(lt) != std::string::npos) found.push_back(t);
  }
  return found;
}

bool ExecutorScriptHit(const std::vector<std::string>& tokens) {
  for (const auto& t : tokens)
    if (t == "loadstring(game:HttpGet(") return true;
  return tokens.size() >= 2;
}

bool MatchReflectiveLoaderScript(const std::wstring& text) {
  static const wchar_t* kFamily[] = {L"DestinyMemDynamicAsm", L"DestinyMemNative", L"DestinyInMemoryEntry",
                                     L"DestinySetNvDllBytes"};
  for (auto f : kFamily)
    if (text.find(f) != std::wstring::npos) return true;
  static const wchar_t* kGeneric[] = {L"DefinePInvokeMethod", L"VirtualAlloc", L"RtlAddFunctionTable",
                                      L"GetDelegateForFunctionPointer"};
  for (auto g : kGeneric)
    if (text.find(g) == std::wstring::npos) return false;
  return true;
}

bool IsBackwardClockChange(int64_t previous_unix, int64_t new_unix, int64_t threshold_s) {
  return previous_unix - new_unix > threshold_s;
}

static int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

bool ParseIsoUtc(const std::wstring& s, int64_t& out) {
  if (s.size() < 19) return false;
  auto num = [&](size_t pos, size_t len, int& v) {
    v = 0;
    for (size_t i = pos; i < pos + len; ++i) {
      if (!std::iswdigit(s[i])) return false;
      v = v * 10 + (s[i] - L'0');
    }
    return true;
  };
  int Y, M, D, h, m, sec;
  if (!num(0, 4, Y) || s[4] != L'-' || !num(5, 2, M) || s[7] != L'-' || !num(8, 2, D) || s[10] != L'T' ||
      !num(11, 2, h) || s[13] != L':' || !num(14, 2, m) || s[16] != L':' || !num(17, 2, sec))
    return false;
  if (M < 1 || M > 12 || D < 1 || D > 31) return false;
  out = DaysFromCivil(Y, static_cast<unsigned>(M), static_cast<unsigned>(D)) * 86400 + h * 3600 + m * 60 + sec;
  return true;
}

std::wstring EventXmlData(const std::wstring& xml, const std::wstring& name) {
  for (const wchar_t* q : {L"\"", L"'"}) {
    std::wstring open = L"<Data Name=" + std::wstring(q) + name + q + L">";
    auto p = xml.find(open);
    if (p == std::wstring::npos) continue;
    p += open.size();
    auto e = xml.find(L"</Data>", p);
    if (e == std::wstring::npos) return {};
    return xml.substr(p, e - p);
  }
  return {};
}

}  // namespace aegis
