// A5: anti-forensics and tamper (TAMP-001..008), AEGIS-DESTINY-006, and the Sigma rules
// from rules/sigma evaluated locally over PowerShell 4104 and Security 4688.
//
// Privacy: script block text and command lines are matched on the device and never
// reported. Findings carry the rule id, event time, a script block id or a hash.

#include <windows.h>
#include <winioctl.h>

#include "../logic/strutil.h"
#include "context.h"
#include "eventlog.h"
#include "winutil.h"
#include "yara_engine.h"

namespace aegis::detect {

namespace {

std::wstring XmlUnescape(std::wstring s) {
  static const std::pair<const wchar_t*, const wchar_t*> kEnt[] = {
      {L"&lt;", L"<"}, {L"&gt;", L">"}, {L"&quot;", L"\""}, {L"&apos;", L"'"}, {L"&#xD;", L"\r"}, {L"&#xA;", L"\n"},
      {L"&amp;", L"&"}};  // &amp; last
  for (auto [from, to] : kEnt) {
    std::wstring f = from;
    for (size_t p = 0; (p = s.find(f, p)) != std::wstring::npos; p += wcslen(to)) s.replace(p, f.size(), to);
  }
  return s;
}

const wchar_t* kDefenderLog = L"Microsoft-Windows-Windows Defender/Operational";

void CheckClearedLogs(Context& ctx) {
  int days = ctx.opts.history_days;
  int count = 0;
  std::wstring latest;
  int n = evt::Query(L"Security", evt::IdWithinDays(1102, days), 1000, [&](const std::wstring& xml) {
    if (latest.empty()) latest = evt::SystemTime(xml);
    ++count;
  });
  if (n < 0) ctx.Skipped("tamper.security_cleared", "Security log not readable (needs elevation)");
  else ctx.Ran("tamper.security_cleared");
  if (count) {
    Finding f;
    f.rule = "AEGIS-TAMP-001";
    f.Add("times_cleared", std::to_string(count)).Add("latest", WideToUtf8(latest)).Add("window_days", std::to_string(days));
    ctx.reporter->Report(std::move(f));
  }

  std::map<std::wstring, std::pair<int, std::wstring>> by_channel;
  n = evt::Query(L"System", evt::IdWithinDays(104, days), 1000, [&](const std::wstring& xml) {
    std::wstring ch = evt::Element(xml, L"Channel", L"<UserData>");
    if (ch.empty()) ch = L"unknown";
    auto& e = by_channel[ch];
    if (e.second.empty()) e.second = evt::SystemTime(xml);
    e.first++;
  });
  if (n >= 0) ctx.Ran("tamper.log_cleared");
  for (const auto& [ch, e] : by_channel) {
    Finding f;
    f.rule = "AEGIS-TAMP-002";
    f.dedupe = WideToUtf8(ch);
    f.Add("channel", WideToUtf8(ch)).Add("times_cleared", std::to_string(e.first)).Add("latest", WideToUtf8(e.second));
    ctx.reporter->Report(std::move(f));
  }
}

void CheckClockChanges(Context& ctx) {
  int hits = 0;
  int n = evt::Query(L"Security", evt::IdWithinDays(4616, ctx.opts.history_days), 2000, [&](const std::wstring& xml) {
    int64_t prev = 0, now = 0;
    if (!ParseIsoUtc(EventXmlData(xml, L"PreviousTime"), prev) || !ParseIsoUtc(EventXmlData(xml, L"NewTime"), now)) return;
    if (!IsBackwardClockChange(prev, now) || hits >= 20) return;
    ++hits;
    Finding f;
    f.rule = "AEGIS-TAMP-003";
    f.dedupe = WideToUtf8(evt::SystemTime(xml));
    f.Add("previous_time", win::UnixToIso(prev))
        .Add("new_time", win::UnixToIso(now))
        .Add("seconds_back", std::to_string(prev - now))
        .Add("process", WideToUtf8(BaseName(EventXmlData(xml, L"ProcessName"))));
    ctx.reporter->Report(std::move(f));
  });
  if (n >= 0) ctx.Ran("tamper.clock");
  else ctx.Skipped("tamper.clock", "Security log not readable");
}

void CheckUsnJournal(Context& ctx) {
  std::wstring drive = win::WindowsDir().substr(0, 2);  // "C:"
  HANDLE vol = CreateFileW((L"\\\\.\\" + drive).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
  if (vol == INVALID_HANDLE_VALUE) {
    ctx.Skipped("tamper.usn_journal", "volume not readable (needs elevation)");
    return;
  }
  USN_JOURNAL_DATA jd{};  // V0 layout; enough for the journal ID
  DWORD got = 0;
  BOOL ok = DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &jd, sizeof(jd), &got, nullptr);
  DWORD err = GetLastError();
  CloseHandle(vol);
  if (!ok) {
    if (err == ERROR_JOURNAL_NOT_ACTIVE || err == ERROR_JOURNAL_DELETE_IN_PROGRESS) {
      Finding f;
      f.rule = "AEGIS-TAMP-004";
      f.Add("volume", WideToUtf8(drive)).Add("state", err == ERROR_JOURNAL_NOT_ACTIVE ? "not_active" : "delete_in_progress");
      ctx.reporter->Report(std::move(f));
    }
    ctx.Ran("tamper.usn_journal");
    return;
  }
  // The journal ID is the FILETIME at which the journal was created.
  int64_t created = FileTimeToUnix(jd.UsnJournalID);
  int64_t now = win::NowUnix();
  auto install = win::RegDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate");
  bool plausible = created > 946684800 && created <= now + 86400;  // after 2000, not in the future
  if (plausible && install && now - created < 14 * 86400 && created - static_cast<int64_t>(*install) > 2 * 86400) {
    Finding f;
    f.rule = "AEGIS-TAMP-004";
    f.Add("volume", WideToUtf8(drive))
        .Add("journal_created", win::UnixToIso(created))
        .Add("windows_installed", win::UnixToIso(*install));
    ctx.reporter->Report(std::move(f));
  }
  ctx.Ran("tamper.usn_journal");
}

void CheckPrefetch(Context& ctx) {
  auto mode = win::RegDword(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
                            L"EnablePrefetcher");
  if (mode && *mode == 0) {
    Finding f;
    f.rule = "AEGIS-TAMP-005";
    f.Add("EnablePrefetcher", "0");
    ctx.reporter->Report(std::move(f));
  }
  std::wstring dir = win::WindowsDir() + L"\\Prefetch";
  if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES) {
    ctx.Skipped("tamper.prefetch_folder", "Prefetch folder not readable");
    return;
  }
  size_t pf = 0;
  for (const auto& e : win::ListDir(dir))
    if (!e.is_dir && IEndsWith(e.name, L".pf")) ++pf;
  uint64_t uptime_h = GetTickCount64() / 3600000ULL;
  if ((!mode || *mode != 0) && pf < 10 && uptime_h >= 2) {
    Finding f;
    f.rule = "AEGIS-TAMP-006";
    f.Add("pf_files", std::to_string(pf)).Add("uptime_hours", std::to_string(uptime_h));
    ctx.reporter->Report(std::move(f));
  }
  ctx.Ran("tamper.prefetch");
}

void ReportExclusion(Context& ctx, const std::wstring& kind, const std::wstring& value, const std::string& source,
                     const std::wstring& when) {
  std::wstring path = win::ExpandEnv(value);
  std::wstring norm = ctx.paths.Normalise(path);
  if (!IsUserWritable(norm)) return;
  Finding f;
  f.rule = "AEGIS-TAMP-007";
  f.dedupe = WideToUtf8(ToLower(norm));
  f.Add("exclusion_type", WideToUtf8(kind)).Add("excluded", WideToUtf8(norm)).Add("source", source);
  if (!when.empty()) f.Add("time", WideToUtf8(when));
  ctx.reporter->Report(std::move(f));
}

void CheckDefender(Context& ctx) {
  int days = ctx.opts.history_days;
  // Exclusions added (5007 records the registry change).
  int n = evt::Query(kDefenderLog, evt::IdWithinDays(5007, days), 2000, [&](const std::wstring& xml) {
    std::wstring nv = XmlUnescape(EventXmlData(xml, L"New Value"));
    auto p = nv.find(L"\\Exclusions\\");
    if (p == std::wstring::npos) return;
    std::wstring rest = nv.substr(p + 12);  // "Paths\C:\... = 0x0"
    auto slash = rest.find(L'\\');
    if (slash == std::wstring::npos) return;
    std::wstring kind = rest.substr(0, slash);
    std::wstring value = rest.substr(slash + 1);
    auto eq = value.rfind(L" = ");
    if (eq != std::wstring::npos) value = value.substr(0, eq);
    if (IEquals(kind, L"Paths") || IEquals(kind, L"Processes"))
      ReportExclusion(ctx, kind, value, "Defender/5007", evt::SystemTime(xml));
  });
  if (n >= 0) ctx.Ran("tamper.defender_events");
  else ctx.Skipped("tamper.defender_events", "Defender log not readable");

  // Current exclusions, where the key is readable (often SYSTEM-only on Windows 11).
  for (const wchar_t* kind : {L"Paths", L"Processes"}) {
    std::wstring key = std::wstring(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\") + kind;
    for (const auto& v : win::RegValueNames(HKEY_LOCAL_MACHINE, key.c_str())) ReportExclusion(ctx, kind, v, "registry", L"");
  }

  // Protection turned off.
  std::map<int, std::pair<int, std::wstring>> off;
  evt::Query(kDefenderLog, evt::IdsWithinDays({5001, 5010, 5012}, days), 500, [&](const std::wstring& xml) {
    std::wstring id = evt::Element(xml, L"EventID");
    int eid = _wtoi(id.c_str());
    auto& e = off[eid];
    if (e.second.empty()) e.second = evt::SystemTime(xml);
    e.first++;
  });
  for (const auto& [eid, e] : off) {
    Finding f;
    f.rule = "AEGIS-TAMP-008";
    f.dedupe = std::to_string(eid);
    f.Add("event_id", std::to_string(eid)).Add("count", std::to_string(e.first)).Add("latest", WideToUtf8(e.second));
    ctx.reporter->Report(std::move(f));
  }
}

void CheckCaptureSettings(Context& ctx) {
  // AEGIS-DESTINY-006. Corroboration only.
  const wchar_t* nv = L"SOFTWARE\\NVIDIA Corporation\\Global\\ShadowPlay\\NVSPCAPS";
  if (auto v = win::RegBinary(HKEY_CURRENT_USER, nv, L"{1B1D3DAA-601D-49E5-8508-81736CA28C6D}")) {
    bool zero = !v->empty();
    for (auto b : *v) zero = zero && b == 0;
    if (zero) {
      Finding f;
      f.rule = "AEGIS-DESTINY-006";
      f.dedupe = "nvspcaps";
      f.Add("key", "HKCU\\SOFTWARE\\NVIDIA Corporation\\Global\\ShadowPlay\\NVSPCAPS")
          .Add("value", "{1B1D3DAA-601D-49E5-8508-81736CA28C6D}")
          .Add("data", "zeroed");
      ctx.reporter->Report(std::move(f));
    }
  }
  if (auto v = win::RegDword(HKEY_CURRENT_USER, L"SOFTWARE\\AMD\\DVR", L"FullRangeOutputOverride"); v && *v == 1) {
    Finding f;
    f.rule = "AEGIS-DESTINY-006";
    f.dedupe = "amd";
    f.confidence = "low";
    f.Add("key", "HKCU\\SOFTWARE\\AMD\\DVR").Add("value", "FullRangeOutputOverride").Add("data", "1");
    ctx.reporter->Report(std::move(f));
  }
  ctx.Ran("tamper.capture_settings");
}

}  // namespace

void CheckTamper(Context& ctx) {
  if (ctx.Skip("tamper")) return;
  CheckClearedLogs(ctx);
  CheckClockChanges(ctx);
  CheckUsnJournal(ctx);
  CheckPrefetch(ctx);
  CheckDefender(ctx);
  CheckCaptureSettings(ctx);
}

void CheckScriptLogs(Context& ctx) {
  if (ctx.Skip("script_logs")) return;
  const std::string kLoaderSigma = "SIGMA-7f3a2c1e-5b8d-4e0a-9c61-2d4f8a9e1b70";
  const std::string kWorkerSigma = "SIGMA-0c9e4b52-8a7d-4f13-b2e6-61a5d3f08c44";

  int n = evt::Query(L"Microsoft-Windows-PowerShell/Operational", evt::IdWithinDays(4104, ctx.opts.history_days), 20000,
                     [&](const std::wstring& xml) {
                       std::wstring text = XmlUnescape(EventXmlData(xml, L"ScriptBlockText"));
                       if (text.empty()) return;
                       std::string block = WideToUtf8(EventXmlData(xml, L"ScriptBlockId"));
                       std::string when = WideToUtf8(evt::SystemTime(xml));
                       if (MatchReflectiveLoaderScript(text)) {
                         Finding f;
                         f.rule = kLoaderSigma;
                         f.dedupe = block;
                         f.Add("source", "PowerShell/4104").Add("script_block_id", block).Add("time", when);
                         f.Add("script_sha256", win::Sha256Bytes(text.data(), text.size() * sizeof(wchar_t)));
                         ctx.reporter->Report(std::move(f));
                       }
                       if (ctx.yara) {
                         std::string utf8 = WideToUtf8(text);
                         for (const auto& m : ctx.yara->ScanMemory(utf8.data(), utf8.size())) {
                           Finding f;
                           f.rule = "AEGIS-YARA-001";
                           f.dedupe = block + "|" + m.rule;
                           f.title = "YARA " + m.rule + " in a PowerShell script block";
                           if (!m.severity.empty()) f.severity = m.severity;
                           f.family = m.family;
                           f.Add("yara_rule", m.rule).Add("source", "PowerShell/4104").Add("script_block_id", block).Add("time", when);
                           ctx.reporter->Report(std::move(f));
                         }
                       }
                     });
  if (n >= 0) ctx.Ran("script_logs.powershell_4104");
  else ctx.Skipped("script_logs.powershell_4104", "PowerShell/Operational not readable");

  // 4688 has command lines only when "Include command line in process creation events" is on.
  n = evt::Query(L"Security", evt::IdWithinDays(4688, ctx.opts.history_days), 50000, [&](const std::wstring& xml) {
    std::wstring cmd = XmlUnescape(EventXmlData(xml, L"CommandLine"));
    if (cmd.empty()) return;
    std::wstring image = BaseName(EventXmlData(xml, L"NewProcessName"));
    std::wstring parent = BaseName(EventXmlData(xml, L"ParentProcessName"));
    if (!MatchHiddenEncodedWorker(image, parent, cmd)) return;
    std::string sha = win::Sha256Bytes(cmd.data(), cmd.size() * sizeof(wchar_t));
    Finding f;
    f.rule = kWorkerSigma;
    f.dedupe = sha;
    f.Add("source", "Security/4688")
        .Add("image", WideToUtf8(image))
        .Add("parent", WideToUtf8(parent))
        .Add("time", WideToUtf8(evt::SystemTime(xml)))
        .Add("command_line_sha256", sha);
    ctx.reporter->Report(std::move(f));
  });
  if (n >= 0) ctx.Ran("script_logs.security_4688");
  else ctx.Skipped("script_logs.security_4688", "Security log not readable");
}

}  // namespace aegis::detect
