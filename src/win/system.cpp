// A3 (driver history vs. vulnerable/malicious driver list) and A4 (system integrity state).

#include <windows.h>
#include <winevt.h>

#include <set>

#include "../logic/strutil.h"
#include "context.h"
#include "eventlog.h"
#include "nt.h"
#include "winutil.h"

namespace aegis::detect {

// ---------------- A4 ----------------

void CheckIntegrity(Context& ctx) {
  if (ctx.Skip("integrity")) return;
  const auto& api = nt::Get();
  if (api.QuerySystemInformation) {
    nt::CodeIntegrityInformation ci{sizeof(ci), 0};
    if (api.QuerySystemInformation(nt::kSystemCodeIntegrityInformation, &ci, sizeof(ci), nullptr) >= 0) {
      auto report = [&](const char* rule) {
        Finding f;
        f.rule = rule;
        f.Add("code_integrity_options", Hex32(ci.CodeIntegrityOptions));
        ctx.reporter->Report(std::move(f));
      };
      if (!(ci.CodeIntegrityOptions & nt::kCiEnabled)) report("AEGIS-SYS-001");
      if (ci.CodeIntegrityOptions & nt::kCiTestSign) report("AEGIS-SYS-002");
      if (ci.CodeIntegrityOptions & nt::kCiDebugMode) report("AEGIS-SYS-003");
      ctx.Ran("integrity.code_integrity");
    } else {
      ctx.Skipped("integrity.code_integrity", "query failed");
    }
    nt::KernelDebuggerInformation kd{};
    if (api.QuerySystemInformation(nt::kSystemKernelDebuggerInformation, &kd, sizeof(kd), nullptr) >= 0) {
      if (kd.KernelDebuggerEnabled) {
        Finding f;
        f.rule = "AEGIS-SYS-004";
        f.Add("debugger_present", kd.KernelDebuggerNotPresent ? "false" : "true");
        ctx.reporter->Report(std::move(f));
      }
      ctx.Ran("integrity.kernel_debugger");
    }
  }

  auto reg_hit = [&](const char* rule, HKEY root, const wchar_t* key, const wchar_t* value, DWORD bad) {
    auto v = win::RegDword(root, key, value);
    if (v && *v == bad) {
      Finding f;
      f.rule = rule;
      f.dedupe = WideToUtf8(value);
      f.Add("key", WideToUtf8(key)).Add("value", WideToUtf8(value)).Add("data", std::to_string(*v));
      ctx.reporter->Report(std::move(f));
      return true;
    }
    return false;
  };
  reg_hit("AEGIS-SYS-005", HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
          L"VulnerableDriverBlocklistEnable", 0);
  reg_hit("AEGIS-SYS-006", HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
          L"UEFISecureBootEnabled", 0);
  reg_hit("AEGIS-SYS-007", HKEY_LOCAL_MACHINE,
          L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", 1);
  reg_hit("AEGIS-SYS-007", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
          L"DisableAntiSpyware", 1);
  reg_hit("AEGIS-SYS-007", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
          L"DisableRealtimeMonitoring", 1);
  if (!reg_hit("AEGIS-SYS-008", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
               L"TamperProtection", 4))
    reg_hit("AEGIS-SYS-008", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
            L"TamperProtection", 0);
  ctx.Ran("integrity.registry");
}

// ---------------- A3 ----------------

namespace {

struct DriverCheck {
  Context& ctx;
  std::set<std::wstring> hashed;  // lowercase paths already checked

  // Returns true if the file is on the list (and reports it under `rule`).
  bool Check(const std::wstring& path, const char* rule, const std::string& source, const std::string& service) {
    std::wstring key = ToLower(path);
    if (!hashed.insert(key).second) return false;
    std::string sha = win::Sha256File(path, 64ull << 20);
    if (sha.empty()) return false;
    auto it = ctx.drivers.find(sha);
    if (it == ctx.drivers.end()) return false;
    Finding f;
    f.rule = rule;
    f.dedupe = sha;
    f.Add("driver_path", ctx.Ev(path))
        .Add("sha256", sha)
        .Add("list_category", it->second.category)
        .Add("list_name", it->second.name)
        .Add("source", source);
    if (!service.empty()) f.Add("service", service);
    auto signer = win::GetSigner(path);
    f.Add("signer", signer.signed_ok ? WideToUtf8(signer.signer) : "unsigned");
    if (it->second.category == "malicious") f.severity = "critical";
    ctx.reporter->Report(std::move(f));
    return true;
  }
};

std::wstring ServiceImageToPath(const std::wstring& image, const std::wstring& service) {
  if (image.empty()) return win::WindowsDir() + L"\\System32\\drivers\\" + service + L".sys";
  std::wstring p = image;
  if (!p.empty() && p[0] == L'"') {
    auto end = p.find(L'"', 1);
    p = p.substr(1, end == std::wstring::npos ? std::wstring::npos : end - 1);
  }
  return win::ToWin32Path(win::ExpandEnv(p));
}

}  // namespace

void CheckDrivers(Context& ctx) {
  if (ctx.Skip("drivers")) return;
  DriverCheck dc{ctx, {}};

  // Loaded drivers. SystemModuleInformation keeps FullPathName even where kernel
  // addresses are hidden from the caller.
  const auto& api = nt::Get();
  if (api.QuerySystemInformation) {
    std::vector<BYTE> buf(1 << 20);
    ULONG need = 0;
    NTSTATUS st = api.QuerySystemInformation(nt::kSystemModuleInformation, buf.data(), static_cast<ULONG>(buf.size()), &need);
    if (st == nt::kInfoLengthMismatch && need) {
      buf.resize(need + 4096);
      st = api.QuerySystemInformation(nt::kSystemModuleInformation, buf.data(), static_cast<ULONG>(buf.size()), &need);
    }
    if (st >= 0) {
      auto* mods = reinterpret_cast<nt::ProcessModules*>(buf.data());
      for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
        std::string ansi(reinterpret_cast<const char*>(mods->Modules[i].FullPathName));
        std::wstring path = win::ToWin32Path(Utf8ToWide(ansi));
        dc.Check(path, "AEGIS-DRV-001", "loaded", "");
      }
      ctx.Ran("drivers.loaded");
    } else {
      ctx.Skipped("drivers.loaded", "SystemModuleInformation failed");
    }
  }

  // Installed driver services (Type 1 kernel, 2 file system).
  const wchar_t* kServices = L"SYSTEM\\CurrentControlSet\\Services";
  for (const auto& svc : win::RegSubkeys(HKEY_LOCAL_MACHINE, kServices)) {
    std::wstring key = std::wstring(kServices) + L"\\" + svc;
    auto type = win::RegDword(HKEY_LOCAL_MACHINE, key.c_str(), L"Type");
    if (!type || (*type != 1 && *type != 2)) continue;
    std::wstring image = win::RegString(HKEY_LOCAL_MACHINE, key.c_str(), L"ImagePath").value_or(L"");
    std::wstring path = ServiceImageToPath(image, svc);
    std::wstring norm = ctx.paths.Normalise(path);
    if (IsUserWritable(norm)) {
      Finding f;
      f.rule = "AEGIS-DRV-003";
      f.dedupe = WideToUtf8(ToLower(norm));
      f.Add("service", WideToUtf8(svc))
          .Add("driver_path", WideToUtf8(norm))
          .Add("file_present", win::FileExists(path) ? "true" : "false")
          .Add("source", "service_registry");
      ctx.reporter->Report(std::move(f));
    }
    if (win::FileExists(path)) dc.Check(path, "AEGIS-DRV-002", "service_registry", WideToUtf8(svc));
  }
  ctx.Ran("drivers.services");

  // Service install history (System 7045). The record outlives the driver file.
  int days = std::max(ctx.opts.history_days, 90);
  int n = evt::Query(L"System", evt::IdWithinDays(7045, days), 5000, [&](const std::wstring& xml) {
    std::wstring image = EventXmlData(xml, L"ImagePath");
    std::wstring type = EventXmlData(xml, L"ServiceType");
    std::wstring name = EventXmlData(xml, L"ServiceName");
    bool driver = IContains(type, L"kernel") || IContains(type, L"file system") || IEndsWith(Trim(image), L".sys");
    if (!driver) return;
    std::wstring path = ServiceImageToPath(image, name);
    std::wstring norm = ctx.paths.Normalise(path);
    if (IsUserWritable(norm)) {
      Finding f;
      f.rule = "AEGIS-DRV-003";
      f.dedupe = WideToUtf8(ToLower(norm));
      f.Add("service", WideToUtf8(name))
          .Add("driver_path", WideToUtf8(norm))
          .Add("file_present", win::FileExists(path) ? "true" : "false")
          .Add("installed", WideToUtf8(evt::SystemTime(xml)))
          .Add("source", "System/7045");
      ctx.reporter->Report(std::move(f));
    }
    if (win::FileExists(path)) dc.Check(path, "AEGIS-DRV-002", "System/7045", WideToUtf8(name));
  });
  if (n >= 0) ctx.Ran("drivers.install_history");
  else ctx.Skipped("drivers.install_history", "System log not readable");
}

}  // namespace aegis::detect
