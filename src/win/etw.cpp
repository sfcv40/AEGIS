// A2: live ETW telemetry from an elevated usermode session.
//
// Providers (roadmap A2 table; Threat-Intelligence is not usable without an ELAM driver):
//   Microsoft-Windows-Kernel-Process       process start/stop, thread start, image load
//   Microsoft-Windows-Kernel-Audit-API-Calls  OpenProcess / OpenThread with desired access
//   Microsoft-Windows-DNS-Client           DNS queries (DESTINY-007)
//   Microsoft-Windows-DotNETRuntime        assembly loads (DESTINY-009)
//
// Rules: GEN-040/041/042/043, DESTINY-003/004/005/007/008/009/011, SELF-001.

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <tdh.h>

#include <atomic>
#include <thread>
#include <unordered_map>

#include "../logic/strutil.h"
#include "context.h"
#include "winutil.h"

namespace aegis::detect {

namespace {

constexpr wchar_t kSessionName[] = L"AEGIS-Live";

// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
const GUID kKernelProcess = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
const GUID kAuditApi = {0xe02a841c, 0x75a3, 0x4fa7, {0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}};
// {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}
const GUID kDnsClient = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
// {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
const GUID kDotNet = {0xe13c0d23, 0xccbc, 0x4e12, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4}};

constexpr ULONGLONG kKwProcess = 0x10, kKwThread = 0x20, kKwImage = 0x40;
constexpr ULONGLONG kKwDotNetLoader = 0x8;

constexpr DWORD kThreadSetContext = 0x0010;
constexpr DWORD kMaximumAllowed = 0x02000000;
constexpr DWORD kGenericAll = 0x10000000;

const wchar_t* kNvidiaCapture[] = {L"nvcontainer.exe", L"NVIDIA Overlay.exe", L"NVIDIA app.exe",
                                   L"NVIDIA Share.exe", L"nvsphelper64.exe",  L"NVDisplay.Container.exe"};
const wchar_t* kAmdCapture[] = {L"AMDRSServ.exe"};

bool InList(const std::wstring& name, const wchar_t* const* list, size_t n) {
  for (size_t i = 0; i < n; ++i)
    if (IEquals(name, list[i])) return true;
  return false;
}
template <size_t N>
bool InList(const std::wstring& name, const wchar_t* const (&list)[N]) {
  return InList(name, list, N);
}

bool IsVendorSigner(const std::wstring& signer, bool allow_microsoft) {
  return IStartsWith(signer, L"NVIDIA") || IStartsWith(signer, L"Advanced Micro Devices") ||
         (allow_microsoft && IStartsWith(signer, L"Microsoft Windows"));
}

// ---- TDH property access ----
bool GetProp(PEVENT_RECORD rec, const wchar_t* name, std::vector<BYTE>& out) {
  PROPERTY_DATA_DESCRIPTOR d{};
  d.PropertyName = reinterpret_cast<ULONGLONG>(name);
  d.ArrayIndex = ULONG_MAX;
  ULONG size = 0;
  if (TdhGetPropertySize(rec, 0, nullptr, 1, &d, &size) != ERROR_SUCCESS || !size) return false;
  out.resize(size);
  return TdhGetProperty(rec, 0, nullptr, 1, &d, size, out.data()) == ERROR_SUCCESS;
}

bool PropUInt(PEVENT_RECORD rec, const wchar_t* name, uint64_t& v) {
  std::vector<BYTE> b;
  if (!GetProp(rec, name, b)) return false;
  switch (b.size()) {
    case 1: v = b[0]; return true;
    case 2: v = *reinterpret_cast<uint16_t*>(b.data()); return true;
    case 4: v = *reinterpret_cast<uint32_t*>(b.data()); return true;
    case 8: v = *reinterpret_cast<uint64_t*>(b.data()); return true;
    default: return false;
  }
}

std::wstring PropStr(PEVENT_RECORD rec, const wchar_t* name) {
  std::vector<BYTE> b;
  if (!GetProp(rec, name, b) || b.size() < 2) return {};
  std::wstring s(reinterpret_cast<wchar_t*>(b.data()), b.size() / sizeof(wchar_t));
  while (!s.empty() && s.back() == L'\0') s.pop_back();
  return s;
}

struct ProcInfo {
  std::wstring name;
  std::wstring path;  // Win32 path, may be empty for processes that predate the session
  DWORD ppid = 0;
  bool started_live = false;       // seen in a ProcessStart during this session
  bool first_thread_seen = false;  // the launcher creates the first thread; skip it
};

}  // namespace

struct EtwMonitor::Impl {
  Context& ctx;
  TRACEHANDLE session = 0;
  TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;
  std::vector<BYTE> props_buf;
  std::thread worker;
  std::atomic<bool> running{false};
  std::atomic<uint64_t> events{0};
  bool restarted = false;

  std::mutex mu;
  std::unordered_map<DWORD, ProcInfo> procs;

  explicit Impl(Context& c) : ctx(c) {}

  EVENT_TRACE_PROPERTIES* Props() {
    size_t size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(kSessionName) + 64;
    props_buf.assign(size, 0);
    auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.data());
    p->Wnode.BufferSize = static_cast<ULONG>(size);
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;  // QPC timestamps
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->BufferSize = 256;  // KB
    p->MinimumBuffers = 32;
    p->MaximumBuffers = 128;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return p;
  }

  ProcInfo Lookup(DWORD pid) {
    std::lock_guard<std::mutex> lock(mu);
    auto it = procs.find(pid);
    return it == procs.end() ? ProcInfo{} : it->second;
  }

  std::wstring PathOf(DWORD pid, const ProcInfo& p) {
    if (!p.path.empty()) return p.path;
    std::wstring path = win::ProcessImagePath(pid);
    if (!path.empty()) {
      std::lock_guard<std::mutex> lock(mu);
      auto it = procs.find(pid);
      if (it != procs.end()) it->second.path = path;
    }
    return path;
  }

  void AddActor(Finding& f, const char* role, DWORD pid, const ProcInfo& p, const std::wstring& path) {
    auto signer = win::GetSigner(path);
    std::string r = role;
    f.Add(r, WideToUtf8(p.name.empty() ? BaseName(path) : p.name))
        .Add(r + "_pid", std::to_string(pid))
        .Add(r + "_path", path.empty() ? "<exited or inaccessible>" : ctx.Ev(path))
        .Add(r + "_signer", signer.signed_ok ? WideToUtf8(signer.signer) : "unsigned");
  }

  // ---- event handlers ----

  void OnProcessStart(DWORD pid, DWORD ppid, const std::wstring& image) {
    ProcInfo info;
    info.path = win::ToWin32Path(image);
    info.name = BaseName(info.path);
    info.ppid = ppid;
    info.started_live = true;
    ProcInfo parent;
    {
      std::lock_guard<std::mutex> lock(mu);
      procs[pid] = info;
      auto it = procs.find(ppid);
      if (it != procs.end()) parent = it->second;
    }

    bool ps = IEquals(info.name, L"powershell.exe") || IEquals(info.name, L"pwsh.exe");
    bool adb = IEquals(info.name, L"adb.exe");
    if (!ps && !adb) return;
    auto cmd = win::ProcessCommandLine(pid);
    if (!cmd) return;

    if (ps && MatchHiddenEncodedWorker(info.name, parent.name, *cmd)) {
      Finding f;
      f.rule = "AEGIS-DESTINY-008";
      f.pid = pid;
      f.Add("image", WideToUtf8(info.name))
          .Add("parent", WideToUtf8(parent.name))
          .Add("parent_pid", std::to_string(ppid))
          .Add("command_line_sha256", win::Sha256Bytes(cmd->data(), cmd->size() * sizeof(wchar_t)))
          .Add("matched", "-EncodedCommand,-WindowStyle Hidden,-NonInteractive,-ExecutionPolicy Bypass");
      if (auto e = win::ProcessElevated(pid)) f.Add("elevated", *e ? "true" : "false");
      ctx.reporter->Report(std::move(f));
      ctx.QueueMemoryScan(pid, 5000);  // the worker maps Destiny.exe a few seconds after start
    }
    if (ps) ctx.sweep_named_objects_now = true;  // DestinyMem_/DestinyEvt_ live only during the hand-off

    if (adb && MatchAdbReverse(info.name, *cmd)) {
      Finding f;
      f.rule = "AEGIS-DESTINY-011";
      f.pid = pid;
      f.Add("image", "adb.exe").Add("matched", "reverse tcp:N tcp:N").Add("parent", WideToUtf8(parent.name));
      ctx.reporter->Report(std::move(f));
    }
  }

  void OnThreadStart(DWORD target, DWORD creator) {
    if (creator == target || creator == 0 || creator == 4) return;
    ProcInfo t;
    {
      std::lock_guard<std::mutex> lock(mu);
      auto it = procs.find(target);
      if (it == procs.end()) return;
      if (it->second.started_live && !it->second.first_thread_seen) {
        it->second.first_thread_seen = true;  // initial thread, created by the launcher
        return;
      }
      t = it->second;
    }
    bool roblox = IEquals(t.name, kRobloxImage);
    bool capture = InList(t.name, kNvidiaCapture) || InList(t.name, kAmdCapture);
    if (!roblox && !capture) return;

    ProcInfo c = Lookup(creator);
    std::wstring cpath = PathOf(creator, c);
    if (c.name.empty()) c.name = BaseName(cpath);

    if (roblox) {
      if (ctx.Allowlisted(c.name, cpath) && !IsScriptHost(c.name)) return;
      Finding f;
      f.rule = "AEGIS-GEN-040";
      f.pid = creator;
      f.dedupe = std::to_string(target);
      AddActor(f, "creator", creator, c, cpath);
      f.Add("roblox_pid", std::to_string(target));
      ctx.reporter->Report(std::move(f));
    } else {
      auto signer = win::GetSigner(cpath);
      if (signer.signed_ok && IsVendorSigner(signer.signer, false)) return;
      Finding f;
      f.rule = "AEGIS-DESTINY-004";
      f.pid = creator;
      f.dedupe = WideToUtf8(t.name);
      AddActor(f, "creator", creator, c, cpath);
      f.Add("target", WideToUtf8(t.name)).Add("target_pid", std::to_string(target));
      ctx.reporter->Report(std::move(f));
    }
  }

  void OnImageLoad(DWORD pid, const std::wstring& image) {
    ProcInfo p = Lookup(pid);
    bool roblox = IEquals(p.name, kRobloxImage);
    bool nvidia = InList(p.name, kNvidiaCapture);
    if (!roblox && !nvidia) return;
    std::wstring path = win::ToWin32Path(image);
    std::wstring norm = ctx.paths.Normalise(path);
    std::wstring dll = BaseName(path);

    if (roblox) {
      if (IEquals(dll, L"clr.dll") || IEquals(dll, L"coreclr.dll")) {
        Finding f;
        f.rule = "AEGIS-GEN-043";
        f.pid = pid;
        f.Add("module", WideToUtf8(dll)).Add("module_path", WideToUtf8(norm));
        ctx.reporter->Report(std::move(f));
      }
      if (IsRobloxInstallPath(norm)) return;
      std::string reason;
      if (IsUserWritable(norm)) reason = "user_writable_path";
      auto signer = win::GetSigner(path);
      if (!signer.signed_ok) reason += reason.empty() ? "unsigned" : ",unsigned";
      if (reason.empty()) return;
      Finding f;
      f.rule = "AEGIS-GEN-042";
      f.pid = pid;
      f.dedupe = WideToUtf8(ToLower(norm));
      f.Add("module", WideToUtf8(dll))
          .Add("module_path", WideToUtf8(norm))
          .Add("module_signer", signer.signed_ok ? WideToUtf8(signer.signer) : "unsigned")
          .Add("reason", reason)
          .Add("module_sha256", win::Sha256File(path));
      ctx.reporter->Report(std::move(f));
      YaraScanFileReport(ctx, path, pid, "DLL loaded into Roblox");
      return;
    }

    // DESTINY-003: non-NVIDIA module from outside Program Files / System32 in a capture process.
    if (IStartsWith(norm, L"%ProgramFiles%\\") || IStartsWith(norm, L"%ProgramFiles(x86)%\\") ||
        IStartsWith(norm, L"%SystemRoot%\\System32\\") || IStartsWith(norm, L"%SystemRoot%\\SysWOW64\\"))
      return;
    auto signer = win::GetSigner(path);
    if (signer.signed_ok && IStartsWith(signer.signer, L"NVIDIA")) return;
    Finding f;
    f.rule = "AEGIS-DESTINY-003";
    f.pid = pid;
    f.dedupe = WideToUtf8(ToLower(norm));
    f.Add("process", WideToUtf8(p.name))
        .Add("module", WideToUtf8(dll))
        .Add("module_path", WideToUtf8(norm))
        .Add("module_signer", signer.signed_ok ? WideToUtf8(signer.signer) : "unsigned")
        .Add("module_sha256", win::Sha256File(path));
    ctx.reporter->Report(std::move(f));
    YaraScanFileReport(ctx, path, pid, "module loaded into NVIDIA capture process");
  }

  void OnOpen(DWORD caller, DWORD target, DWORD desired, uint64_t status, bool thread) {
    if (caller == target || caller == 0 || caller == 4 || caller == GetCurrentProcessId()) return;
    ProcInfo t = Lookup(target);
    bool roblox = IEquals(t.name, kRobloxImage);
    bool capture = !thread && (InList(t.name, kNvidiaCapture) || InList(t.name, kAmdCapture));
    if (!roblox && !capture) return;

    DWORD effective = desired;
    if (desired & (kMaximumAllowed | kGenericAll)) effective |= 0x1FFFFF;

    ProcInfo c = Lookup(caller);
    std::wstring cpath = PathOf(caller, c);
    if (c.name.empty()) c.name = BaseName(cpath);

    if (roblox) {
      bool script_host = IsScriptHost(c.name);
      bool hit;
      if (thread) hit = (effective & kThreadSetContext) != 0;
      else hit = script_host ? (effective & access::kVmMask) != 0 : (effective & access::kInjectMask) != 0;
      if (!hit) return;
      if (!script_host && ctx.Allowlisted(c.name, cpath)) return;
      Finding f;
      f.rule = "AEGIS-GEN-041";
      f.pid = caller;
      f.dedupe = (thread ? "thread|" : "process|") + Hex32(desired);
      AddActor(f, "caller", caller, c, cpath);
      f.Add("object", thread ? "thread" : "process")
          .Add("desired_access", Hex32(desired))
          .Add("desired_rights", thread ? "THREAD_SET_CONTEXT" : DecodeProcessAccess(effective))
          .Add("return_code", Hex32(static_cast<uint32_t>(status)))
          .Add("roblox_pid", std::to_string(target))
          .Add("script_host", script_host ? "true" : "false");
      ctx.reporter->Report(std::move(f));
      if (script_host) ctx.QueueMemoryScan(caller, 0);
      return;
    }

    if (!(effective & (access::kVmWrite | access::kCreateThread))) return;
    auto signer = win::GetSigner(cpath);
    if (signer.signed_ok && IsVendorSigner(signer.signer, true)) return;
    Finding f;
    f.rule = "AEGIS-DESTINY-005";
    f.pid = caller;
    f.dedupe = WideToUtf8(t.name) + "|" + Hex32(desired);
    AddActor(f, "caller", caller, c, cpath);
    f.Add("target", WideToUtf8(t.name))
        .Add("target_pid", std::to_string(target))
        .Add("desired_access", Hex32(desired))
        .Add("desired_rights", DecodeProcessAccess(effective));
    ctx.reporter->Report(std::move(f));
  }

  void OnDns(DWORD pid, const std::wstring& query) {
    std::string hit = MatchDomain(ctx.domains, WideToUtf8(query));
    if (hit.empty()) return;
    ProcInfo p = Lookup(pid);
    Finding f;
    f.rule = "AEGIS-DESTINY-007";
    f.pid = pid;
    f.dedupe = hit;
    f.Add("domain", hit).Add("list_family", ctx.domains.at(hit)).Add("source", "etw.dns_client");
    f.Add("process", WideToUtf8(p.name));
    ctx.reporter->Report(std::move(f));
  }

  void OnAssembly(DWORD pid, const std::wstring& name) {
    if (name.find(L"DestinyMemDynamicAsm") == std::wstring::npos) return;
    ProcInfo p = Lookup(pid);
    Finding f;
    f.rule = "AEGIS-DESTINY-009";
    f.pid = pid;
    f.Add("process", WideToUtf8(p.name)).Add("assembly", "DestinyMemDynamicAsm");
    ctx.reporter->Report(std::move(f));
    ctx.QueueMemoryScan(pid, 3000);
  }

  void Dispatch(PEVENT_RECORD rec) {
    events++;
    const GUID& g = rec->EventHeader.ProviderId;
    const USHORT id = rec->EventHeader.EventDescriptor.Id;
    const DWORD hdr_pid = rec->EventHeader.ProcessId;
    uint64_t a = 0, b = 0, c = 0;
    if (IsEqualGUID(g, kKernelProcess)) {
      switch (id) {
        case 1:  // ProcessStart
          if (PropUInt(rec, L"ProcessID", a) && PropUInt(rec, L"ParentProcessID", b))
            OnProcessStart(static_cast<DWORD>(a), static_cast<DWORD>(b), PropStr(rec, L"ImageName"));
          break;
        case 2:  // ProcessStop
          if (PropUInt(rec, L"ProcessID", a)) {
            std::lock_guard<std::mutex> lock(mu);
            procs.erase(static_cast<DWORD>(a));
          }
          break;
        case 3:  // ThreadStart, logged in the creator's context
          if (PropUInt(rec, L"ProcessID", a)) OnThreadStart(static_cast<DWORD>(a), hdr_pid);
          break;
        case 5:  // ImageLoad
          if (PropUInt(rec, L"ProcessID", a)) OnImageLoad(static_cast<DWORD>(a), PropStr(rec, L"ImageName"));
          break;
      }
    } else if (IsEqualGUID(g, kAuditApi)) {
      if (id == 5 || id == 6) {  // OpenProcess, OpenThread
        if (PropUInt(rec, L"TargetProcessId", a) && PropUInt(rec, L"DesiredAccess", b)) {
          PropUInt(rec, L"ReturnCode", c);
          OnOpen(hdr_pid, static_cast<DWORD>(a), static_cast<DWORD>(b), c, id == 6);
        }
      }
    } else if (IsEqualGUID(g, kDnsClient)) {
      if (id == 3006 || id == 3008) OnDns(hdr_pid, PropStr(rec, L"QueryName"));
    } else if (IsEqualGUID(g, kDotNet)) {
      if (id == 154) OnAssembly(hdr_pid, PropStr(rec, L"FullyQualifiedAssemblyName"));
    }
  }

  static void WINAPI Callback(PEVENT_RECORD rec) {
    auto* self = static_cast<Impl*>(rec->UserContext);
    if (self) self->Dispatch(rec);
  }

  bool Start() {
    // Seed the process table so events about processes started before AEGIS resolve.
    {
      std::lock_guard<std::mutex> lock(mu);
      procs.clear();
      for (const auto& p : win::SnapshotProcesses()) procs[p.pid] = ProcInfo{p.name, L"", p.ppid, false, false};
    }

    auto* props = Props();
    ULONG st = StartTraceW(&session, kSessionName, props);
    if (st == ERROR_ALREADY_EXISTS) {
      // A stale session from a crashed run, or someone squatting on the name.
      ControlTraceW(0, kSessionName, Props(), EVENT_TRACE_CONTROL_STOP);
      props = Props();
      st = StartTraceW(&session, kSessionName, props);
    }
    if (st != ERROR_SUCCESS) {
      win::Log("ETW: StartTrace failed (%lu). Run elevated.", st);
      return false;
    }

    struct P {
      const GUID* guid;
      UCHAR level;
      ULONGLONG keywords;
      const char* name;
    } providers[] = {
        {&kKernelProcess, TRACE_LEVEL_INFORMATION, kKwProcess | kKwThread | kKwImage, "etw.kernel_process"},
        {&kAuditApi, TRACE_LEVEL_VERBOSE, ~0ULL, "etw.audit_api"},
        {&kDnsClient, TRACE_LEVEL_VERBOSE, ~0ULL, "etw.dns_client"},
        {&kDotNet, TRACE_LEVEL_INFORMATION, kKwDotNetLoader, "etw.dotnet"},
    };
    int enabled = 0;
    for (const auto& p : providers) {
      ULONG e = EnableTraceEx2(session, p.guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, p.level, p.keywords, 0, 0, nullptr);
      if (e == ERROR_SUCCESS) {
        ctx.Ran(p.name);
        ++enabled;
      } else {
        ctx.Skipped(p.name, "EnableTraceEx2 error " + std::to_string(e));
      }
    }
    if (!enabled) {
      Stop();
      return false;
    }

    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName = const_cast<LPWSTR>(kSessionName);
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = &Impl::Callback;
    lf.Context = this;
    consumer = OpenTraceW(&lf);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
      win::Log("ETW: OpenTrace failed (%lu)", GetLastError());
      Stop();
      return false;
    }
    running = true;
    worker = std::thread([this] {
      ProcessTrace(&consumer, 1, nullptr, nullptr);
      running = false;
    });
    return true;
  }

  void Stop() {
    if (session) {
      ControlTraceW(session, nullptr, Props(), EVENT_TRACE_CONTROL_STOP);
      session = 0;
    }
    if (consumer != INVALID_PROCESSTRACE_HANDLE) {
      CloseTrace(consumer);
      consumer = INVALID_PROCESSTRACE_HANDLE;
    }
    if (worker.joinable()) worker.join();
  }

  void CheckHealth() {
    if (!session) return;
    auto* props = Props();
    ULONG st = ControlTraceW(session, nullptr, props, EVENT_TRACE_CONTROL_QUERY);
    std::string problem;
    if (st != ERROR_SUCCESS) problem = "session_query_failed:" + std::to_string(st);
    else if (!running) problem = "consumer_stopped";
    if (st == ERROR_SUCCESS && props->EventsLost > 0) {
      Finding f;
      f.rule = "AEGIS-SELF-001";
      f.dedupe = "events_lost";
      f.Add("problem", "events_lost").Add("events_lost", std::to_string(props->EventsLost));
      ctx.reporter->Report(std::move(f));
    }
    if (problem.empty()) return;
    Finding f;
    f.rule = "AEGIS-SELF-001";
    f.dedupe = problem;
    f.Add("problem", problem).Add("events_before", std::to_string(events.load()));
    ctx.reporter->Report(std::move(f));
    if (!restarted && !running) {  // try once to come back; the finding above already records the kill
      restarted = true;
      session = 0;
      if (consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer);
      consumer = INVALID_PROCESSTRACE_HANDLE;
      if (worker.joinable()) worker.join();
      if (Start()) win::Log("ETW: session restarted after it was stopped");
    }
  }
};

EtwMonitor::EtwMonitor(Context& ctx) : impl_(std::make_unique<Impl>(ctx)) {}
EtwMonitor::~EtwMonitor() { Stop(); }
bool EtwMonitor::Start() { return impl_->Start(); }
void EtwMonitor::Stop() { impl_->Stop(); }
void EtwMonitor::CheckHealth() { impl_->CheckHealth(); }

}  // namespace aegis::detect
