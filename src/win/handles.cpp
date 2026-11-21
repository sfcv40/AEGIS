// A1: processes holding VM or thread rights to Roblox (AEGIS-GEN-001/002/003), plus
// AEGIS-DESTINY-011 (a holder that also listens on TCP, IRL mode).
//
// How the Roblox process object is identified: AEGIS opens each Roblox instance ONCE
// with PROCESS_QUERY_LIMITED_INFORMATION (the weakest right that yields a handle), finds
// its own handle in the system handle table to learn the kernel object address, then
// closes it. Every later sample matches other processes' handles against that address
// without touching Roblox again. Roadmap section 1: confirm on a test account that this
// one open does not get the player flagged by Hyperion; `--no-roblox-open` disables A1
// and leaves the ETW OpenProcess audit (GEN-041) as the handle signal.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include <algorithm>

#include "../logic/strutil.h"
#include "context.h"
#include "nt.h"
#include "winutil.h"

namespace aegis::detect {

namespace {

std::vector<BYTE> QueryHandleTable() {
  const auto& api = nt::Get();
  std::vector<BYTE> buf(8u << 20);
  for (int i = 0; i < 8; ++i) {
    ULONG need = 0;
    NTSTATUS st = api.QuerySystemInformation(nt::kSystemExtendedHandleInformation, buf.data(),
                                             static_cast<ULONG>(buf.size()), &need);
    if (st == nt::kInfoLengthMismatch || st == nt::kBufferTooSmall) {
      buf.resize(std::max<size_t>(buf.size() * 2, need + (1u << 20)));
      continue;
    }
    if (st < 0) return {};
    return buf;
  }
  return {};
}

std::set<uint16_t> ListeningPorts(DWORD pid) {
  std::set<uint16_t> ports;
  for (ULONG af : {AF_INET, AF_INET6}) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, af, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (!size) continue;
    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, af, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) continue;
    if (af == AF_INET) {
      auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
      for (DWORD i = 0; i < t->dwNumEntries; ++i)
        if (t->table[i].dwOwningPid == pid) ports.insert(ntohs(static_cast<u_short>(t->table[i].dwLocalPort)));
    } else {
      auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
      for (DWORD i = 0; i < t->dwNumEntries; ++i)
        if (t->table[i].dwOwningPid == pid) ports.insert(ntohs(static_cast<u_short>(t->table[i].dwLocalPort)));
    }
  }
  return ports;
}

}  // namespace

std::set<uint32_t> HandleSampler::Holders() const { return holders_; }

bool HandleSampler::Sample() {
  if (ctx_.Skip("handles") || disabled_) return false;
  if (!nt::Get().QuerySystemInformation) return false;

  auto procs = win::SnapshotProcessMap();
  std::vector<DWORD> roblox;
  for (const auto& [pid, p] : procs)
    if (IEquals(p.name, kRobloxImage)) roblox.push_back(pid);

  // Forget instances that exited. (No create-time check: that would mean opening Roblox
  // again on every sample, which is exactly what A1 avoids.)
  targets_.erase(std::remove_if(targets_.begin(), targets_.end(),
                                [&](const Target& t) {
                                  return std::find(roblox.begin(), roblox.end(), t.pid) == roblox.end();
                                }),
                 targets_.end());
  if (roblox.empty()) return true;

  // Resolve new instances: one brief query-limited open each.
  std::vector<std::pair<DWORD, HANDLE>> opened;
  if (ctx_.opts.open_roblox) {
    for (DWORD pid : roblox) {
      bool known = std::any_of(targets_.begin(), targets_.end(), [&](const Target& t) { return t.pid == pid; });
      if (known) continue;
      HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
      if (h) opened.emplace_back(pid, h);
    }
  }

  auto buf = QueryHandleTable();
  if (buf.empty()) {
    for (auto& [pid, h] : opened) CloseHandle(h);
    if (!warned_) win::Log("A1: NtQuerySystemInformation(SystemExtendedHandleInformation) failed");
    warned_ = true;
    return false;
  }
  auto* info = reinterpret_cast<nt::SystemHandleInformationEx*>(buf.data());
  const ULONG_PTR self = GetCurrentProcessId();

  for (auto& [pid, h] : opened) {
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
      const auto& e = info->Handles[i];
      if (e.UniqueProcessId == self && e.HandleValue == reinterpret_cast<ULONG_PTR>(h)) {
        if (!e.Object) {
          if (!warned_)
            win::Log("A1: kernel object addresses are hidden (needs elevation and SeDebugPrivilege); handle checks off");
          disabled_ = true;  // do not keep re-opening Roblox for nothing
          break;
        }
        targets_.push_back({pid, e.Object, e.ObjectTypeIndex});
        break;
      }
    }
    CloseHandle(h);
  }
  if (targets_.empty()) return false;

  for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
    const auto& e = info->Handles[i];
    const DWORD holder = static_cast<DWORD>(e.UniqueProcessId);
    if (holder == self || holder == 0 || holder == 4) continue;
    auto t = std::find_if(targets_.begin(), targets_.end(), [&](const Target& t) {
      return t.object == e.Object && t.type_index == e.ObjectTypeIndex;
    });
    if (t == targets_.end() || holder == t->pid) continue;

    auto pit = procs.find(holder);
    std::wstring name = pit != procs.end() ? pit->second.name : L"";
    std::wstring path = win::ProcessImagePath(holder);
    if (name.empty()) name = BaseName(path);
    bool allow = ctx_.Allowlisted(name, path);
    HandleRule rule = ClassifyRobloxHandle(e.GrantedAccess, name, allow);
    if (rule == HandleRule::kNone) continue;

    auto signer = win::GetSigner(path);
    std::wstring parent;
    if (pit != procs.end()) {
      auto pp = procs.find(pit->second.ppid);
      if (pp != procs.end()) parent = pp->second.name;
    }

    Finding f;
    f.rule = HandleRuleId(rule);
    f.pid = holder;
    f.dedupe = Hex32(e.GrantedAccess);
    f.Add("holder", WideToUtf8(name))
        .Add("holder_path", path.empty() ? "<inaccessible>" : ctx_.Ev(path))
        .Add("signer", signer.signed_ok ? WideToUtf8(signer.signer) : "unsigned")
        .Add("granted_access", Hex32(e.GrantedAccess))
        .Add("granted_rights", DecodeProcessAccess(e.GrantedAccess))
        .Add("roblox_pid", std::to_string(t->pid))
        .Add("parent", WideToUtf8(parent));
    if (auto elev = win::ProcessElevated(holder)) f.Add("holder_elevated", *elev ? "true" : "false");
    if (!ctx_.reporter->Report(std::move(f))) continue;
    holders_.insert(holder);

    // Follow-ups, once per holder.
    if (rule == HandleRule::kGen002) {
      ctx_.QueueMemoryScan(holder, 0);  // DESTINY-010 / YARA-002: reflectively mapped PE in the script host
    } else if (!path.empty() && !signer.signed_ok) {
      YaraScanFileReport(ctx_, path, holder, "unsigned Roblox handle holder");
    }
  }

  // DESTINY-011: a handle holder serving TCP (IRL viewer for a phone).
  for (uint32_t pid : holders_) {
    if (listener_checked_.count(pid)) continue;
    auto ports = ListeningPorts(pid);
    if (ports.empty()) continue;
    listener_checked_.insert(pid);
    std::string list;
    for (auto p : ports) list += (list.empty() ? "" : ",") + std::to_string(p);
    Finding f;
    f.rule = "AEGIS-DESTINY-011";
    f.pid = pid;
    f.Add("listening_tcp_ports", list);
    auto it = procs.find(pid);
    if (it != procs.end()) f.Add("holder", WideToUtf8(it->second.name));
    ctx_.reporter->Report(std::move(f));
  }
  return true;
}

}  // namespace aegis::detect
