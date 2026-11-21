# AEGIS Detection Roadmap

AEGIS is a usermode (no kernel driver) Windows anticheat for Roblox. The baseline
scope is OS artifact monitoring: Microsoft Defender logs, execution records
(Prefetch, Amcache, ShimCache, BAM), USB device history and display/HDMI device
history.

This document proposes what to build next. It puts most weight on **fileless and
injected cheats**, since those leave no file for Prefetch or Amcache to record. Every
proposal is ranked by detection value against false-positive (FP) risk and
effort, and the privacy cost of each is called out.

> Status: proposal. Nothing here is implemented yet. The repository currently
> contains only a README, so the baseline above is taken from the project
> description, not from code.

---

## 1. Ground rules that shape every detection

These constraints come before any single detection, because they decide what is
even possible.

1. **Usermode cannot beat a kernel-mode cheat.** A cheat that runs a vulnerable
   driver, a hypervisor, or DMA hardware can hide from anything AEGIS can query.
   AEGIS's realistic strength is therefore twofold. It catches the large
   majority of cheats, which are usermode executors and injectors, directly. It
   catches kernel and hardware cheats **indirectly**, through the traces their
   setup leaves behind (driver load history, disabled protections, unusual PCIe
   devices, cleared logs). Design for evidence and corroboration, not for
   absolute prevention.
2. **Roblox ships its own anticheat (Hyperion/Byfron) inside the client.** This
   matters a great deal:
   - Hyperion obfuscates and encrypts the client's code at runtime and installs
     its own hooks. Naive "unbacked executable memory" or "hooked ntdll" checks
     *inside the Roblox process* will fire on Hyperion itself. Every in-process
     check needs a Hyperion baseline and a clean-machine test corpus before it
     can be trusted.
   - Opening the Roblox process with read or query rights may itself look like
     cheat behaviour to Hyperion, and Hyperion may strip or watch handles.
     **Before building anything in Tier 2, test whether AEGIS's own handle to
     `RobloxPlayerBeta.exe` gets a player flagged or kicked.** Prefer
     `PROCESS_QUERY_LIMITED_INFORMATION` and system-wide data sources that never
     touch the Roblox process.
   - Check Roblox's Terms of Use for third-party software that interacts with
     the client before shipping in-process inspection.
3. **Run as two components.** A privileged service (SYSTEM or elevated) owns
   ETW sessions, raw-volume reads and the handle table. A per-user agent reads
   HKCU artifacts and the desktop/window state. The two talk over an
   authenticated local channel.
4. **Score, don't ban.** Each detection emits an event with a severity and a
   confidence. The server combines them into a verdict, and a human reviews
   anything that is not unambiguous. Many signals below are weak alone and
   strong together (for example, "driver loaded" plus "Defender exclusion added"
   plus "Prefetch disabled").
5. **Two time windows.** *Historical* checks run once at session start and look
   back (logs, execution records). *Live* checks run while Roblox is open (ETW,
   handles, memory, windows). Live checks are where fileless cheats get caught.

---

## 2. Ranking at a glance

Value: how much new cheat coverage it adds. FP: how often it fires on clean
machines. Effort: rough build cost for one experienced developer.

| # | Detection | Value | FP risk | Effort | Privacy cost | Tier |
|---|-----------|-------|---------|--------|--------------|------|
| A1 | Handles to Roblox with write/inject rights | Very high | Medium | Medium | Low | 1 |
| A2 | ETW live process, image-load and thread telemetry | Very high | Medium | High | Medium | 1 |
| A3 | Kernel driver load history and vulnerable driver blocklist | High | Low | Medium | Low | 1 |
| A4 | System integrity state (test signing, DSE, HVCI, debug mode) | High | Low | Low | Low | 1 |
| A5 | Anti-forensics and tamper detection | High | Low–Medium | Medium | Low | 1 |
| A6 | Executor artifacts (folders, scripts, pipes, download origin) | High | Low | Low | Medium | 1 |
| A7 | USN journal analysis | High | Low | Medium | Medium | 1 |
| B1 | Remote memory scan of Roblox (unbacked code, manual-mapped PEs) | Very high | High | High | Low | 2 |
| B2 | Remote thread start-address checks | High | Medium–High | Medium | Low | 2 |
| B3 | Overlay window detection (external ESP) | Medium | Medium | Low | Low | 2 |
| B4 | Injected / synthetic input detection | Medium | Medium | Medium | Low | 2 |
| B5 | Suspicious process lineage | Medium | Medium | Low | Medium | 2 |
| B6 | PowerShell script block and AMSI telemetry | Medium | Low | Low | High | 2 |
| B7 | Persistence (WMI, IFEO, Run keys, tasks, COM hijack) | Medium | Low | Low | Low | 2 |
| B8 | Additional execution records (PCA, SRUM, UserAssist, MUICache) | Medium | Low | Medium | Medium | 2 |
| C1 | DMA and second-PC hardware indicators | Medium | Medium | Medium | Low | 3 |
| C2 | Module and hook integrity of system DLLs | Medium | High | Medium | Low | 3 |
| C3 | Hypervisor presence and timing anomalies | Low–Medium | High | Medium | Low | 3 |
| C4 | Roblox client logs and crash dumps | Low–Medium | Low | Low | Low | 3 |
| S | AEGIS self-protection and attestation | Required | n/a | High | Low | All |

---

## 3. Tier 1: build first

### A1. Handles to Roblox with write or inject rights

**Catches:** every injector and most external executors, regardless of whether
their payload ever touches disk. To write into Roblox, a process must hold a
handle with `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` or `PROCESS_CREATE_THREAD`
(or a thread handle with `THREAD_SET_CONTEXT`).

**How:**
- Call `NtQuerySystemInformation(SystemExtendedHandleInformation)` from the
  privileged service and filter for handles whose object is the Roblox process
  or its threads. This never opens Roblox itself.
- Map each holding PID to its image path, Authenticode signer and parent.
- Sample on a short interval while Roblox runs, because injectors often hold the
  handle only for seconds. Pair with A2 so short-lived handles are still seen.

**FP sources:** `csrss.exe`, `lsass.exe`, some `svchost.exe` instances, AV and EDR
products, GPU driver helpers, overlays (Discord, Steam, NVIDIA, OBS game
capture). Handle this with an allowlist keyed on **signer plus path**, never on
process name alone.

**Signal:** an unsigned or unknown-signer process holding write or thread-creation
rights to Roblox is one of the strongest single signals AEGIS can produce.

### A2. ETW live telemetry

**Catches:** injection and fileless loaders as they happen: process starts with
command lines, DLL loads into Roblox, remote thread creation, and handle opens.

**Important correction:** the `Microsoft-Windows-Threat-Intelligence` provider
(remote `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, APC queueing)
is only available to consumers running as **Protected Process Light with an
anti-malware signature**, which requires an ELAM driver signed through
Microsoft's antimalware programme. That is a kernel component and outside a
usermode design, so plan without it.

Usable providers from an elevated usermode service:

| Provider | What it gives |
|----------|---------------|
| `Microsoft-Windows-Kernel-Process` | Process start/stop with command line and parent, image loads, thread start |
| `Microsoft-Windows-Kernel-Audit-API-Calls` | `OpenProcess` and `OpenThread` with the requested access, `TerminateProcess`, `SetContextThread` style calls, with caller and target PIDs |
| NT Kernel Logger (image load, thread, process) | Image base and size per load, thread creation with start address |
| `Microsoft-Windows-DotNETRuntime` | Assembly loads, which catches C# executors and in-memory `Assembly.Load` |
| `Microsoft-Antimalware-Scan-Interface` | AMSI scan buffers (see B6, privacy-heavy) |
| `Microsoft-Windows-Kernel-File` (optional) | File creates in executor-style folders |

**Rules to start with:**
- A thread created in Roblox by a process other than Roblox itself.
- An `OpenProcess` on Roblox requesting write or thread access from an unsigned
  caller (the live counterpart to A1).
- A DLL load into Roblox from a user-writable path (`%TEMP%`, `%APPDATA%`,
  Downloads) or an unsigned DLL.
- A CLR starting inside a process that normally has none.

**Notes:** use one real-time session per provider group, and expect cheats to try
to stop the session (`ControlTrace` stop or provider disable). Detecting that
your own session died is part of S.

### A3. Kernel driver load history and vulnerable driver blocklist

**Catches:** the setup phase of kernel cheats and "bring your own vulnerable
driver" loaders (kdmapper-style tools), even after the driver is unloaded.

**How:**
- Currently loaded drivers: `EnumDeviceDrivers` or
  `NtQuerySystemInformation(SystemModuleInformation)`, then hash and verify the
  signature of each file on disk.
- History: System log event 7045 (service installed), `Microsoft-Windows-CodeIntegrity/Operational`
  (blocked and audited driver loads), service keys under
  `HKLM\SYSTEM\CurrentControlSet\Services` with `Type = 1`, and the existing
  Amcache driver entries.
- Match hashes against the Microsoft vulnerable driver blocklist and the
  community LOLDrivers list. Ship the list as signed data that the server can
  update.

**FP sources:** legitimate hardware tools (RGB, fan control, overclocking) do
load known-vulnerable drivers. Treat a match as medium severity alone and high
when it appears near a Roblox session or alongside A4/A5 signals.

### A4. System integrity state

**Catches:** machines prepared for kernel cheats. Cheap and very low FP.

Check and report:
- Test signing and Code Integrity options:
  `NtQuerySystemInformation(SystemCodeIntegrityInformation)` (test sign,
  debug mode, unsigned allowed).
- Kernel debugger enabled (`SystemKernelDebuggerInformation`) and BCD flags.
- Memory integrity (HVCI) and VBS state, Secure Boot state.
- Whether the Microsoft vulnerable driver blocklist is turned off.
- Defender real-time protection and tamper protection state.

Most clean gaming PCs have test signing off and no kernel debugger. Turning
these on is rare outside development work, so it is strong context.

### A5. Anti-forensics and tamper detection

**Catches:** players who clean up before a check. Cleaning up is itself evidence,
and this makes the existing artifact checks much harder to defeat.

| Signal | Source |
|--------|--------|
| Security log cleared | Security event 1102 |
| Other logs cleared | System event 104 |
| System time changed backwards | Security 4616, `Kernel-General` event 1 |
| USN journal deleted or recreated | Journal ID changed since last check, `fsutil usn deletejournal` in lineage |
| Prefetch disabled | `EnablePrefetcher` value set to 0 |
| Prefetch folder suspiciously empty | File count and oldest timestamp versus uptime |
| Amcache / ShimCache / BAM gaps | Hive or key last-write time far newer than install age with very few entries |
| Defender exclusions added | Defender event 5007, `Exclusions` keys |
| Defender disabled | Defender events 5001, 5010, 5012 |
| Timestomping | `$STANDARD_INFORMATION` vs `$FILE_NAME` times on flagged files (raw NTFS read) |

**FP sources:** Windows feature updates reset some artifacts, and "PC cleaner"
tools clear logs. Weight by proximity to a Roblox session and combine with
other signals.

### A6. Executor artifacts

**Catches:** most public Roblox executors, which follow a recognisable layout
even when renamed.

- **Folder shape:** an executable next to folders named `workspace`, `autoexec`
  and `scripts`, often with `bin` holding a DLL. Search user-writable locations
  for this shape rather than for product names, so renamed copies still match.
- **Script files:** `.lua`, `.luau` and `.txt` files containing executor-only
  Luau calls (for example `loadstring(game:HttpGet(`, `getgenv`, `hookfunction`,
  `getrawmetatable`, `setreadonly`, `firetouchinterest`). Look only in the
  folders found above, not across the whole disk.
- **Named pipes:** enumerate `\\.\pipe\` while Roblox runs. Executors have used
  named pipes for the UI-to-injected-DLL channel. Match against a maintained
  list and flag pipes owned by unsigned processes.
- **Shared memory and mutexes:** enumerate named sections and mutants in the
  session's `BaseNamedObjects` for known names.
- **Download origin:** read the `Zone.Identifier` alternate data stream on
  executables, DLLs and archives. Its `HostUrl` and `ReferrerUrl` fields record
  where a file came from, which ties a renamed binary back to an executor
  distribution site.
- **Signature feed:** keep hashes, pipe names, mutex names, folder names and
  domains in server-delivered, signed rules. The executor scene changes every
  few months, so this list must be updatable without a client release.

### A7. USN journal analysis

**Catches:** self-deleting loaders and files that were renamed or deleted before
a check. The NTFS change journal records create, rename and delete events with
file names even after the file is gone.

- Read with `FSCTL_QUERY_USN_JOURNAL` and `FSCTL_READ_USN_JOURNAL` from the
  privileged service.
- Look for executables, DLLs and `.sys` files created and deleted within a
  short window, files matching A6 names, and Prefetch `.pf` deletions.
- Combine with A5: a journal that was reset recently is itself a signal.

---

## 4. Tier 2: high value, build after Tier 1 is stable

### B1. Remote memory scan of the Roblox process

**Catches:** manual-mapped DLLs and shellcode, which are the core of fileless
injection. **Blocked on the Hyperion test in section 1.**

- Walk regions with `VirtualQueryEx`. Flag `MEM_PRIVATE` regions with execute
  rights, which normal code never uses.
- Look for PE structure in private memory: `MZ` and `PE\0\0` headers, or
  headerless regions with section-like layouts and import thunks (erased headers
  are common).
- For `MEM_IMAGE` regions, compare in-memory section contents with the file on
  disk (`GetMappedFileName`) to catch module stomping.
- Enumerate modules through both the loader list and a region walk; a mapped
  image missing from the loader list is a strong hit.

**FP risk is high** because of Hyperion's own runtime-decrypted code and JIT-style
regions. Do not ship this until it has been run on a large set of clean
machines and every hit is explained. Start in report-only mode.

### B2. Remote thread start-address checks

For each thread in Roblox, read the start address
(`NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`) and check that it
falls inside a known, signed module. Threads that start in private memory are a
classic injection sign. Needs `THREAD_QUERY_INFORMATION` on Roblox threads, so
the same Hyperion caveat applies. A2's thread events give the same data
without touching Roblox and should be preferred.

### B3. Overlay window detection

**Catches:** external ESP and aim overlays. Enumerate top-level windows that are
topmost, layered and click-through (`WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT`)
and cover the Roblox window. Report the owning process's signer and path.
Allowlist signed overlays (Discord, Steam, NVIDIA, AMD, OBS, Xbox Game Bar).

### B4. Injected and synthetic input

**Catches:** aim assist and macros that use `SendInput`. A low-level mouse and
keyboard hook sees the `LLMHF_INJECTED` and `LLKHF_INJECTED` flags on synthetic
events. Count injected events while Roblox has focus. Also list HID devices
whose vendor and product IDs belong to programmable boards commonly used as
hardware input spoofers (for example Arduino Leonardo or Teensy class devices),
which the existing USB history work can extend.

FP sources: accessibility software, remote desktop, some mouse vendor software.
Collect counts and timing only, **never keystroke content**.

### B5. Suspicious process lineage

Using A2 process events:
- Roblox launched by something other than the Roblox launcher, Explorer or the
  browser protocol handler.
- Roblox spawning `cmd`, `powershell`, `rundll32` or `mshta`.
- Unsigned processes started from `%TEMP%` that then open Roblox (links to A1).
- LOLBin chains that load code in memory (`rundll32` with no DLL path,
  `regsvr32 /i:http`, `mshta http…`).

### B6. PowerShell script block logging and AMSI

**Catches:** loaders that run from PowerShell or another AMSI-aware script host.
Read `Microsoft-Windows-PowerShell/Operational` event 4104 and consume the AMSI
ETW provider. Match against loader patterns (`IEX`, `DownloadString`,
reflective `Assembly.Load`, base64 blobs).

**Privacy cost is high:** script blocks can contain anything a user typed,
including credentials. Match locally and send only the rule ID and a hash,
never the script text, unless the player explicitly agrees to share it.

### B7. Persistence

Cheap checks that catch loaders which survive reboot:
- WMI: `root\subscription` `__EventFilter`, `CommandLineEventConsumer`,
  `ActiveScriptEventConsumer` and `__FilterToConsumerBinding` instances.
- Image File Execution Options `Debugger` or `GlobalFlag` set on
  `RobloxPlayerBeta.exe`.
- Run and RunOnce keys, scheduled tasks and services pointing at user-writable
  paths.
- `AppInit_DLLs`, `AppCertDlls` and per-user COM `InprocServer32` overrides.

### B8. Additional execution records

These complement the existing Prefetch, Amcache, ShimCache and BAM coverage:
- **Program Compatibility Assistant** (Windows 11 22H2 and later):
  `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt` lists executable paths with
  last-run times, including ones run from removable media.
- **SRUM** (`C:\Windows\System32\sru\SRUDB.dat`): per-app runtime and network
  usage over about 30 days, which survives file deletion.
- **UserAssist** and **MUICache**: GUI-launched programs per user.
- **ShellBags**: folders the user browsed, including deleted executor folders.
- **Jump lists and LNK files**: recently opened files and their original paths.

---

## 5. Tier 3: research or situational

### C1. DMA and second-PC hardware indicators

DMA cheats read game memory from a second PC through a PCIe card, so nothing
runs on the gaming PC. Usermode can still look for the hardware:
- Enumerate PCI devices with SetupAPI and flag FPGA-class vendor IDs or devices
  whose IDs do not match their reported class or driver (common with spoofed
  firmware).
- Report Kernel DMA Protection and IOMMU state (`msinfo32` equivalent via
  `SystemDmaGuardPolicyInformation` where available).
- Combine with existing HDMI/display history: capture cards and HDMI splitters
  appear alongside second-PC setups.

FP sources: capture cards and developer FPGA boards are legitimate. This is
context for a human reviewer, not an automatic verdict.

### C2. Module and hook integrity of system DLLs

Compare in-memory `.text` of `ntdll`, `kernel32`, `kernelbase`, `user32` and the
graphics DLLs with the on-disk files, in AEGIS's own processes and in processes
that hold handles to Roblox. Inside Roblox itself, Hyperion's hooks make this
noisy, so only use it there with a Hyperion baseline.

### C3. Hypervisor presence and timing anomalies

Cheat hypervisors can read memory invisibly. The CPUID hypervisor bit is set on
any machine with VBS or Hyper-V, so it is useless alone. Timing-based checks
(`rdtsc` around a trapping instruction) are possible but very noisy. Keep as
research.

### C4. Roblox client logs and crash dumps

Read `%LOCALAPPDATA%\Roblox\logs` and Windows Error Reporting archives for
Roblox crashes. Injection often destabilises the client, and crash reports list
loaded modules at the time of the crash. Low effort, worth adding to the
historical scan.

---

## 6. Self-protection and integrity of AEGIS (required for every tier)

A usermode anticheat will be attacked directly, so plan for this from the start.

- **Sign everything** and verify AEGIS's own binaries at start-up.
- **Harden the process:** restrictive process DACL, mitigation policies
  (`SetProcessMitigationPolicy` for dynamic code, extension point disable,
  image load from remote or low-label paths), and statically link where
  possible so DLL hijacking has nothing to load.
- **Watch for tampering:** periodic hashing of AEGIS's own code sections,
  checks that ETW sessions are still running and receiving events, detection of
  suspended or frozen threads, and debugger checks.
- **Server-side attestation:** the server sends a fresh nonce for each
  heartbeat. AEGIS must return results bound to that nonce, so replaying a
  "clean" report fails. Missing heartbeats during a match are a signal in
  themselves.
- **Protect the channel:** TLS with certificate pinning, and keep detection
  rules and signature lists on the server so they can change without a client
  update.
- **Assume compromise:** treat every client result as evidence to weigh, never
  as proof of innocence.

---

## 7. Privacy and player consent

Players install AEGIS knowingly, and they should know exactly what it collects.

1. **Publish a plain-language data notice** before first run that lists each
   data source, what leaves the machine and how long it is kept. Require an
   explicit opt-in.
2. **Match locally, send minimally.** For most checks, send rule IDs, hashes,
   signer names and timestamps, not raw content. Full file paths can include
   real names (`C:\Users\<name>\…`), so normalise user profile paths.
3. **Never collect** keystroke content, screenshots of non-game windows,
   browser history, documents or script text without separate, specific
   consent.
4. **Scope historical scans.** Execution records and USN data reveal every
   program a player ran. Filter on the device against cheat rules and send only
   matches, plus counts for tamper checks.
5. **Retention and access:** keep evidence only as long as an appeal window
   needs, let players request their data, and log who on the review side
   viewed it.
6. **Legal:** many players are minors, and data rules such as GDPR, UK GDPR and
   COPPA may apply depending on where players live. Get advice before launch.

Privacy cost per detection is listed in the ranking table in section 2.

---

## 8. Suggested order of work

1. **Foundation:** service plus user agent, event schema, local rule engine,
   signed report upload, nonce heartbeat (section 6 basics).
2. **Cheap, low-FP wins:** A4, A3, A5, A6, B7. These mostly read static system
   state and logs and can ship quickly.
3. **The fileless core:** A1 and A2, which catch injection live without touching
   the Roblox process.
4. **Hyperion compatibility test**, then B1 and B2 in report-only mode.
5. **Breadth:** A7, B3 to B6, B8, then Tier 3 as research.
