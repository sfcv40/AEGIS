# AEGIS

Usermode Windows anticheat for Roblox. This is the first working slice of the
[roadmap](docs/ROADMAP.md): its Tier 1 signals, wired to the detection rules written
against the two test cheats ([Destiny and FORSAKEN](docs/analysis/README.md)).

AEGIS is a single elevated console program, `aegis.exe`, written in C++20. It reports
**rule hits only**, as JSON lines, and never bans. Each hit carries a severity and a
confidence, and is meant to be weighed by a server or a reviewer (roadmap ground rule 4).

## Commands

```
aegis scan                       one-shot check of the PC
aegis monitor [--duration 600]   scan, then live checks until Ctrl+C, --duration or
              [--until-roblox-exits]  Roblox closing
aegis yara <file-or-folder>      run the embedded YARA rules over files
aegis rules                      list every loaded rule
aegis signer <file>              print a file's Authenticode signer (for allowlist tuning)
```

Common options: `--out <file>` writes the JSON lines to a file, `--no-roblox-open` never
opens the Roblox process (see below), `--history-days <n>` sets the event log look-back
(default 30), `--skip a,b` turns off checks, and `--data-dir <repo>` loads `rules/` and
`data/` from disk instead of the copies built into the exe. Exit code: 0 no hits, 1 hits, 2 error.

Run it from an elevated prompt. Without elevation the handle table, ETW, the Security log,
the change journal and Prefetch are unavailable, and the summary line lists what was skipped.

## What it checks

| Roadmap | Check | Rules | When |
|---|---|---|---|
| A1 | Processes holding VM or thread rights to `RobloxPlayerBeta.exe`, from the system handle table; script hosts (PowerShell etc.) are never allowlisted | GEN-001, GEN-002, GEN-003, DESTINY-011 | scan (if Roblox is open), monitor every 2 s |
| A2 | ETW `Kernel-Process`: remote thread into Roblox, DLL loads into Roblox from user-writable paths or unsigned, CLR in Roblox, hidden encoded PowerShell worker, `adb reverse`, modules or threads injected into NVIDIA/AMD capture processes | GEN-040, GEN-042, GEN-043, DESTINY-003, 004, 008, 011 | monitor |
| A2 | ETW `Kernel-Audit-API-Calls`: `OpenProcess`/`OpenThread` on Roblox or capture software with write or thread rights | GEN-041, DESTINY-005 | monitor |
| A2 | ETW `DNS-Client` and `DotNETRuntime`: Destiny domains, Destiny's dynamic assembly | DESTINY-007, DESTINY-009 | monitor |
| A3 | Loaded drivers, installed driver services and 7045 install history, hashed against 2,221 LOLDrivers SHA-256s; driver services from user-writable paths | DRV-001, 002, 003 | scan |
| A4 | Code Integrity off, test signing, CI debug mode, kernel debugger, vulnerable driver blocklist off, Secure Boot off, Defender off or tamper protection off | SYS-001 to 008 | scan |
| A5 | Security/other logs cleared, clock set back, USN journal recreated, Prefetch off or emptied, Defender exclusions on user-writable paths, Defender disabled; ShadowPlay/ReLive settings tampered | TAMP-001 to 008, DESTINY-006 | scan |
| A6 | Executor folder layout, executor-only Luau scripts inside it, files downloaded from cheat domains (Zone.Identifier), Destiny/FORSAKEN files and execution records (Prefetch, BAM), Destiny named objects, DNS cache | EXEC-001, 002, 004, DESTINY-001, 002, 007, 012, FORSAKEN-002, 003 | scan; named objects every 2 s in monitor |
| B3 (cheap) | Overlay windows over Roblox: topmost click-through layered, or excluded from capture | GEN-010, GEN-011, FORSAKEN-001 | scan (if Roblox is open), monitor every 5 s |
| B6 (local) | Sigma rules over PowerShell 4104 script blocks and Security 4688 command lines | SIGMA-7f3a2c1e…, SIGMA-0c9e4b52… | scan |
| YARA | `rules/yara/*.yar` over executor folders, Downloads/Desktop executables, unsigned handle holders, DLLs loaded into Roblox, PowerShell script blocks, and the private executable memory of a flagged script host (never Roblox) | YARA-001, YARA-002, DESTINY-010 | scan and monitor |
| S | AEGIS's ETW session stopped or losing events; process mitigation policies on AEGIS itself | SELF-001 | monitor |

Rule metadata lives in [`rules/`](rules/README.md) and is compiled into the exe, so the
YAML and Sigma files stay the single source of truth. A unit test fails if the code emits
a rule id that is not defined there.

Not yet built from the PR 2 rules: GEN-020/021 (injected input, mouse hooks; B4), GEN-030
(FFlag writer; needs file ETW), the named-pipe sweep (no vetted pipe list yet) and A7 USN
journal record analysis. GEN-040 and GEN-042 are new, so expect allowlist tuning.

## The Hyperion caveat

Roadmap section 1 warns that Roblox's own anticheat may flag a process that opens Roblox.
AEGIS keeps that to the minimum it can:

- **A1 opens each Roblox instance once**, with `PROCESS_QUERY_LIMITED_INFORMATION` only,
  to learn the kernel address of its process object. It then closes the handle and never
  opens Roblox again: later samples match other processes' handles against that address.
- No other check opens Roblox. Windows are read with `EnumWindows`, threads and DLL loads
  come from ETW, and the memory scan refuses to touch Roblox.
- `--no-roblox-open` turns A1 off entirely. ETW's `OpenProcess` audit (GEN-041) still sees
  handle opens live.

**Test this on an alt account before anything else**: run `aegis monitor`, join a game,
and play for a while. If that one query-limited open gets the account flagged, run with
`--no-roblox-open` and rely on GEN-041.

## Privacy

Following roadmap section 7, AEGIS matches on the device and sends only hits:

- Paths are normalised (`C:\Users\<name>\…` becomes `%USERPROFILE%\…`), and a CI test
  fails if the runner's user name appears anywhere in a report.
- Command lines and PowerShell script text are never emitted. Hits carry a SHA-256, the
  matched flags, or a script block id instead.
- Window titles are compared locally and never reported. Executor scripts are read only
  inside folders that already look like an executor, and only the matched call names leave.
- Historical sources (Prefetch, BAM, event logs) are filtered on the device against
  the rules; there is no inventory of what else ran.

## Building

Visual Studio 2022 with CMake and vcpkg (libyara and OpenSSL come from vcpkg):

```
cmake -S . -B build -A x64 ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
ctest --test-dir build -C Release
```

The result is one statically linked `build\Release\aegis.exe` with the rules inside it.
`-DAEGIS_WITH_YARA=OFF` builds without libyara. On Linux, `cmake -S . -B build` builds
and runs only the portable logic tests. MinGW cross builds also work (pass `-DYARA_ROOT`).

CI (`.github/workflows/build.yml`) builds on Windows, runs the unit tests, and runs
[`tests/e2e/smoke.ps1`](tests/e2e/smoke.ps1). That script stands up harmless fixtures (a
renamed `PING.EXE` as a fake Roblox, a PowerShell holding a `0x438` handle to it, a hidden
encoded PowerShell child, a fake executor folder, a KILLYWARE license file) and checks that
the matching rules fire.

## Updating data

- `data/vulnerable_drivers.tsv`: `python -I tools/update_driver_blocklist.py`
- `data/handle_allowlist.tsv`: signer + path entries; check signers with `aegis signer <file>`
- `data/cheat_domains.tsv`: domains for DNS and Zone.Identifier matching

Pass `--data-dir .` to try edits without rebuilding.

## Layout

```
src/logic/   portable matching, rule metadata, privacy normaliser, reporter (unit-tested anywhere)
src/win/     Windows detectors: handles, etw, system (A3/A4), tamper (A5 + Sigma), artifacts (A6, windows, memory)
rules/       behaviour YAML, Sigma, YARA (from PR 2, plus rules/behavior/aegis-core.yaml)
data/        allowlist, driver hashes, cheat domains
tests/       unit tests, YARA sample test, e2e smoke test
docs/        roadmap and cheat analysis
```
