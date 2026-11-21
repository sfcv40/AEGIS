# Destiny (frappe.win)

External Roblox cheat with a server-side config, an optional fileless launcher, and
modules that hide its overlay from screen recordings. C++20, MSVC 14.51, no packer.
Source checked: `C:\Destiny` (main.cpp, RobloxMemory.cpp, NvidiaStreamproof.cpp,
nv_biosmeth.cpp, AmdStreamproof.cpp, Visuals.cpp, launch*.ps1).

## Files

| File | SHA-256 | Notes |
|---|---|---|
| Destiny.exe | `a7f0cf1d26800c1141ecd2e1ea6566cb16b583f67007b94ed40a344d8fd38531` | PE32+ console, 561,152 B, built 2026-11-20 18:32 UTC. Exports `DestinyInMemoryEntry`, `DestinySetNvDllBytes` (an EXE with exports is unusual on its own) |
| nv_biosmeth.dll | `6302f5a26b24a6f313f6c466cdbfcf9f96f7b119872531a0baea642965e13006` | Exports fake `NvFBC_*` names plus `NvBiosmeth_GetStatus`. Static CRT |
| DestinyScripts.exe | `22f7606db266ebe8148721d1b5a2fd42586ef2b172baee4d3be1c49f3756aacd` | External Lua 5.4 runner using the same memory reader |
| launch.ps1 / launch-memory.ps1 | n/a | Launchers; `launch-memory.ps1` is the fileless loader |

PE: 6 sections, normal names, entropy .text 6.34 / .rdata 5.76, no TLS, no overlay,
manifest `asInvoker`. Imports are not hidden: `OpenProcess`, `ReadProcessMemory`,
`WriteProcessMemory`, `VirtualAllocEx`, `VirtualProtectEx`, `CreateRemoteThread`,
`SetWindowDisplayAffinity`, `SendInput`, WinHTTP (incl. WebSocket), Winsock server calls
(`bind`, `listen`, `accept`), SCM (`OpenServiceW`, `StartServiceW`), `AdjustTokenPrivileges`.

## How it works

### Roblox access (external)
`RobloxMemory.cpp` opens `RobloxPlayerBeta.exe` with
`PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION` (0x438).
If that fails it falls back to `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` (0x410). It reads the DataModel,
VisualEngine view matrix and players. It writes to memory for the HBE, Rage (fly, speed,
noclip, gravity, desync and others) and lighting features. Offsets are built in and can be
refreshed from `https://offsets.imtheo.lol/Offsets.hpp`. Roblox is found by snapshot by name.
It is launched through `roblox://` or `RobloxPlayerBeta.exe` (Roblox, Bloxstrap and Fishstrap
version folders), after server-supplied FFlags are written to `ClientAppSettings.json`.
Other handle masks: 0x1200 / 0x1000 (priority and EcoQoS tweaks), 0x100001 (terminate).

**No code is injected into Roblox.**

### Features
Triggerbot (MB5 hold by default, humanised delay, jitter and cooldown), aimlock (curves,
overshoot, drift, reaction time), HBE, ESP/chams/HUD, and a "Rage" loop that writes Humanoid,
Primitive, Camera and Lighting fields. Input goes through `SendInput` / `SetCursorPos`.

### Overlay
Class `DestinyOverlayWindow`, title `Destiny Visuals`, ex-style
`WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_NOREDIRECTIONBITMAP`
(0x082800A8), with D3D11 + DirectComposition (`dcomp.dll` and `d3dcompiler_47.dll` loaded at
runtime). With `--streamproof` it calls `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` and
falls back to `WDA_MONITOR`.

### Hiding from recordings ("streamproof")
This is aimed at recordings and stream review, not at an anticheat, but it leaves strong traces:
- **NVIDIA (`--nvidia-streamproof`)**: enables `SeDebugPrivilege`, kills NVIDIA App/Overlay/
  nvcontainer, restarts `NvContainerLocalSystem`, copies `nv_biosmeth.dll` to
  `%SystemRoot%\Temp\nv_biosmeth_v5[_<tick>].dll`, sets an SDDL DACL readable by AppContainers, strips
  `:Zone.Identifier`, then injects it with `OpenProcess(0x43A)` + `VirtualAllocEx` +
  `WriteProcessMemory` + `CreateRemoteThread(LoadLibraryW)`. Unload uses `OpenProcess(0x40A)` +
  remote `FreeLibrary`. Inside NVIDIA processes the DLL IAT-hooks and inline-patches
  `GetWindowDisplayAffinity` / `NtUserGetWindowDisplayAffinity` and patches `_nvspcaps64.dll` / `NvFBC64.dll`.
  Registry: zeroes `HKCU\...\ShadowPlay\NVSPCAPS\{1B1D3DAA-601D-49E5-8508-81736CA28C6D}`, sets
  `DwmEnabled`, `DwmEnabledUser`, `DwmDvrEnabledV1`, `IsShadowPlayEnabled`, and deletes the `ShadowPlay\FTS` keys.
- **AMD (`--amd-streamproof`)**: opens `AMDRSServ.exe`, pattern-scans it, and byte-patches it with
  `VirtualProtectEx` + `WriteProcessMemory` so that ReLive spawns `DuplicateDesktop.exe`. Sets
  `HKCU\SOFTWARE\AMD\DVR\FullRangeOutputOverride = 1`.

The hooks only exist inside the NVIDIA processes. AEGIS calling `GetWindowDisplayAffinity`
from its own process gets the real value.

### IRL mode (`--irl`)
Does not show the local overlay. It sends ESP frames as JSON (`{"type":"frame",...}`) over a
WebSocket to `frappe.win/api/v1/irl/ws` (`X-Destiny-Role: publisher`), or serves
`irl.html` / `irl.js` from a local HTTP server for a phone on USB tethering, LAN or
`adb reverse tcp:<p> tcp:<p>`.

### Fileless launch (`launch-memory.ps1`)
1. Downloads `https://frappe.win/downloads/Destiny.exe` and `nv_biosmeth.dll` with
   `System.Net.WebClient` (headers `Authorization: Bearer`, `X-Destiny-Account`,
   `X-Destiny-Client: DestinyLoader/1.0`), or reads the local build.
2. Defines dynamic assembly `DestinyMemDynamicAsm` / module `DestinyMemDynamicMod` with
   P/Invoke `VirtualAlloc`, `LoadLibraryA`, `GetProcAddress`, `RtlAddFunctionTable`.
3. `VirtualAlloc(SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`, copies headers
   and sections, applies relocations, resolves imports, registers `.pdata`, and calls
   `DestinySetNvDllBytes` then `DestinyInMemoryEntry`.
4. Runs once with `--prep-only` (exit code 10 means it needs elevation, 20 means it is ready), then hands off to a
   **hidden worker**: writes PE + DLL + script + args to a named memory-mapped file
   `DestinyMem_<32 hex>`, signals with event `DestinyEvt_<32 hex>`, and starts
   `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ...`,
   with `-Verb RunAs` when elevation is needed. The worker calls `FreeConsole` and runs
   windowless (F3 to exit).

The result is a hidden, possibly elevated, Microsoft-signed `powershell.exe` that holds a 0x438
handle to Roblox, with no `Destiny.exe` on disk or in Prefetch.

## Indicators

| Kind | Value |
|---|---|
| Domains | `frappe.win`, `offsets.imtheo.lol` |
| URL paths | `/api/v1/client/config`, `/api/v1/irl/ws`, `/api/v1/auth/session`, `/downloads/Destiny.exe`, `/downloads/nv_biosmeth.dll` |
| User agents | `DestinyClient/0.1`, `DestinyClient-IRL/0.1`, `DestinyClient-IRL-Video/0.1`, `DestinyLoader/1.0`, `DestinyScriptBridge/1.0` |
| HTTP headers | `X-Destiny-Account`, `X-Destiny-HWID`, `X-Destiny-Role`, `X-Destiny-Client` |
| Events | `Local\Destiny_Instance_Shutdown`, `DestinyEvt_<guid>`, `Local\NV_BIOSMETH_UNLOAD_<pid>`, `Global\` and `Local\FRAPPE_NV_BLOCK_FBC` |
| Sections | `DestinyMem_<guid>`, `Local\NV_BIOSMETH_STATUS_<pid>` |
| Window | class `DestinyOverlayWindow`, title `Destiny Visuals` |
| Files | `%SystemRoot%\Temp\nv_biosmeth_v5*.dll`, `%TEMP%\nv_biosmeth*.dll`, `<Roblox version>\ClientSettings\ClientAppSettings.json` |
| Env vars | `DESTINY_TOKEN`, `DESTINY_ACCOUNT`, `DESTINY_DOMAIN`, `DESTINY_FLAGS`, `DESTINY_PLACE_ID` |
| HWID inputs | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, `C:` volume serial, computer name (sent as `X-Destiny-HWID`). `GetAdaptersAddresses` is used to find LAN IPs for IRL mode and BCrypt to compute the WebSocket accept key |

## Detection mapping

Rules in `rules/behavior/destiny.yaml`, `rules/behavior/generic-external.yaml`,
`rules/yara/destiny.yar`, `rules/sigma/destiny_*.yml`.

| Behaviour | Rule | Roadmap |
|---|---|---|
| 0x438 / 0x410 handle to Roblox | GEN-001, GEN-003 | A1 |
| Handle held by powershell.exe | GEN-002 | A1, B5 |
| Overlay window, capture-excluded | GEN-010, GEN-011 | B3 |
| `SendInput` aim / trigger | GEN-020 | B4 |
| FFlag write | GEN-030 | A6 |
| Named objects | DESTINY-001 | A6 |
| Temp DLL staging | DESTINY-002 | A6, A7 |
| Injection into NVIDIA / patching AMD | DESTINY-003, 004, 005 | A2 |
| Capture settings registry tamper | DESTINY-006 | A5 |
| DNS to frappe.win / imtheo | DESTINY-007 | A6 |
| Hidden encoded worker | DESTINY-008, sigma `destiny_hidden_worker` | B5 |
| Dynamic assembly | DESTINY-009 | A2 (.NET) |
| Reflective PE in PowerShell | DESTINY-010, YARA `AEGIS_Destiny_Client` | B1 |
| Loader script | sigma `destiny_powershell_reflective_loader`, YARA `AEGIS_Destiny_MemoryLoader_Script` | B6 |
| IRL viewer server / adb reverse | DESTINY-011 | B3 |

The best single correlation for this family is a handle to Roblox from a script host, plus a
hidden `-EncodedCommand` parent chain, plus frappe.win in DNS.
