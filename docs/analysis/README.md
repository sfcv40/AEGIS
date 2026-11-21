# Cheat analysis: Destiny and FORSAKEN

Two cheats built by the AEGIS author as test targets. Both were analysed statically
(PE headers, imports, strings, disassembly of call sites) and then checked against
their source. Neither binary was run.

- [destiny.md](destiny.md): Destiny (frappe.win), the more evasive of the two
- [forsaken.md](forsaken.md): FORSAKEN / KILLYWARE
- Rules: [`rules/`](../../rules/README.md)

## Summary

| | Destiny | FORSAKEN |
|---|---|---|
| Type | External, usermode, CLI | External, usermode, ImGui GUI |
| Packed / obfuscated | No (entropy 6.3 .text, plain strings) | No (entropy 6.4 .text, plain strings) |
| Touches Roblox via | `OpenProcess(0x438)` + `ReadProcessMemory` / `WriteProcessMemory` | Same, `OpenProcess(0x438)`, fallback `0x410` |
| Injects into Roblox | **No** | No |
| Injects into anything | Yes, `nv_biosmeth.dll` into NVIDIA ShadowPlay processes (LoadLibraryW remote thread); byte-patches `AMDRSServ.exe` | No |
| Overlay | DirectComposition window, `WDA_EXCLUDEFROMCAPTURE`, or none at all in IRL mode (draws on a phone) | Topmost layered D3D11 window, capture exclusion optional |
| Input | `SendInput` (humanised timing) | `SendInput` + `WH_MOUSE_LL` hook |
| Fileless mode | **Yes**, PowerShell reflective loader streams the PE from frappe.win into a hidden PowerShell | No |
| Network | frappe.win (auth, config, downloads, IRL relay), offsets.imtheo.lol, local HTTP/WebSocket server | None |
| Disk artifacts | Few: `%SystemRoot%\Temp\nv_biosmeth_v5*.dll` (transient), `ClientAppSettings.json` | `%LOCALAPPDATA%\KILLYWARE\license.dat`, `config_last.bin` |
| Kernel component | None | None. The "Kernel IOCTL / Physical CR3 / Ring 0" options are UI labels only: there is no driver, `DeviceIoControl` or service code |

## Which AEGIS signals catch them

Roadmap IDs refer to `docs/ROADMAP.md` (PR #1).

| Signal | FORSAKEN | Destiny (exe on disk) | Destiny (in-memory) | Destiny (IRL mode) |
|---|---|---|---|---|
| Baseline: Prefetch / Amcache / BAM | Caught | Caught | **Missed**: only `powershell.exe` | Depends on launch mode |
| A1 handle to Roblox with write rights | Caught | Caught | **Missed if** the allowlist trusts Microsoft-signed binaries. Fixed by GEN-002 | Caught |
| A2 DLL load / remote thread in Roblox | Silent (not used) | Silent (not used) | Silent | Silent |
| A2 extended to capture software (DESTINY-003/004/005) | n/a | Caught when streamproof is on | Caught when streamproof is on | Caught when streamproof is on |
| A2 .NET dynamic assembly (DESTINY-009) | n/a | n/a | Caught | Depends on launch mode |
| A5 tamper (DESTINY-006) | n/a | Corroborates | Corroborates | Corroborates |
| A6 named objects / files / DNS | Caught (files) | Caught (events, DNS) | Caught (events, DNS) | Caught (DNS) |
| A7 USN journal | Caught | Caught | Partial (only the Temp DLL) | Partial |
| B1 memory scan of script host (DESTINY-010) | n/a | n/a | Caught | Depends |
| B3 overlay window | Caught | Caught (affinity read from AEGIS is truthful) | Caught | **Missed**: no local window. DESTINY-011 covers it |
| B3 screenshot evidence | Caught unless stream-proof on | **Missed** (capture-excluded; recorder stack patched) | **Missed** | **Missed** |
| B4 injected input | Caught | Caught (flag is set; humanisation only beats statistics) | Caught | Caught |
| B5 lineage (DESTINY-008) | n/a | Weak | Caught | Depends |
| B6 PowerShell script block / AMSI | n/a | `launch.ps1` only | Caught | Depends |
| Static YARA on disk | Caught | Caught | **Missed** on disk, caught in memory | Depends |

## Where Destiny gets past AEGIS, and the fix for each

1. **No injection into Roblox.** Every "inside Roblox" check in A2 and B2 stays quiet
   because Destiny reads and writes Roblox from outside. *Fix:* A1 (the handle) is the
   anchor signal for externals. Ship A1 before the in-Roblox checks.
2. **Fileless launch through a trusted signer.** In in-memory mode the handle to Roblox is
   held by `powershell.exe`, signed by Microsoft. An A1 rule that only flags unsigned holders,
   or an allowlist keyed on signer, lets it through, and Prefetch/Amcache never see
   `Destiny.exe`. *Fix:* never allowlist script hosts or LOLBins as handle holders
   (AEGIS-GEN-002); add .NET ETW (DESTINY-009), script block logs (sigma), lineage
   (DESTINY-008), and a targeted memory scan of the flagged PowerShell (DESTINY-010).
3. **Capture-proof overlay.** `WDA_EXCLUDEFROMCAPTURE`, plus injecting into ShadowPlay and patching
   ReLive so that recordings cannot show the overlay. Screenshot or clip review
   will not show it. *Fix:* rely on window enumeration and `GetWindowDisplayAffinity` from
   AEGIS itself (GEN-010/011), which the hook does not reach; and treat tampering with
   recording software as evidence in its own right (DESTINY-003 to 006).
4. **No local overlay in IRL mode.** ESP is drawn on a second device. *Fix:* A1 still sees the
   handle; DESTINY-011 links a listening socket or `adb reverse` to the PID that holds it;
   DESTINY-007 sees frappe.win in DNS.
5. **Humanised aim and trigger.** Jitter, curves, reaction delay and overshoot defeat simple
   statistical aim checks. *Fix:* B4 keys on `LLMHF_INJECTED`, which `SendInput` always sets,
   joined with the handle holder (GEN-020). Server-side aim statistics are a separate project.
6. **Few artifacts.** No executor folders and no pipes; the injected DLL is deleted on unload and its
   Zone.Identifier stripped. *Fix:* named-object sweep (DESTINY-001) and USN journal (A7) for
   the transient Temp DLL.

None of these needs a kernel component. The detections in items 1, 2 and 4 rest on A1. That makes the
Hyperion test the roadmap calls for (does AEGIS's own handle-table query or handle
to Roblox get the player flagged) the first thing to do.
