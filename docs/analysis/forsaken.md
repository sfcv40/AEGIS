# FORSAKEN (KILLYWARE)

External ImGui cheat with a single loader UI for Roblox, CS2 and Minecraft. Only Roblox
has a working backend in this build. C++20, MSVC 14.51, Dear ImGui 1.91.5, no packer.
Source checked: `C:\KILLYWARE` (main.cpp, RobloxMemory.cpp, D3D11Overlay.cpp,
Triggerbot.cpp, SilentAim.cpp, KillywareUI.cpp).

## File

| File | SHA-256 | Notes |
|---|---|---|
| FORSAKEN.exe | `ececb483a8e416478ff24d9358f09519d58eb0018b740ffd43bab0288f8f1e77` | PE32+ GUI, 809,472 B, built 2026-11-21 17:42 UTC. Matches `build\Release\FORSAKEN.exe` by size. `C:\KILLYWARE\KILLYWARE.exe` (685,568 B) is an older build of the same project |

PE: 6 sections, .rdata entropy 7.39. The high value comes from an embedded compressed font and logo, not from
packing. Has a TLS directory (CRT). Imports include `OpenProcess`, `ReadProcessMemory`,
`WriteProcessMemory`, `SetWindowsHookExW`, `SendInput`, `SetWindowDisplayAffinity`,
`SetLayeredWindowAttributes`, `DwmExtendFrameIntoClientArea`, `D3DCompile`. There is no networking
import, no `DeviceIoControl`, and no service API.

## How it works

- **Roblox access:** finds `RobloxPlayerBeta.exe` (also lists `cs2.exe`, `javaw.exe`,
  `Minecraft.Windows.exe`), then calls `OpenProcess(VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION)` =
  0x438, falling back to 0x410. A separate `0x600` handle sets priority (the "Game Optimised" feature).
- **Features:** ESP, triggerbot, camlock / mouselock, a "silent aim" UI option, HBE, WalkSpeed,
  CFrame flight, noclip, desync, lighting overrides, anti-AFK, server hop.
- **Overlay:** window class `FORSAKEN_EXTERNAL_OVERLAY_HOST`, title `FORSAKEN External Overlay`,
  ex-style `WS_EX_TOPMOST|WS_EX_LAYERED|WS_EX_TOOLWINDOW` (0x80088). It adds
  `WS_EX_TRANSPARENT|WS_EX_NOACTIVATE` while the menu is closed. The overlay is lined up on the Roblox window
  (class `WINDOWSCLIENT`). "Stream Safe" toggles `WDA_EXCLUDEFROMCAPTURE` and is off by default.
- **Input:** `SendInput` for clicks. `WH_MOUSE_LL` hook (thread 0, global) that ignores
  `LLMHF_INJECTED` events.
- **Licensing:** offline. It has a hard-coded master key `KW-MASTER-2026-VIP` and an HWID from MachineGuid and
  the volume serial, saved to `%LOCALAPPDATA%\KILLYWARE\license.dat`. Config is saved to
  `%LOCALAPPDATA%\KILLYWARE\config_last.bin`. Fonts load from `C:\KILLYWARE\assets\fonts\` or `.\assets\fonts\`.
- **"Kernel IOCTL", "Physical CR3", "Ring 0 Active", "Kernel Mouse":** UI strings only
  (`kMemModes` in KillywareUI.cpp; the selected `MemoryReadMethod` is never read outside the UI). The binary has no driver interface. All memory access is
  usermode `ReadProcessMemory` / `WriteProcessMemory`.

## Detection mapping

Every standard signal catches FORSAKEN:

| Behaviour | Rule | Roadmap |
|---|---|---|
| Unsigned EXE on disk, in execution records | FORSAKEN-003, YARA `AEGIS_Forsaken_External` | baseline |
| 0x438 handle to Roblox | GEN-001 | A1 |
| Overlay window | FORSAKEN-001, GEN-010, GEN-011 | B3 |
| `SendInput` + `WH_MOUSE_LL` | GEN-020, GEN-021 | B4 |
| License/config files | FORSAKEN-002 | A6 |

It is a good regression target. If AEGIS ever misses FORSAKEN, a core signal is broken.
