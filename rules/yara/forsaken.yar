/*
  AEGIS YARA rules: FORSAKEN / KILLYWARE external multi-game cheat.
  Source: static analysis of FORSAKEN.exe built 2026-11-21, confirmed against source.
*/

rule AEGIS_Forsaken_External
{
    meta:
        author      = "AEGIS"
        family      = "FORSAKEN"
        description = "FORSAKEN (KILLYWARE) external ImGui overlay cheat for Roblox, CS2 and Minecraft"
        severity    = "high"
        sha256      = "ececb483a8e416478ff24d9358f09519d58eb0018b740ffd43bab0288f8f1e77"
    strings:
        $w1 = "FORSAKEN_EXTERNAL_OVERLAY_HOST" wide
        $w2 = "FORSAKEN External Overlay" wide
        $w3 = "\\KILLYWARE" wide
        $w4 = "\\license.dat" wide
        $w5 = "\\config_last.bin" wide
        $a1 = "KW-MASTER-2026-VIP" ascii
        $a2 = "Roblox Player  -  Hyperion External DWM Overlay" ascii
        $a3 = "FORSAKEN Loader" ascii
        $a4 = "Open or hide this Forsaken overlay panel" ascii
        $a5 = "Press [F2] or [INSERT] to reopen the Forsaken loader." ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($w1, $w2, $a1) or 3 of them)
}
