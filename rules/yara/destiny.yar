/*
  AEGIS YARA rules: Destiny (frappe.win) external Roblox cheat.
  Scope: on-disk files AND memory images (the in-memory loader maps the same
  PE into powershell.exe, so these strings are present in that process too).
  Source: static analysis of Destiny.exe built 2026-11-20, confirmed against source.
*/

rule AEGIS_Destiny_Client
{
    meta:
        author      = "AEGIS"
        family      = "Destiny"
        description = "Destiny external Roblox client (Destiny.exe), on disk or reflectively mapped"
        severity    = "high"
        sha256      = "a7f0cf1d26800c1141ecd2e1ea6566cb16b583f67007b94ed40a344d8fd38531"
    strings:
        $exp1 = "DestinyInMemoryEntry" ascii
        $exp2 = "DestinySetNvDllBytes" ascii
        $ua1  = "DestinyClient/0.1" wide
        $ua2  = "DestinyClient-IRL" wide
        $hdr1 = "X-Destiny-HWID: " wide
        $hdr2 = "X-Destiny-Account: " wide
        $evt  = "Local\\Destiny_Instance_Shutdown" wide
        $cls  = "DestinyOverlayWindow" wide
        $log1 = "[Destiny][HBE]" ascii
        $log2 = "[Destiny][Rage]" ascii
        $log3 = "[Destiny][Visuals]" ascii
        $dom1 = "frappe.win" ascii wide
        $dom2 = "offsets.imtheo.lol" ascii wide
    condition:
        ( any of ($exp*) or 2 of ($ua*, $hdr*, $evt, $cls) or 2 of ($log*) or (all of ($dom*) and 1 of ($log*, $hdr*)) )
}

rule AEGIS_Destiny_NvBiosmeth_Dll
{
    meta:
        author      = "AEGIS"
        family      = "Destiny"
        description = "nv_biosmeth.dll: Destiny module injected into NVIDIA ShadowPlay processes to hide the overlay from recordings"
        severity    = "high"
        sha256      = "6302f5a26b24a6f313f6c466cdbfcf9f96f7b119872531a0baea642965e13006"
    strings:
        $e1 = "NvBiosmeth_GetStatus" ascii
        $m1 = "NV_BIOSMETH_STATUS_" wide
        $m2 = "NV_BIOSMETH_UNLOAD_" wide
        $m3 = "FRAPPE_NV_BLOCK_FBC" wide
        $r1 = "{1B1D3DAA-601D-49E5-8508-81736CA28C6D}" wide
    condition:
        uint16(0) == 0x5A4D and (uint16(uint32(0x3C) + 0x16) & 0x2000) != 0 and
        ($e1 or 2 of ($m*) or ($r1 and 1 of ($m*)))
}

rule AEGIS_Destiny_Scripts
{
    meta:
        author      = "AEGIS"
        family      = "Destiny"
        description = "DestinyScripts.exe: Destiny standalone external Lua runner"
        severity    = "high"
        sha256      = "22f7606db266ebe8148721d1b5a2fd42586ef2b172baee4d3be1c49f3756aacd"
    strings:
        $a = "DestinyScriptBridge/1.0" wide
        $b = "Destiny Scripts (Standalone Lua Runner" ascii
        $c = "X-Destiny-HWID: " wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule AEGIS_Destiny_MemoryLoader_Script
{
    meta:
        author      = "AEGIS"
        family      = "Destiny"
        description = "launch-memory.ps1 fileless loader: script text, PowerShell 4104 block, or AMSI buffer"
        severity    = "high"
    strings:
        $n1 = "DestinyMemDynamicAsm" ascii wide nocase
        $n2 = "DestinyMemNative" ascii wide nocase
        $n3 = "DestinyEntryDelegate" ascii wide nocase
        $n4 = "DestinySetNvDllDelegate" ascii wide nocase
        $n5 = "DestinyMem_" ascii wide
        $n6 = "DestinyEvt_" ascii wide
        $n7 = "DestinyLoader/1.0" ascii wide
        $g1 = "DefinePInvokeMethod" ascii wide nocase
        $g2 = "RtlAddFunctionTable" ascii wide nocase
        $g3 = "GetDelegateForFunctionPointer" ascii wide nocase
        $g4 = "/downloads/Destiny.exe" ascii wide nocase
    condition:
        2 of ($n*) or (1 of ($n*) and 2 of ($g*))
}
