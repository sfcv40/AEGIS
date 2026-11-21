<#
  End-to-end smoke test for aegis.exe on a throwaway Windows machine (CI runner or VM).
  It creates harmless fixtures that look like the test cheats to AEGIS, then checks that
  the expected rules fire. Nothing here touches the real Roblox client.

    - %LOCALAPPDATA%\KILLYWARE\license.dat                    -> AEGIS-FORSAKEN-002
    - Desktop\AegisTestExecutor\{autoexec,workspace,bin} + exe -> AEGIS-EXEC-001
    - a Luau script with loadstring(game:HttpGet(...))         -> AEGIS-EXEC-002
    - a copy of PING.EXE named RobloxPlayerBeta.exe ("fake Roblox")
    - this PowerShell process opening it with 0x438            -> AEGIS-GEN-002 (handle table)
                                                                  AEGIS-GEN-041 (ETW OpenProcess audit)
    - a hidden -EncodedCommand PowerShell child                -> AEGIS-DESTINY-008

  Usage (elevated Windows PowerShell): .\tests\e2e\smoke.ps1 -Exe build\Release\aegis.exe
  Do not run this on a PC you care about: it leaves fixture files until -Cleanup runs.
#>
param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [string]$Work = (Join-Path $env:TEMP 'aegis-e2e'),
  [switch]$KeepFixtures
)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force $Work | Out-Null

# ---- fixtures ----
$kw = Join-Path $env:LOCALAPPDATA 'KILLYWARE'
New-Item -ItemType Directory -Force $kw | Out-Null
Set-Content (Join-Path $kw 'license.dat') 'aegis-e2e fixture'

$desktop = [Environment]::GetFolderPath('Desktop')
$execDir = Join-Path $desktop 'AegisTestExecutor'
foreach ($d in 'autoexec', 'workspace', 'bin') { New-Item -ItemType Directory -Force (Join-Path $execDir $d) | Out-Null }
Copy-Item "$env:SystemRoot\System32\whoami.exe" (Join-Path $execDir 'Executor.exe') -Force
Set-Content (Join-Path $execDir 'autoexec\hub.lua') 'loadstring(game:HttpGet("https://example.invalid/hub.lua"))()'

# ---- one-shot scan ----
$scanOut = Join-Path $Work 'scan.jsonl'
& $Exe scan --out $scanOut
if ($LASTEXITCODE -gt 1) { throw "aegis scan failed with exit code $LASTEXITCODE" }

# ---- live monitor ----
$monOut = Join-Path $Work 'monitor.jsonl'
$monErr = Join-Path $Work 'monitor.stderr.txt'
$mon = Start-Process $Exe -ArgumentList 'monitor', '--no-scan', '--duration', '40', '--out', $monOut `
  -PassThru -NoNewWindow -RedirectStandardError $monErr
Start-Sleep -Seconds 8   # let the ETW session come up

$fake = Join-Path $Work 'RobloxPlayerBeta.exe'
Copy-Item "$env:SystemRoot\System32\PING.EXE" $fake -Force
$roblox = Start-Process $fake -ArgumentList '-n', '60', '127.0.0.1' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3

Add-Type -Namespace AegisE2E -Name K -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern System.IntPtr OpenProcess(uint access, bool inherit, int pid);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool CloseHandle(System.IntPtr h);
'@
$h = [AegisE2E.K]::OpenProcess(0x438, $false, $roblox.Id)   # VM_READ|VM_WRITE|VM_OPERATION|QUERY_INFORMATION, as Destiny does
if ($h -eq [IntPtr]::Zero) { throw 'OpenProcess on the fake Roblox failed' }

$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 5'))
Start-Process powershell.exe -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-EncodedCommand', $enc

Start-Sleep -Seconds 12  # several handle-sampler rounds while we hold the handle
[AegisE2E.K]::CloseHandle($h) | Out-Null
$mon.WaitForExit()
Stop-Process -Id $roblox.Id -Force -ErrorAction SilentlyContinue

# ---- results ----
$findings = @()
foreach ($f in $scanOut, $monOut) {
  if (Test-Path $f) { $findings += Get-Content $f | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } }
}
Write-Host "---- monitor stderr ----"
if (Test-Path $monErr) { Get-Content $monErr }
Write-Host "---- findings ----"
$findings | Where-Object { $_.type -eq 'finding' } | ForEach-Object { Write-Host ("{0,-22} {1,-9} {2}" -f $_.rule, $_.severity, $_.title) }
Write-Host "---- summaries ----"
$findings | Where-Object { $_.type -eq 'summary' } | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 4 }

$rules = @($findings | Where-Object { $_.type -eq 'finding' } | ForEach-Object { $_.rule }) | Sort-Object -Unique
$required = 'AEGIS-FORSAKEN-002', 'AEGIS-EXEC-001', 'AEGIS-EXEC-002', 'AEGIS-GEN-002', 'AEGIS-DESTINY-008'
$wanted = 'AEGIS-GEN-041'
$missing = $required | Where-Object { $rules -notcontains $_ }
foreach ($w in $wanted) { if ($rules -notcontains $w) { Write-Warning "expected (not required) rule did not fire: $w" } }

# Privacy check: the runner's user name must not appear in any output.
$leak = Select-String -Path $scanOut, $monOut -SimpleMatch $env:USERNAME -ErrorAction SilentlyContinue
if ($leak) { Write-Host $leak; throw "user name leaked into the report" }

if (-not $KeepFixtures) {
  Remove-Item -Recurse -Force $kw, $execDir -ErrorAction SilentlyContinue
}
if ($missing) { throw "missing rules: $($missing -join ', ')" }
Write-Host "e2e OK: $($rules.Count) distinct rules fired"
