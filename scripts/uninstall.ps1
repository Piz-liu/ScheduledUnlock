$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit $process.ExitCode
}
if (-not [Environment]::Is64BitProcess) { throw 'Please run with 64-bit Windows PowerShell.' }
$clsid = '{A8255267-5B6C-4F76-9827-83FE0A09F593}'
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$comKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
$configKey = 'HKLM:\SOFTWARE\ScheduledUnlock'
$dest = Join-Path $env:ProgramFiles 'ScheduledUnlock'
# Invalidate pending requests before removing scheduler jobs or provider registration.
if (Test-Path $configKey) {
    Remove-ItemProperty -Path $configKey -Name 'Generation' -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $configKey -Name 'Pending' -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $configKey -Name 'Password' -ErrorAction SilentlyContinue
}
foreach ($name in @('ScheduledUnlock-Daily','ScheduledUnlock-Test')) {
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}
foreach ($key in @($providerKey,$comKey,$configKey)) {
    if (Test-Path $key) { Remove-Item $key -Recurse -Force }
}
Get-Process -Name ScheduledUnlock -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq (Join-Path $dest 'ScheduledUnlock.exe') } | Stop-Process -Force
foreach ($path in @((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) '定时解锁.lnk'),(Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'ScheduledUnlock'))) {
    if (Test-Path $path) { Remove-Item $path -Recurse -Force }
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ScheduledUnlockCleanup {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool MoveFileEx(string existing, string replacement, int flags);
}
'@
$reboot = $false
if (Test-Path $dest) {
    $entries = Get-ChildItem -Path $dest -Recurse -Force | Sort-Object { $_.FullName.Length } -Descending
    foreach ($entry in $entries) {
        try { Remove-Item -LiteralPath $entry.FullName -Force -ErrorAction Stop } catch {
            if (-not [ScheduledUnlockCleanup]::MoveFileEx($entry.FullName, $null, 4)) { throw "Cannot remove $($entry.FullName). Reboot and run uninstall again." }
            $reboot = $true
        }
    }
    try { Remove-Item -LiteralPath $dest -Force -ErrorAction Stop } catch {
        if (-not [ScheduledUnlockCleanup]::MoveFileEx($dest, $null, 4)) { throw 'Cannot queue installation directory removal.' }
        $reboot = $true
    }
}
if ($reboot) { Write-Host 'Disabled and credentials removed. Restart Windows to finish deleting loaded files.' }
else { Write-Host 'Uninstalled. Saved credentials and schedules have been removed.' }
