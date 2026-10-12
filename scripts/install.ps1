$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit $process.ExitCode
}
if (-not [Environment]::Is64BitProcess) { throw 'Please run the installer with 64-bit Windows PowerShell.' }
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($architecture -ne 'X64') { throw 'This build supports only Intel/AMD x64 Windows 11, not ARM64.' }
$build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
if ($build -lt 22000) { throw 'This version requires Windows 11.' }
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $env:ProgramFiles 'ScheduledUnlock'
$clsid = '{A8255267-5B6C-4F76-9827-83FE0A09F593}'
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$comKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
$configKey = 'HKLM:\SOFTWARE\ScheduledUnlock'
if (Test-Path $providerKey) {
    Write-Host 'Already installed. Opening settings.'
    Start-Process (Join-Path $dest 'ScheduledUnlock.exe')
    exit 0
}
foreach ($name in @('ScheduledUnlock.exe','ScheduledUnlockProvider.dll')) {
    if (-not (Test-Path (Join-Path "$root\bin" $name))) { throw "Missing bin\$name. Extract the complete package first." }
}
if (Test-Path $dest) { throw 'The installation directory already exists. Run Uninstall.cmd and reboot before reinstalling.' }

try {
    New-Item -ItemType Directory -Path $dest | Out-Null
    # Restrict all executable content to administrator/SYSTEM writes before copying files.
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl -Path $dest -AclObject $acl
    Copy-Item "$root\bin\ScheduledUnlock.exe", "$root\bin\ScheduledUnlockProvider.dll" -Destination $dest
    Copy-Item "$root\scripts" -Destination $dest -Recurse
    Copy-Item "$root\Uninstall.cmd", "$root\README.md" -Destination $dest

    New-Item -Path $configKey -Force | Out-Null
    $regAcl = [Security.AccessControl.RegistrySecurity]::new()
    $regAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $regAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit','None','Allow'))
    }
    Set-Acl -Path $configKey -AclObject $regAcl
    New-ItemProperty -Path $configKey -Name 'ExePath' -PropertyType String -Value (Join-Path $dest 'ScheduledUnlock.exe') -Force | Out-Null
    New-ItemProperty -Path $configKey -Name 'Status' -PropertyType String -Value '尚未启用。请输入账户密码并设置时间。' -Force | Out-Null

    New-Item -Path "$comKey\InprocServer32" -Force | Out-Null
    Set-Item -Path $comKey -Value 'Scheduled Unlock Credential Provider'
    Set-Item -Path "$comKey\InprocServer32" -Value (Join-Path $dest 'ScheduledUnlockProvider.dll')
    New-ItemProperty -Path "$comKey\InprocServer32" -Name 'ThreadingModel' -PropertyType String -Value 'Both' -Force | Out-Null
    # Add only our provider. Do not filter or modify any built-in provider.
    New-Item -Path $providerKey -Force | Out-Null
    Set-Item -Path $providerKey -Value 'Scheduled Unlock'

    $shell = New-Object -ComObject WScript.Shell
    $programs = [Environment]::GetFolderPath('CommonPrograms')
    $shortcutDir = Join-Path $programs 'ScheduledUnlock'
    New-Item -ItemType Directory -Path $shortcutDir -Force | Out-Null
    $shortcut = $shell.CreateShortcut((Join-Path $shortcutDir '定时解锁.lnk'))
    $shortcut.TargetPath = Join-Path $dest 'ScheduledUnlock.exe'
    $shortcut.WorkingDirectory = $dest
    $shortcut.Save()
    $uninstall = $shell.CreateShortcut((Join-Path $shortcutDir '卸载定时解锁.lnk'))
    $uninstall.TargetPath = Join-Path $dest 'Uninstall.cmd'
    $uninstall.WorkingDirectory = $dest
    $uninstall.Save()
    $desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
    Copy-Item (Join-Path $shortcutDir '定时解锁.lnk') -Destination $desktop -Force
    Write-Host 'Installed. No unlock schedule has been enabled yet.'
    Start-Process (Join-Path $dest 'ScheduledUnlock.exe')
} catch {
    # Roll back only the keys/files owned by this application.
    if (Test-Path $providerKey) { Remove-Item $providerKey -Recurse -Force }
    if (Test-Path $comKey) { Remove-Item $comKey -Recurse -Force }
    if (Test-Path $configKey) { Remove-Item $configKey -Recurse -Force }
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Error $_
    exit 1
}
