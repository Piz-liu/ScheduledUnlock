$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
cmake -S $root -B "$root\build" -A x64 -DBUILD_TESTING=ON
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
cmake --build "$root\build" --config Release
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
ctest --test-dir "$root\build" -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
New-Item -ItemType Directory -Force "$root\bin" | Out-Null
Copy-Item "$root\build\bin\Release\ScheduledUnlock.exe" "$root\bin\" -Force
Copy-Item "$root\build\bin\Release\ScheduledUnlockProvider.dll" "$root\bin\" -Force
Get-FileHash "$root\bin\ScheduledUnlock.exe", "$root\bin\ScheduledUnlockProvider.dll" -Algorithm SHA256 | Format-Table
