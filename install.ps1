# CryptoCensus installer for Windows. One command in PowerShell, no admin rights:
#   irm https://raw.githubusercontent.com/MaqsatKendjebekov/cryptocensus/master/install.ps1 | iex
# Downloads the Windows release, checks its SHA-256 against the release's SHA256SUMS, runs
# the binary's self-test, and only then installs it to %LOCALAPPDATA%\cryptocensus and adds
# that folder to your user PATH. It runs in its own scope, so your session's variables and
# settings are left alone.
& {
    $ErrorActionPreference = 'Stop'
    $repo  = 'MaqsatKendjebekov/cryptocensus'
    $asset = 'cryptocensus-x86_64-pc-windows-gnu.zip'
    $base  = "https://github.com/$repo/releases/latest/download"
    $dir   = Join-Path $env:LOCALAPPDATA 'cryptocensus'
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'CryptoCensus needs 64-bit Windows' }
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -and [Environment]::OSVersion.Version.Build -lt 22000) {
        throw 'Windows 10 on ARM cannot run x64 programs: use Windows 11, or build from source with cargo'
    }
    # Windows PowerShell 5.1 may not offer TLS 1.2, which GitHub requires
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('cryptocensus-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        Write-Host '  downloading cryptocensus (Windows x86_64)'
        Invoke-WebRequest "$base/$asset" -OutFile "$tmp\$asset" -UseBasicParsing
        Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing
        $line = Select-String -Path "$tmp\SHA256SUMS" -Pattern (' ' + [regex]::Escape($asset) + '$')
        if (-not $line) { throw "no checksum for $asset in SHA256SUMS, nothing installed" }
        $want = $line.Line.Split(' ')[0]
        $got  = (Get-FileHash "$tmp\$asset" -Algorithm SHA256).Hash.ToLower()
        if ($want -ne $got) { throw "checksum mismatch for $asset, nothing installed" }
        Write-Host '  checksum ok'
        Expand-Archive "$tmp\$asset" -DestinationPath $tmp -Force
        # Run the new binary before it replaces anything. Windows PowerShell 5.1 turns a native
        # program's stderr into errors, so those must not be fatal while it runs.
        $ErrorActionPreference = 'Continue'
        $version = & "$tmp\cryptocensus.exe" --version 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'the binary does not run on this system, nothing installed' }
        $check = & "$tmp\cryptocensus.exe" selftest --no-color 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'self-test failed, nothing installed' }
        $ErrorActionPreference = 'Stop'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        # Windows lets a running exe be renamed but not overwritten
        Remove-Item "$dir\cryptocensus.exe.old" -Force -ErrorAction SilentlyContinue
        if (Test-Path "$dir\cryptocensus.exe") { Move-Item "$dir\cryptocensus.exe" "$dir\cryptocensus.exe.old" -Force }
        Copy-Item "$tmp\cryptocensus.exe" "$dir\cryptocensus.exe" -Force
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  $version installed to $dir"
    Write-Host ('  ' + ($check | Select-Object -Last 1))
    # Read and write the raw registry value, so %VARIABLES% in your PATH stay unexpanded
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    $userPath = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    if (-not (($userPath -split ';') -contains $dir)) {
        $newPath = if ($userPath) { $userPath.TrimEnd(';') + ';' + $dir } else { $dir }
        $key.SetValue('Path', $newPath, 'ExpandString')
        # announce the change to Explorer and new terminals
        [Environment]::SetEnvironmentVariable('CRYPTOCENSUS_PATH_REFRESH', '1', 'User')
        [Environment]::SetEnvironmentVariable('CRYPTOCENSUS_PATH_REFRESH', $null, 'User')
        $env:Path = "$env:Path;$dir"
        Write-Host "  added $dir to your PATH (new terminals pick it up)"
    }
    $key.Close()
    Write-Host '  try:  cryptocensus scan --targets <server IP> --out audit'
    Write-Host '  only scan systems you own or are allowed to test'
}
