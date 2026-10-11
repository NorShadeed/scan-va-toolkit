$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolsDir = Join-Path $projectRoot "tools"
$destination = Join-Path $toolsDir "subfinder.exe"
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDir = Join-Path $tempRoot ("scan-subfinder-" + [Guid]::NewGuid().ToString("N"))

if (-not ([IO.Path]::GetFullPath($tempDir)).StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a temporary path outside the system temporary directory."
}

Write-Host ""
Write-Host "  SCAN - Subfinder setup" -ForegroundColor DarkGreen
Write-Host "  Downloading the latest official Windows release from ProjectDiscovery." -ForegroundColor DarkGray
Write-Host ""

try {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null

    $headers = @{ "User-Agent" = "scan-cli-subfinder-installer" }
    $release = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest" `
        -Headers $headers

    $runtimeArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    $releaseArchitecture = if ($runtimeArchitecture -eq "arm64") { "arm64" } else { "amd64" }

    $zipAsset = $release.assets |
        Where-Object { $_.name -match ("_windows_" + $releaseArchitecture + "\.zip$") } |
        Select-Object -First 1
    $checksumAsset = $release.assets |
        Where-Object { $_.name -match "_checksums\.txt$" } |
        Select-Object -First 1

    if (-not $zipAsset -or -not $checksumAsset) {
        throw "The release does not contain the expected Windows archive and checksum file."
    }

    $zipPath = Join-Path $tempDir $zipAsset.name
    $checksumPath = Join-Path $tempDir $checksumAsset.name
    $extractDir = Join-Path $tempDir "extracted"

    Write-Host "  Release: $($release.tag_name)" -ForegroundColor Gray
    Write-Host "  Downloading $($zipAsset.name)..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $zipAsset.browser_download_url -Headers $headers -OutFile $zipPath
    Invoke-WebRequest -Uri $checksumAsset.browser_download_url -Headers $headers -OutFile $checksumPath

    $checksumLine = Get-Content -LiteralPath $checksumPath |
        Where-Object { $_ -match ([Regex]::Escape($zipAsset.name) + "$") } |
        Select-Object -First 1
    if (-not $checksumLine) {
        throw "Could not find the archive in the official checksum file."
    }

    $expectedHash = ($checksumLine -split "\s+")[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "SHA-256 verification failed. The downloaded archive will not be installed."
    }
    Write-Host "  SHA-256 verified." -ForegroundColor DarkGreen

    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
    $executable = Get-ChildItem -LiteralPath $extractDir -Filter "subfinder.exe" -File -Recurse |
        Select-Object -First 1
    if (-not $executable) {
        throw "subfinder.exe was not present in the verified archive."
    }

    Copy-Item -LiteralPath $executable.FullName -Destination $destination -Force
    Unblock-File -LiteralPath $destination -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  Installed: $destination" -ForegroundColor DarkGreen
    & $destination -version
    Write-Host ""
    Write-Host "  Setup complete. Restart the SCAN desktop app." -ForegroundColor DarkGreen
}
finally {
    if (Test-Path -LiteralPath $tempDir) {
        $resolvedTemp = [IO.Path]::GetFullPath($tempDir)
        if ($resolvedTemp.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
        }
    }
}
