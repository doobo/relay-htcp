$ErrorActionPreference = "Stop"

$distDir = "dist"
if (Test-Path $distDir) {
    Remove-Item -Recurse -Force $distDir
}
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$version = (git describe --tags --always 2>$null)
if (-not $version) { $version = "dev" }

Write-Host "Packaging version: $version"

$platforms = @(
    @{os="windows"; arch="amd64"; ext=".exe"},
    @{os="windows"; arch="arm64"; ext=".exe"},
    @{os="linux"; arch="amd64"; ext=""},
    @{os="linux"; arch="arm64"; ext=""},
    @{os="linux"; arch="386"; ext=""},
    @{os="darwin"; arch="amd64"; ext=""},
    @{os="darwin"; arch="arm64"; ext=""}
)

foreach ($p in $platforms) {
    $os = $p.os
    $arch = $p.arch
    $ext = $p.ext
    $binName = "relay-htcp" + $ext
    $targetName = "relay-htcp-" + $version + "-" + $os + "-" + $arch
    $tempDir = Join-Path $distDir $targetName
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    
    Write-Host "==> Building $os/$arch..."
    $env:CGO_ENABLED = "0"
    $env:GOOS = $os
    $env:GOARCH = $arch
    
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o (Join-Path $tempDir $binName) ./cmd/relay-htcp
    if (Test-Path "LICENSE") {
        Copy-Item "LICENSE" $tempDir -Force
    }
    
    if ($os -eq "windows") {
        $zipPath = Join-Path $distDir ($targetName + ".zip")
        Compress-Archive -Path (Join-Path $tempDir "*") -DestinationPath $zipPath -Force
        Write-Host "  -> $zipPath"
    } else {
        $tarPath = Join-Path $distDir ($targetName + ".tar.gz")
        tar -C $tempDir -czf $tarPath $binName LICENSE
        Write-Host "  -> $tarPath"
    }
    Remove-Item -Recurse -Force $tempDir
}

# Generate SHA256SUMS
Push-Location $distDir
try {
    $hashes = Get-ChildItem -File | Where-Object { $_.Name -like "relay-htcp-*" } | Get-FileHash -Algorithm SHA256 | ForEach-Object {
        $name = Split-Path $_.Path -Leaf
        "$($_.Hash.ToLower())  $name"
    }
    $hashes | Set-Content -Path "SHA256SUMS" -Encoding ascii
    Write-Host "==> SHA256SUMS generated."
} finally {
    Pop-Location
}

Write-Host "Build finished successfully!"
