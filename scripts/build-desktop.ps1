<#
.SYNOPSIS
  Builds the screensharing.me Windows client as a single self-contained executable.

.DESCRIPTION
  Produces artifacts\desktop\screensharing.me.exe (win-x64, no .NET install required) and,
  unless -NoPublishToWebsite is given, copies it to apps\website\public\download so the
  website's Download page serves it with its SHA-256.

  The server URL is compiled in as a *default* (users can change it in Settings).
  No secrets or credentials are embedded in the executable.

.EXAMPLE
  ./scripts/build-desktop.ps1                                   # local development (http://localhost:3000)
  ./scripts/build-desktop.ps1 -ServerUrl https://www.screensharing.me -Version 1.0.1
#>
param(
  [string]$ServerUrl = "http://localhost:3000",
  [string]$Version = "1.0.0",
  [string]$Configuration = "Release",
  [switch]$NoPublishToWebsite,
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$desktop = Join-Path $root "apps\desktop"
$out = Join-Path $root "artifacts\desktop"

# Pick a dotnet host that actually has a .NET 10 SDK (a machine-wide host may only carry runtimes).
$candidates = @((Get-Command dotnet -ErrorAction SilentlyContinue).Source, "$env:USERPROFILE\.dotnet\dotnet.exe", "$env:ProgramFiles\dotnet\dotnet.exe") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$dotnet = $candidates | Where-Object { (& $_ --list-sdks 2>$null) -match '^10\.' } | Select-Object -First 1
if (-not $dotnet) { throw "The .NET 10 SDK was not found. Install it from https://dotnet.microsoft.com/download" }
$env:DOTNET_NOLOGO = "1"; $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

if (-not $SkipTests) {
  Write-Host "==> Running scanner tests" -ForegroundColor Cyan
  & $dotnet test (Join-Path $desktop "tests\Screensharing.Scanner.Tests") -c $Configuration
  if ($LASTEXITCODE -ne 0) { throw "Scanner tests failed" }
}

Write-Host "==> Publishing screensharing.me.exe ($Version, server $ServerUrl)" -ForegroundColor Cyan
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
& $dotnet publish (Join-Path $desktop "src\Screensharing.Desktop\Screensharing.Desktop.csproj") `
  -c $Configuration -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:DebugType=none `
  -p:Version=$Version `
  -p:DefaultServerUrl=$ServerUrl `
  -o $out
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

$exe = Join-Path $out "screensharing.me.exe"
if (-not (Test-Path $exe)) { throw "Expected $exe was not produced" }
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Built $exe ($size MB)" -ForegroundColor Green
Write-Host "SHA-256 $hash"

if (-not $NoPublishToWebsite) {
  $dl = Join-Path $root "apps\website\public\download"
  New-Item -ItemType Directory -Force $dl | Out-Null
  Copy-Item $exe (Join-Path $dl "screensharing.me.exe") -Force
  Write-Host "Copied to apps\website\public\download (served at /download/screensharing.me.exe)" -ForegroundColor Green
  Write-Host "Register the release in Admin > App versions with version $Version and the SHA-256 above."
}
