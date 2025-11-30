Param(
    [string] $Version = $Env:APX_VERSION,
    [string] $Architecture = $Env:APX_ARCH
)

if (-not $Version) { $Version = "0.1.0" }
if (-not $Architecture) { $Architecture = "x86_64" }

$downloadUrl = "https://github.com/apx-project/apx-cli/releases/download/v$Version/apx-windows-$Architecture.exe"
$tempFile = Join-Path $Env:RUNNER_TEMP "apx.exe"

Write-Host "Installing APX CLI v$Version for windows/$Architecture ..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile

$installDir = "$Env:ProgramFiles\APX"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Move-Item -Force -Path $tempFile -Destination (Join-Path $installDir "apx.exe")

Add-Content -Path $Env:GITHUB_PATH -Value $installDir

try {
    & "$installDir\apx.exe" --version
} catch {
    Write-Warning "APX CLI installed, but version check failed (placeholder build)."
}

