[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PythonPath,

    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist-win7")
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$python = (Resolve-Path -LiteralPath $PythonPath).Path
$requirements = Join-Path $repoRoot "requirements-win7-build.txt"
$spec = Join-Path $repoRoot "unlicense.spec"

$version = (& $python -c "import sys; print('.'.join(map(str, sys.version_info[:2])))").Trim()
if ($version -ne "3.8") {
    throw "Windows 7 builds require CPython 3.8; got $version from '$python'."
}

$architecture = (& $python -c "import struct; print('x64' if struct.calcsize('P') == 8 else 'x86')").Trim()
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path $repoRoot "build-win7-$architecture"
$dist = Join-Path $repoRoot "dist-win7-$architecture"

New-Item -ItemType Directory -Force -Path $output | Out-Null

& $python -m pip install --disable-pip-version-check -r $requirements
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

Push-Location $repoRoot
try {
    & $python -m PyInstaller --noconfirm --clean --workpath $work --distpath $dist $spec
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed."
    }
}
finally {
    Pop-Location
}

$builtExe = Join-Path $dist "unlicense.exe"
$finalExe = Join-Path $output "unlicense-win7-$architecture.exe"
Copy-Item -LiteralPath $builtExe -Destination $finalExe -Force

$hash = (Get-FileHash -LiteralPath $finalExe -Algorithm SHA256).Hash
Write-Host "Built: $finalExe"
Write-Host "SHA256: $hash"
