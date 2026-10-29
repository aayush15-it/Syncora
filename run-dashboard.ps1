$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$candidates = @(
    (Join-Path $projectRoot "build\merklechain.exe"),
    (Join-Path $projectRoot "build\merklechain-ui-final.exe"),
    (Join-Path $projectRoot "build\merklechain-redesign.exe")
)

$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"

$exe = $null
foreach ($cand in $candidates) {
    if (Test-Path $cand) {
        $exe = $cand
        break
    }
}

if (-not $exe) {
    throw "MerkleChain executable not found in $projectRoot\build"
}

try {
    & $exe --dashboard @args
    exit $LASTEXITCODE
} catch {
    Write-Warning "Failed to execute '$exe': $_"
    $fallback = Join-Path $projectRoot "build\merklechain-ui-final.exe"
    if ($exe -ne $fallback -and (Test-Path $fallback)) {
        Write-Host "Attempting fallback executable: $fallback" -ForegroundColor Cyan
        & $fallback --dashboard @args
        exit $LASTEXITCODE
    }
    throw $_
}
