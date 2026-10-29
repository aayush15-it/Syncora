# MerkleChain Automated Test Suite Runner
param(
    [string]$ExecutablePath = "build/tests.exe",
    [string]$SignCertThumbprint = ""
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " MerkleChain Test Suite Automation Runner" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if executable exists, build if needed
if (-not (Test-Path $ExecutablePath)) {
    Write-Host "[*] Compiling test binary via mingw32-make..." -ForegroundColor Yellow
    & "C:\msys64\ucrt64\bin\mingw32-make.exe" build/tests.exe
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to compile test binary. Exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

# Ensure UCRT64 toolchain DLLs (libssl, libcrypto, libsqlite3) are first in PATH
$ucrtBin = "C:\msys64\ucrt64\bin"
if (Test-Path $ucrtBin) {
    $env:PATH = "$ucrtBin;" + $env:PATH
}

# Optional code signing
if ($SignCertThumbprint -ne "") {
    Write-Host "[*] Attempting to sign $ExecutablePath with thumbprint $SignCertThumbprint..." -ForegroundColor Yellow
    $cert = Get-Item "Cert:\CurrentUser\My\$SignCertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-Item "Cert:\LocalMachine\My\$SignCertThumbprint" -ErrorAction SilentlyContinue
    }
    if ($cert) {
        Set-AuthenticodeSignature -FilePath $ExecutablePath -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
        Write-Host "[+] Binary signed successfully." -ForegroundColor Green
    } else {
        Write-Warning "Certificate with thumbprint $SignCertThumbprint not found in My store."
    }
}

Write-Host "[*] Launching test suite: $ExecutablePath" -ForegroundColor Cyan
$startTime = Get-Date
$launchException = $null
$exitCode = 1
$isBlocked = $false

$passCount = 0
$failCount = 0
$skipCount = 0

try {
    & $ExecutablePath 2>&1 | ForEach-Object {
        $line = $_.ToString()
        Write-Host $line
        if ($line -match "^\[PASS\]") { $passCount++ }
        elseif ($line -match "^\[FAIL\]") { $failCount++ }
        elseif ($line -match "^\[SKIP\]") { $skipCount++ }
        elseif ($line -match "Test checks:\s+(\d+)\s+passed,\s+(\d+)\s+failed,\s+(\d+)\s+skipped") {
            $passCount = [int]$matches[1]
            $failCount = [int]$matches[2]
            $skipCount = [int]$matches[3]
        }
    }
    $exitCode = $LASTEXITCODE
} catch {
    $launchException = $_.Exception
    Write-Host "`n[!] Execution failed: $_" -ForegroundColor Red
}

if ($exitCode -eq 4551) {
    $isBlocked = $true
} elseif ($null -ne $launchException) {
    if ($launchException.HResult -eq [int]0x800711C7 -or 
        $launchException.Message -match "Application Control|blocked by your system administrator|Smart App Control|Code Integrity") {
        $isBlocked = $true
        $exitCode = 4551
    } elseif ($launchException.InnerException -and 
             ($launchException.InnerException.NativeErrorCode -eq 4551 -or 
              $launchException.InnerException.HResult -eq [int]0x800711C7)) {
        $isBlocked = $true
        $exitCode = 4551
    }
}

$duration = ((Get-Date) - $startTime).TotalSeconds

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($isBlocked) {
    Write-Host "[BLOCKED] Execution blocked by Windows Code Integrity / Smart App Control policy (Error 4551)." -ForegroundColor Yellow
    Write-Host "Policy ID: {0283ac0f-fff1-49ae-ada1-8a933130cad6} (VerifiedAndReputableDesktop)" -ForegroundColor Yellow
    Write-Host "See docs/IMPLEMENTATION_STATUS.md for legitimate administrator signing instructions." -ForegroundColor Yellow
} elseif ($exitCode -eq 0 -and $null -eq $launchException -and $failCount -eq 0) {
    if ($skipCount -gt 0) {
        Write-Host "[SUCCESS] All executed tests passed in $($duration.ToString('F2'))s ($passCount passed, $skipCount skipped). (Exit Code: 0)" -ForegroundColor Green
    } else {
        Write-Host "[SUCCESS] All tests executed and passed in $($duration.ToString('F2'))s ($passCount passed). (Exit Code: 0)" -ForegroundColor Green
    }
} else {
    Write-Host "[FAILED] Test run exited with error code: $exitCode in $($duration.ToString('F2'))s ($failCount failed, $passCount passed, $skipCount skipped)." -ForegroundColor Red
}
Write-Host "==========================================================" -ForegroundColor Cyan

exit $exitCode
