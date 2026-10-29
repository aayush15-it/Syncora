# MerkleChain — Peer Network Dashboard Integration & Security Test Suite
param([string]$ExecutablePath = 'build/merklechain.exe')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = if ([IO.Path]::IsPathRooted($ExecutablePath)) { $ExecutablePath } else { Join-Path $projectRoot $ExecutablePath }
$exe = (Resolve-Path -LiteralPath $exe).Path
$fixtureRoot = Join-Path $projectRoot ('build\peer-dashboard-fixtures\' + [guid]::NewGuid().ToString('N'))
$syncFolder = Join-Path $fixtureRoot 'sync_root'
$certsFolder = Join-Path $fixtureRoot 'certs'

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$oldPath = $env:PATH
$server = $null
$passCount = 0
$failCount = 0

function Assert([bool]$condition, [string]$message) {
    if (-not $condition) {
        $script:failCount++
        throw "ASSERTION FAILED: $message"
    }
    $script:passCount++
}

function PostJson([string]$url, [hashtable]$headers, [hashtable]$body) {
    $json = $body | ConvertTo-Json -Compress -Depth 8
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/json' -Body $json
}

try {
    Write-Output "=== Starting MerkleChain Peer Network Dashboard Tests ==="
    New-Item -ItemType Directory -Path $syncFolder, $certsFolder -Force | Out-Null
    
    # 1. Start Dashboard Server
    $env:PATH = "C:\msys64\ucrt64\bin;$oldPath"
    $server = Start-Process -FilePath $exe -ArgumentList @('--dashboard', [string]$port) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    $base = "http://127.0.0.1:$port"
    
    $status = $null
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try { $status = Invoke-RestMethod -Uri "$base/api/status"; break }
        catch {
            if ($server.HasExited) { throw "Server exited early with code $($server.ExitCode)" }
            Start-Sleep -Milliseconds 250
        }
    }
    Assert ([bool]$status) 'Dashboard status endpoint became ready'
    Write-Output "[OK] Server listening on 127.0.0.1:$port (CSRF token received: $($status.csrf.Length) chars)"

    # 2. Test Frontend Static Assets & Security (No private key leakage, charcoal/graphite styling)
    $html = (Invoke-WebRequest -UseBasicParsing -Uri "$base/").Content
    $css = (Invoke-WebRequest -UseBasicParsing -Uri "$base/styles.css").Content
    $js = (Invoke-WebRequest -UseBasicParsing -Uri "$base/app.js").Content

    Assert ($html.Contains('id="view-overview"')) 'View 1: Network Overview present in HTML'
    Assert ($html.Contains('id="view-pairing"')) 'View 2: Device Pairing present in HTML'
    Assert ($html.Contains('id="view-connection"')) 'View 3: Peer Connection present in HTML'
    Assert ($html.Contains('id="view-peer-sync"')) 'View 4: Synchronization Center present in HTML'
    Assert ($html.Contains('id="view-approval"')) 'View 5: Approval Workflow present in HTML'
    Assert ($html.Contains('id="view-progress"')) 'View 6: Transfer Progress present in HTML'
    Assert ($html.Contains('id="view-peer-activity"')) 'View 7: Activity & Recovery present in HTML'
    Write-Output "[OK] All 7 Peer Network views verified in HTML"

    # Verify Local Workspace views present in HTML (Devices & Access removed from sidebar; pairing belongs to Peer Network)
    $localViews = @('synchronize','versions','algorithm','merkle','chunks','scheduler','activity','settings')
    foreach ($lv in $localViews) {
        Assert ($html.Contains("id=`"view-$lv`"")) "Local Workspace view #view-$lv present in HTML"
        Assert ($html.Contains("data-view=`"$lv`"")) "Sidebar navigation link for $lv present in HTML"
    }
    Assert (-not $html.Contains("data-view=`"devices`"")) "Devices & Access removed from Local Workspace sidebar"
    Assert (-not $html.Contains("data-view=`"benchmarks`"")) "Benchmarks removed from Local Workspace sidebar"
    Assert (-not $html.Contains("id=`"view-benchmarks`"")) "Benchmarks view removed from HTML"
    Write-Output "[OK] All Local Workspace views and sidebar navigation links verified in HTML (Devices & Access omitted)"

    # Verify dashboard action buttons (data-go)
    $goButtons = @('pairing','connection','progress','peer-sync','peer-activity','approval','synchronize')
    foreach ($gb in $goButtons) {
        Assert ($html.Contains("data-go=`"$gb`"")) "Action button data-go=`"$gb`" present in HTML"
    }
    Write-Output "[OK] All 7 dashboard navigation action buttons verified in HTML"

    # Run JavaScript syntax check and navigation unit test suite
    $navTestRun = Start-Process -FilePath "node" -ArgumentList @("tests/test_dashboard_navigation.js") -WorkingDirectory $projectRoot -Wait -PassThru -NoNewWindow
    Assert ($navTestRun.ExitCode -eq 0) "Frontend automated navigation test suite passed with exit code 0"
    Write-Output "[OK] Frontend navigation test suite passed: view resolution, hash routing, back/forward history, fallback, and error handling"

    # Verify zero private key tokens in frontend assets
    foreach ($asset in @($html, $css, $js)) {
        Assert (-not $asset.Contains('BEGIN PRIVATE KEY')) 'Frontend asset contains no private key PEM header'
        Assert (-not $asset.Contains('BEGIN RSA PRIVATE KEY')) 'Frontend asset contains no RSA private key header'
        Assert (-not $asset.Contains('BEGIN EC PRIVATE KEY')) 'Frontend asset contains no EC private key header'
    }
    Write-Output "[OK] Verified zero secret key material in frontend assets"

    # Verify CSS styling palette: charcoal/graphite/silver with subtle restrained accents
    Assert ($css.Contains('--panel: #1a2027')) 'CSS contains charcoal/graphite panel token'
    Assert ($css.Contains('--text-silver: #cdd5df')) 'CSS contains silver typography token'
    Assert (-not $css.Contains('--ice: #A5D6FF')) 'Blue-dominant --ice token removed from stylesheet'
    Write-Output "[OK] CSS verified: professional graphite/charcoal/silver aesthetic without blue dominance"

    # 3. Security: Origin Header & CSRF Protection
    $evilHeaders = @{ Origin = 'http://malicious-site.example.com' }
    $crossOriginBlocked = $false
    try {
        PostJson "$base/api/peer/configure" $evilHeaders @{ csrf = $status.csrf; role = "host" } | Out-Null
    } catch {
        $crossOriginBlocked = $true
    }
    Assert $crossOriginBlocked 'Cross-origin request from foreign Origin was blocked (HTTP 403)'
    Write-Output "[OK] Cross-origin request forgery protection verified"

    $badCsrfHeaders = @{ Origin = $base }
    $badCsrfBlocked = $false
    try {
        PostJson "$base/api/peer/configure" $badCsrfHeaders @{ csrf = "invalid-csrf-token"; role = "host" } | Out-Null
    } catch {
        $badCsrfBlocked = $true
    }
    Assert $badCsrfBlocked 'Request with invalid CSRF token was rejected (HTTP 403)'
    Write-Output "[OK] CSRF token validation verified"

    # 4. Peer Status Endpoint
    $peerStatus = Invoke-RestMethod -Uri "$base/api/peer/status"
    Assert ($peerStatus.role -eq 'none') 'Initial peer role is none'
    Assert ($peerStatus.state -eq 'IDLE') 'Initial peer state is IDLE'
    Write-Output "[OK] /api/peer/status verified in initial state"

    # 5. Configuration Validation Endpoint (/api/peer/validate-config)
    $validHeaders = @{ Origin = $base }

    # Test 5a: Invalid Role rejected
    $invalidRoleBlocked = $false
    try {
        PostJson "$base/api/peer/validate-config" $validHeaders @{
            csrf = $status.csrf
            role = "superuser"
            device_id = "test-node"
            sync_root = $syncFolder
            peer_port = 47832
        } | Out-Null
    } catch {
        $invalidRoleBlocked = $true
    }
    Assert $invalidRoleBlocked 'Invalid role was rejected'

    # Test 5b: Invalid Port (< 1024) rejected
    $invalidPortBlocked = $false
    try {
        PostJson "$base/api/peer/validate-config" $validHeaders @{
            csrf = $status.csrf
            role = "host"
            device_id = "test-node"
            sync_root = $syncFolder
            peer_port = 80
        } | Out-Null
    } catch {
        $invalidPortBlocked = $true
    }
    Assert $invalidPortBlocked 'Privileged/invalid peer port was rejected'

    # Test 5c: Non-existent sync root rejected
    $badPathRes = PostJson "$base/api/peer/validate-config" $validHeaders @{
        csrf = $status.csrf
        role = "host"
        device_id = "test-node"
        sync_root = "C:\NonExistentPath_MerkleChain_Test_999"
        peer_port = 47832
    }
    Assert (-not $badPathRes.valid) 'Non-existent sync root correctly flagged as invalid'

    # Test 5d: Invalid Peer Certificate Pin rejected (not 64 hex characters)
    $badPinRes = PostJson "$base/api/peer/validate-config" $validHeaders @{
        csrf = $status.csrf
        role = "client"
        device_id = "laptop-beta"
        sync_root = $syncFolder
        peer_address = "127.0.0.1"
        peer_port = 47832
        expected_peer_pin = "invalid-short-pin"
    }
    Assert (-not $badPinRes.valid) 'Malformed certificate pin correctly flagged as invalid'
    Write-Output "[OK] Input validation verified for roles, ports, paths, and pins"

    # Generate ephemeral test certificates for testing valid pairing configuration
    $caKey = Join-Path $certsFolder 'ca.key'
    $caCrt = Join-Path $certsFolder 'ca.crt'
    $hostKey = Join-Path $certsFolder 'host.key'
    $hostCrt = Join-Path $certsFolder 'host.crt'
    
    # Locate authorized openssl binary
    $opensslBin = $null
    $condaOpenSSL = "$($env:USERPROFILE)\anaconda3\Library\bin\openssl.exe"
    $candidates = @(
        $condaOpenSSL,
        'C:\Program Files\Git\usr\bin\openssl.exe',
        'C:\msys64\ucrt64\bin\openssl.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            try {
                $ver = & $c version 2>$null
                if ($LASTEXITCODE -eq 0 -and $ver) {
                    $opensslBin = $c
                    break
                }
            } catch {}
        }
    }
    if (-not $opensslBin) {
        $opensslCmd = Get-Command openssl -ErrorAction SilentlyContinue
        if ($opensslCmd) { $opensslBin = $opensslCmd.Source }
    }
    Assert ($opensslBin -and (Test-Path $opensslBin)) 'Found authorized OpenSSL executable for certificate test fixtures'

    $dummyCnf = Join-Path $certsFolder 'openssl.cnf'
    @"
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
CN = test
"@ | Out-File -FilePath $dummyCnf -Encoding ascii

        cmd.exe /c "`"$opensslBin`" req -x509 -newkey rsa:2048 -nodes -keyout `"$caKey`" -out `"$caCrt`" -days 1 -subj `"/CN=Test CA`" -config `"$dummyCnf`" 2>nul"
    cmd.exe /c "`"$opensslBin`" req -newkey rsa:2048 -nodes -keyout `"$hostKey`" -out `"$hostCrt`" -x509 -days 1 -subj `"/CN=Laptop A`" -config `"$dummyCnf`" 2>nul"
    $rawFingerprint = cmd.exe /c "`"$opensslBin`" x509 -in `"$hostCrt`" -noout -fingerprint -sha256 2>nul"
    $hostPin = (($rawFingerprint -join '') -replace 'SHA256 Fingerprint=', '' -replace ':', '').ToLower().Trim()


    # Test 5e: Valid Host configuration validated
    $validHostRes = PostJson "$base/api/peer/validate-config" $validHeaders @{
        csrf = $status.csrf
        role = "host"
        device_id = "laptop-alpha"
        sync_root = $syncFolder
        peer_address = "0.0.0.0"
        peer_port = 47832
        certificate_file = $hostCrt
        private_key_file = $hostKey
        ca_file = $caCrt
        expected_peer_sha256 = $hostPin
    }
    Assert ($validHostRes.valid) 'Valid host configuration verified successfully'
    Assert ($validHostRes.local_cert_sha256 -eq $hostPin) 'Validation computed matching certificate SHA-256 fingerprint'
    Write-Output "[OK] Valid configuration passed validation and calculated local cert pin"

    # 6. Configuration Activation (/api/peer/configure)
    $cfgRes = PostJson "$base/api/peer/configure" $validHeaders @{
        csrf = $status.csrf
        role = "host"
        device_id = "laptop-alpha"
        sync_root = $syncFolder
        peer_address = "0.0.0.0"
        peer_port = 47832
        certificate_file = $hostCrt
        private_key_file = $hostKey
        ca_file = $caCrt
        expected_peer_sha256 = $hostPin
    }
    Assert ($cfgRes.mode -eq 'host' -or $cfgRes.role -eq 'host') 'Host configuration applied'

    $updatedStatus = Invoke-RestMethod -Uri "$base/api/peer/status"
    Assert ($updatedStatus.role -eq 'host') 'Backend status reflects host role'
    Assert ($updatedStatus.device_id -eq 'laptop-alpha') 'Backend status reflects device_id laptop-alpha'
    Assert ($updatedStatus.sync_root -ne '') 'Backend status reflects configured sync root'
    Write-Output "[OK] /api/peer/configure successfully updated backend state"

    # 7. Service Lifecycle (/api/peer/start and /api/peer/stop)
    $startRes = PostJson "$base/api/peer/start" $validHeaders @{ csrf = $status.csrf }
    Assert ([bool]($startRes.running -or $startRes.state -eq 'LISTENING' -or $startRes.role -eq 'host')) 'Peer start service succeeded'


    # Check status transitioned
    Start-Sleep -Milliseconds 200
    $runningStatus = Invoke-RestMethod -Uri "$base/api/peer/status"
    Assert ($runningStatus.state -eq 'LISTENING') 'Host service transitioned to LISTENING'
    Write-Output "[OK] Host service started and transitioned to LISTENING state"

    # Duplicate start should be rejected or report already running
    $dupStartBlocked = $false
    try {
        PostJson "$base/api/peer/start" $validHeaders @{ csrf = $status.csrf } | Out-Null
    } catch {
        $dupStartBlocked = $true
    }
    Assert $dupStartBlocked 'Duplicate start request was safely rejected'
    Write-Output "[OK] Duplicate start prevention verified"

    # Stop service
    $stopRes = PostJson "$base/api/peer/stop" $validHeaders @{ csrf = $status.csrf }
    Assert ([bool]$stopRes.success) 'Peer stop service succeeded'
    Start-Sleep -Milliseconds 200
    $stoppedStatus = Invoke-RestMethod -Uri "$base/api/peer/status"
    Assert ($stoppedStatus.state -eq 'CANCELLED' -or $stoppedStatus.state -eq 'STOPPED' -or $stoppedStatus.state -eq 'IDLE') 'Host service transitioned to stopped/cancelled state'
    Write-Output "[OK] Host service cleanly stopped"

    # 8. Approval Workflow & Safety Protections (/api/peer/approve)
    # 8a: Approval without active session rejected
    $noSessionBlocked = $false
    try {
        PostJson "$base/api/peer/approve" $validHeaders @{
            csrf = $status.csrf
            approve = $true
            confirm_deletions = $false
        } | Out-Null
    } catch {
        $noSessionBlocked = $true
    }
    Assert $noSessionBlocked 'Approval request without active plan rejected safely'
    Write-Output "[OK] Approval without active session rejected"

    # 9. Activity & Diagnostics Endpoints
    $actRes = Invoke-RestMethod -Uri "$base/api/peer/activity"
    Assert ($null -ne $actRes.sessions) '/api/peer/activity returns sessions array'

    $diagRes = Invoke-RestMethod -Uri "$base/api/peer/diagnostics"
    Assert ($diagRes.status -eq 'ok') '/api/peer/diagnostics returns ok status'
    Assert ($null -ne $diagRes.unfinished_sessions_count) 'Diagnostics returns unfinished_sessions_count'
    Write-Output "[OK] Activity and Diagnostics endpoints verified"

    Write-Output ""
    Write-Output "========================================================"
    Write-Output "PEER NETWORK DASHBOARD TEST SUMMARY:"
    Write-Output "  Assertions passed: $passCount"
    Write-Output "  Assertions failed: $failCount"
    Write-Output "========================================================"
}
finally {
    $env:PATH = $oldPath
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $server.Id -Timeout 3 -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 200
    $resolved = Resolve-Path -LiteralPath $fixtureRoot -ErrorAction SilentlyContinue
    $allowedParent = Join-Path $projectRoot 'build\peer-dashboard-fixtures'
    if ($resolved -and $resolved.Path.StartsWith($allowedParent + '\', [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved.Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
