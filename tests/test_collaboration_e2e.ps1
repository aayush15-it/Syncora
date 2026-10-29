# MerkleChain — Host-Client Collaboration End-to-End Integration & Security Test Suite
param([string]$ExecutablePath = 'build/merklechain.exe')
$ErrorActionPreference = 'Stop'
[System.Net.ServicePointManager]::Expect100Continue = $false

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = if ([IO.Path]::IsPathRooted($ExecutablePath)) { $ExecutablePath } else { Join-Path $projectRoot $ExecutablePath }
$exe = (Resolve-Path -LiteralPath $exe).Path

$fixtureRoot = (Join-Path $projectRoot ('build\collab-fixtures\' + [guid]::NewGuid().ToString('N'))).Replace('\', '/')
$clientSrc = (Join-Path $fixtureRoot 'alice_src').Replace('\', '/')
$clientTarget = (Join-Path $fixtureRoot 'alice_target').Replace('\', '/')

$passCount = 0
$failCount = 0

function Assert([bool]$condition, [string]$message) {
    if (-not $condition) {
        $script:failCount++
        throw "ASSERTION FAILED: $message"
    }
    $script:passCount++
    Write-Host "  [PASS] $message" -ForegroundColor Green
}

function PostJson([string]$url, [hashtable]$headers, [hashtable]$body) {
    $json = $body | ConvertTo-Json -Compress -Depth 8
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/json' -Body $json
}

# Find free port
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$oldPath = $env:PATH
$server = $null

try {
    Write-Host "=== Starting MerkleChain Host-Client Collaboration E2E Test Suite ===" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $clientSrc, $clientTarget -Force | Out-Null

    # Create test source files for Alice
    Set-Content -Path (Join-Path $clientSrc "document.txt") -Value "Initial submission from Alice.`r`nVersion 0 draft.`r`n"
    Set-Content -Path (Join-Path $clientSrc "readme.md") -Value "# Alice Project`r`nFirst commit."
    New-Item -ItemType Directory -Path (Join-Path $clientSrc "sub") -Force | Out-Null
    Set-Content -Path (Join-Path $clientSrc "sub\helper.cpp") -Value "int main() { return 0; }"

    # Start dashboard server
    $env:PATH = "C:\msys64\ucrt64\bin;$oldPath"
    $server = Start-Process -FilePath $exe -ArgumentList @('--dashboard', [string]$port) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    $base = "http://127.0.0.1:$port"

    # Wait for server readiness
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $st = Invoke-RestMethod -Uri "$base/api/status"
            if ($st -and $st.csrf) { $ready = $true; break }
        } catch {
            if ($server.HasExited) { throw "Server exited prematurely with code $($server.ExitCode)" }
            Start-Sleep -Milliseconds 250
        }
    }
    Assert $ready "Server successfully booted on port $port"

    # 1. Host Authentication
    Write-Host "`n1. Host Authentication..." -ForegroundColor Yellow
    $hostLogin = PostJson "$base/api/auth/login" @{} @{
        username = "host"
        password = "MerkleHost2026!"
    }
    Assert ($hostLogin.success -eq $true) "Host authenticated successfully"
    Assert ($hostLogin.user.role -eq 'host') "Host role is verified"
    $hostToken = $hostLogin.session_token
    Assert (![string]::IsNullOrEmpty($hostToken)) "Received host session token ($($hostToken.Length) chars)"

    $hostHeaders = @{ 'Authorization' = "Bearer $hostToken" }

    # 2. Host creates Client Account (Alice)
    $aliceUser = "alice_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    Write-Host "`n2. Client Account Provisioning ($aliceUser)..." -ForegroundColor Yellow
    $createClient = PostJson "$base/api/host/clients" $hostHeaders @{
        username = $aliceUser
        password = "alicepassword123"
        permissions = @("submit", "view_versions", "download_updates", "accept_updates")
    }
    Assert ($createClient.success -eq $true) "Client Alice provisioned by Host"
    $clientId = $createClient.user.id

    # Verify clients list
    $clientsList = Invoke-RestMethod -Uri "$base/api/host/clients" -Headers $hostHeaders
    Assert ($clientsList.clients.Count -ge 2) "Host client list contains newly added client (plus seeded client)"
    $aliceInfo = $clientsList.clients | Where-Object { $_.id -eq $clientId }
    Assert ($aliceInfo.username -eq $aliceUser) "Alice client record confirmed in database"

    # 3. Client Authentication (Alice)
    Write-Host "`n3. Client Authentication (Alice)..." -ForegroundColor Yellow
    $aliceLogin = PostJson "$base/api/auth/login" @{} @{
        username = $aliceUser
        password = "alicepassword123"
    }
    Assert ($aliceLogin.success -eq $true) "Alice authenticated successfully"
    Assert ($aliceLogin.user.role -eq 'client') "Alice role is verified"
    $aliceToken = $aliceLogin.session_token
    $aliceHeaders = @{ 'Authorization' = "Bearer $aliceToken" }

    # Verify Alice cannot call Host-only endpoint (RBAC check)
    Write-Host "`n4. Role-Based Access Control (RBAC) Enforcement..." -ForegroundColor Yellow
    $forbiddenHostCall = $false
    try {
        Invoke-RestMethod -Uri "$base/api/host/clients" -Headers $aliceHeaders
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) {
            $forbiddenHostCall = $true
        }
    }
    Assert $forbiddenHostCall "Alice received HTTP 403 when attempting Host-only endpoint"

    # 4. Client Submits Folder
    Write-Host "`n5. Client Submission..." -ForegroundColor Yellow
    $submissionRes = PostJson "$base/api/client/submissions" $aliceHeaders @{
        workspace_id = "ws-default"
        source_folder = $clientSrc
    }
    Assert ($submissionRes.success -eq $true) "Alice folder submitted successfully"
    Assert ($submissionRes.submission.file_count -eq 3) "Submission captured all 3 files"
    Assert (![string]::IsNullOrEmpty($submissionRes.submission.merkle_root)) "Submission computed valid Merkle root ($($submissionRes.submission.merkle_root.Length) hex)"
    $subId = $submissionRes.submission.id

    # 5. Host Inspects Submissions & Accepts
    Write-Host "`n6. Host Review and Working Copy..." -ForegroundColor Yellow
    $subs = Invoke-RestMethod -Uri "$base/api/host/submissions" -Headers $hostHeaders
    $aliceSub = $subs.submissions | Where-Object { $_.id -eq $subId }
    Assert ($aliceSub -ne $null) "Host sees Alice's submission in queue"
    Assert ($aliceSub.status -eq 'PENDING') "Submission status is PENDING"

    # Host accepts submission to establish baseline and working copy
    $acceptRes = PostJson "$base/api/host/submissions" $hostHeaders @{
        submission_id = $subId
        action = "accept"
        notes = "Accepting Alice's initial draft"
    }
    Assert ($acceptRes.success -eq $true) "Host accepted submission into workspace"

    # Host loads workspace files
    $wsFiles = Invoke-RestMethod -Uri "$base/api/host/workspaces/files?workspace_id=ws-default" -Headers $hostHeaders
    Assert ($wsFiles.files.Count -eq 3) "Host workspace contains 3 working files"

    # 6. Host Inspects and Edits Working Copy
    $docFile = Invoke-RestMethod -Uri "$base/api/host/workspaces/files/content?workspace_id=ws-default&path=document.txt" -Headers $hostHeaders
    Assert ($docFile.content.Contains("Initial submission from Alice")) "Host inspected Alice's document content"

    # Host edits the document
    $editedContent = "Initial submission from Alice.`r`nVersion 1 approved with edits by Host.`r`nAdded line 3.`r`n"
    $editRes = PostJson "$base/api/host/workspaces/files/content" $hostHeaders @{
        workspace_id = "ws-default"
        path = "document.txt"
        content = $editedContent
    }
    Assert ($editRes.success -eq $true) "Host saved edits to working copy"

    # 7. Host Diff Check
    Write-Host "`n7. Diff Calculation..." -ForegroundColor Yellow
    $diffRes = Invoke-RestMethod -Uri "$base/api/host/workspaces/diff?workspace_id=ws-default&path=document.txt" -Headers $hostHeaders
    Assert ($diffRes.change_type -eq 'MODIFIED') "File diff correctly identified as MODIFIED"
    Assert ($diffRes.lines.Count -gt 0) "Diff calculated between original submission and edited working copy"
    Write-Host "     Diff summary: $($diffRes.lines.Count) line change entries"

    # Check overall changes summary
    $changesRes = Invoke-RestMethod -Uri "$base/api/host/workspaces/changes?workspace_id=ws-default" -Headers $hostHeaders
    Assert ($changesRes.counts.modified -eq 1) "Changes summary reports 1 modified file"
    Assert ($changesRes.counts.unchanged -eq 2) "Changes summary reports 2 unchanged files"

    # 8. Host Approves and Publishes Version
    Write-Host "`n8. Version Publishing..." -ForegroundColor Yellow
    $publishRes = PostJson "$base/api/host/workspaces/publish" $hostHeaders @{
        workspace_id = "ws-default"
        title = "v1.1-approved"
        summary = "Reviewed and finalized Alice feature branch."
    }
    Assert ($publishRes.success -eq $true) "Host published version $($publishRes.version.title)"
    Assert (![string]::IsNullOrEmpty($publishRes.version.merkle_root)) "Published version has Merkle root $($publishRes.version.merkle_root.Substring(0, 16))..."
    $pubVerId = $publishRes.version.id

    # 9. Client Polls Updates
    Write-Host "`n9. Client Update Polling..." -ForegroundColor Yellow
    $updatesRes = Invoke-RestMethod -Uri "$base/api/client/updates" -Headers $aliceHeaders
    $myUpdate = $updatesRes.updates | Where-Object { $_.version_id -eq $pubVerId }
    Assert ($myUpdate -ne $null) "Alice received update notification for version $pubVerId"
    $updateId = $myUpdate.id

    # 10. Client Applies Update to Local Target Folder
    Write-Host "`n10. Client Update Application..." -ForegroundColor Yellow
    $applyRes = PostJson "$base/api/client/updates" $aliceHeaders @{
        update_id = $updateId
        action = "apply"
        target_folder = $clientTarget
    }
    Assert ($applyRes.success -eq $true) "Client successfully applied update to target folder"

    # Verify Target Folder Contents & Integrity
    $targetDoc = Join-Path $clientTarget "document.txt"
    Assert (Test-Path $targetDoc) "Target document.txt exists"
    $targetDocContent = Get-Content -Path $targetDoc -Raw
    Assert ($targetDocContent.Contains("Version 1 approved with edits by Host")) "Target document matches Host published content"
    Assert (Test-Path (Join-Path $clientTarget "sub\helper.cpp")) "Target subfolder files unpacked correctly"

    # 11. Host Version History & Activity Log
    Write-Host "`n11. Version History and Audit Logs..." -ForegroundColor Yellow
    $hostVersions = Invoke-RestMethod -Uri "$base/api/host/workspaces/versions?workspace_id=ws-default" -Headers $hostHeaders
    Assert ($hostVersions.versions.Count -ge 1) "Host version list records published release"

    $hostActivity = Invoke-RestMethod -Uri "$base/api/host/activity" -Headers $hostHeaders
    Assert ($hostActivity.events.Count -ge 3) "Host audit log tracks submissions, edits, and publication events"

    # 12. Session Invalidation / Logout
    Write-Host "`n12. Authentication Lifecycle and Logout..." -ForegroundColor Yellow
    $logoutRes = PostJson "$base/api/auth/logout" $aliceHeaders @{}
    Assert ($logoutRes.success -eq $true) "Alice successfully logged out"

    $revokedBlocked = $false
    try {
        Invoke-RestMethod -Uri "$base/api/client/updates" -Headers $aliceHeaders
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) {
            $revokedBlocked = $true
        }
    }
    Assert $revokedBlocked "Logged-out token immediately rejected with HTTP 401 Unauthorized"

    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "COLLABORATION E2E TEST SUMMARY: $passCount passed, $failCount failed" -ForegroundColor Green
    Write-Host "========================================================`n" -ForegroundColor Cyan
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
    $env:PATH = $oldPath
    if (Test-Path $fixtureRoot) {
        Remove-Item -Path $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
