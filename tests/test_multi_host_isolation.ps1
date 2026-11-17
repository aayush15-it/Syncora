# Syncora / MerkleChain — Multi-Host & Multi-Client Isolation Verification Suite
param([string]$ExecutablePath = 'build/merklechain.exe')
$ErrorActionPreference = 'Stop'
[System.Net.ServicePointManager]::Expect100Continue = $false

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = if ([IO.Path]::IsPathRooted($ExecutablePath)) { $ExecutablePath } else { Join-Path $projectRoot $ExecutablePath }
$exe = (Resolve-Path -LiteralPath $exe).Path

$passCount = 0
$failCount = 0
$testResults = [System.Collections.Generic.List[PSObject]]::new()

function RecordResult([string]$name, [string]$expected, [string]$actual, [bool]$passed) {
    if ($passed) {
        $script:passCount++
        Write-Host "  [PASS] $name" -ForegroundColor Green
    } else {
        $script:failCount++
        Write-Host "  [FAIL] $($name): Expected '$expected', got '$actual'" -ForegroundColor Red
    }
    $script:testResults.Add([PSCustomObject]@{
        Name     = $name
        Expected = $expected
        Actual   = $actual
        Status   = if ($passed) { 'PASS' } else { 'FAIL' }
    })
}

function PostJson([string]$url, [hashtable]$headers, [hashtable]$body) {
    $json = $body | ConvertTo-Json -Compress -Depth 8
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/json' -Body $json
}

function GetJson([string]$url, [hashtable]$headers) {
    Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType 'application/json'
}

# Find free port
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$oldPath = $env:PATH
$server = $null

try {
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "  Syncora: Multi-Host & Multi-Client Isolation Verification Suite" -ForegroundColor Cyan
    Write-Host "================================================================================`n" -ForegroundColor Cyan

    $env:PATH = "C:\msys64\ucrt64\bin;$oldPath"
    $server = Start-Process -FilePath $exe -ArgumentList @('--dashboard', [string]$port) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    $base = "http://127.0.0.1:$port"

    # Server readiness
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
    RecordResult "Server Initialization" "Server online on port $port" "Server ready" $ready

    # =========================================================================
    # Test 1: Register Multiple Host Accounts & Enforce Unique Hostnames
    # =========================================================================
    Write-Host "`n[Group 1] Host Registration & Identity Management" -ForegroundColor Yellow

    $hostAlphaUser = "host_alpha_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $hostBetaUser  = "host_beta_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $hostAlphaPass = "AlphaHost@2026!"
    $hostBetaPass  = "BetaHost@2026!"

    # 1.1 Register Host Alpha
    $regAlpha = PostJson "$base/api/auth/register" @{} @{
        username = $hostAlphaUser
        password = $hostAlphaPass
    }
    RecordResult "Register Host Alpha" "success=true" "success=$($regAlpha.success)" ($regAlpha.success -eq $true)

    # 1.2 Register Host Beta
    $regBeta = PostJson "$base/api/auth/register" @{} @{
        username = $hostBetaUser
        password = $hostBetaPass
    }
    RecordResult "Register Host Beta" "success=true" "success=$($regBeta.success)" ($regBeta.success -eq $true)

    # 1.3 Reject Duplicate Host Username
    $dupRejected = $false
    try {
        PostJson "$base/api/auth/register" @{} @{
            username = $hostAlphaUser
            password = "AnotherPassword123!"
        } | Out-Null
    } catch {
        $dupRejected = $true
    }
    RecordResult "Reject Duplicate Host Username" "HTTP Error (Rejected)" $(if ($dupRejected) { "HTTP Error (Rejected)" } else { "Allowed duplicate" }) $dupRejected

    # =========================================================================
    # Test 2: Authenticate Independently & Verify Clean Zero Baseline
    # =========================================================================
    Write-Host "`n[Group 2] Host Authentication & Clean Zero Baseline" -ForegroundColor Yellow

    # 2.1 Authenticate Host Alpha
    $loginAlpha = PostJson "$base/api/auth/login" @{} @{
        username = $hostAlphaUser
        password = $hostAlphaPass
    }
    $tokenAlpha = $loginAlpha.session_token
    $hdrAlpha = @{ 'Authorization' = "Bearer $tokenAlpha" }
    RecordResult "Authenticate Host Alpha" "Token received" "Token length=$($tokenAlpha.Length)" (![string]::IsNullOrEmpty($tokenAlpha))

    # 2.2 Authenticate Host Beta
    $loginBeta = PostJson "$base/api/auth/login" @{} @{
        username = $hostBetaUser
        password = $hostBetaPass
    }
    $tokenBeta = $loginBeta.session_token
    $hdrBeta = @{ 'Authorization' = "Bearer $tokenBeta" }
    RecordResult "Authenticate Host Beta" "Token received" "Token length=$($tokenBeta.Length)" (![string]::IsNullOrEmpty($tokenBeta))

    # 2.3 Verify Host Alpha gets dedicated workspace
    $alphaWss = GetJson "$base/api/host/workspaces" $hdrAlpha
    $wsAlphaId = $alphaWss.workspaces[0].id
    RecordResult "Host Alpha Dedicated Workspace" "1 dedicated workspace" "workspaces count=$($alphaWss.workspaces.Count), id=$wsAlphaId" ($alphaWss.workspaces.Count -ge 1 -and ![string]::IsNullOrEmpty($wsAlphaId))

    # 2.4 Verify Host Beta gets dedicated workspace
    $betaWss = GetJson "$base/api/host/workspaces" $hdrBeta
    $wsBetaId = $betaWss.workspaces[0].id
    RecordResult "Host Beta Dedicated Workspace" "1 dedicated workspace" "workspaces count=$($betaWss.workspaces.Count), id=$wsBetaId" ($betaWss.workspaces.Count -ge 1 -and ![string]::IsNullOrEmpty($wsBetaId))
    RecordResult "Distinct Workspaces for Hosts" "wsAlpha != wsBeta" "wsAlpha=$wsAlphaId, wsBeta=$wsBetaId" ($wsAlphaId -ne $wsBetaId)

    # 2.5 Verify Clean Zero Baseline for Host Alpha
    $alphaClients = GetJson "$base/api/host/clients" $hdrAlpha
    $alphaSubs = GetJson "$base/api/host/submissions" $hdrAlpha
    $alphaVers = GetJson "$base/api/host/workspaces/versions" $hdrAlpha
    $alphaZeroClients = ($alphaClients.clients.Count -eq 0)
    $alphaZeroSubs    = ($alphaSubs.submissions.Count -eq 0)
    $alphaZeroVers    = ($alphaVers.versions.Count -eq 0)
    RecordResult "Host Alpha Clean Zero Clients Baseline" "0 clients" "Count=$($alphaClients.clients.Count)" $alphaZeroClients
    RecordResult "Host Alpha Clean Zero Submissions Baseline" "0 submissions" "Count=$($alphaSubs.submissions.Count)" $alphaZeroSubs
    RecordResult "Host Alpha Clean Zero Versions Baseline" "0 versions" "Count=$($alphaVers.versions.Count)" $alphaZeroVers

    # 2.6 Verify Clean Zero Baseline for Host Beta
    $betaClients = GetJson "$base/api/host/clients" $hdrBeta
    $betaSubs = GetJson "$base/api/host/submissions" $hdrBeta
    $betaVers = GetJson "$base/api/host/workspaces/versions" $hdrBeta
    $betaZeroClients = ($betaClients.clients.Count -eq 0)
    $betaZeroSubs    = ($betaSubs.submissions.Count -eq 0)
    $betaZeroVers    = ($betaVers.versions.Count -eq 0)
    RecordResult "Host Beta Clean Zero Clients Baseline" "0 clients" "Count=$($betaClients.clients.Count)" $betaZeroClients
    RecordResult "Host Beta Clean Zero Submissions Baseline" "0 submissions" "Count=$($betaSubs.submissions.Count)" $betaZeroSubs
    RecordResult "Host Beta Clean Zero Versions Baseline" "0 versions" "Count=$($betaVers.versions.Count)" $betaZeroVers

    # =========================================================================
    # Test 3: Client Creation and Host Binding
    # =========================================================================
    Write-Host "`n[Group 3] Client Creation & Ownership Binding" -ForegroundColor Yellow

    $clientA1User = "client_a1_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $clientA2User = "client_a2_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $clientB1User = "client_b1_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $clientB2User = "client_b2_" + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $clientPass   = "ClientSecure@2026!"

    # 3.1 Host Alpha creates Client A1 & Client A2
    $newA1 = PostJson "$base/api/host/clients" $hdrAlpha @{ username = $clientA1User; password = $clientPass; workspace_id = $wsAlphaId }
    $newA2 = PostJson "$base/api/host/clients" $hdrAlpha @{ username = $clientA2User; password = $clientPass; workspace_id = $wsAlphaId }
    $clientA1Id = $newA1.user.id
    $clientA2Id = $newA2.user.id
    RecordResult "Host Alpha Creates Client A1" "Created" "id=$clientA1Id" (![string]::IsNullOrEmpty($clientA1Id))
    RecordResult "Host Alpha Creates Client A2" "Created" "id=$clientA2Id" (![string]::IsNullOrEmpty($clientA2Id))

    # 3.2 Host Beta creates Client B1 & Client B2
    $newB1 = PostJson "$base/api/host/clients" $hdrBeta @{ username = $clientB1User; password = $clientPass; workspace_id = $wsBetaId }
    $newB2 = PostJson "$base/api/host/clients" $hdrBeta @{ username = $clientB2User; password = $clientPass; workspace_id = $wsBetaId }
    $clientB1Id = $newB1.user.id
    $clientB2Id = $newB2.user.id
    RecordResult "Host Beta Creates Client B1" "Created" "id=$clientB1Id" (![string]::IsNullOrEmpty($clientB1Id))
    RecordResult "Host Beta Creates Client B2" "Created" "id=$clientB2Id" (![string]::IsNullOrEmpty($clientB2Id))

    # 3.3 Verify Client list isolation: Host Alpha sees exactly A1 and A2 (Count = 2)
    $alphaClientsAfter = GetJson "$base/api/host/clients" $hdrAlpha
    $alphaClientUsernames = @($alphaClientsAfter.clients | ForEach-Object { $_.username })
    $alphaSeesOnlyA = ($alphaClientsAfter.clients.Count -eq 2 -and ($alphaClientUsernames -contains $clientA1User) -and -not ($alphaClientUsernames -contains $clientB1User))
    RecordResult "Host Alpha Client List Isolation" "Sees 2 clients (A1, A2; no B1, B2)" "Count=$($alphaClientsAfter.clients.Count), HasB1=$($alphaClientUsernames -contains $clientB1User)" $alphaSeesOnlyA

    # 3.4 Verify Client list isolation: Host Beta sees exactly B1 and B2 (Count = 2)
    $betaClientsAfter = GetJson "$base/api/host/clients" $hdrBeta
    $betaClientUsernames = @($betaClientsAfter.clients | ForEach-Object { $_.username })
    $betaSeesOnlyB = ($betaClientsAfter.clients.Count -eq 2 -and ($betaClientUsernames -contains $clientB1User) -and -not ($betaClientUsernames -contains $clientA1User))
    RecordResult "Host Beta Client List Isolation" "Sees 2 clients (B1, B2; no A1, A2)" "Count=$($betaClientsAfter.clients.Count), HasA1=$($betaClientUsernames -contains $clientA1User)" $betaSeesOnlyB

    # =========================================================================
    # Test 4: Client Authentication and Workspace Association
    # =========================================================================
    Write-Host "`n[Group 4] Client Authentication & Session Verification" -ForegroundColor Yellow

    # 4.1 Authenticate Client A1
    $loginA1 = PostJson "$base/api/auth/login" @{} @{ username = $clientA1User; password = $clientPass }
    $tokenA1 = $loginA1.session_token
    $hdrA1 = @{ 'Authorization' = "Bearer $tokenA1" }
    RecordResult "Authenticate Client A1" "Token received" "Token=$($tokenA1.Length) chars" (![string]::IsNullOrEmpty($tokenA1))

    # 4.2 Authenticate Client B1
    $loginB1 = PostJson "$base/api/auth/login" @{} @{ username = $clientB1User; password = $clientPass }
    $tokenB1 = $loginB1.session_token
    $hdrB1 = @{ 'Authorization' = "Bearer $tokenB1" }
    RecordResult "Authenticate Client B1" "Token received" "Token=$($tokenB1.Length) chars" (![string]::IsNullOrEmpty($tokenB1))

    # 4.3 Authenticate Client A2 & B2
    $loginA2 = PostJson "$base/api/auth/login" @{} @{ username = $clientA2User; password = $clientPass }
    $tokenA2 = $loginA2.session_token
    $hdrA2 = @{ 'Authorization' = "Bearer $tokenA2" }
    $loginB2 = PostJson "$base/api/auth/login" @{} @{ username = $clientB2User; password = $clientPass }
    $tokenB2 = $loginB2.session_token
    $hdrB2 = @{ 'Authorization' = "Bearer $tokenB2" }

    # =========================================================================
    # Test 5: Cross-Tenant Submission and Workspace Access Attacks
    # =========================================================================
    Write-Host "`n[Group 5] Cross-Tenant Attacks & Parameter Tampering" -ForegroundColor Yellow

    # Prepare temp files for submissions
    $fixDir = (Join-Path $projectRoot ('build\multi-host-fixtures\' + [guid]::NewGuid().ToString('N'))).Replace('\', '/')
    $a1Dir = "$fixDir/a1_src"
    New-Item -ItemType Directory -Path $a1Dir -Force | Out-Null
    Set-Content -Path "$a1Dir/alpha_doc.txt" -Value "Alpha private content from Client A1"

    # 5.1 Client A1 attempts to list submissions for Host Beta's workspace -> MUST BE REJECTED (403)
    $a1CrossListBlocked = $false
    try {
        GetJson "$base/api/client/submissions?workspace_id=$wsBetaId" $hdrA1 | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $a1CrossListBlocked = $true }
    }
    RecordResult "Cross-Tenant: A1 Listing Beta Submissions" "HTTP 403 Forbidden" $(if ($a1CrossListBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $a1CrossListBlocked

    # 5.2 Client A1 attempts to submit files targeting Host Beta's workspace -> MUST BE REJECTED (403)
    $a1CrossSubmitBlocked = $false
    try {
        PostJson "$base/api/client/submissions" $hdrA1 @{
            workspace_id = $wsBetaId
            source_folder = $a1Dir
            commit_message = "Malicious submission into Beta workspace"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $a1CrossSubmitBlocked = $true }
    }
    RecordResult "Cross-Tenant: A1 Submitting to Beta Workspace" "HTTP 403 Forbidden" $(if ($a1CrossSubmitBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $a1CrossSubmitBlocked

    # 5.3 Client A1 submits files targeting Host Alpha's workspace -> MUST SUCCEED (200)
    $subA1 = PostJson "$base/api/client/submissions" $hdrA1 @{
        workspace_id = $wsAlphaId
        source_folder = $a1Dir
        commit_message = "Legitimate submission into Alpha workspace"
    }
    $subA1Id = $subA1.submission.id
    RecordResult "Legitimate: A1 Submitting to Alpha Workspace" "HTTP 200 OK" "submission_id=$subA1Id" (![string]::IsNullOrEmpty($subA1Id))

    # 5.4 Cross-Tenant Approval Attack: Host Beta attempts to ACCEPT Client A1's submission -> MUST BE REJECTED (403)
    $betaAcceptBlocked = $false
    try {
        PostJson "$base/api/host/submissions/$subA1Id/accept" $hdrBeta @{
            review_notes = "Unauthorized approval from Host Beta"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $betaAcceptBlocked = $true }
    }
    RecordResult "Cross-Tenant: Host Beta Accepting Alpha Submission" "HTTP 403 Forbidden" $(if ($betaAcceptBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $betaAcceptBlocked

    # 5.5 Cross-Tenant Rejection Attack: Host Beta attempts to REJECT Client A1's submission -> MUST BE REJECTED (403)
    $betaRejectBlocked = $false
    try {
        PostJson "$base/api/host/submissions/$subA1Id/reject" $hdrBeta @{
            review_notes = "Unauthorized rejection from Host Beta"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $betaRejectBlocked = $true }
    }
    RecordResult "Cross-Tenant: Host Beta Rejecting Alpha Submission" "HTTP 403 Forbidden" $(if ($betaRejectBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $betaRejectBlocked

    # 5.6 Legitimate Approval: Host Alpha accepts Client A1's submission -> MUST SUCCEED (200)
    $alphaAccept = PostJson "$base/api/host/submissions/$subA1Id/accept" $hdrAlpha @{
        review_notes = "Authorized approval by Host Alpha"
    }
    RecordResult "Legitimate: Host Alpha Accepting Alpha Submission" "success=true" "success=$($alphaAccept.success)" ($alphaAccept.success -eq $true)

    # 5.7 Cross-Tenant Publish Attack: Host Beta attempts to publish version in Alpha's workspace -> MUST BE REJECTED (403)
    $betaPublishBlocked = $false
    try {
        PostJson "$base/api/host/workspaces/publish" $hdrBeta @{
            workspace_id = $wsAlphaId
            version_label = "Malicious v1.0 by Beta"
            notes = "Attempting to overwrite Alpha versions"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $betaPublishBlocked = $true }
    }
    RecordResult "Cross-Tenant: Host Beta Publishing in Alpha Workspace" "HTTP 403 Forbidden" $(if ($betaPublishBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $betaPublishBlocked

    # 5.8 Legitimate Publish: Host Alpha publishes version in Alpha's workspace -> MUST SUCCEED (200)
    $alphaPub = PostJson "$base/api/host/workspaces/publish" $hdrAlpha @{
        workspace_id = $wsAlphaId
        title = "Alpha Release v1.0"
        version_label = "Alpha Release v1.0"
        release_notes = "First verified release for Host Alpha"
        notes = "First verified release for Host Alpha"
    }
    RecordResult "Legitimate: Host Alpha Publishing Version" "success=true" "success=$($alphaPub.success), version=$($alphaPub.version.version_label)" ($alphaPub.success -eq $true)

    # =========================================================================
    # Test 6: Version Distribution and Update Notification Isolation
    # =========================================================================
    Write-Host "`n[Group 6] Version Distribution & Update Notification Isolation" -ForegroundColor Yellow

    # 6.1 Client A1 checks updates -> receives update notification
    $updA1 = GetJson "$base/api/client/updates" $hdrA1
    $a1GotUpdate = ($updA1.updates.Count -ge 1 -and ($updA1.updates[0].version_title -eq "Alpha Release v1.0" -or $updA1.updates[0].version_label -eq "Alpha Release v1.0" -or $updA1.updates[0].version_title -eq "v1.0"))
    RecordResult "Update Distribution: Client A1 Receives Alpha Update" "1 update notification" "Count=$($updA1.updates.Count)" $a1GotUpdate

    # 6.2 Client A2 checks updates -> receives update notification
    $updA2 = GetJson "$base/api/client/updates" $hdrA2
    $a2GotUpdate = ($updA2.updates.Count -ge 1 -and ($updA2.updates[0].version_title -eq "Alpha Release v1.0" -or $updA2.updates[0].version_label -eq "Alpha Release v1.0" -or $updA2.updates[0].version_title -eq "v1.0"))
    RecordResult "Update Distribution: Client A2 Receives Alpha Update" "1 update notification" "Count=$($updA2.updates.Count)" $a2GotUpdate

    # 6.3 Client B1 checks updates -> MUST RECEIVE 0 updates (strictly isolated from Alpha releases)
    $updB1 = GetJson "$base/api/client/updates" $hdrB1
    $b1NoAlphaUpdate = ($updB1.updates.Count -eq 0)
    RecordResult "Update Isolation: Client B1 Receives Zero Alpha Updates" "0 updates" "Count=$($updB1.updates.Count)" $b1NoAlphaUpdate

    # 6.4 Client B2 checks updates -> MUST RECEIVE 0 updates
    $updB2 = GetJson "$base/api/client/updates" $hdrB2
    $b2NoAlphaUpdate = ($updB2.updates.Count -eq 0)
    RecordResult "Update Isolation: Client B2 Receives Zero Alpha Updates" "0 updates" "Count=$($updB2.updates.Count)" $b2NoAlphaUpdate

    # =========================================================================
    # Test 7: Cross-Tenant File & Chunk Download Attacks
    # =========================================================================
    Write-Host "`n[Group 7] File & Chunk Download Authorization" -ForegroundColor Yellow

    # 7.1 Client B1 attempts to download Alpha's published file -> MUST BE REJECTED (403)
    $b1DownloadBlocked = $false
    try {
        GetJson "$base/api/client/download?workspace_id=$wsAlphaId&path=alpha_doc.txt" $hdrB1 | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $b1DownloadBlocked = $true }
    }
    RecordResult "Cross-Tenant Download: Client B1 Accessing Alpha File" "HTTP 403 Forbidden" $(if ($b1DownloadBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $b1DownloadBlocked

    # =========================================================================
    # Test 8: Cross-Tenant Client Account Management (IDOR Attacks)
    # =========================================================================
    Write-Host "`n[Group 8] Client Account Management Isolation (IDOR)" -ForegroundColor Yellow

    # 8.1 Host Alpha attempts to SUSPEND Host Beta's Client (Client B1) -> MUST BE REJECTED (403)
    $suspendBlocked = $false
    try {
        PostJson "$base/api/host/clients/$clientB1Id/suspend" $hdrAlpha @{} | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $suspendBlocked = $true }
    }
    RecordResult "IDOR Attack: Host Alpha Suspending Beta's Client B1" "HTTP 403 Forbidden" $(if ($suspendBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $suspendBlocked

    # 8.2 Host Alpha attempts to RESET PASSWORD of Host Beta's Client (Client B1) -> MUST BE REJECTED (403)
    $resetBlocked = $false
    try {
        PostJson "$base/api/host/clients/$clientB1Id/reset-password" $hdrAlpha @{
            new_password = "HackedPassword123!"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $resetBlocked = $true }
    }
    RecordResult "IDOR Attack: Host Alpha Resetting Beta Client Password" "HTTP 403 Forbidden" $(if ($resetBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $resetBlocked

    # 8.3 Host Beta attempts to SUSPEND Host Alpha's Client (Client A1) -> MUST BE REJECTED (403)
    $betaSuspendBlocked = $false
    try {
        PostJson "$base/api/host/clients/$clientA1Id/suspend" $hdrBeta @{} | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $betaSuspendBlocked = $true }
    }
    RecordResult "IDOR Attack: Host Beta Suspending Alpha's Client A1" "HTTP 403 Forbidden" $(if ($betaSuspendBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $betaSuspendBlocked

    # =========================================================================
    # Test 9: Branching and Working Copy Isolation
    # =========================================================================
    Write-Host "`n[Group 9] Branching & Working Copy Isolation" -ForegroundColor Yellow

    # 9.1 Host Beta attempts to inspect branches of Alpha's workspace -> MUST BE REJECTED (403)
    $branchInspectBlocked = $false
    try {
        GetJson "$base/api/collab/branches?workspace_id=$wsAlphaId" $hdrBeta | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $branchInspectBlocked = $true }
    }
    RecordResult "Cross-Tenant Branch: Host Beta Inspecting Alpha Branches" "HTTP 403 Forbidden" $(if ($branchInspectBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $branchInspectBlocked

    # 9.2 Host Beta attempts to create branch in Alpha's workspace -> MUST BE REJECTED (403)
    $branchCreateBlocked = $false
    try {
        PostJson "$base/api/collab/branches" $hdrBeta @{
            workspace_id = $wsAlphaId
            branch_name = "feature/malicious-branch"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $branchCreateBlocked = $true }
    }
    RecordResult "Cross-Tenant Branch: Host Beta Creating Branch in Alpha" "HTTP 403 Forbidden" $(if ($branchCreateBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $branchCreateBlocked

    # 9.3 Client A1 attempts to switch branch in Beta's workspace -> MUST BE REJECTED (403)
    $branchSwitchBlocked = $false
    try {
        PostJson "$base/api/collab/branches/switch" $hdrA1 @{
            workspace_id = $wsBetaId
            branch_name = "main"
        } | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) { $branchSwitchBlocked = $true }
    }
    RecordResult "Cross-Tenant Branch: Client A1 Switching Branch in Beta" "HTTP 403 Forbidden" $(if ($branchSwitchBlocked) { "HTTP 403 Forbidden" } else { "Not rejected" }) $branchSwitchBlocked

    # =========================================================================
    # Test 10: Activity Log Isolation
    # =========================================================================
    Write-Host "`n[Group 10] Activity Log & Security Event Scoping" -ForegroundColor Yellow

    $actAlpha = GetJson "$base/api/host/activity" $hdrAlpha
    $actAlphaItems = if ($actAlpha.events) { $actAlpha.events } else { $actAlpha.activity }
    $actAlphaTexts = @($actAlphaItems | ForEach-Object { "$($_.event_type) $($_.details)" })
    $actAlphaClean = -not ($actAlphaTexts -match $hostBetaUser -or $actAlphaTexts -match $clientB1User)
    RecordResult "Activity Log Isolation: Host Alpha Sees No Beta Events" "No Beta events in Alpha log" "Alpha log clean=$actAlphaClean" $actAlphaClean

    $actBeta = GetJson "$base/api/host/activity" $hdrBeta
    $actBetaItems = if ($actBeta.events) { $actBeta.events } else { $actBeta.activity }
    $actBetaTexts = @($actBetaItems | ForEach-Object { "$($_.event_type) $($_.details)" })
    $actBetaClean = -not ($actBetaTexts -match $hostAlphaUser -or $actBetaTexts -match $clientA1User)
    RecordResult "Activity Log Isolation: Host Beta Sees No Alpha Events" "No Alpha events in Beta log" "Beta log clean=$actBetaClean" $actBetaClean

    # =========================================================================
    # Test 11: Database Security & Password Hashing Verification
    # =========================================================================
    Write-Host "`n[Group 11] Database Security & Password Hashing" -ForegroundColor Yellow

    $dbFile = Join-Path $projectRoot '.merklechain\collab.sqlite3'
    if (Test-Path $dbFile) {
        $sqliteScript = @"
.headers on
.mode json
SELECT id, username, role, password_hash FROM users WHERE username IN ('$hostAlphaUser', '$clientA1User');
"@
        $userRecordsJson = & "C:\msys64\ucrt64\bin\sqlite3.exe" $dbFile $sqliteScript
        $userRecords = $userRecordsJson | ConvertFrom-Json
        $allHashed = $true
        foreach ($u in $userRecords) {
            # Format must be pbkdf2_sha256$<iterations>$<salt>$<hash>
            if (-not ($u.password_hash -like "pbkdf2_sha256$*")) {
                $allHashed = $false
            }
        }
        RecordResult "Password Hashing (PBKDF2-SHA256)" "Format: pbkdf2_sha256$<iter>$<salt>$<hash>" "All pass: $allHashed" $allHashed
    }

    # =========================================================================
    # Test 12: Session Logout and Token Revocation
    # =========================================================================
    Write-Host "`n[Group 12] Session Expiration & Logout Revocation" -ForegroundColor Yellow

    # Host Alpha logs out
    $logoutAlpha = PostJson "$base/api/auth/logout" $hdrAlpha @{}
    RecordResult "Host Alpha Logout" "success=true" "success=$($logoutAlpha.success)" ($logoutAlpha.success -eq $true)

    # Subsequent request with old token must return 401 Unauthorized
    $revokedBlocked = $false
    try {
        GetJson "$base/api/host/clients" $hdrAlpha | Out-Null
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) { $revokedBlocked = $true }
    }
    RecordResult "Revoked Session Invalidation" "HTTP 401 Unauthorized" $(if ($revokedBlocked) { "HTTP 401 Unauthorized" } else { "Token still valid" }) $revokedBlocked

} finally {
    $env:PATH = $oldPath
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
    if ($fixDir -and (Test-Path $fixDir)) {
        Remove-Item -Path $fixDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  Summary: $($script:passCount) PASSED, $($script:failCount) FAILED" -ForegroundColor $(if ($script:failCount -eq 0) { 'Green' } else { 'Red' })
Write-Host "================================================================================`n" -ForegroundColor Cyan

if ($script:failCount -gt 0) {
    exit 1
} else {
    exit 0
}
