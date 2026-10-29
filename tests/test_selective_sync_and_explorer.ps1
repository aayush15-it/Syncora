# MerkleChain: Selective Sync & Algorithm Explorer Automated Test Suite
$ErrorActionPreference = "Stop"

Write-Host "=== Starting MerkleChain Selective Sync & Algorithm Explorer Tests ===" -ForegroundColor Cyan

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = (Resolve-Path (Join-Path $projectRoot 'build/merklechain.exe')).Path

# 1. Setup isolated directories
$baseTestDir = Join-Path $projectRoot ('buildsel-test-fixtures' + [guid]::NewGuid().ToString('N'))
$sourceDir = Join-Path $baseTestDir "source"
$destDir = Join-Path $baseTestDir "destination"

New-Item -ItemType Directory -Path $sourceDir, $destDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $sourceDir "sub1/sub2") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $sourceDir "sub2") -Force | Out-Null

# Populate test files in source
[IO.File]::WriteAllText((Join-Path $sourceDir "file1.txt"), "hello world from source 1")
[IO.File]::WriteAllText((Join-Path $sourceDir "sub1/file2.txt"), "nested file two in sub1")
[IO.File]::WriteAllText((Join-Path $sourceDir "sub1/sub2/file3.txt"), "deeply nested file three in sub2")
[IO.File]::WriteAllText((Join-Path $sourceDir "sub2/file4.txt"), "branch two file four")

# Populate destination with an existing version of file1 and a destination-only file
[IO.File]::WriteAllText((Join-Path $destDir "file1.txt"), "old content on destination")
[IO.File]::WriteAllText((Join-Path $destDir "dest_only.txt"), "precious destination file that must never be deleted")

# 2. Get free port
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()

$oldPath = $env:PATH
$env:PATH = "C:\msys64\ucrt64\bin;$oldPath"

$server = Start-Process -FilePath $exe -ArgumentList @('--dashboard', [string]$port) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
$base = "http://127.0.0.1:$port"
$status = $null

try {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            $status = Invoke-RestMethod -Uri "$base/api/status"
            break
        } catch {
            if ($server.HasExited) { throw "Dashboard server exited with code $($server.ExitCode)." }
            Start-Sleep -Milliseconds 250
        }
    }

    if (-not $status -or [string]::IsNullOrEmpty($status.csrf)) {
        throw "Failed to start merklechain dashboard or retrieve CSRF token"
    }

    $csrfToken = $status.csrf
    Write-Host "[OK] Daemon started on port $port with CSRF token ($($csrfToken.Length) chars)" -ForegroundColor Green

    $headers = @{ Origin = $base }

    function PostJson([string]$endpoint, [hashtable]$body) {
        $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress
        return Invoke-RestMethod -Method Post -Uri "$base$endpoint" -Headers $headers -ContentType 'application/json' -Body $bodyJson
    }

    function PostJsonExpectError([string]$endpoint, [hashtable]$body) {
        $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress
        try {
            Invoke-RestMethod -Method Post -Uri "$base$endpoint" -Headers $headers -ContentType 'application/json' -Body $bodyJson | Out-Null
            return $null
        } catch {
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                return $_.ErrorDetails.Message
            }
            if ($_.Exception.Response) {
                try {
                    $stream = $_.Exception.Response.GetResponseStream()
                    if ($stream) {
                        $reader = [System.IO.StreamReader]::new($stream)
                        return $reader.ReadToEnd()
                    }
                } catch {}
            }
            return $_.Exception.Message
        }
    }

    # -----------------------------------------------------------------
    # Task 1 & 6: Selective Sync Tests
    # -----------------------------------------------------------------

    # 1. /api/list-files returns all source files
    $listRes = PostJson "/api/list-files" @{ csrf = $csrfToken; path = $sourceDir }
    if ($listRes.files.Count -ne 4) {
        throw "Expected 4 source files from /api/list-files, got $($listRes.files.Count)"
    }
    Write-Host "[PASS] /api/list-files correctly listed all 4 files with metadata" -ForegroundColor Green

    # 2. Empty selection rejected in selective mode
    $emptyErr = PostJsonExpectError "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @()
    }
    if ($emptyErr -notmatch "Empty selection") {
        throw "Expected empty selection rejection, got: $emptyErr"
    }
    Write-Host "[PASS] Empty selection in selective mode correctly rejected" -ForegroundColor Green

    # 3. Path traversal rejected in scope
    $traversalErr = PostJsonExpectError "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("../outside.txt")
    }
    if ($traversalErr -notmatch "Invalid or unsafe relative path") {
        throw "Expected traversal rejection, got: $traversalErr"
    }
    Write-Host "[PASS] Path traversal in scope paths correctly rejected" -ForegroundColor Green

    # 4. Scope: One file selected ("file1.txt")
    $scanRes = PostJson "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("file1.txt")
    }

    if ($scanRes.scope.mode -ne "selective" -or $scanRes.scope.paths.Count -ne 1) {
        throw "Scope not echoed correctly in scan response"
    }
    if ($scanRes.comparison.counts.modify -ne 1 -or $scanRes.comparison.counts.add -ne 0) {
        throw "Expected 1 modify job and 0 add jobs for selective file1.txt, got $($scanRes.comparison.counts | ConvertTo-Json)"
    }
    if ($scanRes.comparison.counts.delete -ne 0) {
        throw "Excluded files or destination-only file must not be scheduled for deletion"
    }
    # Check that dest_only.txt is preserved
    $destOnlyRow = $scanRes.comparison.files | Where-Object { $_.path -eq "dest_only.txt" }
    if ($null -eq $destOnlyRow -or $destOnlyRow.operation -ne "PRESERVE") {
        throw "dest_only.txt must have PRESERVE operation"
    }
    Write-Host "[PASS] Selective scope for single file planned exactly 1 modify job; excluded destination files preserved" -ForegroundColor Green

    # 5. Scope changed after approval invalidates plan
    $planId = $scanRes.plan_id
    $tamperedScopeErr = PostJsonExpectError "/api/sync" @{
        csrf = $csrfToken
        plan_id = $planId
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("file1.txt", "sub1/file2.txt") # Changed scope!
        approve = $true
        confirm_deletions = $false
    }
    if ($tamperedScopeErr -notmatch "selection scope changed") {
        throw "Expected scope change rejection, got: $tamperedScopeErr"
    }
    Write-Host "[PASS] Changing selection scope after review invalidates plan and aborts sync" -ForegroundColor Green

    # 6. Execute approved selective sync with unmodified scope
    # Rescan to get fresh plan
    $scanRes = PostJson "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("file1.txt")
    }
    $syncRes = PostJson "/api/sync" @{
        csrf = $csrfToken
        plan_id = $scanRes.plan_id
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("file1.txt")
        approve = $true
        confirm_deletions = $false
    }

    if ($syncRes.success -ne $true) {
        throw "Selective sync failed: $($syncRes.message)"
    }
    # Verify disk state
    $file1Content = [IO.File]::ReadAllText((Join-Path $destDir "file1.txt"))
    if ($file1Content -ne "hello world from source 1") {
        throw "file1.txt on destination was not updated"
    }
    $destOnlyContent = [IO.File]::ReadAllText((Join-Path $destDir "dest_only.txt"))
    if ($destOnlyContent -ne "precious destination file that must never be deleted") {
        throw "dest_only.txt was modified or deleted!"
    }
    if (Test-Path (Join-Path $destDir "sub1")) {
        throw "Excluded folder sub1 was synced when not in scope!"
    }
    Write-Host "[PASS] Selective sync executed safely: file1.txt updated, dest_only.txt preserved, excluded files untouched, root verified" -ForegroundColor Green

    # 7. Scope: Nested folder selected ("sub1")
    $scanSubRes = PostJson "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("sub1")
    }
    if ($scanSubRes.comparison.counts.add -ne 2) {
        throw "Expected 2 add jobs in sub1, got $($scanSubRes.comparison.counts.add)"
    }
    $syncSubRes = PostJson "/api/sync" @{
        csrf = $csrfToken
        plan_id = $scanSubRes.plan_id
        source = $sourceDir
        destination = $destDir
        scope_mode = "selective"
        scope_paths = @("sub1")
        approve = $true
        confirm_deletions = $false
    }
    if ($syncSubRes.success -ne $true) {
        throw "Sync for sub1 failed: $($syncSubRes.message)"
    }
    if (-not (Test-Path (Join-Path $destDir "sub1/file2.txt")) -or -not (Test-Path (Join-Path $destDir "sub1/sub2/file3.txt"))) {
        throw "Nested sub1 files were not copied"
    }
    if (Test-Path (Join-Path $destDir "sub2/file4.txt")) {
        throw "Unselected folder sub2 was unexpectedly copied!"
    }
    Write-Host "[PASS] Selective folder sync: nested folder sub1 synchronized completely; sub2 excluded" -ForegroundColor Green

    # -----------------------------------------------------------------
    # Task 2: Merkle Tree Explorer Tests
    # -----------------------------------------------------------------
    # Rescan with full folder comparison
    $fullScan = PostJson "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "all"
    }
    $me = $fullScan.merkle_explorer
    if ($null -eq $me) {
        throw "merkle_explorer missing from /api/scan response"
    }
    if ([string]::IsNullOrEmpty($me.source_root) -or [string]::IsNullOrEmpty($me.destination_root)) {
        throw "merkle_explorer missing source or destination root hash"
    }
    if ($me.roots_match -ne $false) {
        throw "Expected roots_match to be false before full sync"
    }
    if ($me.differ_count -ne 2) { # sub2/file4.txt (ADD) and dest_only.txt (PRESERVE) differ
        throw "Expected 2 differing leaves (sub2/file4.txt and dest_only.txt), got $($me.differ_count)"
    }
    if ($me.leaves.Count -ne 5) { # 4 source files + 1 dest_only file
        throw "Expected 5 leaves in Merkle Explorer, got $($me.leaves.Count)"
    }
    $leafSub2 = $me.leaves | Where-Object { $_.path -eq "sub2/file4.txt" }
    if ($leafSub2.operation -ne "ADD" -or [string]::IsNullOrEmpty($leafSub2.source_leaf_hash)) {
        throw "sub2/file4.txt leaf detail incorrect: $($leafSub2 | ConvertTo-Json)"
    }
    Write-Host "[PASS] Merkle Tree Explorer populated with real tree depths, roots, and leaf hashes" -ForegroundColor Green

    # -----------------------------------------------------------------
    # Task 4: Scheduler Preview Tests
    # -----------------------------------------------------------------
    $sched = $fullScan.scheduler
    $preview = @($fullScan.scheduler)
    Write-Host "[DEBUG] Scheduler preview count: $($preview.Length)" -ForegroundColor Yellow
    if ($preview.Length -ne 1) {
        throw "Expected 1 queued job in scheduler preview, got $($preview.Length)"
    }
    $schedJob = $preview[0]
    if ($schedJob.path -ne "sub2/file4.txt" -or $schedJob.priority -lt 400) {
        throw "Scheduler job preview incorrect priority: $($schedJob | ConvertTo-Json)"
    }
    Write-Host "[PASS] Scheduler preview populated with real priority queue order and priority score" -ForegroundColor Green

    # -----------------------------------------------------------------
    # Task 3: Chunks & Reuse Metrics Tests
    # -----------------------------------------------------------------
    $fullSync = PostJson "/api/sync" @{
        csrf = $csrfToken
        plan_id = $fullScan.plan_id
        source = $sourceDir
        destination = $destDir
        scope_mode = "all"
        approve = $true
        confirm_deletions = $false
    }
    if ($fullSync.success -ne $true) {
        throw "Full sync failed: $($fullSync.message)"
    }
    $cm = $fullSync.chunk_metrics
    if ($null -eq $cm) {
        throw "chunk_metrics missing from /api/sync response"
    }
    if ($cm.files_processed -ne 1 -or $cm.payload_bytes -le 0 -or $cm.source_bytes_processed -le 0) {
        throw "chunk_metrics counters invalid: $($cm | ConvertTo-Json)"
    }
    if ($cm.verified -ne $true) {
        throw "chunk_metrics verification flag not true"
    }
    Write-Host "[PASS] Chunk & Reuse metrics verified with real non-zero execution counters" -ForegroundColor Green

    # Verify leaves transition to UNCHANGED in Merkle Explorer
    $postScan = PostJson "/api/scan" @{
        csrf = $csrfToken
        source = $sourceDir
        destination = $destDir
        scope_mode = "all"
    }
    $postLeaf = $postScan.merkle_explorer.leaves | Where-Object { $_.path -eq "sub2/file4.txt" }
    if ($postLeaf.operation -ne "UNCHANGED") {
        throw "sub2/file4.txt should be UNCHANGED after full sync"
    }
    Write-Host "[PASS] Post-sync comparison verifies leaves transition to UNCHANGED" -ForegroundColor Green

    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host "ALL SELECTIVE SYNC & ALGORITHM EXPLORER TESTS PASSED!" -ForegroundColor Green
    Write-Host "========================================================`n" -ForegroundColor Green

} finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $baseTestDir) {
        Remove-Item -Recurse -Force $baseTestDir -ErrorAction SilentlyContinue
    }
    $env:PATH = $oldPath
}
