param([string]$ExecutablePath = 'build/merklechain.exe')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exe = if ([IO.Path]::IsPathRooted($ExecutablePath)) { $ExecutablePath } else { Join-Path $projectRoot $ExecutablePath }
$exe = (Resolve-Path -LiteralPath $exe).Path
$fixtureRoot = Join-Path $projectRoot ('build\dashboard-smoke-fixtures\' + [guid]::NewGuid().ToString('N'))
$source = Join-Path $fixtureRoot 'source'
$destination = Join-Path $fixtureRoot 'destination'
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start(); $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop()
$oldPath = $env:PATH
$server = $null
function Assert([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
function PostJson([string]$url, [hashtable]$headers, [hashtable]$body) {
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress -Depth 8)
}
try {
    New-Item -ItemType Directory -Path $source, $destination -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $source 'add.txt') -Value 'new payload' -NoNewline
    Set-Content -LiteralPath (Join-Path $source 'edit.txt') -Value 'updated payload' -NoNewline
    Set-Content -LiteralPath (Join-Path $destination 'edit.txt') -Value 'old payload' -NoNewline
    Set-Content -LiteralPath (Join-Path $destination 'keep.txt') -Value 'destination only' -NoNewline

    $env:PATH = "C:\msys64\ucrt64\bin;$oldPath"
    $server = Start-Process -FilePath $exe -ArgumentList @('--dashboard', [string]$port) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    $base = "http://127.0.0.1:$port"
    $status = $null
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try { $status = Invoke-RestMethod -Uri "$base/api/status"; break }
        catch { if ($server.HasExited) { throw "Dashboard exited with code $($server.ExitCode)." }; Start-Sleep -Milliseconds 250 }
    }
    Assert ([bool]$status) 'Dashboard status endpoint did not become ready.'
    Assert ($status.mode -eq 'local' -and -not $status.network_enabled) 'Dashboard status must identify Local Mode with networking disabled.'
    $html = (Invoke-WebRequest -UseBasicParsing -Uri "$base/").Content
    foreach ($page in @('Overview','Synchronize','Devices &amp; Access','Versions','Algorithm Explorer','Merkle tree','Chunks &amp; reuse','Scheduler','Activity &amp; Diagnostics','Settings')) { Assert ($html.Contains($page)) "Dashboard page missing: $page" }
    Assert (-not $html.Contains('id="view-benchmarks"')) 'Benchmarks view cleanly removed'
    Assert (-not $html.Contains('data-view="benchmarks"')) 'Benchmarks nav link cleanly removed'
    $headers = @{ Origin = $base }
    $scan = PostJson "$base/api/scan" $headers @{ csrf=$status.csrf; source=$source; destination=$destination }
    $files = @($scan.comparison.files)
    $addRow = $files | Where-Object { $_.path -eq 'add.txt' -and $_.operation -eq 'ADD' }; Assert ([bool]$addRow -and [bool]$addRow.source_hash) 'ADD leaf or source digest missing.'
    $modifyRow = $files | Where-Object { $_.path -eq 'edit.txt' -and $_.operation -eq 'MODIFY' }; Assert ([bool]$modifyRow -and [bool]$modifyRow.source_hash -and [bool]$modifyRow.destination_hash) 'MODIFY leaf digests missing.'
    $preserveRow = $files | Where-Object { $_.path -eq 'keep.txt' -and $_.operation -eq 'PRESERVE' }; Assert ([bool]$preserveRow -and [bool]$preserveRow.destination_hash) 'Destination-only PRESERVE row/digest missing.'
    Assert (@($scan.scheduler).Count -eq 2 -and $null -ne $scan.scheduler[0].priority -and $null -ne $scan.scheduler[0].size) 'Scheduler queue preview is missing ordering inputs.'
    Assert ($null -ne $addRow.source_modified_ms -and $addRow.source_modified_ms -gt 0) 'Source modification time missing from file details.'

    $rejected = $false
    try { PostJson "$base/api/sync" $headers @{ csrf=$status.csrf; plan_id=$scan.plan_id; source=$source; destination=$destination; approve=$false; confirm_deletions=$false } | Out-Null }
    catch { $rejected = $true }
    Assert $rejected 'Unapproved synchronization was not rejected.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $destination 'add.txt'))) 'Unapproved request mutated the destination.'

    Set-Content -LiteralPath (Join-Path $source 'add.txt') -Value 'changed after review' -NoNewline
    $staleRejected = $false
    try { PostJson "$base/api/sync" $headers @{ csrf=$status.csrf; plan_id=$scan.plan_id; source=$source; destination=$destination; approve=$true; confirm_deletions=$false } | Out-Null }
    catch { $staleRejected = $true }
    Assert $staleRejected 'Stale reviewed plan was not rejected.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $destination 'add.txt'))) 'Stale plan mutated the destination.'

    $scan = PostJson "$base/api/scan" $headers @{ csrf=$status.csrf; source=$source; destination=$destination }
    $sync = PostJson "$base/api/sync" $headers @{ csrf=$status.csrf; plan_id=$scan.plan_id; source=$source; destination=$destination; approve=$true; confirm_deletions=$false }
    Assert ($sync.success -and $sync.final_merkle_root -eq $sync.expected_merkle_root) 'Approved synchronization failed final Merkle verification.'
    Assert ([bool]($sync.jobs | Where-Object { $_.path -eq 'add.txt' -and $_.verified -and $_.bytes_transferred -gt 0 })) 'Sync response omitted verified payload byte accounting.'
    Assert ((Get-Content -Raw -LiteralPath (Join-Path $destination 'keep.txt')) -eq 'destination only') 'Destination-only file was not preserved.'
    $activity = PostJson "$base/api/activity" $headers @{ csrf=$status.csrf; destination=$destination }
    Assert (@($activity.activity).Count -gt 0) 'Activity endpoint returned no recorded sync rows.'
    $versions = PostJson "$base/api/versions" $headers @{ csrf=$status.csrf; destination=$destination }
    Assert (@($versions.versions).Count -ge 2) 'Pre/post synchronization snapshots were not listed.'
    Write-Output 'PASS all dashboard views served'
    Write-Output 'PASS scan returned roots, leaf hashes, preservation rows, and scheduler preview inputs'
    Write-Output 'PASS approval rejection and stale-plan mutation checks'
    Write-Output 'PASS approved sync, final-root verification, and destination-only preservation'
    Write-Output 'PASS real SQLite activity and version history endpoints'
}
finally {
    $env:PATH = $oldPath
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
    $resolved = Resolve-Path -LiteralPath $fixtureRoot -ErrorAction SilentlyContinue
    $allowedParent = Join-Path $projectRoot 'build\dashboard-smoke-fixtures'
    if ($resolved -and $resolved.Path.StartsWith($allowedParent + '\', [StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $resolved.Path -Recurse -Force }
}
