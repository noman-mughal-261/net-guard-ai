# End-to-end test: Docker Compose stack + HTTP checks.
# Prerequisites: Docker Desktop (or Docker Engine) running.
# Run from repository root:  .\scripts\e2e_test.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==> docker compose up --build -d"
docker compose up --build -d

$base = "http://127.0.0.1:8000"
$deadline = (Get-Date).AddSeconds(120)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-RestMethod -Uri "$base/api/health" -Method Get -TimeoutSec 5
        if ($r.mongodb -eq $true -and $r.model_loaded -eq $true) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $ready) {
    Write-Error "API did not become ready (Mongo + model). Check: docker compose logs api"
    docker compose logs api --tail 80
    exit 1
}

Write-Host "==> API health OK; running HTTP checks"
$code = 1
if (Get-Command python -ErrorAction SilentlyContinue) {
    python scripts/e2e_test.py --base-url $base --frontend-url http://127.0.0.1:8080
    $code = $LASTEXITCODE
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 scripts/e2e_test.py --base-url $base --frontend-url http://127.0.0.1:8080
    $code = $LASTEXITCODE
} else {
    Write-Host "Python not found; running minimal checks in PowerShell only"
    $bodyObj = Get-Content -Raw "$Root\data\sample_single_flow.json" | ConvertFrom-Json
    $sourceIp = $bodyObj.source_ip
    $feat = @{}
    $bodyObj.PSObject.Properties | ForEach-Object {
        if ($_.Name -ne "source_ip") { $feat[$_.Name] = $_.Value }
    }
    $analyzeBody = @{ source_ip = $sourceIp; features = $feat } | ConvertTo-Json -Depth 6
    Invoke-RestMethod -Uri "$base/api/analyze" -Method Post -Body $analyzeBody -ContentType "application/json" | Out-Null
    Invoke-RestMethod -Uri "$base/api/logs?limit=5" -Method Get | Out-Null
    Invoke-RestMethod -Uri "$base/api/analytics/summary" -Method Get | Out-Null
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:8080/" -UseBasicParsing -TimeoutSec 15 | Out-Null
        Write-Host "OK  GET frontend /"
    } catch {
        Write-Warning "Frontend check skipped or failed: $_"
    }
    Write-Host "OK  minimal API checks"
    $code = 0
}

Write-Host "==> docker compose down"
docker compose down

exit $code
