$base = "http://localhost:8000"
$fails = 0

function Check($name, $ok) {
    if ($ok) { Write-Host "PASS  $name" -ForegroundColor Green }
    else { Write-Host "FAIL  $name" -ForegroundColor Red; $script:fails++ }
}

try {
    $h = Invoke-RestMethod "$base/healthz" -TimeoutSec 3
    Check "healthz" ($h.status -eq "ok")
} catch { Check "healthz" $false }

try {
    $e = Invoke-RestMethod "$base/api/events?limit=5" -TimeoutSec 3
    Check "events" ($null -ne $e)
} catch { Check "events" $false }

try {
    $body = @{ text = "URGENT: verify your PayPal account now" } | ConvertTo-Json
    $p = Invoke-RestMethod "$base/api/phish" -Method Post -Body $body -ContentType "application/json"
    Check "phish endpoint" ($null -ne $p.is_phishing)
} catch { Check "phish endpoint" $false }

try {
    $body = @{ source = "x = input()`neval(x)"; path = "test.py" } | ConvertTo-Json
    $c = Invoke-RestMethod "$base/api/code/scan" -Method Post -Body $body -ContentType "application/json"
    Check "code scanner" ($c.severity -eq "critical")
} catch { Check "code scanner" $false }

if ($fails -eq 0) {
    Write-Host "`nAll checks passed" -ForegroundColor Green
} else {
    Write-Host "`n$fails check(s) failed" -ForegroundColor Red
}