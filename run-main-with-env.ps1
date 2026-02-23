$env:DP_SINGBOX_SIDECAR_ADDR = '127.0.0.1:19081'

$configPath = Join-Path $PSScriptRoot 'config.yaml'
$subscriptionUseEnvProxy = $false
$subscriptionProxyEnabled = $false
$subscriptionProxyURL = ''

$inSubscriptionProxyBlock = $false
foreach ($line in Get-Content $configPath) {
    if ($line -match '^\s*subscription_use_env_proxy:\s*(.+?)\s*$') {
        $subscriptionUseEnvProxy = ($Matches[1].Trim().ToLower() -eq 'true')
        continue
    }

    if ($line -match '^\s*subscription_proxy:\s*$') {
        $inSubscriptionProxyBlock = $true
        continue
    }

    if ($inSubscriptionProxyBlock -and $line -match '^[A-Za-z0-9_]+\s*:') {
        $inSubscriptionProxyBlock = $false
    }

    if (-not $inSubscriptionProxyBlock) {
        continue
    }

    if ($line -match '^\s*enabled:\s*(.+?)\s*$') {
        $subscriptionProxyEnabled = ($Matches[1].Trim().ToLower() -eq 'true')
        continue
    }

    if ($line -match '^\s*url:\s*"?([^"#]+)"?\s*(#.*)?$') {
        $subscriptionProxyURL = $Matches[1].Trim()
        continue
    }
}

if ($subscriptionProxyEnabled -and -not [string]::IsNullOrWhiteSpace($subscriptionProxyURL)) {
    $env:HTTP_PROXY = $subscriptionProxyURL
    $env:HTTPS_PROXY = $subscriptionProxyURL
    Write-Host "[run-main] use subscription proxy from config: $subscriptionProxyURL"
} elseif ($subscriptionUseEnvProxy) {
    Write-Host "[run-main] keep existing HTTP_PROXY/HTTPS_PROXY from environment"
} else {
    Remove-Item Env:HTTP_PROXY -ErrorAction SilentlyContinue
    Remove-Item Env:HTTPS_PROXY -ErrorAction SilentlyContinue
    Write-Host "[run-main] subscription proxy disabled"
}

& 'C:\Program Files\Go\bin\go.exe' run .\main.go
