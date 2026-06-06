# Start standalone Tor (Scoop: scoop install tor) so SOCKS5 is available at 127.0.0.1:9050.
# VoidAccess reads TOR_PROXY_HOST / TOR_PROXY_PORT from .env (defaults match this).
# Tor Browser uses port 9150 by default; if you only run the browser, set TOR_PROXY_PORT=9150.

$ErrorActionPreference = "Stop"
$port = 9050

if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    Write-Host "Tor already listening on 127.0.0.1:$port"
    exit 0
}

$torShim = Join-Path $env:USERPROFILE "scoop\shims\tor.exe"
$wd = Join-Path $env:USERPROFILE "scoop\apps\tor\current"

if (-not (Test-Path $torShim)) {
    Write-Error "Tor shim not found at $torShim. Install with: scoop install tor"
}

Start-Process -FilePath $torShim -WorkingDirectory $wd -WindowStyle Hidden
Write-Host "Started tor; SOCKS5 at 127.0.0.1:$port (wait a few seconds before scraping)."
