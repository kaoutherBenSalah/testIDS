# Cybersecurity Platform - Web Interface Startup Script (Windows)
# Run as Administrator for packet capture capabilities

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Cybersecurity Platform Web Interface" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️  WARNING: Not running as Administrator!" -ForegroundColor Yellow
    Write-Host "   Packet capture features may not work." -ForegroundColor Yellow
    Write-Host "   Consider running PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host ""
}

# Set location to project root
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

# Check if dependencies are installed
Write-Host "📦 Checking dependencies..." -ForegroundColor Yellow
try {
    python -c "import django" 2>$null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "✅ Dependencies OK" -ForegroundColor Green
} catch {
    Write-Host "❌ Django not installed!" -ForegroundColor Red
    Write-Host "   Run: pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Run migrations if needed
Write-Host "🔧 Running database migrations..." -ForegroundColor Yellow
python manage.py migrate --noinput

Write-Host ""
Write-Host "🚀 Starting web server..." -ForegroundColor Green
Write-Host ""
Write-Host "   Dashboard:  http://localhost:8000/" -ForegroundColor Cyan
Write-Host "   Attacker:   http://localhost:8000/attacker/" -ForegroundColor Cyan
Write-Host "   Defender:   http://localhost:8000/defender/" -ForegroundColor Cyan
Write-Host "   IDS:        http://localhost:8000/ids/" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

# Set PYTHONPATH and start server
$env:PYTHONPATH = "$scriptPath;$env:PYTHONPATH"
python manage.py runserver 0.0.0.0:8000
