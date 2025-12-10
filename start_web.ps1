# =============================================================================
# Cybersecurity Platform - Web Interface Startup Script (Windows)
# =============================================================================
# This script initializes and starts the Django web server for the IDS platform
# IMPORTANT: Run as Administrator for full packet capture capabilities
# 
# Features:
#   - Checks for Administrator privileges
#   - Validates Django installation
#   - Runs database migrations
#   - Starts the Django development server
# =============================================================================

# Display header banner with formatting
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Cybersecurity Platform Web Interface" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# ============ STEP 1: Check Administrator Privileges ============
# Retrieve current Windows principal identity
# Determine if the current PowerShell session has Administrator role
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If not running as Administrator, warn the user about packet capture limitations
if (-not $isAdmin) {
    Write-Host "⚠️  WARNING: Not running as Administrator!" -ForegroundColor Yellow
    Write-Host "   Packet capture features may not work." -ForegroundColor Yellow
    Write-Host "   Consider running PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host ""
}

# ============ STEP 2: Set Working Directory ============
# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
# Change to the project root directory
Set-Location $scriptPath

# ============ STEP 3: Check Dependencies ============
# Verify that Django is installed before proceeding
Write-Host "📦 Checking dependencies..." -ForegroundColor Yellow
try {
    # Try to import Django module via Python
    python -c "import django" 2>$null
    # Check if the previous command succeeded
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "✅ Dependencies OK" -ForegroundColor Green
} catch {
    # If Django is not found, display error and exit
    Write-Host "❌ Django not installed!" -ForegroundColor Red
    Write-Host "   Run: pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# ============ STEP 4: Run Database Migrations ============
# Execute Django migrations to create/update database tables
# --noinput: Skip interactive prompts
Write-Host "🔧 Running database migrations..." -ForegroundColor Yellow
python manage.py migrate --noinput

Write-Host ""

# ============ STEP 5: Display Server Information ============
# Show where the web interface will be accessible
Write-Host "🚀 Starting web server..." -ForegroundColor Green
Write-Host ""
Write-Host "   Dashboard:  http://localhost:8000/" -ForegroundColor Cyan
Write-Host "   Attacker:   http://localhost:8000/attacker/" -ForegroundColor Cyan
Write-Host "   Defender:   http://localhost:8000/defender/" -ForegroundColor Cyan
Write-Host "   IDS:        http://localhost:8000/ids/" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

# ============ STEP 6: Start Django Development Server ============
# Set PYTHONPATH to include current directory for module imports
$env:PYTHONPATH = "$scriptPath;$env:PYTHONPATH"
# Start Django development server on all interfaces (0.0.0.0) on port 8000
# This allows access from localhost and other machines on the network
python manage.py runserver 0.0.0.0:8000
