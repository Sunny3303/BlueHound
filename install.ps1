# ─────────────────────────────────────────────────────────────────────────────
# BlueHound — Install Script (Windows PowerShell)
# Run with:  powershell -ExecutionPolicy Bypass -File install.ps1
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

function Write-Info    { Write-Host "[*] $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warn    { Write-Host "[!] $args" -ForegroundColor Yellow }
function Write-Fail    { Write-Host "[X] $args" -ForegroundColor Red; exit 1 }

# ── Banner ───────────────────────────────────────────────────────────────────
Write-Host @"
`n
  ██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
  ██╔══██╗██║     ██║   ██║██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
  ██████╔╝██║     ██║   ██║█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
  ██╔══██╗██║     ██║   ██║██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
  ██████╔╝███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝

  Active Directory Threat Modeling Engine — Installer
"@ -ForegroundColor Blue

# ── 1. Python version check ──────────────────────────────────────────────────
Write-Info "Checking Python version..."

try {
    $pyver = python --version 2>&1
} catch {
    Write-Fail "Python not found. Install Python 3.11+ from https://python.org and re-run."
}

$match = $pyver -match "Python (\d+)\.(\d+)"
if (-not $match) { Write-Fail "Could not determine Python version." }

$major = [int]$Matches[1]
$minor = [int]$Matches[2]

if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 11)) {
    Write-Fail "Python 3.11+ required. Found: $pyver"
}

Write-Success "Python $major.$minor"

# ── 2. pip check ─────────────────────────────────────────────────────────────
Write-Info "Checking pip..."
try { python -m pip --version | Out-Null } catch { Write-Fail "pip not available." }
Write-Success "pip available"

# ── 3. Neo4j check ───────────────────────────────────────────────────────────
Write-Info "Checking Neo4j on bolt://localhost:7687..."

$neo4jOk = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("localhost", 7687)
    $tcp.Close()
    $neo4jOk = $true
} catch {}

if ($neo4jOk) {
    Write-Success "Neo4j reachable at bolt://localhost:7687"
} else {
    Write-Warn "Neo4j not detected on localhost:7687"
    Write-Host ""
    Write-Host "  BlueHound requires Neo4j 5.x Community (or Enterprise)."
    Write-Host "  Download from: https://neo4j.com/download/"
    Write-Host ""
    Write-Host "  After installing Neo4j Desktop or the Windows service:"
    Write-Host "    neo4j-admin dbms set-initial-password <yourpassword>"
    Write-Host ""
    $reply = Read-Host "  Continue anyway? [y/N]"
    if ($reply -notmatch "^[Yy]$") { Write-Host "Aborting."; exit 0 }
}

# ── 4. Install BlueHound ─────────────────────────────────────────────────────
Write-Info "Installing BlueHound..."

$isLocalRepo = (Test-Path "pyproject.toml") -and ((Get-Content "pyproject.toml" -Raw) -match 'name = "bluehound"')

if ($isLocalRepo) {
    Write-Info "Local repo detected — running editable install..."
    python -m pip install -e ".[dev]" --quiet
} else {
    Write-Info "Installing from PyPI..."
    python -m pip install bluehound --quiet
}

Write-Success "BlueHound installed"

# ── 5. Verify CLI ────────────────────────────────────────────────────────────
Write-Info "Verifying installation..."

$bhPath = (Get-Command bluehound -ErrorAction SilentlyContinue)?.Source

if (-not $bhPath) {
    # Check Scripts directory in user Python path
    $userScripts = python -c "import site; print(site.getusersitepackages())" 2>$null
    Write-Warn "'bluehound' not found on PATH."
    Write-Host ""
    Write-Host "  Add your Python Scripts folder to PATH, then restart your terminal."
    Write-Host "  Typical path:  %APPDATA%\Python\Python3xx\Scripts"
    Write-Host ""
} else {
    $ver = bluehound --version 2>&1
    Write-Success "bluehound $ver"
}

# ── 6. Config setup ──────────────────────────────────────────────────────────
$configDir  = "$env:USERPROFILE\.bluehound"
$configFile = "$configDir\config.json"

if (-not (Test-Path $configFile)) {
    Write-Info "Creating default config at $configFile..."
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    @"
{
  "neo4j": {
    "uri": "bolt://localhost:7687",
    "username": "neo4j"
  }
}
"@ | Set-Content $configFile -Encoding UTF8
    Write-Success "Config written (password will be prompted at runtime)"
}

# ── 7. Done ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  BlueHound installed successfully!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  Quick start:"
Write-Host ""
Write-Host "    1. Ingest SharpHound data:"
Write-Host "         bluehound ingest your-data.zip"
Write-Host ""
Write-Host "    2. Analyze a snapshot:"
Write-Host "         bluehound analyze snapshots\<timestamp>"
Write-Host ""
Write-Host "    3. Open the dashboard:"
Write-Host "         http://localhost:8080"
Write-Host ""
Write-Host "    4. Compare two snapshots:"
Write-Host "         bluehound diff snapshots\<baseline> snapshots\<current>"
Write-Host ""
Write-Host "    bluehound --help    for all commands"
Write-Host ""
