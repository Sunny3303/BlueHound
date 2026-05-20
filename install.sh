#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# BlueHound — Install Script (Linux / macOS)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
BLUE='\033[1;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "${BLUE}"
cat <<'EOF'
██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
██╔══██╗██║     ██║   ██║██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██████╔╝██║     ██║   ██║█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██╗██║     ██║   ██║██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██████╔╝███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
EOF
echo -e "${NC}"
echo -e "  Active Directory Threat Modeling Engine — Installer"
echo ""

# ── 1. Python version check ──────────────────────────────────────────────────
info "Checking Python version..."

if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install Python 3.11+ and re-run."
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11 ]]; then
    error "Python 3.11+ required. Found: $PY_VERSION"
fi

success "Python $PY_VERSION"

# ── 2. pip check ─────────────────────────────────────────────────────────────
info "Checking pip..."

if ! python3 -m pip --version &>/dev/null; then
    error "pip not found. Install pip and re-run."
fi

success "pip available"

# ── 3. Neo4j check ───────────────────────────────────────────────────────────
info "Checking Neo4j..."

NEO4J_OK=false

# Check if Bolt port is reachable
if command -v nc &>/dev/null; then
    if nc -z localhost 7687 2>/dev/null; then
        NEO4J_OK=true
    fi
elif command -v curl &>/dev/null; then
    if curl -sf http://localhost:7474 &>/dev/null; then
        NEO4J_OK=true
    fi
fi

if $NEO4J_OK; then
    success "Neo4j reachable at bolt://localhost:7687"
else
    warn "Neo4j not detected on localhost:7687"
    echo ""
    echo "  BlueHound requires Neo4j 5.x Community (or Enterprise)."
    echo "  Quick install options:"
    echo ""
    echo "    Linux (apt):   sudo apt install neo4j"
    echo "    macOS (brew):  brew install neo4j && brew services start neo4j"
    echo "    Manual:        https://neo4j.com/download/"
    echo ""
    echo "  After installing Neo4j, set an initial password:"
    echo "    neo4j-admin dbms set-initial-password <yourpassword>"
    echo ""
    read -rp "  Continue anyway? [y/N] " REPLY
    [[ "$REPLY" =~ ^[Yy]$ ]] || { echo "Aborting."; exit 0; }
fi

# ── 4. Install BlueHound ─────────────────────────────────────────────────────
info "Installing BlueHound..."

# Detect if we're inside the repo (editable install) or should install from PyPI
if [[ -f "pyproject.toml" ]] && grep -q 'name = "bluehound"' pyproject.toml 2>/dev/null; then
    info "Detected local repo — running editable install..."
    python3 -m pip install -e ".[dev]" --quiet
else
    info "Installing from PyPI..."
    python3 -m pip install bluehound --quiet
fi

success "BlueHound installed"

# ── 5. Verify CLI ────────────────────────────────────────────────────────────
info "Verifying installation..."

if ! command -v bluehound &>/dev/null; then
    # pip installed to user bin that may not be on PATH
    USER_BIN=$(python3 -m site --user-base)/bin
    if [[ -f "$USER_BIN/bluehound" ]]; then
        warn "'bluehound' not on PATH. Add the following to your shell profile:"
        echo ""
        echo "    export PATH=\"$USER_BIN:\$PATH\""
        echo ""
    else
        warn "'bluehound' CLI not found. Try: python3 -m pip install --user bluehound"
    fi
else
    BH_VERSION=$(bluehound --version 2>&1)
    success "bluehound $BH_VERSION"
fi

# ── 6. Config setup ──────────────────────────────────────────────────────────
CONFIG_DIR="$HOME/.bluehound"
CONFIG_FILE="$CONFIG_DIR/config.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
    info "Creating default config at $CONFIG_FILE..."
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<JSON
{
  "neo4j": {
    "uri": "bolt://localhost:7687",
    "username": "neo4j"
  }
}
JSON
    success "Config written (password will be prompted at runtime)"
fi

# ── 7. Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  BlueHound installed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Quick start:"
echo ""
echo "    1. Ingest SharpHound data:"
echo "         bluehound ingest your-data.zip"
echo ""
echo "    2. Analyze a snapshot:"
echo "         bluehound analyze snapshots/<timestamp>"
echo ""
echo "    3. Open the dashboard:"
echo "         http://localhost:8080"
echo ""
echo "    4. Compare two snapshots:"
echo "         bluehound diff snapshots/<baseline> snapshots/<current>"
echo ""
echo "    bluehound --help    for all commands"
echo ""
