# BlueHound

**Active Directory Threat Modeling Engine** — analyzes SharpHound data to detect attack paths to Tier-0 assets, score behavioral risk, and track security posture over time.

```
██████╗ ██╗     ██╗   ██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
██╔══██╗██║     ██║   ██║██╔════╝██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██████╔╝██║     ██║   ██║█████╗  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██╔══██╗██║     ██║   ██║██╔══╝  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██████╔╝███████╗╚██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
```

---

## Features

- **Five detection categories** covering 12 individually tuned rules across privilege exposure, Kerberos abuse, delegation misconfiguration, ADCS exploitation, and Tier-0 reachability
- **Four-dimensional behavioral risk scoring** — Stealth (30%), Exploitability (25%), Persistence (25%), Blast Radius (20%) — producing a normalized 0–10 global score
- **Snapshot diffing engine** for detecting privilege creep, new attack paths, and Tier-0 exposure regressions between assessments
- **REST API + React dashboard** — pre-built frontend served directly from the Python package with no separate server required
- **Write-guard** on all Neo4j mutations so analysis runs are always read-only
- **PyPI distribution** — a single `pip install bluehound` installs everything including the compiled dashboard

---

## Quick Start

### PyPI

```bash
pip install bluehound
bluehound --version
```

### From Source

```bash
git clone https://github.com/vShresthh/BlueHound
cd bluehound
pip install -e ".[dev]"
```

### Windows (PowerShell)

```powershell
.\install.ps1
```

### Linux / macOS (Shell)

```bash
chmod +x install.sh && ./install.sh
```

---

## Usage

```bash
# 1. Ingest a SharpHound collection ZIP into Neo4j
bluehound ingest XXXXXXXXXXXXXXXXX.zip

# 2. Analyze the ingested snapshot
bluehound analyze snapshots/20XX-XX-XX_XXXXXX/

# 3. Open the dashboard
#    http://localhost:8080

# 4. Start the dashboard server manually against saved results
bluehound serve --port 8080

# 5. Diff two snapshots to track posture change
bluehound diff .bluehound\results\baseline .bluehound\results\current

# 6. List all snapshots
bluehound list-snapshots
```

---

## Architecture

```
SharpHound ZIP
      │
      ▼
┌──────────────────┐
│   Ingestion      │  SharpHoundIngester — normalizes, validates,
│   Layer          │  writes to Neo4j, saves snapshot metadata
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Graph          │  GraphView — cached, typed, read-only view
│   Abstraction    │  over Neo4j nodes and relationships
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Detection      │  DetectionContext — pre-computed indexes:
│   Context        │  admin_to_computers, group_closure, tier0_sids,
│                  │  ACE lookups, certificate template data
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Detection      │  DetectionEngine orchestrates 5 category modules
│   Engine         │  → 12 rules → List[Finding]
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Risk Scoring   │  EdgeRiskEvaluator + RiskEngine → RiskResult
│   Engine         │  (global score, exposure level, attack paths)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Output         │  ThreatModelAssembler → ThreatModelResult JSON
│   Assembly       │  saved to .bluehound/results/
└────────┬─────────┘
         │
         ├───────────────────────────────┐
         ▼                               ▼
┌──────────────────┐         ┌──────────────────────┐
│   Diff Engine    │         │   API + Dashboard    │
│   (optional)     │         │   FastAPI + React    │
│   SnapshotDiff   │         │   localhost:8080     │
└──────────────────┘         └──────────────────────┘
```

---

## Detection Category Index

| ID | Category | Rules | MITRE Coverage |
|----|----------|-------|----------------|
| **A** | Privilege & Identity Exposure | A1 Excessive Local Admin · A2 Orphaned Privileged Accounts · A3 Hidden Privileged Membership · A4 Dangerous ACEs on Tier-0 | T1078, T1484.001 |
| **B** | Kerberos Abuse | B1 Kerberoastable Accounts · B2 AS-REP Roastable · B3 SPN on Human Accounts | T1558.003, T1558.004 |
| **C** | Delegation Abuse | C1 Unconstrained Delegation · C2 RBCD to Tier-0 · C3 Machine Account Quota | T1134.001, T1098 |
| **D** | ADCS Exploitation | D1 ESC1 Vulnerable Template · D2 ESC4 Template Permissions · D3 ESC8 NTLM Relay | T1649, T1187 |
| **E** | Tier-0 Reachability | E1 User→Tier-0 Path · E2 Workstation→DC Admin | T1078.003, T1484.001 |

See [docs/detection-catalog.md](docs/detection-catalog.md) for full per-rule documentation.

---

## Use Cases

**Red Team / Penetration Testers** — Quickly identify the highest-value attack paths and ESC misconfigurations in a target domain without manually parsing BloodHound data.

**Blue Team / Defenders** — Run BlueHound weekly as a scheduled job and use the diff engine to catch privilege creep before attackers do.

**Purple Team Exercises** — Use the MITRE ATT&CK mappings to correlate BlueHound findings with detection rule coverage in your SIEM.

**Security Auditors** — Export the structured ThreatModelResult JSON for integration into audit reports or GRC tooling.

**CI/CD Security Gates** — The `bluehound diff` command exits with code 1 on regressions, making it suitable as a blocking step in deployment pipelines.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Graph database | Neo4j 5.14+ via `neo4j` Python driver |
| CLI framework | Click 8.1+ |
| Terminal output | Rich 13.7+ |
| REST API | FastAPI 0.104+ |
| API server | Uvicorn with standard extras |
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS + Recharts + SWR |
| Configuration | PyYAML 6.0+ + python-dotenv |
| Distribution | PyPI via setuptools + wheel |
| Python | 3.11+ (uses `slots=True` dataclasses) |

---

## Configuration

BlueHound reads Neo4j connection settings from three sources in priority order: environment variables, then `~/.bluehound/config.json`, then built-in defaults.

```bash
# Environment variables
export BLUEHOUND_NEO4J_URI=bolt://localhost:7687
export BLUEHOUND_NEO4J_PASSWORD=mypassword
```

```json
// ~/.bluehound/config.json
{
  "neo4j": {
    "uri": "bolt://localhost:7687",
    "username": "neo4j"
  }
}
```

Passwords are never stored in the config file. If not found in env vars, BlueHound prompts interactively.

---

## Documentation

- [Architecture Deep Dive](docs/architecture.md)
- [Detection Catalog](docs/detection-catalog.md)
- [ADCS Deep Dive](docs/adcs-deep-dive.md)
- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Development Guide](docs/development.md)

---

## License

MIT — see [LICENSE](LICENSE).
