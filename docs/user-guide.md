# BlueHound User Guide

Complete end-to-end guide covering installation, configuration, the full ingest → analyze → serve → diff workflow, and troubleshooting.

---

## Installation

### PyPI (recommended)

```bash
pip install bluehound
bluehound --version
```

This installs the `bluehound` command globally. The package includes the pre-built React dashboard — no Node.js required.

### From Source

```bash
git clone https://github.com/vShresthh/BlueHound
cd bluehound
pip install -e ".[dev]"
```

The `[dev]` extra installs pytest, httpx, and build tools. Omit it for production installs.

### Windows PowerShell Script

```powershell
.\install.ps1
```

The script creates a Python virtual environment, installs BlueHound with pip, and adds the `bluehound` command to your PATH for the current session. Run as a normal user — no administrator rights required.

### Linux / macOS Shell Script

```bash
chmod +x install.sh && ./install.sh
```

Equivalent to the PowerShell script for Unix systems.

### Requirements

- Python 3.11 or newer
- Neo4j 5.14 or newer with the Bolt protocol enabled
- A SharpHound (BloodHound CE compatible) ZIP file to analyze

---

## Configuration

BlueHound reads Neo4j connection settings from three sources in priority order.

**1. Environment variables (highest priority)**

```bash
export BLUEHOUND_NEO4J_URI=bolt://localhost:7687
export BLUEHOUND_NEO4J_USER=neo4j
export BLUEHOUND_NEO4J_PASSWORD=mypassword
```

**2. Config file at `~/.bluehound/config.json`**

```json
{
  "neo4j": {
    "uri": "bolt://localhost:7687",
    "username": "neo4j"
  }
}
```

The password field is intentionally not stored in the config file. Set it via environment variable or use the interactive prompt.

**3. Built-in defaults**

| Setting | Default |
|---------|---------|
| Neo4j URI | `bolt://localhost:7687` |
| Neo4j username | `neo4j` |
| Neo4j password | Interactive prompt |

**Config file schema:**

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `neo4j.uri` | string | No | Full Bolt URI including port |
| `neo4j.username` | string | No | Neo4j username |
| `neo4j.password` | string | No | Stored in plaintext — prefer env var |

You can save non-sensitive settings programmatically:

```bash
python -c "from bluehound.config.settings import save_neo4j_config; save_neo4j_config('bolt://myserver:7687', 'neo4j')"
```

---

## Full Workflow

### Step 1: Collect SharpHound Data

Use SharpHound or BloodHound CE to collect Active Directory data. The output is a ZIP file named like `XXXXXXXXXXXXXXXXXX.zip`. BlueHound supports both the legacy (v4) and CE SharpHound output formats.

```powershell
# On a domain-joined Windows host
.\SharpHound.exe --CollectionMethods All --OutputDirectory C:\Temp\
```

Transfer the ZIP to the analysis workstation.

### Step 2: Ingest

```bash
bluehound ingest XXXXXXXXXXXXXXXXXXX.zip 
```

BlueHound prompts for the Neo4j password if not set in the environment. After ingestion:

- Nodes and relationships are written to Neo4j
- A snapshot metadata file is saved to `snapshots/<timestamp>/metadata.json`
- Ingestion statistics are printed to the terminal

To clear the graph before ingesting (when switching between domains):

```bash
bluehound ingest ./collection.zip --clear-graph
```

You will be asked to confirm before any deletion occurs.

**Ingestion flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `SHARPHOUND_ZIP` | path | required | Path to SharpHound ZIP file |
| `--neo4j-uri` | string | from config | Neo4j Bolt URI |
| `--neo4j-user` | string | from config | Neo4j username |
| `--neo4j-password` | string | from config/prompt | Neo4j password |
| `--output-dir` | path | `snapshots/` | Where to save snapshot metadata |
| `--clear-graph` | flag | False | Delete all graph data before ingesting |

### Step 3: Analyze

```bash
bluehound analyze ./snapshots/20XX-XX-XX_XXXXXX/
```

This command:
1. Connects to Neo4j (read-only — no writes during analysis)
2. Loads all AD data into memory
3. Warns if the Neo4j graph does not match the snapshot's recorded statistics
4. Runs all five detection categories
5. Scores behavioral risk across four dimensions
6. Saves results to `.bluehound/results/<timestamp>.json`
7. Prints a summary and starts the dashboard server

**Analysis flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `SNAPSHOT_DIR` | path | required | Path to snapshot directory |
| `--neo4j-uri` | string | from config | Neo4j Bolt URI |
| `--neo4j-user` | string | from config | Neo4j username |
| `--neo4j-password` | string | from config/prompt | Neo4j password |
| `--port` | integer | 8080 | Dashboard server port |
| `--no-dashboard` | flag | False | Skip starting dashboard after analysis |
| `--output` | path | auto | Custom path for the result JSON file |

### Step 4: View the Dashboard

The dashboard starts automatically after `bluehound analyze` unless `--no-dashboard` is passed. Open `http://localhost:8080` in your browser.

To start the dashboard manually against saved results:

```bash
bluehound serve --port 8080
```

**Serve flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | integer | 8080 | Port to bind |
| `--host` | string | `127.0.0.1` | Host/interface to listen on |
| `--reload` | flag | False | Enable auto-reload on code changes |
| `--dev` | flag | False | Development mode — opens CORS, expects React dev server on :3000 |

### Step 5: List Snapshots

```bash
bluehound list-snapshots
```

Displays all collected snapshots with their timestamps, domains, and object counts.

```bash
bluehound list-snapshots --dir ./snapshots
```

### Step 6: Diff Two Snapshots

```bash
bluehound diff .bluehound\results\baseline .bluehound\results\current
```

Accepts either snapshot directories or direct analysis result JSON files:

```bash
bluehound diff .bluehound/results/2026-01-15_093000.json .bluehound/results/2026-02-04_173820.json --format json --output diff-report.json
```

**Diff flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `BASELINE` | path | required | Baseline snapshot dir or JSON file |
| `CURRENT` | path | required | Current snapshot dir or JSON file |
| `--output` | path | None | Save report to file |
| `--format` | `text`/`json` | `text` | Output format |

The command exits with code 1 when a security regression is detected, enabling use as a CI/CD gate.

---

## Workflow Examples

### Penetration Test Assessment

```bash
# Day 1: Collect and ingest
bluehound ingest ./20260204_collection.zip --clear-graph

# Day 1: Analyze and review findings
bluehound analyze ./snapshots/2026-02-04_*/
# Open http://localhost:8080 — review critical and high findings

# Day 2: After some remediation, collect again and compare
bluehound ingest ./20260205_collection.zip --clear-graph
bluehound analyze ./snapshots/2026-02-05_*/
bluehound diff ./snapshots/2026-02-04_*/ ./snapshots/2026-02-05_*/ --format json
```

### Weekly Security Monitoring (Cron Job)

```bash
#!/bin/bash
# weekly-bluehound.sh — runs every Sunday at 02:00

COLLECTION_DIR="/opt/sharphound-collections"
LATEST=$(ls -t "$COLLECTION_DIR"/*.zip | head -1)
PREVIOUS=$(ls -t "$COLLECTION_DIR"/*.zip | sed -n '2p')

# Ingest latest collection
bluehound ingest "$LATEST" --clear-graph \
    --neo4j-password "$BLUEHOUND_NEO4J_PASSWORD" \
    --no-dashboard

# Analyze
bluehound analyze ./snapshots/$(ls -t snapshots/ | head -1)/ \
    --no-dashboard \
    --neo4j-password "$BLUEHOUND_NEO4J_PASSWORD"

# Diff against previous week
if [ -n "$PREVIOUS" ]; then
    bluehound diff \
        $(ls -dt snapshots/* | sed -n '2p') \
        $(ls -dt snapshots/* | head -1) \
        --format json \
        --output "/opt/bluehound-reports/$(date +%Y-%m-%d)-diff.json"
fi
```

### CI/CD Security Gate

```yaml
# .github/workflows/ad-security-check.yml
name: AD Security Gate

on:
  schedule:
    - cron: '0 3 * * 1'  # Every Monday at 03:00

jobs:
  bluehound:
    runs-on: self-hosted
    steps:
      - name: Install BlueHound
        run: pip install bluehound

      - name: Ingest latest collection
        env:
          BLUEHOUND_NEO4J_PASSWORD: ${{ secrets.NEO4J_PASSWORD }}
        run: |
          bluehound ingest ${{ vars.SHARPHOUND_ZIP_PATH }} --clear-graph

      - name: Analyze snapshot
        env:
          BLUEHOUND_NEO4J_PASSWORD: ${{ secrets.NEO4J_PASSWORD }}
        run: |
          SNAP=$(ls -dt snapshots/* | head -1)
          bluehound analyze "$SNAP" --no-dashboard

      - name: Compare with baseline
        run: |
          # Exit code 1 = regression → job fails → blocks deployment
          bluehound diff ./baseline/ $(ls -dt snapshots/* | head -1) \
              --format json --output regression-report.json

      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bluehound-regression-report
          path: regression-report.json
```

---

## Troubleshooting

### "No analysis results found. Run 'bluehound analyze' first."

The dashboard API server looks for results in `.bluehound/results/` relative to the **working directory where you ran `bluehound serve`**. Run `bluehound serve` from the same directory where you ran `bluehound analyze`.

### "Neo4j graph does not match this snapshot"

You see this warning when the node counts in Neo4j differ from the counts recorded when the snapshot was ingested. This happens when a new collection is ingested on top of an old one without `--clear-graph`. Re-ingest with `--clear-graph` before analyzing to get accurate per-snapshot results.

This was a bug addressed during development: the `analyze` command now reads `stats` from `metadata.json` (not `statistics`) and compares against Neo4j live counts correctly.

### "Invalid SID format: ..."

BlueHound validates all SIDs against the pattern `^S-1-\d+(-\d+)+$`. Malformed SIDs in SharpHound output are skipped during ingestion with a warning. If you see this frequently, the collection may be from a non-standard BloodHound exporter.

### SID lookups returning None

The `SID-to-name` lookup in `ThreatModelAssembler` uses a cache built at startup. If a SID appears in a finding's `affected_principals` but not in the cache, the SID string is used as the display name. This is expected for well-known SIDs (like `S-1-1-0` for Everyone) that may not have dedicated nodes in the Neo4j graph.

This was a known issue corrected in the current version: the cache now correctly includes computer accounts (not just users and groups).

### AS-REP Roasting MITRE ID

The correct MITRE technique for AS-REP Roasting is **T1558.004** (not T1558.003 which covers Kerberoasting). BlueHound's category B detectors use the correct IDs — B2 emits T1558.004 and B1/B3 emit T1558.003.

### `=+1` typo in risk formula

Earlier development builds had a typo `blast_radius =+ len(principals)` that assigned rather than incremented. The current codebase correctly computes `blast_radius = min(len(principals) / total, 1.0)`.

### `blast_radius` type mismatch in ThreatModelResult

`ThreatModelResult.blast_radius` is a `float`, not a `set`. Earlier builds serialized the `affected_principals` set accidentally as the blast radius. The current version correctly serializes the float fraction.

### `category_breakdown` field name

The statistics endpoint returns `category_breakdown`, not `findingsByCategory`. If you are querying an older result file, this key may be missing — the API returns an empty dict as a safe default.

### `time_to_domain_admin` and `detection_surface` are null

These fields are populated by `ThreatModelAssembler` only when specific Tier-0 paths are detected. If no Tier-0 reachability is found in the analysis, both fields will be `null` in the result JSON. This is expected behavior, not a bug.

### Timestamp regex validation

The `find_result_by_timestamp` function in `server.py` validates that the timestamp parameter does not contain path traversal characters. Only alphanumeric characters, hyphens, and underscores are accepted. Attempting to load `../../../etc/passwd` as a snapshot ID returns HTTP 400.

### FastAPI lifespan warning

If you see a deprecation warning about event handlers (`@app.on_event`), this is resolved in the current version. BlueHound uses the `@asynccontextmanager` lifespan pattern as recommended by FastAPI 0.95+:

```python
@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("BlueHound starting…")
    yield
    logger.info("BlueHound shutting down.")
```
