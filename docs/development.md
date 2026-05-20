# BlueHound Development Guide

Full contributor guide covering project structure, test fixtures, rule addition walkthroughs, risk engine modification, API/dashboard extension, code conventions, and release process.

---

## Project Structure

```
bluehound/
├── pyproject.toml              # Build config, dependencies, entry points
├── MANIFEST.in                 # Non-Python files to include in sdist
├── install.ps1                 # Windows one-step installer
├── install.sh                  # Linux/macOS one-step installer
├── requirements.txt            # Pinned dev dependencies
├── pytest.ini                  # Pytest configuration
│
├── bluehound/                  # Main package
│   ├── __init__.py
│   ├── cli/
│   │   ├── main.py             # Click CLI: ingest, analyze, diff, serve, list-snapshots
│   │   └── preflight.py        # Pre-flight checks (disk space, connectivity)
│   ├── config/
│   │   └── settings.py         # Config loading: env vars → config file → defaults
│   ├── core/
│   │   ├── types.py            # All data models: ADUser, ADComputer, Finding, etc.
│   │   ├── graph.py            # GraphConnector — Neo4j driver wrapper + write-guard
│   │   ├── graph_view.py       # GraphView — cached typed read-only view
│   │   ├── detection_context.py# DetectionContext — pre-computed indexes
│   │   └── indexes.py          # Index helpers used by DetectionContext
│   ├── ingestion/
│   │   ├── sharphound.py       # SharpHoundIngester — ZIP → Neo4j
│   │   └── adcs.py             # ADCS data ingestion (templates, CAs)
│   ├── detection/
│   │   ├── engine.py           # DetectionEngine orchestrator
│   │   ├── factory.py          # FindingFactory — typed constructors
│   │   ├── category_a.py       # A: Privilege Exposure (A1–A4)
│   │   ├── category_b.py       # B: Kerberos Abuse (B1–B3)
│   │   ├── category_c.py       # C: Delegation Abuse (C1–C3)
│   │   ├── category_d.py       # D: ADCS Exploitation (D1–D3)
│   │   └── category_e.py       # E: Tier-0 Reachability (E1–E2)
│   ├── risk/
│   │   ├── engine.py           # RiskEngine — path construction, global scoring
│   │   └── edge_scoring.py     # EdgeRiskEvaluator — 4-dimensional per-finding score
│   ├── output/
│   │   └── assembler.py        # ThreatModelAssembler — combines findings + risk
│   ├── diff/
│   │   └── engine.py           # SnapshotDiffEngine — compares ThreatModelResult pairs
│   ├── api/
│   │   └── server.py           # FastAPI application — 9 REST endpoints
│   └── dashboard/
│       ├── dist/               # Pre-built React bundle (shipped with package)
│       │   ├── index.html
│       │   └── assets/
│       ├── src/                # React source (TypeScript + Tailwind)
│       │   ├── App.tsx
│       │   ├── api/client.ts
│       │   ├── components/
│       │   │   ├── Dashboard.tsx
│       │   │   ├── FindingsTable.tsx
│       │   │   ├── FindingsChart.tsx
│       │   │   ├── RiskScoreCard.tsx
│       │   │   ├── AttackPathVisualization.tsx
│       │   │   ├── TopFixes.tsx
│       │   │   ├── LoadingSpinner.tsx
│       │   │   └── ErrorBoundary.tsx
│       │   └── types/index.ts
│       ├── package.json
│       └── vite.config.ts
│
├── tests/
│   └── unit/
│
├── docs/
│   ├── architecture.md
│   ├── detection-catalog.md
│   ├── user-guide.md
│   ├── api-reference.md
│   └── development.md          # (this file)
│
├── snapshots/                  # Snapshot metadata directories (gitignored)
└── .bluehound/results/         # Analysis result JSON files (gitignored)
```

---

## Dev Environment Setup

```bash
git clone https://github.com/vShresthh/BlueHound
cd bluehound

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# Install in editable mode with dev extras
pip install -e ".[dev]"

# Verify installation
bluehound --version
pytest --co -q  # Collect tests without running
```

---

## Running Tests

```bash
# All tests
pytest

# One test file
pytest tests/unit/test_risk_engine.py

# One test function
pytest tests/unit/test_risk_engine.py::test_global_score_formula

# With coverage
pytest --cov=bluehound --cov-report=html
open htmlcov/index.html  # Linux: xdg-open
```

Most tests use in-memory mock objects rather than a live Neo4j instance. Tests that require Neo4j are marked with `@pytest.mark.integration` and skipped by default unless `--run-integration` is passed.

---

## Test Fixtures and How to Use Them

The test suite uses a small set of builder helpers defined in `tests/unit/` to construct typed model objects without Neo4j.

**Building an ADUser:**

```python
from bluehound.core.types import ADUser
from datetime import datetime, timezone

def make_user(sid="S-1-5-21-100-1", name="testuser", enabled=True, spns=None, **kwargs):
    return ADUser(
        sid=sid,
        sam_account_name=name,
        enabled=enabled,
        spns=spns or [],
        admin_count=kwargs.get("admin_count", 0),
        last_logon=kwargs.get("last_logon"),
        kerberos_preauth_not_required=kwargs.get("preauth_not_required", False),
        distinguished_name=kwargs.get("dn", f"CN={name},DC=corp,DC=local"),
    )
```

**Building a GraphView mock:**

```python
from unittest.mock import MagicMock
from bluehound.core.graph_view import GraphView

def make_view(users=None, computers=None, groups=None):
    view = MagicMock(spec=GraphView)
    view.get_users.return_value = users or []
    view.get_computers.return_value = computers or []
    view.get_groups.return_value = groups or []
    view.get_statistics.return_value = {
        "users": len(users or []),
        "computers": len(computers or []),
        "groups": len(groups or []),
    }
    view.get_domain_info.return_value = {}
    view.get_certificate_templates.return_value = []
    view.get_certificate_authorities.return_value = []
    return view
```

**Building a DetectionContext mock:**

```python
from unittest.mock import MagicMock
from bluehound.core.detection_context import DetectionContext

def make_context(tier0_sids=None, admin_map=None, aces=None):
    ctx = MagicMock(spec=DetectionContext)
    tier0 = set(tier0_sids or [])
    ctx.is_tier0.side_effect = lambda sid: sid in tier0
    ctx.tier0_sids = tier0
    ctx.admin_to_computers = admin_map or {}
    ctx.group_closure = {}
    ctx.get_dangerous_aces_by_principal.return_value = aces or []
    ctx.get_aces_on_target.return_value = []
    return ctx
```

**Example test using fixtures:**

```python
def test_excessive_admin_detection():
    user = make_user(sid="S-1-5-21-100-1", name="jdoe")
    view = make_view(users=[user])
    
    admin_map = {user.sid: {f"S-1-5-21-100-{i}" for i in range(15)}}
    context = make_context(admin_map=admin_map)
    
    factory = FindingFactory()
    findings = _detect_excessive_local_admin(view, context, factory)
    
    assert len(findings) == 1
    assert findings[0].evidence.raw_data["computer_count"] == 15
```

---

## Adding a New Detection Rule

**Step 1: Write the detector function**

```python
# bluehound/detection/category_a.py

STALE_PASSWORD_DAYS = 365

def _detect_stale_privileged_passwords(view, context, factory):
    """A5 — Privileged accounts with passwords older than 1 year."""
    
    findings = []
    threshold = datetime.now(timezone.utc) - timedelta(days=STALE_PASSWORD_DAYS)
    
    for user in view.get_users():
        if not user.enabled:
            continue
        if not context.is_tier0(user.sid):
            continue
        if user.pwd_last_set is None or user.pwd_last_set > threshold:
            continue
        
        days_old = (datetime.now(timezone.utc) - user.pwd_last_set).days
        
        findings.append(
            factory.create_privilege_finding(
                title=f"Stale Privileged Password: {user.sam_account_name} ({days_old} days)",
                description=(
                    f"Privileged account '{user.sam_account_name}' has not had its "
                    f"password changed in {days_old} days."
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "user_name": user.sam_account_name,
                    "days_since_password_change": days_old,
                    "is_tier0": True,
                },
                severity=Severity.MEDIUM,
                remediation=(
                    f"Reset the password for '{user.sam_account_name}'. "
                    f"Establish a password rotation policy for all privileged accounts."
                ),
            )
        )
    
    return findings
```

**Step 2: Register in the entry point**

```python
def detect_privilege_exposure(view, context, factory):
    findings = []
    findings.extend(_detect_excessive_local_admin(view, context, factory))
    findings.extend(_detect_orphaned_privileged_accounts(view, context, factory))
    findings.extend(_detect_hidden_privileged_membership(view, context, factory))
    findings.extend(_detect_dangerous_aces_on_tier0(view, context, factory))
    findings.extend(_detect_stale_privileged_passwords(view, context, factory))  # NEW
    return findings
```

**Step 3: Add the ADUser field if needed**

If `pwd_last_set` is a new field, add it to `ADUser` in `core/types.py` and populate it in `GraphView.load()` from the Neo4j property.

**Step 4: Write a test**

```python
# tests/unit/test_category_a.py

def test_stale_password_detection():
    old_date = datetime.now(timezone.utc) - timedelta(days=400)
    user = make_user(sid="S-1-5-21-100-1", name="da_admin")
    user.pwd_last_set = old_date
    
    view = make_view(users=[user])
    context = make_context(tier0_sids={"S-1-5-21-100-1"})
    factory = FindingFactory()
    
    findings = _detect_stale_privileged_passwords(view, context, factory)
    
    assert len(findings) == 1
    assert "400" in findings[0].title or "400" in str(findings[0].evidence.raw_data)
```

---

## Adding a New Detection Category

**Step 1: Add enum value to types**

```python
# bluehound/core/types.py

class FindingCategory(str, Enum):
    PRIVILEGE_EXPOSURE = "privilege_exposure"
    KERBEROS_ABUSE = "kerberos_abuse"
    DELEGATION_ABUSE = "delegation_abuse"
    ADCS_ABUSE = "adcs_abuse"
    TIER0_EXPOSURE = "tier0_exposure"
    LATERAL_MOVEMENT = "lateral_movement"      # NEW
```

**Step 2: Create the category module**

```python
# bluehound/detection/category_f.py

def detect_lateral_movement(view, context, factory):
    """Category F: Lateral Movement Paths"""
    findings = []
    findings.extend(_detect_pass_the_hash_paths(view, context, factory))
    return findings
```

**Step 3: Register in the engine**

```python
# bluehound/detection/engine.py

def run_all_detections(self):
    # ... existing categories ...
    
    try:
        from bluehound.detection.category_f import detect_lateral_movement
        findings += self.run_category(
            FindingCategory.LATERAL_MOVEMENT,
            detect_lateral_movement,
        )
    except ImportError:
        self.logger.warning("Category F not available — skipping")
    
    return self.deduplicate_findings(findings)
```

**Step 4: Add risk engine entries**

```python
# bluehound/risk/engine.py

CATEGORY_BIAS = {
    FindingCategory.ADCS_ABUSE: 1.30,
    FindingCategory.DELEGATION_ABUSE: 1.20,
    FindingCategory.KERBEROS_ABUSE: 1.10,
    FindingCategory.PRIVILEGE_EXPOSURE: 1.00,
    FindingCategory.TIER0_EXPOSURE: 1.00,
    FindingCategory.LATERAL_MOVEMENT: 1.15,  # NEW
}

CATEGORY_PRIORITY = {
    FindingCategory.ADCS_ABUSE: 5,
    FindingCategory.DELEGATION_ABUSE: 4,
    FindingCategory.KERBEROS_ABUSE: 3,
    FindingCategory.TIER0_EXPOSURE: 2,
    FindingCategory.PRIVILEGE_EXPOSURE: 1,
    FindingCategory.LATERAL_MOVEMENT: 3,     # NEW
}
```

---

## Modifying the Risk Engine

### Changing Dimension Weights

```python
# bluehound/risk/edge_scoring.py

# Must sum to 1.0
STEALTH_WEIGHT = 0.25         # was 0.30
EXPLOITABILITY_WEIGHT = 0.30  # was 0.25
PERSISTENCE_WEIGHT = 0.25     # unchanged
BLAST_RADIUS_WEIGHT = 0.20    # unchanged
```

### Adding Category-Specific Scoring

```python
def _compute_stealth_score(self, finding):
    c = finding.category
    t = finding.title.lower()
    
    if c == FindingCategory.LATERAL_MOVEMENT:
        if "pass the hash" in t:
            return 8.0
        return 7.0
    
    # ... existing cases ...
```

### Adjusting Exposure Level Thresholds

```python
def _determine_exposure(self, tier0, path, blast):
    # Make CATASTROPHIC require a lower score
    if tier0 and path.path_score >= 8.5:  # was 9.0
        return ExposureLevel.CATASTROPHIC
    # ... rest unchanged ...
```

---

## Extending the API

**Adding a new endpoint:**

```python
# bluehound/api/server.py

@app.get("/api/principals/{sid}", summary="Principal details by SID")
async def get_principal(
    sid: str,
    snapshot: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Return findings affecting a specific principal SID."""
    data = _resolve_snapshot(snapshot)
    findings = [
        f for f in data.get("findings", [])
        if sid in f.get("affected_principals", [])
    ]
    return {
        "sid": sid,
        "finding_count": len(findings),
        "findings": findings,
    }
```

**Testing an endpoint:**

```python
# tests/unit/test_api_server.py
from fastapi.testclient import TestClient
from bluehound.api import server

client = TestClient(server.app)

def test_my_endpoint(tmp_path, monkeypatch):
    # Write a test result file
    result = {"findings": [...], "risk_score": 5.0, ...}
    results_dir = tmp_path / ".bluehound/results"
    results_dir.mkdir(parents=True)
    (results_dir / "2026-01-01_000000.json").write_text(json.dumps(result))
    
    monkeypatch.setattr(server, "RESULTS_DIR", results_dir)
    
    r = client.get("/api/principals/S-1-5-21-100-1")
    assert r.status_code == 200
    assert "findings" in r.json()
```

---

## Extending the Dashboard

The React frontend is in `bluehound/dashboard/src/`. The API client uses SWR hooks defined in `src/api/client.ts`.

**Adding a new data hook:**

```typescript
// src/api/client.ts
import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then(r => r.json());

export function usePrincipal(sid: string) {
  return useSWR(`/api/principals/${sid}`, fetcher);
}
```

**Adding a new component:**

```typescript
// src/components/PrincipalDetail.tsx
import { usePrincipal } from "../api/client";

export function PrincipalDetail({ sid }: { sid: string }) {
  const { data, error } = usePrincipal(sid);
  
  if (error) return <div>Failed to load</div>;
  if (!data) return <div>Loading...</div>;
  
  return (
    <div>
      <h2>Findings for {sid}</h2>
      <p>{data.finding_count} findings</p>
    </div>
  );
}
```

**Rebuilding the dashboard:**

```bash
cd bluehound/dashboard
npm install
npm run build
# Built files land in dist/ which is shipped with the Python package
```

---

## Code Conventions

**Types:** All public functions should have type annotations. Use `from __future__ import annotations` at the top of every module to enable forward references.

**Logging:** Use module-level loggers (`logger = logging.getLogger(__name__)`). Detection modules use `logger.info` at category start/end and `logger.error` for per-rule failures. Never use `print()` in library code.

**Error handling:** Detection functions must not propagate exceptions to the engine. Wrap the rule body in try/except and return an empty list on failure. The engine's `run_category` already does this at the category level, but per-rule robustness is preferred.

**Finding IDs:** Finding IDs are generated by `FindingFactory` using SHA-256 over the category, title, and sorted affected principal SIDs. Do not generate IDs manually.

**Evidence data:** Always include `user_sid` or `computer_sid` as the primary key field in `evidence_data` so that findings can be correlated across snapshots.

**Test naming:** Test functions follow `test_<what>_<condition>_<expected_outcome>`, e.g. `test_kerberoastable_machine_account_excluded`.

**No breaking serialization changes:** Fields added to `ThreatModelResult` or `Finding` must have safe defaults. The `from_dict` deserializer must handle missing fields gracefully to remain backward compatible with older result files.

---

## Release Process

**1. Update version**

```python
# pyproject.toml
version = "1.1.0"

# bluehound/cli/main.py
@click.version_option("1.1.0")
```

**2. Build**

```bash
pip install build twine
python -m build
# Produces dist/bluehound-1.1.0.tar.gz and dist/bluehound-1.1.0-py3-none-any.whl
```

**3. Test the build locally**

```bash
pip install dist/bluehound-1.1.0-py3-none-any.whl --force-reinstall
bluehound --version
```

**4. Publish to PyPI**

```bash
twine upload dist/*
```

**5. Tag the release**

```bash
git tag v1.1.0
git push origin v1.1.0
```

**Dashboard rebuild before release:** Always rebuild the React dashboard and commit the updated `dist/` directory before building the Python wheel. The dashboard bundle is included in `MANIFEST.in` and shipped as package data via `pyproject.toml`:

```toml
[tool.setuptools.package-data]
"bluehound.dashboard" = [
    "dist/index.html",
    "dist/assets/*",
]
```
