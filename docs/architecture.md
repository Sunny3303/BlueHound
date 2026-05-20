# BlueHound Architecture

This document describes all eight layers of the BlueHound pipeline, the write-guard implementation, the full analysis data flow, performance characteristics by domain size, and the extension points available to contributors.

---

## The Eight Layers

### Layer 1 — Ingestion

**Module:** `bluehound/ingestion/sharphound.py`, `bluehound/ingestion/adcs.py`

The ingestion layer owns every interaction with SharpHound ZIP files and with Neo4j writes. It is the only layer permitted to call `graph.enable_writes()`. After ingestion completes, writes are immediately disabled.

`SharpHoundIngester` extracts JSON files from the SharpHound ZIP, validates SIDs with a strict regex pattern (`^S-1-\d+(-\d+)+$`), normalizes account names, and writes nodes and relationships to Neo4j via parameterized Cypher queries. Only relationships in the `ALLOWED_REL_TYPES` allowlist are imported — any relationship type not in the set is silently skipped, preventing data from malformed or attacker-crafted ZIPs from reaching the graph.

After writing graph data, the ingester serializes a `SnapshotMetadata` object to disk under `snapshots/<timestamp>/metadata.json`. This metadata includes a SHA-256 signature of the ZIP contents for later integrity verification.

ADCS data (certificate templates and certificate authorities) is loaded via the separate `adcs.py` ingester and stored on the `GraphView` instance rather than in Neo4j, since BloodHound CE does not model ADCS objects natively. See [docs/adcs-deep-dive.md](adcs-deep-dive.md) for a full explanation of the ADCS ingestion schema, each ESC class BlueHound detects, and their exploitation chains.

**Key design decisions:**
- SID normalization converts all representations to uppercase canonical form before any write operation, preventing duplicate node creation from case variation.
- A timestamp extracted from the SharpHound ZIP filename is used as the `collected_at` field in `SnapshotMetadata`, so the metadata reflects the time of collection rather than the time of ingestion.
- Statistics (user count, computer count, group count, relationship count) are captured immediately after ingestion so `analyze` can warn when the Neo4j graph has changed since this snapshot was captured.

---

### Layer 2 — Graph Abstraction

**Module:** `bluehound/core/graph_view.py`

`GraphView` is a cached, typed, read-only facade over the Neo4j graph. Every entity model in `bluehound/core/types.py` (`ADUser`, `ADComputer`, `ADGroup`, `ACE`, `Edge`) is materialized from Neo4j once during `view.load()` and cached in in-memory dictionaries keyed by SID. After `load()`, all graph access happens in O(1) from these dictionaries — no further database queries are issued during detection.

The view exposes these primary accessor families:

```python
view.get_users()                    # → Iterable[ADUser]
view.get_computers()                # → Iterable[ADComputer]
view.get_groups()                   # → Iterable[ADGroup]
view.get_node(sid: str)             # → ADUser | ADComputer | ADGroup | None
view.get_user(sid: str)             # → ADUser | None
view.get_computer(sid: str)         # → ADComputer | None
view.get_group(sid: str)            # → ADGroup | None
view.get_edges()                    # → Iterable[Edge]
view.get_statistics()               # → dict with users/computers/groups counts
view.get_domain_info()              # → dict with ms-ds-machineaccountquota, fqdn, etc.
view.get_certificate_templates()    # → List[CertTemplate]
view.get_certificate_authorities()  # → List[CertAuthority]
```

`GraphView` also builds the Tier-0 canonical group list. Any group whose name matches the `TIER0_GROUP_NAMES` constant set (e.g. `DOMAIN ADMINS`, `ENTERPRISE ADMINS`, `SCHEMA ADMINS`, etc.) is treated as a Tier-0 root, and its SID is included in the `tier0_sids` set used throughout detection.

**Isolation guarantee:** Detection modules must import only from `bluehound.core.graph_view` and `bluehound.core.detection_context`. Direct use of `bluehound.core.graph.GraphConnector` inside detection code is a contributor error.

---

### Layer 3 — Detection Context

**Module:** `bluehound/core/detection_context.py`

`DetectionContext` is the pre-computation layer. It runs once during `context.build()` and produces the data structures that make detection logic fast and concise.

Built indexes available to all detectors:

| Index | Type | Description |
|-------|------|-------------|
| `tier0_sids` | `set[str]` | All SIDs transitively reachable from Tier-0 groups |
| `admin_to_computers` | `dict[str, set[str]]` | Maps principal SID → set of computer SIDs where that principal has AdminTo |
| `group_closure` | `dict[str, set[str]]` | Transitive group membership: member SID → set of all ancestor group SIDs |
| `aces_by_principal` | `dict[str, list[ACE]]` | All ACEs indexed by the trustee (principal) SID |
| `aces_by_target` | `dict[str, list[ACE]]` | All ACEs indexed by the target object SID or name |
| `kerberoastable_users` | `list[ADUser]` | Pre-filtered: enabled, has SPNs, not machine account, not krbtgt |
| `asrep_users` | `list[ADUser]` | Pre-filtered: enabled, `kerberos_preauth_not_required = True` |

Context accessor methods available to detectors:

```python
context.is_tier0(sid: str) -> bool
context.get_dangerous_aces_by_principal(sid: str) -> list[ACE]
context.get_aces_on_target(target_name_or_sid: str) -> list[ACE]
```

`is_tier0` uses the transitive closure approach: a user is Tier-0 if their SID appears in `tier0_sids`, which includes both direct and nested group membership paths.

---

### Layer 4 — Detection Engine

**Module:** `bluehound/detection/engine.py`, `bluehound/detection/category_[a-e].py`

`DetectionEngine` is the orchestrator. It calls each category detector in a deterministic order, aggregates the returned `Finding` lists, deduplicates on `finding.id`, and returns the complete `List[Finding]` to the caller.

Execution order is significant for coverage measurement: A → B → C → D → E. Categories D and E are loaded inside try/except blocks so that a missing dependency or partially unavailable data source degrades gracefully without aborting the analysis.

Each category module exposes a single public function matching the signature:

```python
def detect_<category>(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:
    ...
```

`FindingFactory` (`bluehound/detection/factory.py`) provides typed constructors that populate all required `Finding` fields consistently:

```python
factory.create_finding(...)           # Generic — requires all fields
factory.create_privilege_finding(...) # Category A defaults + MITRE T1078
factory.create_kerberos_finding(...)  # Category B defaults + MITRE T1558
factory.create_delegation_finding(...)# Category C defaults + MITRE T1134
factory.create_adcs_finding(...)      # Category D defaults + MITRE T1649
```

Deduplication uses `Finding.id`, which is derived deterministically from the category, title, and affected principal SIDs using SHA-256. Two independent rules that detect the same misconfiguration for the same account will produce identical IDs and one finding will be silently dropped.

---

### Layer 5 — Risk Scoring Engine

**Module:** `bluehound/risk/engine.py`, `bluehound/risk/edge_scoring.py`

The risk engine has two sub-components.

**EdgeRiskEvaluator** scores each individual finding across four behavioral dimensions:

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| Stealth | 30% | How easily the technique evades detection |
| Exploitability | 25% | Attacker skill and tooling required |
| Persistence | 25% | Whether the vulnerability persists without remediation |
| Blast Radius | 20% | Number of principals affected or tier-0 involvement |

Each dimension is scored on a 1–10 scale using heuristic rules based on `FindingCategory` and specific technique markers in the finding title. The overall edge score is: `stealth * 0.30 + exploitability * 0.25 + persistence * 0.25 + blast_radius * 0.20`.

**RiskEngine** constructs `AttackPath` objects from findings, applies category-specific bias multipliers, and aggregates to a global score.

Category bias multipliers applied during path scoring:

| Category | Bias |
|----------|------|
| ADCS_ABUSE | 1.30× |
| DELEGATION_ABUSE | 1.20× |
| KERBEROS_ABUSE | 1.10× |
| PRIVILEGE_EXPOSURE | 1.00× |
| TIER0_EXPOSURE | 1.00× |

Path score formula:

```
path_score = max_edge_risk × category_bias × length_modifier
             + TIER0_BONUS (1.0 if path reaches tier0, else 0.0)
```

Length modifier penalizes longer kill chains: 1.0 for ≤2 hops, 0.9 for 3 hops, 0.8 for 4, 0.7 for 5, 0.6 for 6+.

Global score formula:

```
global_score = max_path_score + avg_top5_score × 0.15 + min(critical_count × 0.3, 2.0) × 0.2
```

All scores are capped at 10.0. The final `ExposureLevel` is determined by whether tier-0 paths exist, the highest path score, and the blast radius fraction:

| ExposureLevel | Conditions |
|---------------|-----------|
| CATASTROPHIC | Tier-0 path confirmed AND path score ≥ 9.0 |
| DOMAIN_WIDE | Tier-0 path via TIER0_EXPOSURE finding AND score ≥ 7.5 AND blast_radius ≥ 20% |
| LOCALIZED | Tier-0 theoretically reachable but no confirmed direct path |
| CONTAINED | No tier-0 reachability detected |

---

### Layer 6 — Output Assembly

**Module:** `bluehound/output/assembler.py`

`ThreatModelAssembler` combines the outputs of the detection and risk engines into a single serializable `ThreatModelResult`. It resolves SID references to human-readable names using a cache built from `GraphView`, constructs `KillPath` objects from the most dangerous attack path, selects the top remediation recommendations from `Finding.remediation` fields, and computes summary fields like `time_to_domain_admin` and `detection_surface`.

The result is serialized to `.bluehound/results/<timestamp>.json`. The file name is a timestamp in `%Y-%m-%d_%H%M%S` format, which enables lexicographic sorting to find the latest result quickly.

`ThreatModelResult.to_json()` and `ThreatModelResult.from_dict()` form the stable serialization contract. Every field that the API layer or diff engine consumes must be present in this serialization. Breaking changes to this contract require a version bump in the metadata.

---

### Layer 7 — Snapshot Diffing

**Module:** `bluehound/diff/engine.py`

`SnapshotDiffEngine.compare(baseline, current)` accepts two `ThreatModelResult` objects and returns a `SnapshotDiff` dataclass containing all dimensions of change between the two snapshots.

Diff dimensions computed:

- Risk score delta and classification change
- Exposure level change
- New findings (present in current but not baseline), keyed by finding ID
- Removed findings (present in baseline but not current)
- Changed findings (same ID, different severity)
- Severity escalations and improvements
- Privilege creep: principals that gained new Tier-0 group memberships
- Tier-0 exposure regression: new attack paths to Tier-0 that did not exist in baseline
- Blast radius delta as an absolute percentage change
- New and removed MITRE technique IDs

`SnapshotDiff.improvement_score` is a signed float where positive values indicate regression and negative values indicate improvement. The `is_regression()` and `is_improvement()` convenience methods use this score, and the `bluehound diff` CLI command exits with code 1 when `is_regression()` returns True.

---

### Layer 8 — API and Dashboard

**Module:** `bluehound/api/server.py`, `bluehound/dashboard/dist/`

The FastAPI application is strictly read-only. It loads pre-computed `ThreatModelResult` JSON files from `.bluehound/results/` and serves them through nine REST endpoints.

CORS is configured to allow `localhost:3000` and `localhost:8080`, covering both the React development server and the production bundle served from the same origin. In production, the pre-built React bundle from `bluehound/dashboard/dist/` is mounted as a static directory. The catch-all route returns `index.html` for all non-API paths so React Router client-side navigation works correctly.

The server is started either automatically after `bluehound analyze` completes (unless `--no-dashboard` is passed) or explicitly with `bluehound serve`.

---

## The Write-Guard Implementation

All Neo4j write operations are guarded by an explicit mode flag on `GraphConnector`. The interface is:

```python
graph.enable_writes()   # Called by SharpHoundIngester before any MERGE/CREATE
graph.disable_writes()  # Called immediately after ingestion completes
```

`GraphConnector.execute_write()` checks this flag and raises `PermissionError` if writes are attempted while the guard is active. The guard is disabled in the finally block of the `ingest` CLI command so that even a mid-ingestion exception leaves the connector in the safe read-only state.

The `analyze` command never calls `enable_writes()`. Detection, risk scoring, and output assembly are all purely read-side operations. The dashboard API server also has no write code path.

---

## Analysis Data Flow Trace

Tracing a single call to `bluehound analyze ./snapshots/2026-02-04_173820/`:

1. CLI reads `snapshots/2026-02-04_173820/metadata.json` → builds `SnapshotMetadata`
2. `GraphConnector` establishes Bolt connection to Neo4j
3. `GraphView.__init__` receives the connector
4. `GraphView.load()` issues Cypher queries: all User nodes, Computer nodes, Group nodes, MemberOf/AdminTo/HasSession/ACE edges → hydrates typed model caches
5. `GraphView.get_statistics()` counts cached collections; `analyze` CLI warns if counts diverge from recorded snapshot stats
6. `DetectionContext(view)` is constructed; `context.build()` iterates all nodes/edges once to populate `tier0_sids`, `admin_to_computers`, `group_closure`, and ACE indexes — O(n) in node+edge count
7. `DetectionEngine(context).run_all_detections()` calls each category function; each function reads only from `view.*()` and `context.*()` methods — no database I/O
8. Findings list returned; `DetectionEngine.deduplicate_findings()` removes SHA-256 collision duplicates
9. `RiskEngine(view, context).compute_risk(findings)` builds `AttackPath` objects, runs `EdgeRiskEvaluator.evaluate_finding()` for each, sorts by score, computes global score
10. `ThreatModelAssembler(view).assemble(findings, risk_result, metadata)` resolves SIDs → names, constructs `KillPath`, selects top fixes
11. `ThreatModelResult.to_json()` serializes to `.bluehound/results/<timestamp>.json`
12. `GraphConnector.disconnect()` closes the Bolt session
13. If `--no-dashboard` not set, `uvicorn.run("bluehound.api.server:app", ...)` starts serving

---

## Performance by Domain Size

All numbers are approximate wall-clock times on a single-core workload with Neo4j running locally.

| Domain Size | Users | Computers | Groups | `GraphView.load()` | `context.build()` | Detection | Risk Scoring |
|-------------|-------|-----------|--------|-------------------|-------------------|-----------|-------------|
| Small | < 1 K | < 500 | < 200 | < 1 s | < 0.5 s | < 2 s | < 0.5 s |
| Medium | 5 K | 2 K | 1 K | 3–8 s | 2–4 s | 5–15 s | 1–3 s |
| Large | 20 K | 8 K | 4 K | 20–40 s | 10–20 s | 30–60 s | 5–10 s |
| Enterprise | 100 K+ | 40 K+ | 20 K+ | 2–5 min | 1–2 min | 5–10 min | 30–60 s |

The primary bottleneck for large domains is the initial Neo4j query in `GraphView.load()`. Once cached in memory, all detection logic runs in linear time against Python dictionaries.

Memory usage scales at roughly 1–2 KB per node and 200–400 bytes per edge. A 100,000-node domain uses approximately 200–400 MB of Python heap during analysis.

---

## Extension Points

### Adding a New Detection Rule to an Existing Category

```python
# bluehound/detection/category_a.py

def _detect_my_new_rule(view, context, factory):
    findings = []
    for user in view.get_users():
        if not _my_condition(user, context):
            continue
        findings.append(
            factory.create_privilege_finding(
                title=f"My Rule: {user.sam_account_name}",
                description="What was found and why it matters.",
                affected_principals=[user.sid],
                evidence_data={"user_sid": user.sid, "custom_field": "value"},
                severity=Severity.HIGH,
                remediation="Steps to fix this.",
            )
        )
    return findings

# Then add to detect_privilege_exposure():
findings.extend(_detect_my_new_rule(view, context, factory))
```

### Adding a New Detection Category

Create `bluehound/detection/category_f.py` with the canonical signature:

```python
from bluehound.core.types import Finding, FindingCategory

def detect_my_category(view, context, factory) -> list[Finding]:
    ...
```

Register in `DetectionEngine.run_all_detections()`:

```python
from bluehound.detection.category_f import detect_my_category
findings += self.run_category(FindingCategory.MY_CATEGORY, detect_my_category)
```

Add the new `FindingCategory` enum value to `bluehound/core/types.py`. Add a corresponding `CATEGORY_BIAS` entry and `CATEGORY_PRIORITY` entry to `bluehound/risk/engine.py`.

### Modifying the Risk Scoring Model

The four dimension weights are module-level constants in `edge_scoring.py`:

```python
STEALTH_WEIGHT = 0.30        # Modify these to rebalance the model
EXPLOITABILITY_WEIGHT = 0.25
PERSISTENCE_WEIGHT = 0.25
BLAST_RADIUS_WEIGHT = 0.20
```

The weights must sum to 1.0 or scores will fall outside the intended 1–10 range. Category-specific overrides are implemented in `_compute_stealth_score`, `_compute_exploitability_score`, etc. — add new `if c == FindingCategory.X:` branches there.

### Adding a New API Endpoint

```python
# bluehound/api/server.py

@app.get("/api/my-endpoint", summary="My new endpoint")
async def my_endpoint(
    snapshot: Optional[str] = Query(None, description="Snapshot timestamp"),
) -> Dict[str, Any]:
    data = _resolve_snapshot(snapshot)
    # ... extract and return what you need
    return {"my_field": data.get("my_field")}
```

### Extending the Dashboard

The React source is in `bluehound/dashboard/src/`. The API client at `src/api/client.ts` uses SWR hooks for data fetching. Add a new component in `src/components/` and import it in `src/components/Dashboard.tsx`. After changes, rebuild with `npm run build` from `bluehound/dashboard/`.
