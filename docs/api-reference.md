# BlueHound API Reference

The BlueHound REST API is served by FastAPI at `http://localhost:8080` (default). Interactive Swagger docs are available at `/api/docs`. All endpoints are read-only — no mutations are exposed.

---

## Base URL

```
http://localhost:8080
```

---

## Authentication

The API has no authentication. It is bound to `127.0.0.1` by default and intended for local use only. Do not expose it on a public interface.

---

## Common Query Parameters

All endpoints that return snapshot data accept an optional `snapshot` query parameter:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `snapshot` | string | No | Snapshot timestamp (e.g. `2026-03-29_164539`). Omit to use the latest result. |

Snapshot timestamps match the file stems in `.bluehound/results/`. Use `GET /api/snapshots` to enumerate available values.

---

## Endpoints

### GET /api/health

Health check. Always succeeds while the server is running.

**Request:** No parameters.

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-03-29T16:45:39Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Always `"healthy"` |
| `version` | string | API version |
| `timestamp` | string | ISO 8601 UTC timestamp of the response |

**Status codes:** `200 OK`

**Examples:**

```bash
# curl
curl http://localhost:8080/api/health

# Python
import requests
r = requests.get("http://localhost:8080/api/health")
print(r.json())

# PowerShell
Invoke-RestMethod http://localhost:8080/api/health

# JavaScript
const r = await fetch("http://localhost:8080/api/health").then(r => r.json());
```

---

### GET /api/threat-model

Returns the complete raw `ThreatModelResult` JSON for the latest or named snapshot.

**Query Parameters:** `snapshot` (optional)

**Response:** Full `ThreatModelResult` object. Key top-level fields:

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | float | Global risk score 0.0–10.0 |
| `risk_classification` | string | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `exposure_level` | string | `contained` / `localized` / `domain_wide` / `catastrophic` |
| `tier0_reachable` | boolean | Whether any Tier-0 path was found |
| `findings` | array | Full list of `Finding` objects |
| `primary_kill_path` | object or null | Most dangerous attack path |
| `blast_radius` | float | Fraction of principals affected (0.0–1.0) |
| `top_fixes` | array[string] | Prioritized remediation steps |
| `metadata` | object | Domain, collection timestamp, collector |
| `category_breakdown` | object | Finding counts by category slug |
| `time_to_domain_admin` | integer or null | Minimum hop count to DA (null if not reachable) |
| `detection_surface` | integer or null | Total principals in detection scope |

**Status codes:** `200 OK`, `404 Not Found` (no results or snapshot not found)

**Examples:**

```bash
# Latest result
curl http://localhost:8080/api/threat-model

# Specific snapshot
curl "http://localhost:8080/api/threat-model?snapshot=2026-03-29_164539"
```

```python
import requests

data = requests.get("http://localhost:8080/api/threat-model").json()
print(f"Risk: {data['risk_score']}/10 ({data['risk_classification']})")
print(f"Tier-0 reachable: {data['tier0_reachable']}")
```

```powershell
$tm = Invoke-RestMethod http://localhost:8080/api/threat-model
Write-Host "Risk: $($tm.risk_score)/10"
```

---

### GET /api/summary

Returns a concise summary suitable for a dashboard headline panel.

**Query Parameters:** `snapshot` (optional)

**Response:**

```json
{
  "risk_score": 7.8,
  "risk_classification": "HIGH",
  "exposure_level": "domain_wide",
  "tier0_reachable": true,
  "total_findings": 23,
  "critical_findings": 4,
  "high_findings": 9,
  "medium_findings": 8,
  "low_findings": 2,
  "domain": "CORP.LOCAL",
  "analysis_timestamp": "2026-03-29T16:43:10Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | float | Global score 0.0–10.0 |
| `risk_classification` | string | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `exposure_level` | string | Current exposure level |
| `tier0_reachable` | boolean | Whether Tier-0 paths exist |
| `total_findings` | integer | Total finding count |
| `critical_findings` | integer | Count of CRITICAL severity findings |
| `high_findings` | integer | Count of HIGH severity findings |
| `medium_findings` | integer | Count of MEDIUM severity findings |
| `low_findings` | integer | Count of LOW severity findings |
| `domain` | string | Domain FQDN from snapshot metadata |
| `analysis_timestamp` | string | ISO 8601 collection timestamp |

**Status codes:** `200 OK`, `404 Not Found`

**Examples:**

```bash
curl http://localhost:8080/api/summary | jq '.risk_score, .tier0_reachable'
```

```javascript
const summary = await fetch("/api/summary").then(r => r.json());
document.getElementById("score").textContent = summary.risk_score.toFixed(1);
```

---

### GET /api/findings

Returns findings, optionally filtered by category and/or severity.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `snapshot` | string | No | Snapshot timestamp |
| `category` | string | No | Category slug: `privilege_exposure`, `kerberos_abuse`, `delegation_abuse`, `adcs_abuse`, `tier0_exposure` |
| `severity` | string | No | Severity: `critical`, `high`, `medium`, `low` |
| `limit` | integer | No | Maximum results to return (1–1000) |

**Response:**

```json
{
  "total": 4,
  "filters": {
    "category": "adcs_abuse",
    "severity": "critical",
    "limit": null
  },
  "findings": [
    {
      "id": "d1-adcs-UserTemplate-f9c1",
      "category": "adcs_abuse",
      "severity": "critical",
      "confidence": "explicit",
      "title": "ESC1: Vulnerable Certificate Template 'UserTemplate'",
      "description": "...",
      "affected_principals": ["S-1-5-21-1234-5678-9012-4001"],
      "evidence": { "type": "certificate_template", "raw_data": { ... } },
      "mitre_techniques": ["T1649"],
      "remediation": "..."
    }
  ]
}
```

**Finding object fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Deterministic SHA-256 derived ID |
| `category` | string | Category slug |
| `severity` | string | `critical` / `high` / `medium` / `low` |
| `confidence` | string | `explicit` (directly observed) or `inferred` (heuristic) |
| `title` | string | Human-readable one-line description |
| `description` | string | Extended description with context |
| `affected_principals` | array[string] | SIDs of affected AD principals |
| `evidence` | object | Evidence container with `type` and `raw_data` |
| `mitre_techniques` | array[string] | MITRE ATT&CK technique IDs |
| `remediation` | string | Step-by-step remediation guidance |

**Status codes:** `200 OK`, `404 Not Found`, `422 Unprocessable Entity` (invalid `limit`)

**Examples:**

```bash
# All critical ADCS findings
curl "http://localhost:8080/api/findings?category=adcs_abuse&severity=critical"

# First 10 high findings
curl "http://localhost:8080/api/findings?severity=high&limit=10"
```

```python
import requests

findings = requests.get(
    "http://localhost:8080/api/findings",
    params={"category": "tier0_exposure", "severity": "critical"}
).json()["findings"]

for f in findings:
    print(f["title"])
```

```powershell
$findings = Invoke-RestMethod "http://localhost:8080/api/findings?severity=critical"
$findings.findings | Select-Object title, category
```

---

### GET /api/findings/{finding_id}

Returns a single finding by its unique ID.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `finding_id` | string | The `id` field from a finding object |

**Query Parameters:** `snapshot` (optional)

**Response:** Single `Finding` object (same schema as items in `/api/findings`).

**Status codes:** `200 OK`, `404 Not Found`

**Examples:**

```bash
curl http://localhost:8080/api/findings/d1-adcs-UserTemplate-f9c1
```

```python
r = requests.get(f"http://localhost:8080/api/findings/{finding_id}")
if r.status_code == 200:
    f = r.json()
    print(f["remediation"])
```

---

### GET /api/statistics

Returns aggregate statistics broken down by category and severity, plus blast radius and tier-0 metadata.

**Query Parameters:** `snapshot` (optional)

**Response:**

```json
{
  "total_findings": 23,
  "by_category": {
    "privilege_exposure": 8,
    "kerberos_abuse": 6,
    "delegation_abuse": 3,
    "adcs_abuse": 3,
    "tier0_exposure": 3
  },
  "by_severity": {
    "critical": 4,
    "high": 9,
    "medium": 8,
    "low": 2
  },
  "blast_radius": 0.34,
  "tier0_reachable": true,
  "time_to_domain_admin": 2,
  "detection_surface": 4201,
  "category_breakdown": {
    "privilege_exposure": 8,
    "kerberos_abuse": 6
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `total_findings` | integer | Total finding count |
| `by_category` | object | Count per category slug |
| `by_severity` | object | Count per severity level |
| `blast_radius` | float | Fraction of domain principals affected (0.0–1.0) |
| `tier0_reachable` | boolean | Whether Tier-0 paths were found |
| `time_to_domain_admin` | integer or null | Shortest hop count to Domain Admin |
| `detection_surface` | integer or null | Total users + computers analyzed |
| `category_breakdown` | object | Alias for `by_category`, from stored result |

**Status codes:** `200 OK`, `404 Not Found`

**Examples:**

```bash
curl http://localhost:8080/api/statistics | jq '.blast_radius'
```

```python
stats = requests.get("http://localhost:8080/api/statistics").json()
print(f"Blast radius: {stats['blast_radius']:.1%}")
print(f"DA reachable in: {stats['time_to_domain_admin']} hops")
```

---

### GET /api/attack-paths

Returns the primary kill path and tier-0 reachability information.

**Query Parameters:** `snapshot` (optional)

**Response:**

```json
{
  "tier0_reachable": true,
  "primary_kill_path": {
    "nodes": ["jsmith", "SRV-APP01", "DC01"],
    "techniques": ["WriteDACL", "AdminTo"],
    "total_hops": 2,
    "risk_score": 9.1
  },
  "time_to_domain_admin": 2
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tier0_reachable` | boolean | Whether any path to Tier-0 was found |
| `primary_kill_path` | object or null | Most dangerous attack path (null if none) |
| `primary_kill_path.nodes` | array[string] | Principal names along the path |
| `primary_kill_path.techniques` | array[string] | Techniques at each hop |
| `primary_kill_path.total_hops` | integer | Number of hops |
| `primary_kill_path.risk_score` | float | Score for this specific path |
| `time_to_domain_admin` | integer or null | Minimum hop count |

**Status codes:** `200 OK`, `404 Not Found`

**Examples:**

```bash
curl http://localhost:8080/api/attack-paths | jq '.primary_kill_path.nodes'
```

```javascript
const paths = await fetch("/api/attack-paths").then(r => r.json());
if (paths.tier0_reachable) {
  const killPath = paths.primary_kill_path.nodes.join(" → ");
  console.warn(`Kill path detected: ${killPath}`);
}
```

---

### GET /api/snapshots

Lists all available analysis result files with lightweight metadata for each.

**Request:** No parameters.

**Response:**

```json
{
  "snapshots": [
    {
      "timestamp": "2026-03-29_164539",
      "domain": "CORP.LOCAL",
      "risk_score": 7.8,
      "risk_classification": "HIGH",
      "findings_count": 23
    },
    {
      "timestamp": "2026-03-29_164310",
      "domain": "CORP.LOCAL",
      "risk_score": 8.2,
      "risk_classification": "CRITICAL",
      "findings_count": 27
    }
  ]
}
```

Snapshots are returned in reverse chronological order (newest first). Corrupt or unparseable result files are silently skipped.

> **Note:** The server-side file path is intentionally omitted from each entry. Use the `timestamp` field as the identifier in subsequent requests (e.g. `GET /api/threat-model?snapshot=2026-03-29_164539`).

**Status codes:** `200 OK`

**Examples:**

```bash
curl http://localhost:8080/api/snapshots | jq '.snapshots[].timestamp'
```

```python
snapshots = requests.get("http://localhost:8080/api/snapshots").json()["snapshots"]
for s in snapshots:
    print(f"{s['timestamp']} — {s['domain']} — {s['risk_score']}")
```

---

### GET /api/diff

Compares two named snapshots and returns a full diff report.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `baseline` | string | Yes | Baseline snapshot timestamp |
| `current` | string | Yes | Current snapshot timestamp |

**Response:** `SnapshotDiff` object:

```json
{
  "baseline_timestamp": "2026-01-15T09:30:00Z",
  "current_timestamp": "2026-03-29T16:45:39Z",
  "baseline_domain": "CORP.LOCAL",
  "current_domain": "CORP.LOCAL",
  "time_delta": "P73DT7H15M39S",
  "risk_score_delta": -0.4,
  "risk_classification_change": "HIGH → HIGH",
  "exposure_level_change": "domain_wide → domain_wide",
  "new_findings": [...],
  "removed_findings": [...],
  "changed_findings": [...],
  "unchanged_finding_count": 18,
  "new_findings_by_category": { "adcs_abuse": 1, "kerberos_abuse": 2 },
  "removed_findings_by_category": { "delegation_abuse": 1 },
  "new_critical_count": 1,
  "removed_critical_count": 0,
  "severity_escalations": [],
  "severity_improvements": [],
  "privilege_creep_detected": false,
  "privilege_creep_principals": [],
  "tier0_exposure_regression": false,
  "new_tier0_paths": [],
  "blast_radius_delta": -0.02,
  "affected_principal_delta": -84,
  "new_mitre_techniques": ["T1649"],
  "removed_mitre_techniques": ["T1134.001"],
  "total_findings_delta": 2,
  "improvement_score": -1.8
}
```

**Key diff fields:**

| Field | Type | Description |
|-------|------|-------------|
| `risk_score_delta` | float | Positive = worse, negative = better |
| `new_findings` | array | Findings in current not in baseline |
| `removed_findings` | array | Findings in baseline not in current |
| `privilege_creep_detected` | boolean | Whether principals gained new Tier-0 access |
| `tier0_exposure_regression` | boolean | Whether new Tier-0 attack paths appeared |
| `improvement_score` | float | Signed score: positive = regression, negative = improvement |

**Status codes:** `200 OK`, `404 Not Found` (snapshot not found), `400 Bad Request` (invalid timestamp)

**Examples:**

```bash
curl "http://localhost:8080/api/diff?baseline=2026-01-15_093000&current=2026-03-29_164539" \
    | jq '{delta: .risk_score_delta, new: (.new_findings | length)}'
```

```python
diff = requests.get(
    "http://localhost:8080/api/diff",
    params={"baseline": "2026-01-15_093000", "current": "2026-03-29_164539"}
).json()

if diff["tier0_exposure_regression"]:
    print("⚠️ TIER-0 REGRESSION DETECTED")
    for path in diff["new_tier0_paths"]:
        print(f"  • {path}")
```

```javascript
const params = new URLSearchParams({
  baseline: "2026-01-15_093000",
  current: "2026-03-29_164539"
});
const diff = await fetch(`/api/diff?${params}`).then(r => r.json());
```

---

## Error Responses

All error responses follow the FastAPI default format:

```json
{
  "detail": "No analysis results found. Run 'bluehound analyze' first."
}
```

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Invalid snapshot identifier (path traversal attempt) |
| `404 Not Found` | No result files, or the specified snapshot does not exist |
| `422 Unprocessable Entity` | Query parameter validation failed (e.g. `limit` out of range) |
| `500 Internal Server Error` | Corrupt or unparseable result JSON |
