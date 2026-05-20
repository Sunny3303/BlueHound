"""
BlueHound Dashboard Backend

FastAPI REST API for serving threat model analysis results.

Features:
- Read-only API (serves pre-computed results only)
- Loads JSON from .bluehound/results/
- CORS restricted to localhost origins only
- Filtering and querying support
- Snapshot comparison via SnapshotDiffEngine
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("BlueHound Dashboard Backend starting…")
    logger.info("Results directory: %s", RESULTS_DIR.absolute())
    yield
    logger.info("BlueHound Dashboard Backend shutting down.")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="BlueHound API",
    description="REST API for Active Directory Threat Modeling",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Response:
    """
    Attach security response headers to every reply.

    - X-Content-Type-Options: prevents browsers from MIME-sniffing a response
      away from the declared Content-Type (blocks drive-by download attacks).
    - X-Frame-Options: blocks the page from being embedded in an <iframe>,
      preventing clickjacking attacks.
    - Content-Security-Policy: restricts what resources the browser may load.
      'unsafe-inline' is required by the Vite-compiled React bundle (inline
      event handlers in the built HTML); tighten this if you add a nonce-based
      build step in future.
    - Referrer-Policy: prevents the full URL from being sent as a Referer
      header to third-party origins.
    - X-XSS-Protection: legacy header for older browsers; modern browsers use
      CSP instead, but this costs nothing to include.
    """
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self';"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# Snapshot timestamp format: YYYY-MM-DD_HHMMSS  e.g. 2026-03-29_164539
_SNAPSHOT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{6}$")

# Results directory — relative to the working directory where `bluehound serve`
# is invoked (i.e. the project root).
RESULTS_DIR = Path(".bluehound/results")


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _results_dir() -> Path:
    """Return the results directory (allows monkeypatching in tests)."""
    return RESULTS_DIR


def get_latest_result_file() -> Path:
    """Return the most recent result JSON file, sorted lexicographically."""
    rd = _results_dir()
    if not rd.exists():
        raise HTTPException(
            status_code=404,
            detail="No analysis results found. Run 'bluehound analyze' first.",
        )

    result_files = sorted(rd.glob("*.json"), reverse=True)
    if not result_files:
        raise HTTPException(
            status_code=404,
            detail="No analysis results found. Run 'bluehound analyze' first.",
        )

    return result_files[0]


def find_result_by_timestamp(timestamp: str) -> Path:
    # Validate format before touching the filesystem at all.
    # Accepts only YYYY-MM-DD_HHMMSS (e.g. 2026-03-29_164539).
    # Anything else — path traversal attempts, arbitrary strings — is
    # rejected here with a 400 before we even resolve a path.
    if not _SNAPSHOT_RE.match(timestamp):
        raise HTTPException(status_code=400, detail="Invalid snapshot identifier.")

    rd = _results_dir().resolve()
    result_file = (rd / f"{timestamp}.json").resolve()

    # Belt-and-suspenders path traversal guard — the regex above already
    # rules out ".." components, but this check costs nothing and ensures
    # the resolved path stays inside the results directory regardless.
    if not str(result_file).startswith(str(rd)):
        raise HTTPException(status_code=400, detail="Invalid snapshot identifier.")

    if not result_file.exists():
        raise HTTPException(status_code=404, detail="Snapshot not found.")

    return result_file


def load_threat_model(file_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and return raw ThreatModelResult JSON from disk."""
    if file_path is None:
        file_path = get_latest_result_file()

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Analysis result not found.")
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500, detail="Result file contains invalid JSON."
        )


def _resolve_snapshot(snapshot: Optional[str]) -> Dict[str, Any]:
    """Centralised helper — load a named snapshot or fall back to latest."""
    if snapshot:
        return load_threat_model(find_result_by_timestamp(snapshot))
    return load_threat_model()


# ---------------------------------------------------------------------------
# Serialisation helper for diff output
# ---------------------------------------------------------------------------


def _make_serialisable(obj: Any) -> Any:
    """Recursively convert dataclass / enum / datetime objects to JSON-safe types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _make_serialisable(v) for k, v in dataclasses.asdict(obj).items()}
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "value"):          # Enum
        return obj.value
    if hasattr(obj, "isoformat"):      # datetime / timedelta-like
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _make_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_serialisable(i) for i in obj]
    return obj


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health", summary="Health check")
async def health_check() -> Dict[str, Any]:
    """
    Returns the current health status of the API.

    No analysis data required — always succeeds while the server is running.
    """
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@app.get("/api/threat-model", summary="Full ThreatModelResult")
async def get_threat_model(
    snapshot: Optional[str] = Query(
        None, description="Snapshot timestamp, e.g. 2026-03-29_164539"
    )
) -> Dict[str, Any]:
    """
    Return the complete raw ThreatModelResult JSON for the latest (or a
    named) snapshot.
    """
    return _resolve_snapshot(snapshot)


@app.get("/api/summary", summary="High-level risk summary")
async def get_summary(
    snapshot: Optional[str] = Query(None, description="Snapshot timestamp")
) -> Dict[str, Any]:
    """
    Return a concise summary suitable for a dashboard headline panel.

    Includes risk score, classification, finding counts by severity, domain,
    and tier-0 reachability.
    """
    data = _resolve_snapshot(snapshot)
    findings = data.get("findings", [])

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1

    return {
        "risk_score": data.get("risk_score", 0.0),
        "risk_classification": data.get("risk_classification", "UNKNOWN"),
        "exposure_level": data.get("exposure_level", "unknown"),
        "tier0_reachable": data.get("tier0_reachable", False),
        "total_findings": len(findings),
        "critical_findings": counts["critical"],
        "high_findings": counts["high"],
        "medium_findings": counts["medium"],
        "low_findings": counts["low"],
        "domain": data.get("metadata", {}).get("domain_fqdn", "UNKNOWN"),
        "analysis_timestamp": data.get("metadata", {}).get("collected_at", ""),
    }


@app.get("/api/findings", summary="List findings (with optional filters)")
async def get_findings(
    snapshot: Optional[str] = Query(None, description="Snapshot timestamp"),
    category: Optional[str] = Query(
        None,
        description="Filter by category slug, e.g. privilege_exposure, kerberos_abuse",
    ),
    severity: Optional[str] = Query(
        None,
        description="Filter by severity: critical | high | medium | low",
    ),
    limit: Optional[int] = Query(
        None, ge=1, le=1000, description="Maximum number of findings to return"
    ),
) -> Dict[str, Any]:
    """
    Return findings, optionally filtered by category and/or severity.

    ``category`` matches against the slug returned by ``Finding.category.label()``
    (e.g. ``privilege_exposure``).
    """
    data = _resolve_snapshot(snapshot)
    findings: List[Dict[str, Any]] = data.get("findings", [])

    if category:
        findings = [f for f in findings if f.get("category") == category]

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]

    if limit is not None:
        findings = findings[:limit]

    return {
        "total": len(findings),
        "filters": {"category": category, "severity": severity, "limit": limit},
        "findings": findings,
    }


@app.get("/api/findings/{finding_id}", summary="Single finding by ID")
async def get_finding(
    finding_id: str,
    snapshot: Optional[str] = Query(None, description="Snapshot timestamp"),
) -> Dict[str, Any]:
    """Return a single finding object matched by its unique ``id`` field."""
    data = _resolve_snapshot(snapshot)
    for finding in data.get("findings", []):
        if finding.get("id") == finding_id:
            return finding

    raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")


@app.get("/api/statistics", summary="Detailed statistics breakdown")
async def get_statistics(
    snapshot: Optional[str] = Query(None, description="Snapshot timestamp")
) -> Dict[str, Any]:
    """
    Return aggregate statistics broken down by category and severity.

    Also surfaces blast_radius, tier0_reachable, time_to_domain_admin and
    detection_surface from the threat model.
    """
    data = _resolve_snapshot(snapshot)
    findings: List[Dict[str, Any]] = data.get("findings", [])

    by_category: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    for f in findings:
        cat = f.get("category", "unknown")
        sev = f.get("severity", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total_findings": len(findings),
        "by_category": by_category,
        "by_severity": by_severity,
        "blast_radius": data.get("blast_radius"),
        "tier0_reachable": data.get("tier0_reachable", False),
        "time_to_domain_admin": data.get("time_to_domain_admin"),
        "detection_surface": data.get("detection_surface"),
        "category_breakdown": data.get("category_breakdown", {}),
    }


@app.get("/api/attack-paths", summary="Tier-0 kill path")
async def get_attack_paths(
    snapshot: Optional[str] = Query(None, description="Snapshot timestamp")
) -> Dict[str, Any]:
    """
    Return the primary kill path (if one exists) and tier-0 reachability
    information.
    """
    data = _resolve_snapshot(snapshot)

    return {
        "tier0_reachable": data.get("tier0_reachable", False),
        "primary_kill_path": data.get("primary_kill_path"),
        "time_to_domain_admin": data.get("time_to_domain_admin"),
    }


@app.get("/api/snapshots", summary="List available snapshots")
async def list_snapshots() -> Dict[str, Any]:
    """
    Enumerate every result file in ``.bluehound/results/`` and return a
    lightweight summary for each one.

    The server-side file path is intentionally omitted from each snapshot
    entry to avoid leaking filesystem layout information to API consumers.
    Use the ``timestamp`` field as the snapshot identifier in subsequent
    requests (e.g. ``GET /api/threat-model?snapshot=<timestamp>``).

    Files that cannot be parsed are silently skipped so a single corrupt
    file does not break the listing.
    """
    rd = _results_dir()
    if not rd.exists():
        return {"snapshots": []}

    snapshots: List[Dict[str, Any]] = []
    for result_file in sorted(rd.glob("*.json"), reverse=True):
        try:
            with open(result_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            snapshots.append(
                {
                    "timestamp": result_file.stem,
                    "domain": data.get("metadata", {}).get("domain_fqdn", "UNKNOWN"),
                    "risk_score": data.get("risk_score", 0.0),
                    "risk_classification": data.get("risk_classification", "UNKNOWN"),
                    "findings_count": len(data.get("findings", [])),
                    # file_path intentionally omitted — exposing the server-side
                    # filesystem path would leak implementation details to consumers.
                    # The timestamp field is the canonical snapshot identifier.
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load %s: %s", result_file, exc)

    return {"snapshots": snapshots}


@app.get("/api/diff", summary="Compare two snapshots")
async def compare_snapshots(
    baseline: str = Query(..., description="Baseline snapshot timestamp"),
    current: str = Query(..., description="Current snapshot timestamp"),
) -> JSONResponse:
    """
    Run the SnapshotDiffEngine against two named snapshots and return the
    full diff payload as JSON.

    Both ``baseline`` and ``current`` must be timestamps that correspond to
    files in ``.bluehound/results/``.
    """
    from bluehound.diff.engine import SnapshotDiffEngine
    from bluehound.core.types import ThreatModelResult

    baseline_data = load_threat_model(find_result_by_timestamp(baseline))
    current_data = load_threat_model(find_result_by_timestamp(current))

    baseline_result = ThreatModelResult.from_dict(baseline_data)
    current_result = ThreatModelResult.from_dict(current_data)

    diff_engine = SnapshotDiffEngine()
    diff_result = diff_engine.compare(baseline_result, current_result)

    return JSONResponse(content=_make_serialisable(diff_result))


# ---------------------------------------------------------------------------
# React dashboard — serve built frontend
# ---------------------------------------------------------------------------

_DASHBOARD_DIST = Path(__file__).parent.parent / "dashboard" / "dist"

if _DASHBOARD_DIST.exists():
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse as _FileResponse

    _assets = _DASHBOARD_DIST / "assets"
    if _assets.exists():
        app.mount("/assets", StaticFiles(directory=str(_assets)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _serve_spa(full_path: str) -> _FileResponse:
        """
        Catch-all that returns index.html for any non-API path, enabling
        React Router's client-side navigation to work correctly.
        """
        index = _DASHBOARD_DIST / "index.html"
        return _FileResponse(str(index))


# ---------------------------------------------------------------------------
# Dev entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "bluehound.api.server:app",
        host="127.0.0.1",
        port=8080,
        reload=True,
        log_level="info",
    )
