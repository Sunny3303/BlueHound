"""
Tests for bluehound.api.server

Uses FastAPI's TestClient (backed by httpx) for in-process request
testing — no running server required.

Monkeypatching strategy:
    All tests that need result files monkeypatch ``bluehound.api.server.RESULTS_DIR``
    so the server points at a tmp_path directory populated by the test.
    This keeps tests hermetic and avoids touching any real .bluehound/results/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import bluehound.api.server as server_module
from bluehound.api.server import app

client = TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_result(directory: Path, filename: str, payload: dict) -> Path:
    """Write *payload* as JSON to *directory*/*filename* and return the path."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _minimal_result(**overrides) -> dict:
    """Minimal valid ThreatModelResult payload for test use."""
    base = {
        "metadata": {
            "version": "1.0.0",
            "collected_at": "2026-03-29T16:45:39+00:00",
            "domain_fqdn": "TEST.LOCAL",
            "collector": "sharphound",
            "signature": "abc123",
        },
        "risk_score": 7.5,
        "risk_classification": "HIGH",
        "exposure_level": "localized",
        "tier0_reachable": True,
        "blast_radius": 0.42,
        "time_to_domain_admin": "2–8 hours",
        "detection_surface": "Medium",
        "category_breakdown": {"privilege_exposure": 2, "kerberos_abuse": 1},
        "findings": [],
        "top_fixes": [],
        "primary_kill_path": None,
    }
    base.update(overrides)
    return base


def _make_finding(
    fid: str,
    severity: str = "high",
    category: str = "privilege_exposure",
) -> dict:
    return {
        "id": fid,
        "category": category,
        "severity": severity,
        "confidence": "explicit",
        "title": f"Test finding {fid}",
        "description": "A test finding.",
        "evidence": {
            "type": "account",
            "raw_data": {},
            "reasoning": "Test reasoning.",
        },
        "affected_principals": ["S-1-5-21-test"],
        "mitre_techniques": ["T1078.002"],
        "remediation": "Fix it.",
    }


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_returns_200(self):
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_status_healthy(self):
        data = client.get("/api/health").json()
        assert data["status"] == "healthy"

    def test_has_version(self):
        data = client.get("/api/health").json()
        assert "version" in data
        assert data["version"] == "1.0.0"

    def test_has_timestamp(self):
        data = client.get("/api/health").json()
        assert "timestamp" in data
        # Timestamp ends with Z (UTC)
        assert data["timestamp"].endswith("Z")


# ---------------------------------------------------------------------------
# /api/threat-model
# ---------------------------------------------------------------------------


class TestThreatModel:
    def test_returns_full_payload(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "2026-03-29_164539.json", _minimal_result())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        response = client.get("/api/threat-model")
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == 7.5
        assert data["metadata"]["domain_fqdn"] == "TEST.LOCAL"

    def test_no_results_returns_404(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        rd.mkdir(parents=True)
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        response = client.get("/api/threat-model")
        assert response.status_code == 404

    def test_named_snapshot(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "2026-03-29_164310.json", _minimal_result(risk_score=5.0))
        _write_result(rd, "2026-03-29_164539.json", _minimal_result(risk_score=7.5))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        response = client.get("/api/threat-model?snapshot=2026-03-29_164310")
        assert response.status_code == 200
        assert response.json()["risk_score"] == 5.0

    def test_unknown_snapshot_returns_404(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "2026-03-29_164539.json", _minimal_result())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        response = client.get("/api/threat-model?snapshot=9999-01-01_000000")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# /api/summary
# ---------------------------------------------------------------------------


class TestSummary:
    def test_risk_score_propagated(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", _minimal_result(risk_score=8.8))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/summary").json()
        assert data["risk_score"] == 8.8

    def test_finding_counts_by_severity(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        result = _minimal_result(
            findings=[
                _make_finding("F1", severity="critical"),
                _make_finding("F2", severity="critical"),
                _make_finding("F3", severity="high"),
                _make_finding("F4", severity="medium"),
                _make_finding("F5", severity="low"),
            ]
        )
        _write_result(rd, "snap.json", result)
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/summary").json()
        assert data["total_findings"] == 5
        assert data["critical_findings"] == 2
        assert data["high_findings"] == 1
        assert data["medium_findings"] == 1
        assert data["low_findings"] == 1

    def test_domain_extracted(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", _minimal_result())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/summary").json()
        assert data["domain"] == "TEST.LOCAL"

    def test_tier0_reachable_propagated(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", _minimal_result(tier0_reachable=False))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/summary").json()
        assert data["tier0_reachable"] is False


# ---------------------------------------------------------------------------
# /api/findings
# ---------------------------------------------------------------------------


class TestFindings:
    def _result_with_findings(self) -> dict:
        return _minimal_result(
            findings=[
                _make_finding("F1", severity="critical", category="privilege_exposure"),
                _make_finding("F2", severity="high",     category="kerberos_abuse"),
                _make_finding("F3", severity="critical", category="privilege_exposure"),
                _make_finding("F4", severity="medium",   category="delegation_abuse"),
                _make_finding("F5", severity="high",     category="kerberos_abuse"),
            ]
        )

    def test_all_findings_returned(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/findings").json()
        assert data["total"] == 5

    def test_filter_by_severity_critical(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/findings?severity=critical").json()
        assert data["total"] == 2
        assert all(f["severity"] == "critical" for f in data["findings"])

    def test_filter_by_category(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/findings?category=kerberos_abuse").json()
        assert data["total"] == 2
        assert all(f["category"] == "kerberos_abuse" for f in data["findings"])

    def test_combined_filters(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get(
            "/api/findings?category=privilege_exposure&severity=critical"
        ).json()
        assert data["total"] == 2

    def test_limit_respected(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/findings?limit=2").json()
        assert len(data["findings"]) == 2

    def test_filters_echoed_in_response(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/findings?severity=high&limit=10").json()
        assert data["filters"]["severity"] == "high"
        assert data["filters"]["limit"] == 10

    def test_unknown_severity_returns_empty(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", self._result_with_findings())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/findings?severity=ultrafire").json()
        assert data["total"] == 0


# ---------------------------------------------------------------------------
# /api/findings/{finding_id}
# ---------------------------------------------------------------------------


class TestFindingById:
    def test_existing_finding_returned(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(
            rd,
            "snap.json",
            _minimal_result(findings=[_make_finding("PRIV-abc123")]),
        )
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        response = client.get("/api/findings/PRIV-abc123")
        assert response.status_code == 200
        assert response.json()["id"] == "PRIV-abc123"

    def test_missing_finding_returns_404(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", _minimal_result(findings=[]))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        response = client.get("/api/findings/DOES-NOT-EXIST")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# /api/statistics
# ---------------------------------------------------------------------------


class TestStatistics:
    def test_structure(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(
            rd,
            "snap.json",
            _minimal_result(
                findings=[
                    _make_finding("F1", severity="high", category="privilege_exposure"),
                    _make_finding("F2", severity="medium", category="kerberos_abuse"),
                ]
            ),
        )
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/statistics").json()

        assert data["total_findings"] == 2
        assert data["by_category"]["privilege_exposure"] == 1
        assert data["by_category"]["kerberos_abuse"] == 1
        assert data["by_severity"]["high"] == 1
        assert data["by_severity"]["medium"] == 1
        assert data["blast_radius"] == pytest.approx(0.42)
        assert data["tier0_reachable"] is True


# ---------------------------------------------------------------------------
# /api/attack-paths
# ---------------------------------------------------------------------------


class TestAttackPaths:
    def test_no_kill_path(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "snap.json", _minimal_result(tier0_reachable=False))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/attack-paths").json()
        assert data["tier0_reachable"] is False
        assert data["primary_kill_path"] is None

    def test_with_kill_path(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        kp = {
            "nodes": ["intern1", "WS01", "Domain Admin"],
            "techniques": ["Kerberoast", "AdminTo"],
            "estimated_time": "2–8 hours",
            "stealth_level": "Medium",
        }
        _write_result(
            rd,
            "snap.json",
            _minimal_result(tier0_reachable=True, primary_kill_path=kp),
        )
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/attack-paths").json()
        assert data["tier0_reachable"] is True
        assert data["primary_kill_path"]["nodes"] == ["intern1", "WS01", "Domain Admin"]


# ---------------------------------------------------------------------------
# /api/snapshots
# ---------------------------------------------------------------------------


class TestSnapshots:
    def test_empty_when_no_results_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(server_module, "RESULTS_DIR", tmp_path / "nonexistent")
        data = client.get("/api/snapshots").json()
        assert data == {"snapshots": []}

    def test_lists_all_snapshots(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "2026-03-29_164310.json", _minimal_result(risk_score=5.0))
        _write_result(rd, "2026-03-29_164539.json", _minimal_result(risk_score=7.5))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/snapshots").json()
        assert len(data["snapshots"]) == 2

    def test_snapshot_metadata_fields(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "2026-03-29_164539.json", _minimal_result())
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        snap = client.get("/api/snapshots").json()["snapshots"][0]
        assert snap["timestamp"] == "2026-03-29_164539"
        assert snap["domain"] == "TEST.LOCAL"
        assert snap["risk_score"] == 7.5
        assert snap["risk_classification"] == "HIGH"
        assert snap["findings_count"] == 0
        # file_path must NOT be present — exposing the server-side filesystem
        # path to API consumers leaks implementation details.
        assert "file_path" not in snap

    def test_snapshots_sorted_newest_first(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        _write_result(rd, "2026-01-01_000000.json", _minimal_result(risk_score=3.0))
        _write_result(rd, "2026-06-01_000000.json", _minimal_result(risk_score=9.0))
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        snaps = client.get("/api/snapshots").json()["snapshots"]
        assert snaps[0]["timestamp"] == "2026-06-01_000000"
        assert snaps[1]["timestamp"] == "2026-01-01_000000"

    def test_corrupt_file_skipped_gracefully(self, tmp_path, monkeypatch):
        rd = tmp_path / ".bluehound" / "results"
        rd.mkdir(parents=True, exist_ok=True)
        _write_result(rd, "2026-03-29_164539.json", _minimal_result())
        (rd / "corrupt.json").write_text("THIS IS NOT JSON", encoding="utf-8")
        monkeypatch.setattr(server_module, "RESULTS_DIR", rd)

        data = client.get("/api/snapshots").json()
        # Corrupt file is skipped; valid snapshot still listed
        assert len(data["snapshots"]) == 1


# ---------------------------------------------------------------------------
# CORS headers
# ---------------------------------------------------------------------------


class TestCORS:
    def test_cors_header_present_for_allowed_origin(self):
        response = client.get(
            "/api/health",
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers
