"""
tests/unit/test_cli_diff.py

CLI diff command tests.

Uses the actual ThreatModelResult / to_dict() schema so that round-tripping
through from_dict() works without field mismatches.
"""

import json
import pytest
from click.testing import CliRunner
from bluehound.cli.main import cli


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_result(risk_score: float = 5.0, timestamp: str = "2026-02-10T09:00:00+00:00") -> dict:
    """
    Build a minimal but valid ThreatModelResult dict that matches
    the actual to_dict() output schema of this codebase.
    """
    return {
        "metadata": {
            "version": "1.0.0",
            "collected_at": timestamp,
            "domain_fqdn": "TEST.LOCAL",
            "collector": "sharphound",
            "signature": "abc123",
        },
        # Fields produced by assembler / to_dict()
        "risk_score": risk_score,
        "exposure_level": "contained",
        "tier0_reachable": False,
        "blast_radius": 0.1,
        "time_to_domain_admin": None,
        "detection_surface": None,
        "category_breakdown": {},
        "findings": [],
        "top_fixes": [],
        "primary_kill_path": None,
        # mitre_techniques is stored at result level by the assembler
        "mitre_techniques": [],
    }


# ─── Tests ───────────────────────────────────────────────────────────────────

def test_diff_command_exists():
    """diff --help must exit 0 and mention comparison."""
    runner = CliRunner()
    result = runner.invoke(cli, ["diff", "--help"])

    assert result.exit_code == 0
    assert "compare" in result.output.lower()


def test_diff_missing_files():
    """diff with non-existent paths must fail."""
    runner = CliRunner()
    result = runner.invoke(cli, ["diff", "nonexistent_a.json", "nonexistent_b.json"])

    assert result.exit_code != 0


def test_diff_same_snapshot_no_regression(tmp_path):
    """Comparing identical snapshots must NOT be a regression (exit 0)."""
    data = _make_result(risk_score=5.0)

    bfile = tmp_path / "baseline.json"
    cfile = tmp_path / "current.json"

    bfile.write_text(json.dumps(data))
    cfile.write_text(json.dumps(data))

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(bfile), str(cfile)])

    assert "Snapshot Comparison" in result.output
    assert result.exit_code == 0


def test_diff_with_risk_increase_is_regression(tmp_path):
    """
    When risk score increases between snapshots the command must
    exit 1 (regression) and show the comparison header.
    """
    baseline = _make_result(risk_score=5.0, timestamp="2026-02-10T09:00:00+00:00")
    current  = _make_result(risk_score=8.0, timestamp="2026-02-11T09:00:00+00:00")

    bfile = tmp_path / "b.json"
    cfile = tmp_path / "c.json"

    bfile.write_text(json.dumps(baseline))
    cfile.write_text(json.dumps(current))

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(bfile), str(cfile)])

    assert "Snapshot Comparison" in result.output
    assert result.exit_code == 1


def test_diff_with_risk_decrease_is_improvement(tmp_path):
    """
    When risk score decreases the command must exit 0 (improvement).
    """
    baseline = _make_result(risk_score=8.0, timestamp="2026-02-10T09:00:00+00:00")
    current  = _make_result(risk_score=5.0, timestamp="2026-02-11T09:00:00+00:00")

    bfile = tmp_path / "b.json"
    cfile = tmp_path / "c.json"

    bfile.write_text(json.dumps(baseline))
    cfile.write_text(json.dumps(current))

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(bfile), str(cfile)])

    assert "Snapshot Comparison" in result.output
    assert result.exit_code == 0


def test_diff_saves_text_report(tmp_path):
    """--output with --format text writes a file."""
    data    = _make_result()
    bfile   = tmp_path / "b.json"
    cfile   = tmp_path / "c.json"
    outfile = tmp_path / "report.txt"

    bfile.write_text(json.dumps(data))
    cfile.write_text(json.dumps(data))

    runner = CliRunner()
    runner.invoke(cli, [
        "diff", str(bfile), str(cfile),
        "--output", str(outfile),
        "--format", "text",
    ])

    assert outfile.exists()
    assert outfile.stat().st_size > 0


def test_diff_saves_json_report(tmp_path):
    """--output with --format json writes valid JSON."""
    baseline = _make_result(risk_score=5.0, timestamp="2026-02-10T09:00:00+00:00")
    current  = _make_result(risk_score=5.0, timestamp="2026-02-11T09:00:00+00:00")

    bfile   = tmp_path / "b.json"
    cfile   = tmp_path / "c.json"
    outfile = tmp_path / "report.json"

    bfile.write_text(json.dumps(baseline))
    cfile.write_text(json.dumps(current))

    runner = CliRunner()
    runner.invoke(cli, [
        "diff", str(bfile), str(cfile),
        "--output", str(outfile),
        "--format", "json",
    ])

    assert outfile.exists()
    parsed = json.loads(outfile.read_text())
    assert isinstance(parsed, dict)


def test_diff_domain_mismatch_shows_warning(tmp_path):
    """Comparing results from different domains must print a warning."""
    baseline = _make_result()
    current  = _make_result()
    current["metadata"]["domain_fqdn"] = "OTHER.LOCAL"

    bfile = tmp_path / "b.json"
    cfile = tmp_path / "c.json"

    bfile.write_text(json.dumps(baseline))
    cfile.write_text(json.dumps(current))

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(bfile), str(cfile)])

    assert "mismatch" in result.output.lower() or "Domain" in result.output


def test_from_dict_round_trip(tmp_path):
    """ThreatModelResult.from_dict(result.to_dict()) must be lossless for core fields."""
    from bluehound.core.types import ThreatModelResult, SnapshotMetadata, ExposureLevel
    from datetime import datetime, timezone

    meta = SnapshotMetadata(
        version="1.0.0",
        collected_at=datetime(2026, 2, 10, 9, 0, 0, tzinfo=timezone.utc),
        domain_fqdn="TEST.LOCAL",
        collector="sharphound",
        signature="sig",
    )

    original = ThreatModelResult(
        metadata=meta,
        risk_score=7.5,
        exposure_level=ExposureLevel.LOCALIZED,
        tier0_reachable=True,
        blast_radius="0.25",
    )

    reconstructed = ThreatModelResult.from_dict(original.to_dict())

    assert reconstructed.risk_score        == original.risk_score
    assert reconstructed.exposure_level    == original.exposure_level
    assert reconstructed.tier0_reachable   == original.tier0_reachable
    assert reconstructed.metadata.domain_fqdn == original.metadata.domain_fqdn
