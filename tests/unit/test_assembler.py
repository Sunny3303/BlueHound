import pytest
from unittest.mock import Mock
from datetime import datetime, timezone

from bluehound.output.assembler import ThreatModelAssembler
from bluehound.core.types import (
    Finding,
    FindingCategory,
    Severity,
    Confidence,
    Evidence,
    SnapshotMetadata,
    ExposureLevel,
    ThreatModelResult,
)
from bluehound.risk.engine import RiskResult, AttackPath
from bluehound.risk.edge_scoring import EdgeRiskScore


def create_mock_view():
    v = Mock()
    v.get_statistics.return_value = {"users": 1000, "computers": 500}
    return v


def create_finding(category, severity, remediation="1. Fix issue"):
    return Finding(
        id=f"ID-{category.value}",
        category=category,
        severity=severity,
        confidence=Confidence.EXPLICIT,
        title="Test",
        description="desc",
        evidence=Evidence("src", {}, "reason"),
        affected_principals=[],
        mitre_techniques=[],
        remediation=remediation,
    )


def create_snapshot():
    return SnapshotMetadata(
        version="1.0",
        collected_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        domain_fqdn="TEST.LOCAL",
        collector="collector",
        signature="sig",
    )


def create_risk():
    evidence = Evidence(
        "src",
        {
            "start_user_sid": "user1",
            "path_hops": [
                {"to": "Domain Admin", "technique": "ACL Abuse"}
            ],
            "hop_count": 1,
        }, "reason"
    )

    f = Finding(
        id="ID-E",
        category=FindingCategory.TIER0_EXPOSURE,
        severity=Severity.CRITICAL,
        confidence=Confidence.EXPLICIT,
        title="Tier0",
        description="desc",
        evidence=evidence,
        affected_principals=[],
        mitre_techniques=[],
        remediation="1. Break attack path",
    )

    path = AttackPath(
        path_id="P1",
        findings=[f],
        edge_scores=[EdgeRiskScore(8, 9, 8, 9, 8.5, "Test", FindingCategory.TIER0_EXPOSURE)],
        path_score=9.5,
        hop_count=1,
        reaches_tier0=True,
        max_edge_risk=8.5,
        average_edge_risk=8.5,
        primary_category=FindingCategory.TIER0_EXPOSURE,
    )

    return RiskResult(
        global_risk_score=9.5,
        risk_classification="CRITICAL",
        exposure_level=ExposureLevel.CATASTROPHIC,
        attack_paths=[path],
        most_dangerous_path=path,
        tier0_reachable=True,
        shortest_tier0_path_hops=1,
        risk_by_category={FindingCategory.TIER0_EXPOSURE: 9.5},
        blast_radius=0.1,
        affected_principals=set(),
        total_principals=1500,
        finding_counts={"CRITICAL": 1},
        critical_finding_count=1,
    )


def test_basic_assembly():
    assembler = ThreatModelAssembler(create_mock_view())
    result = assembler.assemble(
        [create_finding(FindingCategory.PRIVILEGE_EXPOSURE, Severity.CRITICAL)],
        create_risk(),
        create_snapshot(),
    )
    assert isinstance(result, ThreatModelResult)
    assert result.risk_score == 9.5
    assert result.tier0_reachable


def test_kill_path_formatting():
    assembler = ThreatModelAssembler(create_mock_view())
    result = assembler.assemble(
        [create_finding(FindingCategory.TIER0_EXPOSURE, Severity.CRITICAL)],
        create_risk(),
        create_snapshot(),
    )
    assert "→" in result.primary_kill_path


def test_json_serialization():
    assembler = ThreatModelAssembler(create_mock_view())
    result = assembler.assemble(
        [create_finding(FindingCategory.PRIVILEGE_EXPOSURE, Severity.CRITICAL)],
        create_risk(),
        create_snapshot(),
    )
    json_str = result.to_json()
    assert isinstance(json_str, str)
    assert "risk_score" in json_str