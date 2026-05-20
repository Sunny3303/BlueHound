import pytest
from datetime import datetime, timezone

from bluehound.diff.engine import SnapshotDiffEngine
from bluehound.core.types import (
    ThreatModelResult,
    Finding,
    FindingCategory,
    Severity,
    Confidence,
    Evidence,
    SnapshotMetadata,
    ExposureLevel,
)


def create_test_metadata(domain="TEST.LOCAL", timestamp=None):
    """Helper to create test metadata"""

    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    return SnapshotMetadata(
        version="1.0.0",
        collected_at=timestamp,
        domain_fqdn=domain,
        collector="test",
        signature="test123",
    )


def create_test_finding(
    finding_id: str,
    category: FindingCategory,
    severity: Severity,
    title: str = "Test Finding",
    affected_principals: list[str] = None,
) -> Finding:
    """Helper to create a test Finding"""

    return Finding(
        id=finding_id,
        category=category,
        severity=severity,
        confidence=Confidence.EXPLICIT,
        title=title,
        description="Test description",
        evidence=Evidence("test", {}, "test"),
        affected_principals=affected_principals or [],
        mitre_techniques=[],
        remediation="",
    )


def create_test_threat_model(
    metadata: SnapshotMetadata,
    findings: list[Finding],
    risk_score: float = 5.0,
    risk_classification: str = "MEDIUM",
    exposure_level: ExposureLevel = ExposureLevel.CONTAINED,
    tier0_reachable: bool = False,
    shortest_tier0_path_hops: int = None,
    primary_kill_path: str = "No path",
    blast_radius: float = 0.1,
    affected_principal_count: int = 10,
    mitre_techniques: list[str] = None,
):

    category_counts = {}
    severity_counts = {}

    for finding in findings:
        cat = finding.category.value
        sev = finding.severity.value

        category_counts[cat] = category_counts.get(cat, 0) + 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return ThreatModelResult(
        metadata=metadata,
        risk_score=risk_score,
        exposure_level=exposure_level,
        findings=findings,
        top_fixes=[],
        primary_kill_path=primary_kill_path,
        blast_radius=blast_radius,
        category_breakdown=category_counts,
        tier0_reachable=tier0_reachable,
        mitre_techniques=mitre_techniques or [],
    )


def test_diff_engine_initialization():
    engine = SnapshotDiffEngine()
    assert engine is not None


def test_diff_identical_snapshots():

    engine = SnapshotDiffEngine()

    metadata = create_test_metadata()

    findings = [
        create_test_finding(
            "A-001",
            FindingCategory.PRIVILEGE_EXPOSURE,
            Severity.HIGH,
        )
    ]

    baseline = create_test_threat_model(metadata, findings)
    current = create_test_threat_model(metadata, findings)

    diff = engine.compare(baseline, current)

    assert len(diff.new_findings) == 0
    assert len(diff.removed_findings) == 0
    assert diff.risk_score_delta == 0.0
    assert diff.total_findings_delta == 0


def test_diff_new_findings():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline_findings = [
        create_test_finding(
            "A-001",
            FindingCategory.PRIVILEGE_EXPOSURE,
            Severity.HIGH,
        )
    ]

    current_findings = [
        create_test_finding(
            "A-001",
            FindingCategory.PRIVILEGE_EXPOSURE,
            Severity.HIGH,
        ),
        create_test_finding(
            "B-001",
            FindingCategory.KERBEROS_ABUSE,
            Severity.MEDIUM,
        ),
    ]

    baseline = create_test_threat_model(metadata, baseline_findings)
    current = create_test_threat_model(metadata, current_findings)

    diff = engine.compare(baseline, current)

    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].id == "B-001"
    assert diff.total_findings_delta == 1


def test_diff_removed_findings():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline_findings = [
        create_test_finding(
            "A-001",
            FindingCategory.PRIVILEGE_EXPOSURE,
            Severity.HIGH,
        ),
        create_test_finding(
            "B-001",
            FindingCategory.KERBEROS_ABUSE,
            Severity.MEDIUM,
        ),
    ]

    current_findings = [
        create_test_finding(
            "A-001",
            FindingCategory.PRIVILEGE_EXPOSURE,
            Severity.HIGH,
        )
    ]

    baseline = create_test_threat_model(metadata, baseline_findings)
    current = create_test_threat_model(metadata, current_findings)

    diff = engine.compare(baseline, current)

    assert len(diff.removed_findings) == 1
    assert diff.removed_findings[0].id == "B-001"
    assert diff.total_findings_delta == -1


def test_diff_risk_score_increase():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(metadata, [], risk_score=5.0)
    current = create_test_threat_model(metadata, [], risk_score=8.5)

    diff = engine.compare(baseline, current)

    assert diff.risk_score_delta == 3.5
    assert diff.is_regression()


def test_diff_risk_score_decrease():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(metadata, [], risk_score=8.5)
    current = create_test_threat_model(metadata, [], risk_score=5.0)

    diff = engine.compare(baseline, current)

    assert diff.risk_score_delta == -3.5
    assert diff.is_improvement()


def test_diff_privilege_creep_detection():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(metadata, [])

    current_findings = [
        create_test_finding(
            "A-001",
            FindingCategory.PRIVILEGE_EXPOSURE,
            Severity.HIGH,
            affected_principals=["S-1-5-21-1-2-3-1001"],
        )
    ]

    current = create_test_threat_model(metadata, current_findings)

    diff = engine.compare(baseline, current)

    assert diff.privilege_creep_detected is True
    assert len(diff.privilege_creep_principals) > 0


def test_diff_tier0_regression_detection():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(
        metadata,
        [],
        tier0_reachable=False,
    )

    current = create_test_threat_model(
        metadata,
        [],
        tier0_reachable=True,
        primary_kill_path="attacker → Domain Admin",
    )

    diff = engine.compare(baseline, current)

    assert diff.tier0_exposure_regression is True
    assert len(diff.new_tier0_paths) > 0


def test_diff_severity_escalation():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline_finding = create_test_finding(
        "A-001",
        FindingCategory.PRIVILEGE_EXPOSURE,
        Severity.MEDIUM,
    )

    current_finding = create_test_finding(
        "A-001",
        FindingCategory.PRIVILEGE_EXPOSURE,
        Severity.CRITICAL,
    )

    baseline = create_test_threat_model(metadata, [baseline_finding])
    current = create_test_threat_model(metadata, [current_finding])

    diff = engine.compare(baseline, current)

    assert len(diff.severity_escalations) == 1


def test_diff_mitre_technique_changes():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(
        metadata,
        [],
        mitre_techniques=["T1558.003", "T1484.001"],
    )

    current = create_test_threat_model(
        metadata,
        [],
        mitre_techniques=["T1558.003", "T1649"],
    )

    diff = engine.compare(baseline, current)

    assert "T1649" in diff.new_mitre_techniques
    assert "T1484.001" in diff.removed_mitre_techniques


def test_diff_blast_radius_change():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(metadata, [], blast_radius=0.1)
    current = create_test_threat_model(metadata, [], blast_radius=0.3)

    diff = engine.compare(baseline, current)

    assert diff.blast_radius_delta == 0.2


def test_diff_get_summary():

    engine = SnapshotDiffEngine()
    metadata = create_test_metadata()

    baseline = create_test_threat_model(metadata, [], risk_score=5.0)
    current = create_test_threat_model(metadata, [], risk_score=8.0)

    diff = engine.compare(baseline, current)

    summary = diff.get_summary()

    assert isinstance(summary, str)
    assert len(summary) > 0