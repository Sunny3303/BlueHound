from datetime import datetime, timezone
import pytest

from bluehound.core.types import (
    Node,
    Edge,
    ADUser,
    ADComputer,
    ADGroup,
    ACE,
    CertificateTemplate,
    CertificateAuthority,
    ADCSInfrastructure,
    Finding,
    Evidence,
    FindingCategory,
    Severity,
    Confidence,
    SnapshotMetadata,
    ThreatModelResult,
    ExposureLevel,
    KillPath,
)


# ============================================================
# Graph Primitive Tests
# ============================================================


def test_node_property_access():
    node = Node(
        id="S-1-5-21-1-2-3-1001",
        labels=["User"],
        properties={"samaccountname": "testuser", "enabled": True},
    )

    assert node.get_property("samaccountname") == "testuser"
    assert node.get_property("nonexistent", "default") == "default"


def test_edge_repr():
    edge = Edge("A", "B", "AdminTo")
    assert "AdminTo" in repr(edge)


# ============================================================
# AD Entity Tests
# ============================================================


def test_aduser_from_node():
    node = Node(
        id="S-1-5-21-1-2-3-1001",
        labels=["User"],
        properties={
            "samaccountname": "testuser",
            "distinguishedname": "CN=Test,DC=corp,DC=local",
            "enabled": True,
            "admincount": 0,
            "serviceprincipalnames": ["HTTP/test"],
        },
    )

    user = ADUser.from_node(node)

    assert user.sid == node.id
    assert user.sam_account_name == "testuser"
    assert user.spns == ["HTTP/test"]


def test_adcomputer_from_node():
    node = Node(
        id="S-1-5-21-1-2-3-2001",
        labels=["Computer"],
        properties={
            "samaccountname": "WS01$",
            "enabled": True,
            "operatingsystem": "Windows 10",
            "unconstraineddelegation": True,
        },
    )

    computer = ADComputer.from_node(node)

    assert computer.unconstrained_delegation is True
    assert computer.operating_system == "Windows 10"


def test_adgroup_from_node():
    node = Node(
        id="S-1-5-21-1-2-3-3001",
        labels=["Group"],
        properties={
            "samaccountname": "Domain Admins",
            "admincount": 1,
        },
    )

    group = ADGroup.from_node(node)

    assert group.sam_account_name == "Domain Admins"
    assert group.admin_count == 1


# ============================================================
# ACE Tests
# ============================================================


def test_ace_is_dangerous():
    dangerous = ACE(
        trustee="S-1",
        right_name="GenericAll",
        ace_type="Allow",
    )

    assert dangerous.is_dangerous()

    safe = ACE(
        trustee="S-1",
        right_name="ReadProperty",
        ace_type="Allow",
    )

    assert not safe.is_dangerous()


# ============================================================
# ADCS Tests
# ============================================================


def test_certificate_template_esc1_detection():
    vulnerable = CertificateTemplate(
        name="ESC1",
        display_name="ESC1",
        oid="1.2.3",
        schema_version=2,
        enrollee_supplies_subject=True,
        client_authentication=True,
        authorized_signatures_required=0,
        manager_approval_required=False,
    )

    assert vulnerable.is_vulnerable_to_esc1()

    safe = CertificateTemplate(
        name="SAFE",
        display_name="SAFE",
        oid="1.2.4",
        schema_version=2,
        enrollee_supplies_subject=False,
        client_authentication=True,
    )

    assert not safe.is_vulnerable_to_esc1()


def test_adcs_template_lookup_case_insensitive():
    template = CertificateTemplate(
        name="Template1",
        display_name="Template1",
        oid="1.2.3",
        schema_version=2,
        enrollee_supplies_subject=False,
        client_authentication=True,
    )

    adcs = ADCSInfrastructure(certificate_templates=[template])

    assert adcs.get_template("template1") == template
    assert adcs.get_template("TEMPLATE1") == template
    assert adcs.get_template("missing") is None


# ============================================================
# Finding Tests
# ============================================================


def test_finding_serialization():
    finding = Finding(
        id="TEST-001",
        category=FindingCategory.KERBEROS_ABUSE,
        severity=Severity.HIGH,
        confidence=Confidence.EXPLICIT,
        title="Kerberoastable Account",
        description="User has SPN set",
        evidence=Evidence(
            evidence_type="direct_attribute",
            raw_data={"spns": ["HTTP/test"]},
            reasoning="SPN present",
        ),
        affected_principals=["S-1"],
        mitre_techniques=["T1558.003"],
        remediation="Remove SPN",
    )

    data = finding.to_dict()

    assert data["id"] == "TEST-001"
    assert data["category"] == "kerberos_abuse"
    assert data["severity"] == "high"
    assert data["confidence"] == "explicit"


# ============================================================
# ThreatModelResult Tests
# ============================================================


def test_threat_model_result_validation():
    metadata = SnapshotMetadata(
        version="1.0.0",
        collected_at=datetime.now(timezone.utc),
        domain_fqdn="CORP.LOCAL",
        collector="sharphound",
        signature="sig",
    )

    with pytest.raises(ValueError):
        ThreatModelResult(
            metadata=metadata,
            risk_score=15.0,  # invalid
            exposure_level=ExposureLevel.CONTAINED,
            tier0_reachable=False,
        )


def test_threat_model_result_json_serialization():
    metadata = SnapshotMetadata(
        version="1.0.0",
        collected_at=datetime.now(timezone.utc),
        domain_fqdn="CORP.LOCAL",
        collector="sharphound",
        signature="sig",
    )

    finding = Finding(
        id="PRIV-001",
        category=FindingCategory.PRIVILEGE_EXPOSURE,
        severity=Severity.CRITICAL,
        confidence=Confidence.EXPLICIT,
        title="GenericAll on DA",
        description="User controls DA group",
        evidence=Evidence("acl_chain", {}, "Test"),
    )

    kill_path = KillPath(
        nodes=["intern1", "WS01", "Domain Admins", "DC01"],
        techniques=["Local Admin Abuse", "ACL Abuse"],
        estimated_time="Minutes",
        stealth_level="Low",
    )

    result = ThreatModelResult(
        metadata=metadata,
        risk_score=9.5,
        exposure_level=ExposureLevel.DOMAIN_WIDE,
        tier0_reachable=True,
        findings=[finding],
        top_fixes=["Remove GenericAll"],
        primary_kill_path=kill_path,
        blast_radius="0.25",  # should be serialized as string in JSON
        time_to_domain_admin="Minutes",
        detection_surface="Minimal",
        category_breakdown={"A": 1},
    )

    json_str = result.to_json()
    assert "9.5" in json_str
    assert "domain-wide" in json_str

    data = result.to_dict()
    assert data["primary_kill_path"]["nodes"][0] == "intern1"
    assert data["blast_radius"] == "0.25"
    assert data["time_to_domain_admin"] == "Minutes"


def test_threat_model_result_filtering():
    metadata = SnapshotMetadata(
        version="1.0.0",
        collected_at=datetime.now(timezone.utc),
        domain_fqdn="TEST.LOCAL",
        collector="test",
        signature="sig",
    )

    findings = [
        Finding(
            id="PRIV-001",
            category=FindingCategory.PRIVILEGE_EXPOSURE,
            severity=Severity.CRITICAL,
            confidence=Confidence.EXPLICIT,
            title="Test1",
            description="Test",
            evidence=Evidence("direct", {}, "reason"),
        ),
        Finding(
            id="KERB-001",
            category=FindingCategory.KERBEROS_ABUSE,
            severity=Severity.HIGH,
            confidence=Confidence.EXPLICIT,
            title="Test2",
            description="Test",
            evidence=Evidence("direct", {}, "reason"),
        ),
    ]

    result = ThreatModelResult(
        metadata=metadata,
        risk_score=7.5,
        exposure_level=ExposureLevel.LOCALIZED,
        tier0_reachable=False,
        findings=findings,
    )

    priv_findings = result.get_findings_by_category(
        FindingCategory.PRIVILEGE_EXPOSURE
    )

    assert len(priv_findings) == 1
    assert priv_findings[0].id == "PRIV-001"

    critical_findings = result.get_critical_findings()

    assert len(critical_findings) == 1
    assert critical_findings[0].id == "PRIV-001"