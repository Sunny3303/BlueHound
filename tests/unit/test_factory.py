import pytest

from bluehound.detection.factory import FindingFactory
from bluehound.core.types import (
    FindingCategory,
    Severity,
    Confidence,
)


def test_factory_initialization():
    factory = FindingFactory()
    assert factory._finding_count == 0


def test_create_finding():
    factory = FindingFactory()

    finding = factory.create_finding(
        category=FindingCategory.PRIVILEGE_EXPOSURE,
        severity=Severity.HIGH,
        confidence=Confidence.EXPLICIT,
        title="Shadow Admin",
        description="Privilege exposure",
        evidence_type="acl_chain",
        evidence_data={"sid": "S-1"},
        evidence_reasoning="ACL detected",
        affected_principals=["S-1"],
    )

    assert finding.id.startswith("PRIV-")


def test_deterministic_id():
    factory = FindingFactory()

    id1 = factory.generate_finding_id(
        FindingCategory.KERBEROS_ABUSE,
        "Kerberoastable",
        ["S-1"],
    )

    id2 = factory.generate_finding_id(
        FindingCategory.KERBEROS_ABUSE,
        "Kerberoastable",
        ["S-1"],
    )

    assert id1 == id2


def test_invalid_evidence():
    factory = FindingFactory()

    with pytest.raises(ValueError):
        factory.validate_evidence({})
