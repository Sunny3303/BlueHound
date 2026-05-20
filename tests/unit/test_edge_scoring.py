import pytest
from unittest.mock import Mock

from bluehound.risk.edge_scoring import EdgeRiskEvaluator
from bluehound.core.types import FindingCategory, Severity


def create_mock_finding(title, category):

    f = Mock()
    f.title = title
    f.category = category
    f.severity = Severity.CRITICAL
    f.affected_principals = ["user"]

    evidence = Mock()
    evidence.raw_data = {}

    f.evidence = evidence
    return f


def test_adcs_esc1_high_stealth():
    ev = EdgeRiskEvaluator()
    f = create_mock_finding(
        "ESC1 Abuse",
        FindingCategory.ADCS_ABUSE,
    )
    score = ev.evaluate_finding(f)
    assert score.stealth >= 8.0


def test_kerberoast_high_exploitability():
    ev = EdgeRiskEvaluator()
    f = create_mock_finding(
        "Kerberoast",
        FindingCategory.KERBEROS_ABUSE,
    )
    score = ev.evaluate_finding(f)
    assert score.exploitability >= 7.0


def test_adcs_high_persistence():
    ev = EdgeRiskEvaluator()
    f = create_mock_finding(
        "ESC1",
        FindingCategory.ADCS_ABUSE,
    )
    score = ev.evaluate_finding(f)
    assert score.persistence >= 9.0


def test_tier0_high_blast_radius():
    ev = EdgeRiskEvaluator()
    f = create_mock_finding(
        "Tier0 Path",
        FindingCategory.TIER0_EXPOSURE,
    )
    score = ev.evaluate_finding(f)
    assert score.blast_radius >= 9.0