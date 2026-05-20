import pytest
from unittest.mock import Mock

from bluehound.risk.engine import RiskEngine
from bluehound.core.types import (
    FindingCategory,
    Severity,
)


def create_mock_view():
    v = Mock()
    v.get_statistics.return_value = {
        "users": 100,
        "computers": 100,
    }
    return v


def create_mock_finding(category, hops=1):

    f = Mock()
    f.title = "Test"
    f.category = category
    f.severity = Severity.CRITICAL
    f.affected_principals = ["user"]

    evidence = Mock()
    evidence.raw_data = {
        "hop_count": hops,
        "target_tier0": True,
    }

    f.evidence = evidence
    return f


def test_single_hop_tier0_catastrophic():

    engine = RiskEngine(
        create_mock_view(),
        Mock(),
    )

    result = engine.compute_risk([
        create_mock_finding(
            FindingCategory.TIER0_EXPOSURE,
            1,
        )
    ])

    assert result.tier0_reachable


def test_category_bias_prioritized():

    engine = RiskEngine(
        create_mock_view(),
        Mock(),
    )

    findings = [
        create_mock_finding(
            FindingCategory.PRIVILEGE_EXPOSURE
        ),
        create_mock_finding(
            FindingCategory.ADCS_ABUSE
        ),
    ]

    result = engine.compute_risk(findings)

    assert (
        result.attack_paths[0]
        .primary_category
        == FindingCategory.ADCS_ABUSE
    )