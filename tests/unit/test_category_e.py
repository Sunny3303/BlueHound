import pytest
from unittest.mock import Mock

from bluehound.detection.category_e import (
    detect_tier0_exposure,
    _assess_path_severity,
    _format_attack_path,
)

from bluehound.core.types import ADUser, ADComputer, Severity
from bluehound.detection.factory import FindingFactory


def create_mock_view():
    v = Mock()
    v.get_users.return_value = []
    v.get_computers.return_value = []
    v.get_node.return_value = None
    v.get_computer.return_value = None
    return v


def create_mock_context():
    c = Mock()
    c.is_tier0.return_value = False
    c.get_dangerous_aces_by_principal.return_value = []
    c.admin_to_computers = {}
    return c


def test_empty_environment():
    findings = detect_tier0_exposure(
        create_mock_view(),
        create_mock_context(),
        FindingFactory(),
    )
    assert isinstance(findings, list)


def test_severity_logic():
    assert _assess_path_severity(1) == Severity.CRITICAL
    assert _assess_path_severity(4) == Severity.HIGH


def test_format_path():
    path = {
        "hops": [
            {"from": "u", "to": "DA", "technique": "GenericAll"}
        ]
    }
    result = _format_attack_path(path)
    assert "GenericAll" in result