import pytest
from unittest.mock import Mock

from bluehound.detection.category_d import (
    detect_adcs_abuse,
    _detect_esc1_vulnerable_templates,
)

from bluehound.core.types import (
    CertificateTemplate,
    CertificateAuthority,
    Severity,
    Confidence,
)

from bluehound.detection.factory import FindingFactory


def create_mock_context():
    ctx = Mock()
    ctx.is_tier0.return_value = False
    ctx.get_aces_on_target.return_value = []
    return ctx


def create_mock_view():
    view = Mock()
    view.get_node.return_value = None
    view.get_certificate_templates.return_value = []
    view.get_certificate_authorities.return_value = []
    return view


def test_no_adcs_data():
    findings = detect_adcs_abuse(
        create_mock_view(),
        create_mock_context(),
        FindingFactory(),
    )
    assert findings == []


def test_esc1_detection():

    template = CertificateTemplate(
        name="ESC1",
        display_name="ESC1",
        oid="",
        schema_version=2,
        enrollee_supplies_subject=True,
        client_authentication=True,
        manager_approval_required=False,
        authorized_signatures_required=0,
        enrollment_permissions=["S-1"],
    )

    findings = _detect_esc1_vulnerable_templates(
        create_mock_view(),
        create_mock_context(),
        FindingFactory(),
        [template],
    )

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence == Confidence.EXPLICIT


def test_esc8_detection():

    view = create_mock_view()
    ctx = create_mock_context()

    view.get_certificate_templates.return_value = [
        CertificateTemplate(
            name="User",
            display_name="User",
            oid="",
            schema_version=2,
            enrollee_supplies_subject=False,
            client_authentication=True,
            enrollment_permissions=[],
        )
    ]

    view.get_certificate_authorities.return_value = [
        CertificateAuthority(
            name="CA01",
            dns_hostname="ca.local",
            web_enrollment_enabled=True,
            web_enrollment_url="https://ca/certsrv",
            ntlm_allowed=True,
            templates=["User"],
        )
    ]

    findings = detect_adcs_abuse(
        view,
        ctx,
        FindingFactory(),
    )

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.INFERRED