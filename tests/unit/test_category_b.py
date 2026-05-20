import pytest
from unittest.mock import Mock

from bluehound.detection.category_b import (
    detect_kerberos_abuse,
    _is_service_account,
)

from bluehound.core.types import ADUser, Severity
from bluehound.detection.factory import FindingFactory


def create_mock_view():
    view = Mock()
    view.get_users.return_value = []
    return view


def create_mock_context():
    ctx = Mock()
    ctx.is_tier0.return_value = False
    return ctx


def test_empty():
    findings = detect_kerberos_abuse(
        create_mock_view(),
        create_mock_context(),
        FindingFactory(),
    )
    assert findings == []


def test_kerberoastable():
    view = create_mock_view()
    ctx = create_mock_context()

    user = ADUser(
        sid="S-1",
        sam_account_name="svc_web",
        distinguished_name="CN=x",
        enabled=True,
        admin_count=0,
        spns=["HTTP/web"],
    )

    view.get_users.return_value = [user]

    findings = detect_kerberos_abuse(view, ctx, FindingFactory())

    assert any("Kerberoastable" in f.title for f in findings)


def test_asrep():
    view = create_mock_view()
    ctx = create_mock_context()

    user = ADUser(
        sid="S-2",
        sam_account_name="user",
        distinguished_name="CN=x",
        enabled=True,
        admin_count=0,
        kerberos_preauth_not_required=True,
    )

    view.get_users.return_value = [user]

    findings = detect_kerberos_abuse(view, ctx, FindingFactory())

    assert any("AS-REP" in f.title for f in findings)


def test_service_pattern():
    assert _is_service_account("svc_sql") is True
    assert _is_service_account("john.doe") is False


def test_spn_human():
    view = create_mock_view()
    ctx = create_mock_context()

    user = ADUser(
        sid="S-3",
        sam_account_name="john.doe",
        distinguished_name="CN=x",
        enabled=True,
        admin_count=0,
        spns=["HTTP/test"],
    )

    view.get_users.return_value = [user]

    findings = detect_kerberos_abuse(view, ctx, FindingFactory())

    assert any("SPN on Human Account" in f.title for f in findings)