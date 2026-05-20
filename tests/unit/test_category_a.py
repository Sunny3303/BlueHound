import pytest
from unittest.mock import Mock
from datetime import datetime, timezone, timedelta

from bluehound.detection.category_a import detect_privilege_exposure
from bluehound.core.types import ADUser, Severity
from bluehound.detection.factory import FindingFactory


def create_mock_view():
    v = Mock()
    v.get_users.return_value = []
    v.get_computer.return_value = None
    v.get_group.return_value = None
    v.get_node.return_value = None
    return v


def create_mock_context():
    c = Mock()
    c.is_tier0.return_value = False
    c.admin_to_computers = {}
    c.group_closure = {}
    c.tier0_sids = set()
    c.get_dangerous_aces_by_principal.return_value = []
    return c


def test_empty_detection():
    view = create_mock_view()
    ctx = create_mock_context()
    factory = FindingFactory()

    findings = detect_privilege_exposure(view, ctx, factory)

    assert findings == []


def test_excessive_admin():

    view = create_mock_view()
    ctx = create_mock_context()
    factory = FindingFactory()

    user = ADUser(
        sid="S-1",
        sam_account_name="helpdesk",
        distinguished_name="CN=x",
        enabled=True,
        admin_count=0,
    )

    view.get_users.return_value = [user]

    ctx.admin_to_computers = {
        "S-1": {f"C{i}" for i in range(15)}
    }

    findings = detect_privilege_exposure(view, ctx, factory)

    assert any("Excessive Local Admin" in f.title for f in findings)


def test_orphaned_account():

    view = create_mock_view()
    ctx = create_mock_context()
    factory = FindingFactory()

    old = datetime.now(timezone.utc) - timedelta(days=120)

    user = ADUser(
        sid="S-2",
        sam_account_name="old_admin",
        distinguished_name="CN=x",
        enabled=True,
        admin_count=1,
        last_logon=old,
    )

    view.get_users.return_value = [user]
    ctx.is_tier0.return_value = True

    findings = detect_privilege_exposure(view, ctx, factory)

    assert any("Orphaned" in f.title for f in findings)


def test_disabled_users_skipped():

    view = create_mock_view()
    ctx = create_mock_context()
    factory = FindingFactory()

    user = ADUser(
        sid="S-3",
        sam_account_name="disabled",
        distinguished_name="CN=x",
        enabled=False,
        admin_count=0,
    )

    view.get_users.return_value = [user]

    findings = detect_privilege_exposure(view, ctx, factory)

    assert findings == []