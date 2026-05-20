import pytest
from unittest.mock import Mock

from bluehound.detection.category_c import (
    detect_delegation_abuse,
    _is_domain_controller,
    _parse_spn_targets,
    DEFAULT_MACHINE_ACCOUNT_QUOTA,
)

from bluehound.core.types import (
    ADComputer,
    Severity,
    FindingCategory,
)

from bluehound.detection.factory import FindingFactory


# ============================================================
# MOCK HELPERS
# ============================================================

def create_mock_context():
    ctx = Mock()
    ctx.is_tier0.return_value = False
    ctx.tier0_sids = {
        "S-1-5-21-1-2-3-512",
        "S-1-5-21-1-2-3-516",
    }
    return ctx


def create_mock_view():
    view = Mock()
    view.get_computers.return_value = []
    view.get_domain_info.return_value = {}
    return view


# ============================================================
# BASE TEST
# ============================================================

def test_detect_delegation_abuse_empty():

    view = create_mock_view()
    ctx = create_mock_context()

    findings = detect_delegation_abuse(
        view,
        ctx,
        FindingFactory(),
    )

    assert isinstance(findings, list)
    assert len(findings) == 0


# ============================================================
# C1 — UNCONSTRAINED DELEGATION
# ============================================================

def test_unconstrained_delegation_detection():

    view = create_mock_view()
    ctx = create_mock_context()

    comp = ADComputer(
        sid="S-1-2001",
        sam_account_name="WEB01$",
        distinguished_name="CN=WEB01,OU=Servers,DC=test,DC=local",
        enabled=True,
        unconstrained_delegation=True,
        operating_system="Windows Server 2019",
    )

    view.get_computers.return_value = [comp]

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    matches = [
        f for f in findings
        if "Unconstrained Delegation" in f.title
    ]

    assert len(matches) == 1
    assert matches[0].severity == Severity.HIGH
    assert matches[0].category == FindingCategory.DELEGATION_ABUSE


def test_domain_controller_unconstrained_skipped():

    view = create_mock_view()
    ctx = create_mock_context()

    dc = ADComputer(
        sid="S-1-1001",
        sam_account_name="DC01$",
        distinguished_name="CN=DC01,OU=Domain Controllers,DC=test,DC=local",
        enabled=True,
        unconstrained_delegation=True,
        operating_system="Windows Server Domain Controller",
    )

    view.get_computers.return_value = [dc]

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    assert len(findings) == 0


# ============================================================
# DOMAIN CONTROLLER DETECTION
# ============================================================

def test_is_domain_controller_detection():

    ctx = create_mock_context()

    dc = ADComputer(
        sid="S-1",
        sam_account_name="DC01$",
        distinguished_name="CN=DC01,OU=Domain Controllers,DC=test,DC=local",
        enabled=True,
        operating_system="Windows Server",
    )

    assert _is_domain_controller(dc, ctx) is True

    server = ADComputer(
        sid="S-2",
        sam_account_name="WEB01$",
        distinguished_name="CN=WEB01,OU=Servers,DC=test,DC=local",
        enabled=True,
        operating_system="Windows Server",
    )

    assert _is_domain_controller(server, ctx) is False


# ============================================================
# SPN PARSER
# ============================================================

def test_parse_spn_targets():

    spns = [
        "HTTP/web01.domain.com",
        "CIFS/file01.domain.com",
        "MSSQLSvc/sql01:1433",
        "HOST/DC01.domain.com",
    ]

    targets = _parse_spn_targets(spns)

    assert "WEB01" in targets
    assert "FILE01" in targets
    assert "SQL01" in targets
    assert "DC01" in targets
    assert len(targets) == 4


# ============================================================
# C2 — RBCD
# ============================================================

def test_rbcd_to_tier0_detection():

    view = create_mock_view()
    ctx = create_mock_context()

    dc = ADComputer(
        sid="S-DC",
        sam_account_name="DC01$",
        distinguished_name="CN=DC01,OU=Domain Controllers,DC=test,DC=local",
        enabled=True,
    )

    web = ADComputer(
        sid="S-WEB",
        sam_account_name="WEB01$",
        distinguished_name="CN=WEB01,OU=Servers,DC=test,DC=local",
        enabled=True,
        allowed_to_delegate_to=[
            "HOST/DC01.test.local"
        ],
    )

    view.get_computers.return_value = [dc, web]

    def tier0_check(sid):
        return sid == dc.sid

    ctx.is_tier0.side_effect = tier0_check

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    rbcd = [f for f in findings if "RBCD" in f.title]

    assert len(rbcd) == 1
    assert rbcd[0].severity == Severity.HIGH


def test_tier0_to_tier0_rbcd_not_flagged():

    view = create_mock_view()
    ctx = create_mock_context()

    dc1 = ADComputer(
        sid="S1",
        sam_account_name="DC01$",
        distinguished_name="CN=DC01,OU=Domain Controllers,DC=test,DC=local",
        enabled=True,
        allowed_to_delegate_to=["HOST/DC02"],
    )

    dc2 = ADComputer(
        sid="S2",
        sam_account_name="DC02$",
        distinguished_name="CN=DC02,OU=Domain Controllers,DC=test,DC=local",
        enabled=True,
    )

    view.get_computers.return_value = [dc1, dc2]

    ctx.is_tier0.return_value = True

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    assert len(findings) == 0


# ============================================================
# C3 — MACHINE ACCOUNT QUOTA
# ============================================================

def test_machine_account_quota_detection():

    view = create_mock_view()
    ctx = create_mock_context()

    view.get_domain_info.return_value = {
        "fqdn": "TEST.LOCAL",
        "ms-ds-machineaccountquota": 10,
    }

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    quota = [
        f for f in findings
        if "Machine Account Quota" in f.title
    ]

    assert len(quota) == 1
    assert quota[0].severity == Severity.MEDIUM


def test_machine_account_quota_zero_not_flagged():

    view = create_mock_view()
    ctx = create_mock_context()

    view.get_domain_info.return_value = {
        "fqdn": "TEST.LOCAL",
        "ms-ds-machineaccountquota": 0,
    }

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    assert len(findings) == 0


# ============================================================
# DISABLED COMPUTERS
# ============================================================

def test_disabled_computers_skipped():

    view = create_mock_view()
    ctx = create_mock_context()

    comp = ADComputer(
        sid="S-X",
        sam_account_name="OLDWEB$",
        distinguished_name="CN=OLDWEB,OU=Servers,DC=test,DC=local",
        enabled=False,
        unconstrained_delegation=True,
    )

    view.get_computers.return_value = [comp]

    findings = detect_delegation_abuse(
        view, ctx, FindingFactory()
    )

    assert len(findings) == 0