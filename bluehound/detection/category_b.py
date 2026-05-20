"""
BlueHound Category B Detection: Kerberos Abuse

Detects:
- B1: Kerberoastable Service Accounts
- B2: AS-REP Roastable Users
- B3: SPN on Non-Service Users
"""

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.factory import FindingFactory
from bluehound.core.types import Finding, Severity

import logging

logger = logging.getLogger(__name__)


# ============================================================
# CONSTANTS
# ============================================================

SERVICE_ACCOUNT_PATTERNS = [
    "svc",
    "service",
    "sql",
    "iis",
    "apache",
    "nginx",
    "tomcat",
    "jboss",
    "weblogic",
    "websphere",
]


# ============================================================
# ENTRY POINT
# ============================================================

def detect_kerberos_abuse(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    logger.info("Starting Category B: Kerberos Abuse detection")

    findings: list[Finding] = []

    findings.extend(
        _detect_kerberoastable_accounts(view, context, factory)
    )

    findings.extend(
        _detect_asrep_roastable_users(view, context, factory)
    )

    findings.extend(
        _detect_spn_on_human_accounts(view, context, factory)
    )

    logger.info(f"Category B complete: {len(findings)} findings")
    return findings


# ============================================================
# B1 — Kerberoastable Accounts
# ============================================================

def _detect_kerberoastable_accounts(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    findings = []

    for user in view.get_users():

        if not user.enabled:
            continue

        if not user.spns:
            continue

        if user.sam_account_name.endswith("$"):
            continue

        if user.sam_account_name.lower() == "krbtgt":
            continue

        is_tier0 = context.is_tier0(user.sid)
        severity = Severity.HIGH if is_tier0 else Severity.MEDIUM

        spn_preview = ", ".join(user.spns[:3])
        if len(user.spns) > 3:
            spn_preview += f" (and {len(user.spns)-3} more)"

        findings.append(
            factory.create_kerberos_finding(
                title=f"Kerberoastable Account: {user.sam_account_name}",
                description=(
                    f"Account '{user.sam_account_name}' has "
                    f"{len(user.spns)} SPN(s) and is vulnerable to "
                    f"Kerberoasting attacks. SPNs: {spn_preview}"
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "user_name": user.sam_account_name,
                    "spns": user.spns,
                    "spn_count": len(user.spns),
                    "is_tier0": is_tier0,
                },
                severity=severity,
                remediation=(
                    f"Use a long, random password (25+ chars) for '{user.sam_account_name}' to make offline cracking infeasible. "
                    f"Where possible, migrate SPNs to Group Managed Service Accounts (gMSA) which auto-rotate passwords. "
                    f"If the SPN is no longer needed, remove it entirely."
                ),
            )
        )

    return findings


# ============================================================
# B2 — AS-REP Roastable Users
# ============================================================

def _detect_asrep_roastable_users(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    findings = []

    for user in view.get_users():

        if not user.enabled:
            continue

        if not user.kerberos_preauth_not_required:
            continue

        is_tier0 = context.is_tier0(user.sid)
        severity = Severity.HIGH if is_tier0 else Severity.MEDIUM

        findings.append(
            factory.create_kerberos_finding(
                title=f"AS-REP Roastable: {user.sam_account_name}",
                description=(
                    f"User '{user.sam_account_name}' does not require "
                    f"Kerberos pre-authentication and is vulnerable "
                    f"to AS-REP Roasting."
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "user_name": user.sam_account_name,
                    "kerberos_preauth_not_required": True,
                    "is_tier0": is_tier0,
                },
                severity=severity,
                remediation=(
                    f"Enable Kerberos pre-authentication on '{user.sam_account_name}' "
                    f"by unchecking 'Do not require Kerberos preauthentication' in the account properties. "
                    f"This setting should almost never be disabled on user accounts."
                ),
            )
        )

    return findings


# ============================================================
# SERVICE ACCOUNT HELPER
# ============================================================

def _is_service_account(name: str) -> bool:

    name = name.lower()

    if name.startswith("svc_") or name.startswith("service_"):
        return True

    return any(p in name for p in SERVICE_ACCOUNT_PATTERNS)


# ============================================================
# B3 — SPN on Human Accounts
# ============================================================

def _detect_spn_on_human_accounts(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    findings = []

    for user in view.get_users():

        if not user.enabled:
            continue

        if not user.spns:
            continue

        if user.sam_account_name.endswith("$"):
            continue

        if user.sam_account_name.lower() == "krbtgt":
            continue

        if _is_service_account(user.sam_account_name):
            continue

        spn_preview = ", ".join(user.spns[:3])
        if len(user.spns) > 3:
            spn_preview += f" (and {len(user.spns)-3} more)"

        findings.append(
            factory.create_kerberos_finding(
                title=f"SPN on Human Account: {user.sam_account_name}",
                description=(
                    f"Human user '{user.sam_account_name}' has "
                    f"{len(user.spns)} SPN(s). "
                    f"This is unusual and increases Kerberoasting risk. "
                    f"SPNs: {spn_preview}"
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "user_name": user.sam_account_name,
                    "spns": user.spns,
                    "spn_count": len(user.spns),
                },
                severity=Severity.MEDIUM,
                remediation=(
                    f"Remove SPNs from the human account '{user.sam_account_name}' and reassign them to a dedicated service account or gMSA. "
                    f"Human accounts with SPNs are high-value Kerberoasting targets because users often have weak, memorable passwords."
                ),
            )
        )

    return findings