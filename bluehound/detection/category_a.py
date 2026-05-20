"""
BlueHound Category A Detection: Privilege & Identity Exposure

Implements:
A1 - Excessive Local Administrator Rights
A2 - Orphaned Privileged Accounts
A3 - Hidden Privileged Group Membership
A4 - Dangerous ACEs on Tier-0 Objects
"""

from datetime import datetime, timezone, timedelta
import logging

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.factory import FindingFactory
from bluehound.core.types import Finding, Severity

logger = logging.getLogger(__name__)

EXCESSIVE_ADMIN_THRESHOLD = 10
ORPHANED_ACCOUNT_DAYS = 90


# ============================================================
# ENTRYPOINT
# ============================================================

def detect_privilege_exposure(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory
) -> list[Finding]:

    logger.info("Category A detection started")

    findings: list[Finding] = []

    findings.extend(
        _detect_excessive_local_admin(view, context, factory)
    )

    findings.extend(
        _detect_orphaned_privileged_accounts(view, context, factory)
    )

    findings.extend(
        _detect_hidden_privileged_membership(view, context, factory)
    )

    findings.extend(
        _detect_dangerous_aces_on_tier0(view, context, factory)
    )

    logger.info("Category A complete: %d findings", len(findings))
    return findings


# ============================================================
# A1 — Excessive Local Admin Rights
# ============================================================

def _detect_excessive_local_admin(view, context, factory):

    findings = []

    for user in view.get_users():

        if not user.enabled:
            continue

        if context.is_tier0(user.sid):
            continue

        admin_set = context.admin_to_computers.get(user.sid, set())
        count = len(admin_set)

        if count < EXCESSIVE_ADMIN_THRESHOLD:
            continue

        sample_names = []

        for sid in list(admin_set)[:5]:
            comp = view.get_computer(sid)
            if comp:
                sample_names.append(comp.sam_account_name)

        findings.append(
            factory.create_privilege_finding(
                title=f"Excessive Local Admin: {user.sam_account_name} has admin rights on {count} computers",
                description=(
                    f"{user.sam_account_name} has administrator access "
                    f"to {count} computers exceeding allowed threshold."
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "user_name": user.sam_account_name,
                    "computer_count": count,
                    "sample_computers": sample_names,
                },
                severity=Severity.HIGH,
            )
        )

    return findings


# ============================================================
# A2 — Orphaned Privileged Accounts
# ============================================================

def _detect_orphaned_privileged_accounts(view, context, factory):

    findings = []

    threshold = datetime.now(timezone.utc) - timedelta(
        days=ORPHANED_ACCOUNT_DAYS
    )

    for user in view.get_users():

        if not user.enabled:
            continue

        if not context.is_tier0(user.sid):
            continue

        orphaned = False
        days_since = None

        if user.last_logon is None:
            orphaned = True
            days_since = "never"

        elif user.last_logon < threshold:
            orphaned = True
            days_since = (
                datetime.now(timezone.utc) - user.last_logon
            ).days

        if not orphaned:
            continue

        findings.append(
            factory.create_privilege_finding(
                title=f"Orphaned Privileged Account: {user.sam_account_name}",
                description=(
                    "Privileged account inactive for extended period."
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "user_name": user.sam_account_name,
                    "admin_count": user.admin_count,
                    "days_since_logon": days_since,
                },
                severity=Severity.HIGH,
                remediation=(
                    f"Disable or delete the orphaned privileged account '{user.sam_account_name}'. "
                    f"If the account is still required, enforce a password reset and review its group memberships. "
                    f"Inactive privileged accounts should be disabled after {ORPHANED_ACCOUNT_DAYS} days."
                ),
            )
        )

    return findings


# ============================================================
# A3 — Hidden Privileged Membership
# ============================================================

def _detect_hidden_privileged_membership(view, context, factory):

    findings = []

    for user in view.get_users():

        if not user.enabled:
            continue

        if user.admin_count > 0:
            continue

        if not context.is_tier0(user.sid):
            continue

        groups = context.group_closure.get(user.sid, set())
        tier0_groups = groups.intersection(context.tier0_sids)

        group_names = []

        for gid in tier0_groups:
            g = view.get_group(gid)
            if g:
                group_names.append(g.sam_account_name)

        findings.append(
            factory.create_privilege_finding(
                title=f"Hidden Privileged Membership: {user.sam_account_name}",
                description=(
                    "User gains Tier-0 access via nested membership "
                    "without admin_count flag."
                ),
                affected_principals=[user.sid],
                evidence_data={
                    "user_sid": user.sid,
                    "tier0_groups": group_names,
                    "admin_count": user.admin_count,
                },
                severity=Severity.HIGH,
            )
        )

    return findings


# ============================================================
# A4 — Dangerous ACE on Tier-0
# ============================================================

def _detect_dangerous_aces_on_tier0(view, context, factory):

    findings = []

    DANGEROUS = {"GenericAll", "WriteDACL", "WriteOwner"}

    for user in view.get_users():

        if not user.enabled:
            continue

        if context.is_tier0(user.sid):
            continue

        aces = context.get_dangerous_aces_by_principal(user.sid)

        for ace in aces:

            if ace.right_name not in DANGEROUS:
                continue

            if not context.is_tier0(ace.target):
                continue

            target = view.get_node(ace.target)
            target_name = (
                target.sam_account_name
                if target else ace.target
            )

            findings.append(
                factory.create_privilege_finding(
                    title=f"Dangerous ACE on Tier-0: {user.sam_account_name} has {ace.right_name}",
                    description="Dangerous permission on Tier-0 object enables privilege escalation.",
                    affected_principals=[user.sid],
                    evidence_data={
                        "principal_sid": user.sid,
                        "target_sid": ace.target,
                        "right_name": ace.right_name,
                    },
                    severity=Severity.CRITICAL,
                )
            )

    return findings