"""
BlueHound Category C Detection: Delegation Abuse

Detects:
- C1: Unconstrained Delegation
- C2: Resource-Based Constrained Delegation (RBCD)
- C3: Machine Account Abuse
"""

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.factory import FindingFactory
from bluehound.core.types import Finding, Severity

import logging

logger = logging.getLogger(__name__)

DEFAULT_MACHINE_ACCOUNT_QUOTA = 10


# ============================================================
# ENTRYPOINT
# ============================================================

def detect_delegation_abuse(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    logger.info("Starting Category C detection")

    findings: list[Finding] = []

    findings.extend(
        _detect_unconstrained_delegation(view, context, factory)
    )

    findings.extend(
        _detect_rbcd_abuse(view, context, factory)
    )

    findings.extend(
        _detect_machine_account_abuse(view, context, factory)
    )

    logger.info("Category C complete (%d findings)", len(findings))
    return findings


# ============================================================
# DOMAIN CONTROLLER DETECTION
# ============================================================

def _is_domain_controller(computer, context: DetectionContext) -> bool:

    if not computer:
        return False

    dn = (computer.distinguished_name or "").lower()
    if "ou=domain controllers" in dn:
        return True

    os_name = (computer.operating_system or "").lower()
    if "domain controller" in os_name:
        return True

    name = computer.sam_account_name.rstrip("$").lower()
    if name.startswith("dc") or "-dc" in name:
        return True

    return False


# ============================================================
# C1 — UNCONSTRAINED DELEGATION
# ============================================================

def _detect_unconstrained_delegation(
    view,
    context,
    factory,
):

    findings = []

    for comp in view.get_computers():

        if not comp.enabled:
            continue

        if not getattr(comp, "unconstrained_delegation", False):
            continue

        if _is_domain_controller(comp, context):
            continue

        findings.append(
            factory.create_delegation_finding(
                title=f"Unconstrained Delegation: {comp.sam_account_name}",
                description=(
                    f"Computer '{comp.sam_account_name}' allows "
                    f"unconstrained delegation enabling impersonation "
                    f"of ANY authenticating user."
                ),
                affected_principals=[comp.sid],
                evidence_data={
                    "computer_sid": comp.sid,
                    "computer_name": comp.sam_account_name,
                    "unconstrained_delegation": True,
                    "is_domain_controller": False,
                    "operating_system": comp.operating_system,
                },
                severity=Severity.HIGH,
                remediation=(
                    f"Disable unconstrained delegation on '{comp.sam_account_name}' and replace it with constrained delegation or Resource-Based Constrained Delegation (RBCD). "
                    f"Until remediated, mark all tier-0 accounts as 'sensitive and cannot be delegated' to prevent TGT capture."
                ),
            )
        )

    return findings


# ============================================================
# SPN TARGET PARSER
# ============================================================

def _parse_spn_targets(spns: list[str]) -> set[str]:

    targets = set()

    for spn in spns or []:

        if "/" not in spn:
            continue

        host = spn.split("/", 1)[1]

        if ":" in host:
            host = host.split(":")[0]

        hostname = host.split(".")[0].upper()
        targets.add(hostname)

    return targets


# ============================================================
# C2 — RBCD ABUSE
# ============================================================

def _detect_rbcd_abuse(
    view,
    context,
    factory,
):

    findings = []
    computers = view.get_computers()

    for source in computers:

        if not source.enabled:
            continue

        spns = getattr(source, "allowed_to_delegate_to", None)
        if not spns:
            continue

        if context.is_tier0(source.sid):
            continue

        targets = _parse_spn_targets(spns)

        tier0_targets = []

        for comp in computers:
            name = comp.sam_account_name.rstrip("$").upper()

            if name in targets and context.is_tier0(comp.sid):
                tier0_targets.append(comp)

        if not tier0_targets:
            continue

        findings.append(
            factory.create_delegation_finding(
                title=(
                    f"RBCD to Tier-0: "
                    f"{source.sam_account_name} can delegate "
                    f"to {len(tier0_targets)} Tier-0 computer(s)"
                ),
                description=(
                    "Non-Tier-0 computer can impersonate users "
                    "toward Tier-0 systems via RBCD."
                ),
                affected_principals=[
                    source.sid,
                    *[t.sid for t in tier0_targets],
                ],
                evidence_data={
                    "source_computer_sid": source.sid,
                    "target_tier0": True,
                    "target_count": len(tier0_targets),
                    "target_spns": spns,
                },
                severity=Severity.HIGH,
            )
        )

    return findings


# ============================================================
# C3 — MACHINE ACCOUNT ABUSE
# ============================================================

def _detect_machine_account_abuse(
    view,
    context,
    factory,
):

    findings = []

    domain_info = view.get_domain_info() or {}

    if "ms-ds-machineaccountquota" not in domain_info:
        return findings
    
    quota = domain_info["ms-ds-machineaccountquota"]

    if quota == 0:
        return findings

    domain_sid = domain_info.get("domain_sid", "DOMAIN")
    fqdn = domain_info.get("fqdn", "UNKNOWN")

    findings.append(
        factory.create_delegation_finding(
            title=(
                f"Machine Account Quota Enabled: "
                f"Users can create {quota} computer accounts"
            ),
            description=(
                f"Domain '{fqdn}' allows authenticated users "
                f"to create machine accounts."
            ),
            affected_principals=[domain_sid],
            evidence_data={
                "machine_account_quota": quota,
                "domain_fqdn": fqdn,
            },
            severity=Severity.MEDIUM,
        )
    )

    return findings