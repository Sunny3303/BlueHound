"""
BlueHound Category E Detection: Tier-0 Exposure

Capstone detection layer.

Detects:
E1 — Non-Privileged User → Tier-0 Path
E2 — Workstation → Domain Controller Path
"""

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.factory import FindingFactory
from bluehound.core.types import Finding, Severity, Confidence, FindingCategory

import logging

logger = logging.getLogger(__name__)

# -----------------------------
# Path severity thresholds
# -----------------------------
CATASTROPHIC_HOP_COUNT = 1
CRITICAL_HOP_COUNT = 3
HIGH_HOP_COUNT = 5


# ============================================================
# ENTRYPOINT
# ============================================================

def detect_tier0_exposure(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    logger.info("Starting Category E: Tier-0 Exposure")

    findings: list[Finding] = []

    findings.extend(
        _detect_user_to_tier0_paths(view, context, factory)
    )

    findings.extend(
        _detect_workstation_to_dc_paths(view, context, factory)
    )

    logger.info(f"Category E complete: {len(findings)} findings")
    return findings


# ============================================================
# E1 — USER → TIER0 PATH
# ============================================================

def _detect_user_to_tier0_paths(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    findings = []

    users = [
        u for u in view.get_users()
        if u.enabled and not context.is_tier0(u.sid)
    ]

    for user in users:

        paths = _find_paths_to_tier0(user, view, context)
        if not paths:
            continue

        best_path = min(paths, key=lambda p: p["hop_count"])
        severity = _assess_path_severity(best_path["hop_count"])

        finding = factory.create_finding(
            category=FindingCategory.TIER0_EXPOSURE,
            severity=severity,
            confidence=Confidence.EXPLICIT,
            title=(
                f"Tier-0 Exposure: "
                f"{user.sam_account_name} can reach Tier-0 "
                f"in {best_path['hop_count']} hop(s)"
            ),
            description=(
                f"User '{user.sam_account_name}' has a privilege "
                f"escalation path to Tier-0.\n\n"
                f"Attack Path:\n"
                f"{_format_attack_path(best_path)}"
            ),
            evidence_type="attack_path",
            evidence_data={
                "start_user_sid": user.sid,
                "end_tier0_sid": best_path["target_sid"],
                "hop_count": best_path["hop_count"],
                "path_hops": best_path["hops"],
                "attack_primitives": best_path["primitives"],
            },
            evidence_reasoning=(
                f"Attack path from {user.sam_account_name} "
                f"to Tier-0 detected."
            ),
            affected_principals=[
                user.sid,
                best_path["target_sid"],
            ],
            mitre_techniques=_get_path_mitre(best_path["primitives"]),
            remediation=_generate_path_remediation(
                best_path["hops"]
            ),
        )

        findings.append(finding)

    return findings


# ============================================================
# PATH DISCOVERY ENGINE
# ============================================================

def _find_paths_to_tier0(user, view, context):

    paths = []

    # -------- Direct ACL Abuse --------
    aces = context.get_dangerous_aces_by_principal(user.sid)

    for ace in aces:
        if not context.is_tier0(ace.target):
            continue

        target = view.get_node(ace.target)
        name = getattr(target, "sam_account_name", ace.target)

        paths.append({
            "target_sid": ace.target,
            "target_name": name,
            "hop_count": 1,
            "hops": [{
                "from": user.sam_account_name,
                "to": name,
                "technique": ace.right_name
            }],
            "primitives": ["ACL_Abuse"]
        })

    # -------- AdminTo Chain --------
    admin_targets = context.admin_to_computers.get(
        user.sid, set()
    )

    for comp_sid in admin_targets:
        if not context.is_tier0(comp_sid):
            continue

        comp = view.get_computer(comp_sid)
        name = getattr(comp, "sam_account_name", comp_sid)

        paths.append({
            "target_sid": comp_sid,
            "target_name": name,
            "hop_count": 2,
            "hops": [
                {
                    "from": user.sam_account_name,
                    "to": user.sam_account_name,
                    "technique": "Credential Abuse",
                },
                {
                    "from": user.sam_account_name,
                    "to": name,
                    "technique": "AdminTo",
                },
            ],
            "primitives": ["AdminTo_Chain"],
        })

    return paths


# ============================================================
# SEVERITY MODEL
# ============================================================

def _assess_path_severity(hops: int) -> Severity:

    if hops <= CATASTROPHIC_HOP_COUNT:
        return Severity.CRITICAL
    elif hops <= CRITICAL_HOP_COUNT:
        return Severity.CRITICAL
    elif hops <= HIGH_HOP_COUNT:
        return Severity.HIGH
    return Severity.MEDIUM


# ============================================================
# FORMATTERS
# ============================================================

def _format_attack_path(path: dict) -> str:
    lines = []
    for i, hop in enumerate(path["hops"], 1):
        lines.append(
            f"{i}. {hop['from']} → {hop['to']} via {hop['technique']}"
        )
    return "\n".join(lines)


def _generate_path_remediation(hops):

    steps = []
    for hop in hops:
        steps.append(
            f"- Remove or mitigate: {hop['technique']}"
        )
    return "\n".join(steps)


def _get_path_mitre(primitives):

    mapping = {
        "ACL_Abuse": "T1484.001",
        "AdminTo_Chain": "T1078.003",
    }

    return [
        mapping[p]
        for p in primitives
        if p in mapping
    ] or ["T1078"]


# ============================================================
# E2 — WORKSTATION → DC
# ============================================================

def _detect_workstation_to_dc_paths(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    findings = []

    computers = view.get_computers()

    dcs = [
        c for c in computers
        if c.enabled and context.is_tier0(c.sid)
        and "Domain Controller" in (c.operating_system or "")
    ]

    workstations = [
        c for c in computers
        if c.enabled
        and not context.is_tier0(c.sid)
        and ("Windows 10" in (c.operating_system or "")
             or "Windows 11" in (c.operating_system or ""))
    ]

    for ws in workstations:
        admin_targets = context.admin_to_computers.get(
            ws.sid, set()
        )

        for dc in dcs:
            if dc.sid not in admin_targets:
                continue

            findings.append(
                factory.create_finding(
                    category=FindingCategory.TIER0_EXPOSURE,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.EXPLICIT,
                    title=(
                        f"Tier-0 Boundary Collapse: "
                        f"{ws.sam_account_name} → {dc.sam_account_name}"
                    ),
                    description=(
                        "Workstation has administrative "
                        "access to Domain Controller."
                    ),
                    evidence_type="attack_path",
                    evidence_data={
                        "workstation_sid": ws.sid,
                        "dc_sid": dc.sid,
                        "path_type": "admin_chain",
                    },
                    evidence_reasoning="AdminTo path to DC detected",
                    affected_principals=[ws.sid, dc.sid],
                    mitre_techniques=["T1078.003"],
                    remediation=(
                        "Remove workstation administrative "
                        "access from Domain Controllers."
                    ),
                )
            )

    return findings