"""
BlueHound Category D Detection: ADCS Abuse

Detects:
- D1: ESC1 (Vulnerable Certificate Template) - EXPLICIT
- D2: ESC4 (Dangerous Template Permissions) - INFERRED
- D3: ESC8 (NTLM Relay to ADCS) - INFERRED
"""

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.detection.factory import FindingFactory
from bluehound.core.types import (
    Finding,
    Severity,
    Confidence,
    FindingCategory,
)

import logging

logger = logging.getLogger(__name__)

# ESC4 dangerous permissions
DANGEROUS_TEMPLATE_RIGHTS = {
    "WriteDACL",
    "WriteOwner",
    "GenericAll",
}


# ============================================================
# ENTRY POINT
# ============================================================

def detect_adcs_abuse(
    view: GraphView,
    context: DetectionContext,
    factory: FindingFactory,
) -> list[Finding]:

    logger.info("Starting Category D: ADCS Abuse detection")

    findings: list[Finding] = []

    adcs_data = _get_adcs_data(view)
    if not adcs_data:
        logger.warning("No ADCS data found. Skipping Category D.")
        return findings

    templates, cas = adcs_data

    findings.extend(
        _detect_esc1_vulnerable_templates(
            view, context, factory, templates
        )
    )

    findings.extend(
        _detect_esc4_template_permissions(
            view, context, factory, templates
        )
    )

    findings.extend(
        _detect_esc8_ntlm_relay(
            view, context, factory, cas, templates
        )
    )

    logger.info(f"Category D complete: {len(findings)} findings")
    return findings


# ============================================================
# ADCS DATA ACCESS
# ============================================================

def _get_adcs_data(view: GraphView):
    """
    Retrieve ADCS snapshot from GraphView.
    Safe optional access.
    """

    if not hasattr(view, "get_certificate_templates"):
        return None

    templates = view.get_certificate_templates()
    cas = view.get_certificate_authorities()

    if not templates and not cas:
        return None

    return templates, cas


# ============================================================
# D1 — ESC1
# ============================================================

def _detect_esc1_vulnerable_templates(
    view,
    context,
    factory,
    templates,
):

    findings = []

    for template in templates:

        if not template.enrollee_supplies_subject:
            continue

        if not template.client_authentication:
            continue

        if template.manager_approval_required:
            continue

        if template.authorized_signatures_required > 0:
            continue

        enrollable = template.enrollment_permissions
        if not enrollable:
            continue

        non_tier0 = [
            sid for sid in enrollable
            if not context.is_tier0(sid)
        ]

        if not non_tier0:
            continue

        findings.append(
            factory.create_adcs_finding(
                title=f"ESC1: Vulnerable Certificate Template '{template.name}'",
                description=(
                    f"Template '{template.name}' allows subject supply "
                    f"and client authentication without approval. "
                    f"{len(non_tier0)} non-privileged principals "
                    f"can enroll certificates."
                ),
                affected_principals=non_tier0,
                evidence_data={
                    "template_name": template.name,
                    "esc_type": "ESC1",
                    "non_privileged_enrollers": len(non_tier0),
                },
                severity=Severity.CRITICAL,
                confidence=Confidence.EXPLICIT,
            )
        )

    return findings


# ============================================================
# D2 — ESC4
# ============================================================

def _detect_esc4_template_permissions(
    view,
    context,
    factory,
    templates,
):

    findings = []

    for template in templates:

        if not template.client_authentication:
            continue

        aces = context.get_aces_on_target(template.name)

        for ace in aces:

            if ace.right_name not in DANGEROUS_TEMPLATE_RIGHTS:
                continue

            if context.is_tier0(ace.trustee):
                continue

            principal = view.get_node(ace.trustee)
            pname = (
                getattr(principal, "sam_account_name", ace.trustee)
            )

            findings.append(
                factory.create_adcs_finding(
                    title=(
                        f"ESC4: Dangerous Template Permission "
                        f"({ace.right_name}) on '{template.name}'"
                    ),
                    description=(
                        f"Principal '{pname}' can modify "
                        f"certificate template '{template.name}'."
                    ),
                    affected_principals=[ace.trustee],
                    evidence_data={
                        "template_name": template.name,
                        "principal_sid": ace.trustee,
                        "permission": ace.right_name,
                        "esc_type": "ESC4",
                    },
                    severity=Severity.CRITICAL,
                    confidence=Confidence.INFERRED,
                )
            )

    return findings


# ============================================================
# D3 — ESC8
# ============================================================

def _detect_esc8_ntlm_relay(
    view,
    context,
    factory,
    cas,
    templates,
):

    findings = []

    template_map = {t.name: t for t in templates}

    for ca in cas:

        if not ca.web_enrollment_enabled:
            continue

        if not ca.ntlm_allowed:
            continue

        vulnerable_templates = []

        for tname in ca.templates:
            tmpl = template_map.get(tname)
            if tmpl and tmpl.client_authentication:
                vulnerable_templates.append(tname)

        if not vulnerable_templates:
            continue

        findings.append(
            factory.create_adcs_finding(
                title=f"ESC8: NTLM Relay to ADCS Web Enrollment ({ca.name})",
                description=(
                    f"CA '{ca.name}' exposes web enrollment "
                    f"with NTLM authentication enabled."
                ),
                affected_principals=["DOMAIN"],
                evidence_data={
                    "ca_name": ca.name,
                    "dns_hostname": ca.dns_hostname,
                    "client_auth_templates": vulnerable_templates,
                    "esc_type": "ESC8",
                },
                severity=Severity.CRITICAL,
                confidence=Confidence.INFERRED,
            )
        )

    return findings