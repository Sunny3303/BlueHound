from __future__ import annotations

import hashlib
import logging
from typing import Optional

from bluehound.core.types import (
    Finding,
    FindingCategory,
    Severity,
    Confidence,
    Evidence,
)

# --------------------------------------------------
# Finding Category → Enterprise ID Prefix Mapping
# --------------------------------------------------
CATEGORY_PREFIX = {
    FindingCategory.PRIVILEGE_EXPOSURE: "PRIV",
    FindingCategory.KERBEROS_ABUSE: "KERB",
    FindingCategory.DELEGATION_ABUSE: "DELEG",
    FindingCategory.ADCS_ABUSE: "ADCS",
    FindingCategory.TIER0_EXPOSURE: "TIER0",
}


class FindingFactory:

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._finding_count = 0

    # =========================================================

    def create_finding(
        self,
        category: FindingCategory,
        severity: Severity,
        confidence: Confidence,
        title: str,
        description: str,
        evidence_type: str,
        evidence_data: dict,
        evidence_reasoning: str,
        affected_principals: list[str],
        mitre_techniques: Optional[list[str]] = None,
        remediation: Optional[str] = None,
    ) -> Finding:

        if not title or len(title) > 200:
            raise ValueError("Invalid title")

        if not affected_principals:
            raise ValueError("Affected principals required")

        self.validate_evidence(evidence_data)

        fid = self.generate_finding_id(
            category,
            title,
            affected_principals,
        )

        evidence = Evidence(
            evidence_type,
            dict(evidence_data),
            evidence_reasoning,
        )

        self._finding_count += 1

        return Finding(
            id=fid,
            category=category,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence=evidence,
            affected_principals=affected_principals,
            mitre_techniques=mitre_techniques or [],
            remediation=remediation or "",
        )

    # =========================================================
    # Privilege Findings
    # =========================================================

    def create_privilege_finding(
        self,
        title: str,
        description: str,
        affected_principals: list[str],
        evidence_data: dict,
        severity: Severity,
        confidence: Confidence = Confidence.EXPLICIT,
        remediation: str = "",
    ) -> Finding:
        """Convenience wrapper for Category A findings."""

        return self.create_finding(
            category=FindingCategory.PRIVILEGE_EXPOSURE,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence_type="privilege_exposure",
            evidence_data=evidence_data,
            evidence_reasoning=title,
            affected_principals=affected_principals,
            remediation=remediation,
            mitre_techniques=["T1078.002"],
        )

    # =========================================================
    # Kerberos Findings
    # =========================================================

    def create_kerberos_finding(
        self,
        title: str,
        description: str,
        affected_principals: list[str],
        evidence_data: dict,
        severity: Severity,
        confidence: Confidence = Confidence.EXPLICIT,
        remediation: str = "",
    ) -> Finding:
        """Convenience wrapper for Category B findings."""

        if "as-rep" in title.lower() or "asrep" in title.lower():
            mitre = ["T1558.004"]
        else:
            mitre = ["T1558.003"]

        return self.create_finding(
            category=FindingCategory.KERBEROS_ABUSE,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence_type="kerberos_abuse",
            evidence_data=evidence_data,
            evidence_reasoning=title,
            affected_principals=affected_principals,
            remediation=remediation,
            mitre_techniques=mitre,
        )

    # =========================================================
    # Delegation Findings
    # =========================================================

    def create_delegation_finding(
        self,
        title: str,
        description: str,
        affected_principals: list[str],
        evidence_data: dict,
        severity: Severity,
        confidence: Confidence = Confidence.EXPLICIT,
        remediation: str = "",
    ) -> Finding:
        """Convenience wrapper for Category C findings."""

        return self.create_finding(
            category=FindingCategory.DELEGATION_ABUSE,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence_type="delegation_abuse",
            evidence_data=evidence_data,
            evidence_reasoning=title,
            affected_principals=affected_principals,
            remediation=remediation,
            mitre_techniques=["T1558", "T1134"],
        )

    # =========================================================
    # ADCS Findings
    # =========================================================

    def create_adcs_finding(
        self,
        title: str,
        description: str,
        affected_principals: list[str],
        evidence_data: dict,
        severity: Severity = Severity.CRITICAL,
        confidence: Confidence = Confidence.EXPLICIT,
        remediation: str = "",
    ) -> Finding:
        """Convenience wrapper for Category D findings."""

        mitre_techniques = ["T1649"]

        if "ESC4" in title:
            mitre_techniques.append("T1556.004")

        if "ESC8" in title or "NTLM" in title:
            mitre_techniques.append("T1557.001")

        evidence_type = (
            "template_config"
            if confidence == Confidence.EXPLICIT
            else "inference"
        )

        return self.create_finding(
            category=FindingCategory.ADCS_ABUSE,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence_type=evidence_type,
            evidence_data=evidence_data,
            evidence_reasoning=f"ADCS abuse detected: {title}",
            affected_principals=affected_principals,
            remediation=remediation,
            mitre_techniques=mitre_techniques,
        )

    # =========================================================

    def generate_finding_id(
        self,
        category: FindingCategory,
        title: str,
        principals: list[str],
    ) -> str:

        content = f"{title}:{':'.join(sorted(principals))}"
        hash_digest = hashlib.sha256(content.encode()).hexdigest()[:8]
        prefix = CATEGORY_PREFIX.get(category, "UNK")
        return f"{prefix}-{hash_digest}"

    # =========================================================

    def validate_evidence(self, data: dict):

        if not isinstance(data, dict):
            raise ValueError("Evidence must be dict")

        if not data:
            raise ValueError("Evidence cannot be empty")
