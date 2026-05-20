"""
BlueHound Edge Risk Scoring

Behavioral edge evaluation using:
1. Stealth
2. Exploitability
3. Persistence
4. Blast Radius

Scores are heuristic and used for prioritization.
"""

from dataclasses import dataclass
import logging

from bluehound.core.types import Finding, FindingCategory

logger = logging.getLogger(__name__)

STEALTH_WEIGHT = 0.30
EXPLOITABILITY_WEIGHT = 0.25
PERSISTENCE_WEIGHT = 0.25
BLAST_RADIUS_WEIGHT = 0.20


@dataclass
class EdgeRiskScore:
    stealth: float
    exploitability: float
    persistence: float
    blast_radius: float
    overall_score: float
    technique_name: str
    category: FindingCategory


class EdgeRiskEvaluator:

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    # =====================================================
    # PUBLIC
    # =====================================================

    def evaluate_finding(self, finding: Finding) -> EdgeRiskScore:

        data = self._get_raw_data(finding)
        tier0 = self._involves_tier0(finding, data)

        stealth = self._compute_stealth_score(finding)
        exploit = self._compute_exploitability_score(finding, data)
        persist = self._compute_persistence_score(finding)
        blast = self._compute_blast_radius_score(
            finding, tier0
        )

        overall = self._compute_overall(
            stealth, exploit, persist, blast
        )

        return EdgeRiskScore(
            round(stealth, 1),
            round(exploit, 1),
            round(persist, 1),
            round(blast, 1),
            round(overall, 1),
            finding.title,
            finding.category,
        )

    # =====================================================
    # SAFE ACCESS
    # =====================================================

    def _get_raw_data(self, finding: Finding) -> dict:
        evidence = getattr(finding, "evidence", None)
        if not evidence:
            return {}
        return getattr(evidence, "raw_data", {}) or {}

    # =====================================================
    # DIMENSIONS
    # =====================================================

    def _compute_stealth_score(self, finding):

        t = finding.title.lower()
        c = finding.category

        if c == FindingCategory.ADCS_ABUSE:
            if "esc1" in t or "esc4" in t:
                return 9.0
            if "esc8" in t:
                return 7.5

        if c == FindingCategory.KERBEROS_ABUSE:
            if "kerberoast" in t or "as-rep" in t:
                return 8.5
            return 7.0

        if c == FindingCategory.DELEGATION_ABUSE:
            return 6.0

        if c == FindingCategory.PRIVILEGE_EXPOSURE:
            return 6.5

        if c == FindingCategory.TIER0_EXPOSURE:
            return 5.5

        return 5.0

    def _compute_exploitability_score(self, finding, data):

        c = finding.category
        t = finding.title.lower()

        if c == FindingCategory.KERBEROS_ABUSE:
            # Requires domain foothold + offline cracking — not instant RCE
            return 7.0

        if c == FindingCategory.ADCS_ABUSE:
            if "esc1" in t:
                return 8.5
            if "esc4" in t:
                return 6.5
            return 6.0

        if c == FindingCategory.PRIVILEGE_EXPOSURE:
            # Orphaned/hidden accounts have no active attack vector by themselves
            return 5.5

        if c == FindingCategory.DELEGATION_ABUSE:
            return 6.5

        if c == FindingCategory.TIER0_EXPOSURE:
            hops = data.get("hop_count", 5)
            return 9.0 if hops == 1 else 7.5

        return 5.0

    def _compute_persistence_score(self, finding):

        c = finding.category

        if c == FindingCategory.ADCS_ABUSE:
            return 9.5

        if c == FindingCategory.DELEGATION_ABUSE:
            # Config persists but exploitation requires active coercion
            return 7.5

        if c == FindingCategory.PRIVILEGE_EXPOSURE:
            # Inactive accounts don't provide persistent access on their own
            return 6.0

        if c == FindingCategory.KERBEROS_ABUSE:
            return 6.0

        if c == FindingCategory.TIER0_EXPOSURE:
            return 7.5

        return 5.0

    def _compute_blast_radius_score(
        self,
        finding,
        is_tier0,
    ):

        if is_tier0:
            return 9.5

        affected = len(
            getattr(finding, "affected_principals", [])
        )

        if affected > 100:
            return 8.5
        if affected > 10:
            return 7.0
        if affected > 0:
            return 5.5

        return 4.0

    # =====================================================

    def _compute_overall(
        self,
        s,
        e,
        p,
        b,
    ):
        return (
            s * STEALTH_WEIGHT +
            e * EXPLOITABILITY_WEIGHT +
            p * PERSISTENCE_WEIGHT +
            b * BLAST_RADIUS_WEIGHT
        )

    def _involves_tier0(self, finding, data):

        if finding.category == FindingCategory.TIER0_EXPOSURE:
            return True

        return bool(
            data.get("is_tier0")
            or data.get("target_tier0")
        )