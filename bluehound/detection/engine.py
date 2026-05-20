from __future__ import annotations

import logging
from typing import Callable, List

from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.core.types import Finding, FindingCategory
from bluehound.detection.factory import FindingFactory


class DetectionEngine:
    """
    BlueHound Detection Orchestrator.
    """

    def __init__(self, context: DetectionContext):

        self.context = context
        self.view: GraphView = context.view
        self.factory = FindingFactory()
        self.logger = logging.getLogger(__name__)

        self._stats = {
            "total_findings": 0,
            "by_category": {},
            "by_severity": {},
        }

    # =========================================================

    def run_all_detections(self) -> List[Finding]:

        self.logger.info("Preparing DetectionContext...")

        findings: List[Finding] = []

        from bluehound.detection.category_a import detect_privilege_exposure
        from bluehound.detection.category_b import detect_kerberos_abuse
        from bluehound.detection.category_c import detect_delegation_abuse

        findings += self.run_category(
            FindingCategory.PRIVILEGE_EXPOSURE,
            detect_privilege_exposure,
        )

        findings += self.run_category(
            FindingCategory.KERBEROS_ABUSE,
            detect_kerberos_abuse,
        )

        findings += self.run_category(
            FindingCategory.DELEGATION_ABUSE,
            detect_delegation_abuse,
        )

        try:
            from bluehound.detection.category_d import detect_adcs_abuse

            findings += self.run_category(
                FindingCategory.ADCS_ABUSE,
                detect_adcs_abuse,
            )

            self.logger.info("Category D (ADCS Abuse) executed")

        except ImportError:
            self.logger.warning(
                "Category D (ADCS Abuse) not available — skipping"
            )

        try:
            from bluehound.detection.category_e import detect_tier0_exposure

            findings += self.run_category(
                FindingCategory.TIER0_EXPOSURE,
                detect_tier0_exposure,
            )

            self.logger.info("Category E (Tier-0 Exposure) executed")

        except ImportError:
            self.logger.warning(
                "Category E (Tier-0 Exposure) not available — skipping"
            )

        findings = self.deduplicate_findings(findings)
        self._update_statistics(findings)

        return findings

    # =========================================================

    def run_category(
        self,
        category: FindingCategory,
        detector: Callable,
    ) -> List[Finding]:

        try:
            return detector(self.view, self.context, self.factory)
        except Exception as exc:
            self.logger.error(f"{category.value} failed: {exc}")
            return []

    # =========================================================

    def deduplicate_findings(self, findings: List[Finding]):

        seen = set()
        unique = []

        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                unique.append(f)

        return unique

    # =========================================================

    def _update_statistics(self, findings: List[Finding]):

        from bluehound.core.types import Severity

        self._stats["total_findings"] = len(findings)

        for cat in FindingCategory:
            self._stats["by_category"][cat.value] = sum(
                1 for f in findings if f.category == cat
            )

        for sev in Severity:
            self._stats["by_severity"][sev.value] = sum(
                1 for f in findings if f.severity == sev
            )

    def get_statistics(self):
        return self._stats.copy()
