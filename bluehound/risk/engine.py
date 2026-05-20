"""
BlueHound Behavioral Risk Engine
"""

from dataclasses import dataclass
from typing import Optional
import logging

from bluehound.core.types import (
    Finding,
    FindingCategory,
    ExposureLevel,
    Severity,
)
from bluehound.core.graph_view import GraphView
from bluehound.core.detection_context import DetectionContext
from bluehound.risk.edge_scoring import EdgeRiskEvaluator

logger = logging.getLogger(__name__)

CATEGORY_BIAS = {
    FindingCategory.ADCS_ABUSE: 1.30,
    FindingCategory.DELEGATION_ABUSE: 1.20,
    FindingCategory.KERBEROS_ABUSE: 1.10,
    FindingCategory.PRIVILEGE_EXPOSURE: 1.00,
    FindingCategory.TIER0_EXPOSURE: 1.00,
}

CATEGORY_PRIORITY = {
    FindingCategory.ADCS_ABUSE: 5,
    FindingCategory.DELEGATION_ABUSE: 4,
    FindingCategory.KERBEROS_ABUSE: 3,
    FindingCategory.TIER0_EXPOSURE: 2,
    FindingCategory.PRIVILEGE_EXPOSURE: 1,
}

TIER0_BONUS = 1.0


@dataclass
class AttackPath:
    path_id: str
    findings: list
    edge_scores: list
    path_score: float
    hop_count: int
    reaches_tier0: bool
    max_edge_risk: float
    average_edge_risk: float
    primary_category: FindingCategory


@dataclass
class RiskResult:
    global_risk_score: float
    risk_classification: str
    exposure_level: ExposureLevel
    attack_paths: list
    most_dangerous_path: Optional[AttackPath]
    tier0_reachable: bool
    shortest_tier0_path_hops: Optional[int]
    risk_by_category: dict
    blast_radius: float
    affected_principals: set
    total_principals: int
    finding_counts: dict
    critical_finding_count: int


class RiskEngine:

    def __init__(
        self,
        view: GraphView,
        context: DetectionContext,
    ):
        self.view = view
        self.context = context
        self.edge_eval = EdgeRiskEvaluator()

    # =====================================================

    def compute_risk(self, findings):

        if not findings:
            return self._zero()

        paths = self._construct_attack_paths(findings)

        for p in paths:
            p.path_score = self._score_path(p)

        paths.sort(
            key=lambda p: (
                p.path_score,
                CATEGORY_PRIORITY.get(p.primary_category, 0),
                p.max_edge_risk,
            ),
            reverse=True,
        )

        global_score = self._compute_global(
            paths,
            findings,
        )

        tier0_paths = [
            p for p in paths if p.reaches_tier0
        ]

        affected = self._affected(findings)
        blast = self._blast_radius(affected)

        exposure = self._determine_exposure(
            bool(tier0_paths),
            paths[0] if paths else None,
            blast,
        )

        stats = self.view.get_statistics()
        total = stats["users"] + stats["computers"]

        counts = self._count(findings)

        return RiskResult(
            round(global_score, 1),
            self._classify(global_score),
            exposure,
            paths,
            paths[0] if paths else None,
            bool(tier0_paths),
            min(
                (p.hop_count for p in tier0_paths),
                default=None,
            ),
            {},
            blast,
            affected,
            total,
            counts,
            counts["CRITICAL"],
        )

    # =====================================================
    # PATH BUILDING (FIXED ORDER)
    # =====================================================

    def _construct_attack_paths(self, findings):

        paths = []
        idx = 0

        tier0 = [
            f for f in findings
            if f.category ==
            FindingCategory.TIER0_EXPOSURE
        ]

        others = [
            f for f in findings
            if f.category !=
            FindingCategory.TIER0_EXPOSURE
        ]

        ordered = tier0 + others

        for f in ordered:

            edge = self.edge_eval.evaluate_finding(f)

            data = getattr(
                getattr(f, "evidence", None),
                "raw_data",
                {},
            )

            hop = data.get("hop_count", 1)

            paths.append(
                AttackPath(
                    f"PATH-{idx:03}",
                    [f],
                    [edge],
                    0.0,
                    hop,
                    self._could_reach_tier0(f),
                    edge.overall_score,
                    edge.overall_score,
                    f.category,
                )
            )
            idx += 1

        return paths

    # =====================================================

    def _score_path(self, path):

        bias = CATEGORY_BIAS.get(
            path.primary_category,
            1.0,
        )

        modifier = self._length_modifier(path.hop_count)

        # Use biased_max * modifier only — avoids double-counting
        # when a path has a single finding (max == avg).
        score = (
            path.max_edge_risk * bias * modifier +
            (
                TIER0_BONUS
                if path.reaches_tier0
                else 0.0
            )
        )

        return min(score, 10.0)
        
    # =====================================================

    def _length_modifier(self, hops):

        if hops <= 2:
            return 1.0
        if hops == 3:
            return 0.9
        if hops == 4:
            return 0.8
        if hops == 5:
            return 0.7
        return 0.6

    # =====================================================

    def _compute_global(self, paths, findings):

        max_path = paths[0].path_score

        top = paths[:5]
        avg_top = sum(
            p.path_score for p in top
        ) / len(top)

        critical = sum(
            1 for f in findings
            if f.severity == Severity.CRITICAL
        )

        bonus = min(critical * 0.3, 2.0)

        return min(
            max_path +
            avg_top * 0.15 +
            bonus * 0.2,
            10.0,
        )

    # =====================================================

    def _determine_exposure(
        self,
        tier0,
        path,
        blast,
    ):
        if not path:
            return ExposureLevel.CONTAINED

        # CATASTROPHIC: confirmed tier0 path AND very high score
        if tier0 and path.path_score >= 9:
            return ExposureLevel.CATASTROPHIC

        # DOMAIN_WIDE: confirmed tier0 path from a TIER0_EXPOSURE finding
        # (i.e. a directly traced path, not just a potential via orphaned accounts)
        # AND high blast radius
        if (
            tier0
            and path.primary_category == FindingCategory.TIER0_EXPOSURE
            and path.path_score >= 7.5
            and blast >= 0.2
        ):
            return ExposureLevel.DOMAIN_WIDE

        # LOCALIZED: tier0 is theoretically reachable but no confirmed direct path
        if tier0:
            return ExposureLevel.LOCALIZED

        return ExposureLevel.CONTAINED

    def _classify(self, score):

        if score >= 9:
            return "CRITICAL"
        if score >= 7.5:
            return "HIGH"
        if score >= 5:
            return "MEDIUM"
        return "LOW"

    # =====================================================

    def _affected(self, findings):
        s = set()
        for f in findings:
            s.update(
                getattr(
                    f,
                    "affected_principals",
                    [],
                )
            )
        return s

    def _blast_radius(self, principals):

        stats = self.view.get_statistics()
        total = stats["users"] + stats["computers"]

        if total == 0:
            return 0.0

        return min(
            len(principals) / total,
            1.0,
        )

    def _count(self, findings):

        out = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for f in findings:
            severity = getattr(f, "severity", None)

            if not severity:
                continue    

            key = str(severity.value).upper()

            if key in out:
                out[key] += 1
            else:
                logger.debug(
                "Unknown severity level: %s",
                severity.value,
                )

        return out

    def _could_reach_tier0(self, f):

        if f.category == FindingCategory.ADCS_ABUSE:
            return True

        data = getattr(
            getattr(f, "evidence", None),
            "raw_data",
            {},
        )

        return bool(data.get("target_tier0") or data.get("is_tier0") or data.get("admin_count"))

    def _zero(self):

        stats = self.view.get_statistics()
        total = stats["users"] + stats["computers"]

        return RiskResult(
            0.0,
            "LOW",
            ExposureLevel.CONTAINED,
            [],
            None,
            False,
            None,
            {},
            0.0,
            set(),
            total,
            {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
            0,
        )