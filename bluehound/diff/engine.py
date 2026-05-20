"""
BlueHound Snapshot Diffing Engine

Compares two ThreatModelResult snapshots to detect:
- Risk score changes
- New/removed/changed findings
- Privilege creep
- Tier-0 exposure regression
- Attack surface changes
"""

from bluehound.core.types import (
    ThreatModelResult,
    Finding,
    FindingCategory,
    Severity,
)
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class SnapshotDiff:
    """Result of comparing two ThreatModelResult snapshots"""

    baseline_timestamp: datetime
    current_timestamp: datetime
    baseline_domain: str
    current_domain: str
    time_delta: timedelta

    risk_score_delta: float
    risk_classification_change: str
    exposure_level_change: str

    new_findings: list[Finding]
    removed_findings: list[Finding]
    changed_findings: list[tuple[Finding, Finding]]
    unchanged_finding_count: int

    new_findings_by_category: dict[str, int]
    removed_findings_by_category: dict[str, int]

    new_critical_count: int
    removed_critical_count: int
    severity_escalations: list[tuple[Finding, Finding]]
    severity_improvements: list[tuple[Finding, Finding]]

    privilege_creep_detected: bool
    privilege_creep_principals: list[str]

    tier0_exposure_regression: bool
    new_tier0_paths: list[str]

    blast_radius_delta: float
    affected_principal_delta: int

    new_mitre_techniques: list[str]
    removed_mitre_techniques: list[str]

    total_findings_delta: int
    improvement_score: float

    def is_regression(self) -> bool:
        return self.improvement_score > 0

    def is_improvement(self) -> bool:
        return self.improvement_score < 0

    def get_summary(self) -> str:
        direction = "WORSE" if self.is_regression() else "BETTER"

        summary = f"Security posture: {direction}\n"
        summary += f"Risk score change: {self.risk_score_delta:+.1f}\n"
        summary += f"Findings delta: {self.total_findings_delta:+d}\n"
        summary += f"New findings: {len(self.new_findings)}\n"
        summary += f"Removed findings: {len(self.removed_findings)}\n"

        if self.tier0_exposure_regression:
            summary += "⚠ Tier-0 exposure regression detected\n"

        if self.privilege_creep_detected:
            summary += f"⚠ Privilege creep detected ({len(self.privilege_creep_principals)} principals)\n"

        return summary


class SnapshotDiffEngine:
    """Compares two ThreatModelResult snapshots"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def compare(
        self,
        baseline: ThreatModelResult,
        current: ThreatModelResult,
    ) -> SnapshotDiff:

        self.logger.info(
            f"Comparing snapshots {baseline.metadata.domain_fqdn}"
        )

        time_delta = current.metadata.collected_at - baseline.metadata.collected_at

        new_findings = self._find_new_findings(baseline, current)
        removed_findings = self._find_removed_findings(baseline, current)
        changed_findings = self._find_changed_findings(baseline, current)

        unchanged_count = (
            len(baseline.findings)
            - len(removed_findings)
            - len(changed_findings)
        )

        new_by_category = self._count_by_category(new_findings)
        removed_by_category = self._count_by_category(removed_findings)

        new_critical = [
            f for f in new_findings if f.severity == Severity.CRITICAL
        ]
        removed_critical = [
            f for f in removed_findings if f.severity == Severity.CRITICAL
        ]

        severity_escalations = [
            (old, new)
            for old, new in changed_findings
            if self._severity_value(new.severity)
            > self._severity_value(old.severity)
        ]

        severity_improvements = [
            (old, new)
            for old, new in changed_findings
            if self._severity_value(new.severity)
            < self._severity_value(old.severity)
        ]

        privilege_creep, creep_principals = self._detect_privilege_creep(
            baseline, current
        )

        tier0_regression, new_paths = self._detect_tier0_regression(
            baseline, current
        )

        blast_radius_delta = round(
            float(current.blast_radius or 0) - float(baseline.blast_radius or 0),
            3
        )

        affected_delta = (
            getattr(current, "affected_principal_count", 0)
            - getattr(baseline, "affected_principal_count", 0)
        )

        baseline_techniques = set(getattr(baseline, "mitre_techniques", []))
        current_techniques = set(getattr(current, "mitre_techniques", []))

        for f in baseline.findings:
            baseline_techniques.update(getattr(f, "mitre_techniques", []))

        for f in current.findings:
            current_techniques.update(getattr(f, "mitre_techniques", []))


        new_techniques = sorted(current_techniques - baseline_techniques)
        removed_techniques = sorted(baseline_techniques - current_techniques)

        risk_delta = current.risk_score - baseline.risk_score

        risk_change = (
            f"{getattr(baseline, 'risk_classification', 'UNKNOWN')} → "
            f"{getattr(current, 'risk_classification', 'UNKNOWN')}"
        )

        exposure_change = (
            f"{baseline.exposure_level.value} → "
            f"{current.exposure_level.value}"
        )

        findings_delta = len(current.findings) - len(baseline.findings)

        diff = SnapshotDiff(
            baseline_timestamp=baseline.metadata.collected_at,
            current_timestamp=current.metadata.collected_at,
            baseline_domain=baseline.metadata.domain_fqdn,
            current_domain=current.metadata.domain_fqdn,
            time_delta=time_delta,
            risk_score_delta=risk_delta,
            risk_classification_change=risk_change,
            exposure_level_change=exposure_change,
            new_findings=new_findings,
            removed_findings=removed_findings,
            changed_findings=changed_findings,
            unchanged_finding_count=unchanged_count,
            new_findings_by_category=new_by_category,
            removed_findings_by_category=removed_by_category,
            new_critical_count=len(new_critical),
            removed_critical_count=len(removed_critical),
            severity_escalations=severity_escalations,
            severity_improvements=severity_improvements,
            privilege_creep_detected=privilege_creep,
            privilege_creep_principals=creep_principals,
            tier0_exposure_regression=tier0_regression,
            new_tier0_paths=new_paths,
            blast_radius_delta=blast_radius_delta,
            affected_principal_delta=affected_delta,
            new_mitre_techniques=new_techniques,
            removed_mitre_techniques=removed_techniques,
            total_findings_delta=findings_delta,
            improvement_score=0.0,
        )

        diff.improvement_score = self._compute_improvement_score(diff)

        return diff

    def _find_new_findings(self, baseline, current):

        baseline_ids = {f.id for f in baseline.findings}

        return [f for f in current.findings if f.id not in baseline_ids]

    def _find_removed_findings(self, baseline, current):

        current_ids = {f.id for f in current.findings}

        return [f for f in baseline.findings if f.id not in current_ids]

    def _find_changed_findings(self, baseline, current):

        baseline_map = {f.id: f for f in baseline.findings}
        current_map = {f.id: f for f in current.findings}

        common_ids = set(baseline_map) & set(current_map)

        changed = []

        for fid in common_ids:

            old = baseline_map[fid]
            new = current_map[fid]

            if old.severity != new.severity or set(
                old.affected_principals
            ) != set(new.affected_principals):

                changed.append((old, new))

        return changed

    def _detect_privilege_creep(self, baseline, current):

        new_priv = [
            f
            for f in self._find_new_findings(baseline, current)
            if f.category == FindingCategory.PRIVILEGE_EXPOSURE
        ]

        if not new_priv:
            return (False, [])

        principals = set()

        for f in new_priv:
            raw_data = getattr(f.evidence, "raw_data", {}) or {}
            name = raw_data.get("user_name") or raw_data.get("principal_sid")
            if name:
                principals.add(name)
            else:
                principals.update(f.affected_principals)

        return (True, sorted(principals))

    def _detect_tier0_regression(self, baseline, current):

        if not baseline.tier0_reachable and current.tier0_reachable:
            return (True, [current.primary_kill_path])

        if baseline.tier0_reachable and current.tier0_reachable:

            baseline_hops = getattr(baseline, "shortest_tier0_path_hops", None) or 999
            current_hops = getattr(current, "shortest_tier0_path_hops", None) or 999

            if current_hops < baseline_hops:
                return (
                    True,
                    [f"Shorter path: {current_hops} hops"],
                )

        new_tier0 = [
            f
            for f in self._find_new_findings(baseline, current)
            if f.category == FindingCategory.TIER0_EXPOSURE
        ]

        if new_tier0:
            return (True, [f.title for f in new_tier0])

        return (False, [])
    
    def _extract_mitre_techniques(self, model: ThreatModelResult) -> set[str]:

        techniques = set()

        techniques.update(getattr(model, "mitre_techniques", []))

        for finding in getattr(model, "findings", []):
            techniques.update(getattr(finding, "mitre_techniques", []))

        return techniques

    def _compute_improvement_score(self, diff: SnapshotDiff) -> float:

        score = 0.0

        score += diff.risk_score_delta

        score += diff.new_critical_count * 1.0
        score -= diff.removed_critical_count * 1.0

        if diff.tier0_exposure_regression:
            score += 3.0

        if diff.privilege_creep_detected:
            score += 2.0

        score += len(diff.severity_escalations) * 0.5
        score -= len(diff.severity_improvements) * 0.5

        score += diff.blast_radius_delta * 10.0

        score = max(-10.0, min(10.0, score))

        return round(score, 1)

    def _count_by_category(self, findings):

        counts = {}

        for f in findings:
            cat = f.category.value
            counts[cat] = counts.get(cat, 0) + 1

        return counts

    def _severity_value(self, severity):

        mapping = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }

        return mapping.get(severity, 0)