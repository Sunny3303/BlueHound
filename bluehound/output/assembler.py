"""
BlueHound ThreatModelResult Assembler

Pure output construction layer.

Combines:
- Findings (Detection Engine)
- RiskResult (Risk Engine)
- Snapshot metadata

Produces canonical ThreatModelResult.
"""

from datetime import datetime, timezone
import logging
from typing import Optional

from bluehound.core.types import (
    ThreatModelResult,
    Finding,
    SnapshotMetadata,
    FindingCategory,
    Severity,
    KillPath,
    ExposureLevel,
)
from bluehound.risk.engine import RiskResult
from bluehound.core.graph_view import GraphView

logger = logging.getLogger(__name__)


class ThreatModelAssembler:
    """Assembles ThreatModelResult deterministically."""

    def __init__(self, view: GraphView):
        self.view = view
        self._sid_lookup = {}

        # Build SID → name cache
        try:
            for node in (
                list(view.get_users())
                + list(view.get_groups())
                + list(view.get_computers())
            ):
                sid = getattr(node, "sid", None)
                name = getattr(node, "sam_account_name", None)

                if sid and name:
                    self._sid_lookup[sid.upper()] = name
        except Exception:
            pass

    # ============================================================
    # PUBLIC
    # ============================================================

    def assemble(
        self,
        findings: list[Finding],
        risk_result: RiskResult,
        snapshot_metadata: SnapshotMetadata,
    ) -> ThreatModelResult:

        category_counts, _ = self._compute_finding_counts(findings)

        top_fixes = self._generate_top_fixes(findings, risk_result)

        primary_kill_path = self._format_primary_kill_path(risk_result)

        time_to_da = self._compute_time_to_domain_admin(risk_result)
        detection_surface = self._compute_detection_surface(findings)

        return ThreatModelResult(
            metadata=snapshot_metadata,
            risk_score=risk_result.global_risk_score,
            risk_classification=risk_result.risk_classification,
            exposure_level=risk_result.exposure_level,
            tier0_reachable=risk_result.tier0_reachable,
            findings=findings,
            top_fixes=top_fixes,
            primary_kill_path=primary_kill_path,
            blast_radius=round(risk_result.blast_radius, 3),
            time_to_domain_admin=time_to_da,
            detection_surface=detection_surface,
            category_breakdown=category_counts,
        )

    # ============================================================
    # REMEDIATION PRIORITIZATION (DETERMINISTIC)
    # ============================================================

    def _generate_top_fixes(
        self,
        findings: list[Finding],
        risk_result: RiskResult,
    ) -> list[str]:

        prioritized = []

        # 1. Findings on most dangerous path
        if risk_result.most_dangerous_path:
            path_ids = {f.id for f in risk_result.most_dangerous_path.findings}
            prioritized.extend(f for f in findings if f.id in path_ids)

        # 2. Tier-0 findings
        prioritized.extend(
            f for f in findings
            if f.category == FindingCategory.TIER0_EXPOSURE
            and f not in prioritized
        )

        # 3. ADCS findings
        prioritized.extend(
            f for f in findings
            if f.category == FindingCategory.ADCS_ABUSE
            and f not in prioritized
        )

        # 4. CRITICAL severity
        prioritized.extend(
            f for f in findings
            if f.severity == Severity.CRITICAL
            and f not in prioritized
        )

        # 5. HIGH severity
        prioritized.extend(
            f for f in findings
            if f.severity == Severity.HIGH
            and f not in prioritized
        )

        # 6. MEDIUM severity — ensures PRIV/KERB findings are never silently dropped
        prioritized.extend(
            f for f in findings
            if f.severity == Severity.MEDIUM
            and f not in prioritized
        )

        prioritized.sort(
            key=lambda f: (
                f.category.value,
                f.severity.value,
                f.id,
            )
        )

        fixes = []
        for f in prioritized:
            fix = self._extract_primary_fix(f)
            if fix and fix not in fixes:
                fixes.append(fix)
            if len(fixes) >= 10:
                break

        return fixes

    def _extract_primary_fix(self, finding: Finding) -> str:
        if not finding.remediation:
            return f"Address: {finding.title}"

        for line in finding.remediation.strip().split("\n"):
            line = line.strip()
            if not line or line.endswith(":"):
                continue
            line = line.lstrip("0123456789.-• ").strip()
            if line:
                # Cut at sentence boundary if possible, otherwise at word boundary
                if len(line) <= 160:
                    return line
                for punct in (". ", "! ", "? "):
                    idx = line.find(punct)
                    if 0 < idx <= 160:
                        return line[:idx + 1]
                truncated = line[:160]
                last_space = truncated.rfind(" ")
                return truncated[:last_space] + "..." if last_space > 80 else truncated

        return f"Address: {finding.title}"

    # ============================================================
    # TIME TO DOMAIN ADMIN
    # ============================================================

    def _compute_time_to_domain_admin(self, risk_result: RiskResult) -> str:
        """
        Estimate realistic time-to-domain-admin based on the most dangerous
        path category and hop count.
        """
        path = risk_result.most_dangerous_path
        if not path:
            return "Undetermined"

        hops = risk_result.shortest_tier0_path_hops
        cat = path.primary_category

        if cat == FindingCategory.ADCS_ABUSE:
            return "< 1 hour"
        if cat == FindingCategory.TIER0_EXPOSURE:
            return "< 30 minutes" if (hops and hops <= 2) else "< 2 hours"
        if cat == FindingCategory.DELEGATION_ABUSE:
            return "2–8 hours"
        if cat == FindingCategory.KERBEROS_ABUSE:
            return "Hours to days (depends on password strength)"
        if cat == FindingCategory.PRIVILEGE_EXPOSURE:
            return "Hours to days (requires credential access)"
        return "Undetermined"

    # ============================================================
    # DETECTION SURFACE
    # ============================================================

    def _compute_detection_surface(self, findings: list[Finding]) -> str:
        """
        Summarise the detection surface as a human-readable string
        based on what categories of findings were detected.
        """
        cats = {f.category for f in findings}
        labels = []

        if FindingCategory.TIER0_EXPOSURE in cats:
            labels.append("direct Tier-0 path")
        if FindingCategory.DELEGATION_ABUSE in cats:
            labels.append("delegation abuse")
        if FindingCategory.KERBEROS_ABUSE in cats:
            labels.append("Kerberos attack surface")
        if FindingCategory.PRIVILEGE_EXPOSURE in cats:
            labels.append("orphaned/over-privileged accounts")
        if FindingCategory.ADCS_ABUSE in cats:
            labels.append("ADCS misconfiguration")

        if not labels:
            return "None detected"

        return ", ".join(labels).capitalize()

    # ============================================================
    # PRIMARY KILL PATH
    # ============================================================

    def _format_primary_kill_path(
        self,
        risk_result: RiskResult,
    ) -> Optional[KillPath]:

        path = risk_result.most_dangerous_path
        if not path:
            return None

        nodes: list[str] = []
        techniques: list[str] = []

        for finding in path.findings:
            data = self._get_raw_data(finding)

            # ── TIER0_EXPOSURE findings (category_e) ──────────────
            # Keys: start_user_sid, path_hops[{from, to, technique}], end_tier0_sid
            if "start_user_sid" in data or "path_hops" in data:
                start = data.get("start_user_sid")
                if start and start not in nodes:
                    nodes.append(self._resolve_sid(start))

                for hop in data.get("path_hops", []):
                    target = hop.get("to")
                    if target and target not in nodes:
                        nodes.append(self._resolve_sid(target))
                    tech = hop.get("technique")
                    if tech:
                        techniques.append(tech)

                tier0 = data.get("end_tier0_sid")
                if tier0:
                    resolved = self._resolve_sid(tier0)
                    if resolved not in nodes:
                        nodes.append(resolved)

            # ── DELEGATION findings (category_c) ──────────────────
            # Keys: computer_sid, computer_name
            # Enrich: find a source user and a Tier-0 target from the graph
            elif "computer_sid" in data:
                comp_sid = data["computer_sid"]
                comp_name = data.get("computer_name") or self._resolve_sid(comp_sid)

                # 1. Find a non-tier0 user who can reach this computer (AdminTo or similar)
                source_name = None
                try:
                    for edge in self.view.get_incoming_edges(comp_sid):
                        principal = (
                            self.view.get_user(edge.source)
                            or self.view.get_computer(edge.source)
                        )
                        if principal and not self.view.is_tier0(edge.source):
                            source_name = principal.sam_account_name
                            break
                except Exception:
                    pass

                # 2. Find a Tier-0 target reachable from this computer
                tier0_name = None
                try:
                    for edge in self.view.get_outgoing_edges(comp_sid):
                        if self.view.is_tier0(edge.target):
                            t = self.view.get_node(edge.target)
                            if t:
                                tier0_name = t.sam_account_name
                                break
                    # fallback: prefer well-known Tier-0 groups over arbitrary admin_count groups
                    if not tier0_name:
                        PREFERRED = {
                            "DOMAIN ADMINS", "ENTERPRISE ADMINS",
                            "ADMINISTRATORS", "SCHEMA ADMINS",
                            "DOMAIN CONTROLLERS",
                        }
                        groups = self.view.get_tier0_groups()
                        # try well-known first
                        for g in groups:
                            if g.sam_account_name.upper() in PREFERRED:
                                tier0_name = g.sam_account_name
                                break
                        # fall back to first available
                        if not tier0_name and groups:
                            tier0_name = groups[0].sam_account_name
                except Exception:
                    pass

                if source_name and source_name not in nodes:
                    nodes.append(source_name)
                if comp_name and comp_name not in nodes:
                    nodes.append(comp_name)
                if tier0_name and tier0_name not in nodes:
                    nodes.append(tier0_name)

                techniques.append("Unconstrained Delegation")

            # ── KERBEROS / PRIVILEGE findings (category_a/b) ──────
            # Keys: user_sid, user_name, optionally target_sid
            elif "user_sid" in data:
                user = data.get("user_name") or self._resolve_sid(data["user_sid"])
                if user and user not in nodes:
                    nodes.append(user)
                target_sid = data.get("target_sid")
                if target_sid:
                    resolved = self._resolve_sid(target_sid)
                    if resolved not in nodes:
                        nodes.append(resolved)

            if finding.mitre_techniques:
                techniques.extend(finding.mitre_techniques)

        techniques = list(dict.fromkeys(techniques))

        # estimated time — based on category of most dangerous path + hop count
        hops = risk_result.shortest_tier0_path_hops
        most_dangerous = risk_result.most_dangerous_path
        primary_cat = most_dangerous.primary_category if most_dangerous else None

        if hops is None:
            estimated_time = "Unknown"
        elif primary_cat == FindingCategory.TIER0_EXPOSURE and hops <= 2:
            # Directly traced short path — fast exploitation
            estimated_time = "Minutes"
        elif primary_cat == FindingCategory.DELEGATION_ABUSE:
            # Requires coercion + capturing TGT — moderate effort
            estimated_time = "Hours"
        else:
            # PRIV/KERB paths require password cracking or spray — more time
            estimated_time = "Hours" if hops <= 3 else "Days"

        # stealth level (derived from exposure level — presentation only)
        stealth_map = {
            ExposureLevel.CATASTROPHIC: "Low",
            ExposureLevel.DOMAIN_WIDE: "Medium",
            ExposureLevel.LOCALIZED: "High",
            ExposureLevel.CONTAINED: "Very High",
        }

        stealth_level = stealth_map.get(
            risk_result.exposure_level,
            "Unknown",
        )

        if not nodes:

            # try to extract affected principals
            for finding in path.findings:
                if finding.affected_principals:
                    nodes = [
                        self._resolve_sid(p)
                        for p in list(finding.affected_principals)[:2]
                    ]
                    break

            if not nodes:
                nodes = ["Tier-0 Exposure"]

        return KillPath(
            nodes=nodes,
            techniques=techniques,
            estimated_time=estimated_time,
            stealth_level=stealth_level,
        )

    # ============================================================
    # MITRE EXTRACTION
    # ============================================================

    def _extract_mitre_techniques(
        self,
        findings: list[Finding],
    ) -> list[str]:

        techniques = set()
        for f in findings:
            if f.mitre_techniques:
                techniques.update(f.mitre_techniques)

        return sorted(techniques)

    # ============================================================
    # STATISTICS
    # ============================================================

    CATEGORY_LABELS = {
        "A": "privilege_exposure",
        "B": "kerberos_abuse",
        "C": "delegation_abuse",
        "D": "adcs_abuse",
        "E": "tier0_exposure",
    }

    def _compute_finding_counts(
        self,
        findings: list[Finding],
    ) -> tuple[dict[str, int], dict[str, int]]:

        category_counts = {}
        severity_counts = {}

        for f in findings:
            raw = f.category.value
            label = self.CATEGORY_LABELS.get(raw, raw)
            category_counts[label] = (
                category_counts.get(label, 0) + 1
            )
            severity_counts[f.severity.value] = (
                severity_counts.get(f.severity.value, 0) + 1
            )

        return category_counts, severity_counts

    # ============================================================
    # SAFE ACCESS
    # ============================================================

    def _get_raw_data(self, finding: Finding) -> dict:
        evidence = getattr(finding, "evidence", None)
        if not evidence:
            return {}
        return getattr(evidence, "raw_data", {}) or {}
    
    def _resolve_sid(self, sid: str) -> str:
        """
        Resolve SID → readable name using cached lookup.
        """

        if not sid:
            return sid

        if not sid.startswith("S-1-"):
            return sid

        return self._sid_lookup.get(sid.upper(), sid)