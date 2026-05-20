"""
BlueHound Core Type System

Canonical internal data structures for the BlueHound threat modeling engine.

Design Principles:
- Pure data layer (no detection, no risk math, no graph queries)
- Deterministic serialization contract
- Engine-first architecture
- Structured threat modeling output
- Immutable where appropriate
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any, Dict, List
import json


# ============================================================
# Graph Primitives
# ============================================================


@dataclass(slots=True)
class Node:
    """
    Represents a Neo4j graph node.

    NOTE:
    `id` must represent the canonical ObjectIdentifier (e.g., SID, GUID).
    Neo4j internal numeric IDs must NOT be used here.
    """

    id: str
    labels: List[str]
    properties: Dict[str, Any] = field(default_factory=dict)

    def get_property(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)

    def __repr__(self) -> str:
        return f"Node(id={self.id!r}, labels={self.labels!r})"


@dataclass(slots=True)
class Edge:
    """
    Represents a relationship between two graph nodes.
    """

    source: str
    target: str
    relationship_type: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"Edge(source={self.source!r}, "
            f"target={self.target!r}, "
            f"type={self.relationship_type!r})"
        )


# ============================================================
# Snapshot Metadata
# ============================================================


@dataclass(frozen=True, slots=True)
class SnapshotMetadata:
    """
    Immutable metadata for AD snapshot.
    All timestamps must be UTC.
    """

    version: str
    collected_at: datetime
    domain_fqdn: str
    collector: str
    signature: str

    def __post_init__(self) -> None:
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware (UTC)")
        if self.collected_at.tzinfo != timezone.utc:
            raise ValueError("collected_at must use UTC timezone")


# ============================================================
# AD Entity Models
# ============================================================


@dataclass(slots=True)
class ADUser:
    sid: str
    sam_account_name: str
    distinguished_name: str
    enabled: bool
    admin_count: int = 0
    spns: List[str] = field(default_factory=list)
    kerberos_preauth_not_required: bool = False
    group_memberships: List[str] = field(default_factory=list)
    last_logon: Optional[datetime] = None
    password_last_set: Optional[datetime] = None

    @classmethod
    def from_node(cls, node: Node) -> ADUser:
        props = node.properties
        return cls(
            sid=node.id,
            sam_account_name=props.get("samaccountname", ""),
            distinguished_name=props.get("distinguishedname", ""),
            enabled=props.get("enabled", True),
            admin_count=props.get("admincount", 0),
            spns=props.get("serviceprincipalnames", []),
            kerberos_preauth_not_required=props.get("dontreqpreauth", False),
        )


@dataclass(slots=True)
class ADComputer:
    sid: str
    sam_account_name: str
    distinguished_name: str
    enabled: bool
    operating_system: str = ""
    unconstrained_delegation: bool = False
    allowed_to_delegate_to: List[str] = field(default_factory=list)
    admin_count: int = 0

    @classmethod
    def from_node(cls, node: Node) -> ADComputer:
        props = node.properties
        return cls(
            sid=node.id,
            sam_account_name=props.get("samaccountname", ""),
            distinguished_name=props.get("distinguishedname", ""),
            enabled=props.get("enabled", True),
            operating_system=props.get("operatingsystem", ""),
            unconstrained_delegation=props.get("unconstraineddelegation", False),
            admin_count=props.get("admincount", 0),
        )


@dataclass(slots=True)
class ADGroup:
    sid: str
    sam_account_name: str
    distinguished_name: str
    members: List[str] = field(default_factory=list)
    admin_count: int = 0

    @classmethod
    def from_node(cls, node: Node) -> ADGroup:
        props = node.properties
        return cls(
            sid=node.id,
            sam_account_name=props.get("samaccountname", ""),
            distinguished_name=props.get("distinguishedname", ""),
            admin_count=props.get("admincount", 0),
        )


# ============================================================
# ACL / Permission Models
# ============================================================


@dataclass(frozen=True, slots=True)
class ACE:
    trustee: str
    right_name: str
    ace_type: str = "Allow"
    inherited: bool = False

    def is_dangerous(self) -> bool:
        dangerous_rights = {
            "GenericAll",
            "WriteDACL",
            "WriteOwner",
            "GenericWrite",
            "AddMember",
            "ForceChangePassword",
        }
        return self.right_name in dangerous_rights and self.ace_type == "Allow"

    @classmethod
    def from_edge(cls, edge: Edge) -> ACE:
        return cls(
            trustee=edge.source,
            right_name=edge.relationship_type,
            inherited=edge.properties.get("isinherited", False),
        )


# ============================================================
# ADCS Models
# ============================================================


@dataclass(slots=True)
class CertificateTemplate:
    name: str
    display_name: str
    oid: str
    schema_version: int
    enrollee_supplies_subject: bool
    client_authentication: bool
    authorized_signatures_required: int = 0
    manager_approval_required: bool = False
    enrollment_permissions: List[str] = field(default_factory=list)

    def is_vulnerable_to_esc1(self) -> bool:
        return (
            self.enrollee_supplies_subject
            and self.client_authentication
            and self.authorized_signatures_required == 0
            and not self.manager_approval_required
        )


@dataclass(slots=True)
class CertificateAuthority:
    name: str
    dns_hostname: str
    web_enrollment_enabled: bool = False
    web_enrollment_url: Optional[str] = None
    templates: List[str] = field(default_factory=list)
    ntlm_allowed: bool = True


@dataclass(slots=True)
class ADCSInfrastructure:
    certificate_authorities: List[CertificateAuthority] = field(default_factory=list)
    certificate_templates: List[CertificateTemplate] = field(default_factory=list)

    def get_template(self, name: str) -> Optional[CertificateTemplate]:
        for template in self.certificate_templates:
            if template.name.lower() == name.lower():
                return template
        return None


# ============================================================
# Detection Output Models
# ============================================================


class FindingCategory(Enum):
    PRIVILEGE_EXPOSURE = "A"
    KERBEROS_ABUSE = "B"
    DELEGATION_ABUSE = "C"
    ADCS_ABUSE = "D"
    TIER0_EXPOSURE = "E"

    def label(self) -> str:
        """Human-readable name for JSON output."""
        return self.name.lower()


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(Enum):
    EXPLICIT = "explicit"
    INFERRED = "inferred"
    POSSIBLE = "possible"


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_type: str
    raw_data: Dict[str, Any]
    reasoning: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.evidence_type,
            "raw_data": self.raw_data,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: Evidence
    affected_principals: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.label(),
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence.to_dict(),
            "affected_principals": self.affected_principals,
            "mitre_techniques": self.mitre_techniques,
            "remediation": self.remediation,
        }


# ============================================================
# Structured Kill Path
# ============================================================


@dataclass(frozen=True, slots=True)
class KillPath:
    nodes: List[str]
    techniques: List[str]
    estimated_time: str
    stealth_level: str

    def __str__(self) -> str:
        return " → ".join(self.nodes)
    
    def __contains__(self, item: str) -> bool:
        return item in str(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "techniques": self.techniques,
            "estimated_time": self.estimated_time,
            "stealth_level": self.stealth_level,
        }


# ============================================================
# Risk & Exposure
# ============================================================


class ExposureLevel(Enum):
    CONTAINED = "contained"
    LOCALIZED = "localized"
    DOMAIN_WIDE = "domain-wide"
    CATASTROPHIC = "catastrophic"


@dataclass(slots=True)
class ThreatModelResult:
    metadata: SnapshotMetadata
    risk_score: float
    exposure_level: ExposureLevel
    tier0_reachable: bool
    findings: List[Finding] = field(default_factory=list)
    top_fixes: List[str] = field(default_factory=list)
    primary_kill_path: Optional[KillPath] = None
    blast_radius: Optional[float] = None
    time_to_domain_admin: Optional[str] = None
    detection_surface: Optional[str] = None
    category_breakdown: Dict[str, int] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)
    risk_classification: str = "UNKNOWN"

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk_score <= 10.0:
            raise ValueError("risk_score must be between 0.0 and 10.0")

    def get_findings_by_category(
        self, category: FindingCategory
    ) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def get_critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "version": self.metadata.version,
                "collected_at": self.metadata.collected_at.isoformat(),
                "domain_fqdn": self.metadata.domain_fqdn,
                "collector": self.metadata.collector,
                "signature": self.metadata.signature,
            },
            "risk_score": self.risk_score,
            "risk_classification": self.risk_classification,
            "exposure_level": self.exposure_level.value,
            "tier0_reachable": self.tier0_reachable,
            "blast_radius": self.blast_radius,
            "time_to_domain_admin": self.time_to_domain_admin,
            "detection_surface": self.detection_surface,
            "category_breakdown": self.category_breakdown,
            "findings": [f.to_dict() for f in self.findings],
            "top_fixes": self.top_fixes,
            "primary_kill_path": (
                self.primary_kill_path.to_dict()
                if self.primary_kill_path
                else None
            ),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatModelResult":
        """
        Reconstruct a ThreatModelResult from a to_dict() / to_json() payload.

        Handles the following architectural realities of this codebase:
        - Evidence is serialised with key "type", not "evidence_type"
        - FindingCategory is serialised via label() (e.g. "privilege_exposure"),
          not by enum value ("A"), so we reverse-map by name
        - KillPath is serialised as a dict and must be reconstructed
        - blast_radius may be a float in the JSON (assembler stores float, field
          type is Optional[str]) — both are accepted
        - Fields that do not exist on this dataclass are silently ignored
        """

        from datetime import datetime

        metadata = SnapshotMetadata(
            version=data["metadata"]["version"],
            collected_at=datetime.fromisoformat(data["metadata"]["collected_at"]),
            domain_fqdn=data["metadata"]["domain_fqdn"],
            collector=data["metadata"]["collector"],
            signature=data["metadata"]["signature"],
        )

        # ── Findings ──────────────────────────────────────────────────────
        findings = []

        for f in data.get("findings", []):

            ev = f["evidence"]

            evidence = Evidence(
                # serialised as "type" by Evidence.to_dict()
                evidence_type=ev.get("type") or ev.get("evidence_type", ""),
                raw_data=ev.get("raw_data", {}),
                reasoning=ev.get("reasoning", ""),
            )

            # category is serialised via label() → "privilege_exposure" etc.
            # Enum values are "A"/"B"/… so we look up by name.
            raw_cat = f["category"]
            try:
                category = FindingCategory[raw_cat.upper()]
            except KeyError:
                # fall back to value lookup for forward compatibility
                category = FindingCategory(raw_cat)

            finding = Finding(
                id=f["id"],
                category=category,
                severity=Severity(f["severity"]),
                confidence=Confidence(f["confidence"]),
                title=f["title"],
                description=f["description"],
                evidence=evidence,
                affected_principals=f.get("affected_principals", []),
                mitre_techniques=f.get("mitre_techniques", []),
                remediation=f.get("remediation", ""),
            )

            findings.append(finding)

        # ── KillPath ──────────────────────────────────────────────────────
        kp_data = data.get("primary_kill_path")
        primary_kill_path: Optional[KillPath] = None

        if isinstance(kp_data, dict):
            primary_kill_path = KillPath(
                nodes=kp_data.get("nodes", []),
                techniques=kp_data.get("techniques", []),
                estimated_time=kp_data.get("estimated_time", "Unknown"),
                stealth_level=kp_data.get("stealth_level", "Unknown"),
            )

        # ── blast_radius — must be float ───────────────────────────
        raw_br = data.get("blast_radius")
        try:
            blast_radius = float(raw_br) if raw_br is not None else None
        except (ValueError, TypeError):
            blast_radius = None   # gracefully handles "Domain-wide" type values

        return cls(
            metadata=metadata,
            risk_score=data["risk_score"],
            exposure_level=ExposureLevel(data["exposure_level"]),
            tier0_reachable=data.get("tier0_reachable", False),
            findings=findings,
            top_fixes=data.get("top_fixes", []),
            primary_kill_path=primary_kill_path,
            blast_radius=blast_radius,
            time_to_domain_admin=data.get("time_to_domain_admin"),
            detection_surface=data.get("detection_surface"),
            category_breakdown=data.get("category_breakdown", {}),
            mitre_techniques=data.get("mitre_techniques", []),
            risk_classification=data.get("risk_classification", "UNKNOWN"),
        )