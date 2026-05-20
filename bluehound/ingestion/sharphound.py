from __future__ import annotations

import json
import zipfile
import hashlib
import logging
import re

from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Iterable

from bluehound.core.types import SnapshotMetadata
from bluehound.core.graph import GraphConnector

logger = logging.getLogger(__name__)

# ============================================================
# CONSTANTS
# ============================================================

SID_PATTERN = re.compile(r"^S-1-\d+(-\d+)+$")

ALLOWED_REL_TYPES = {
    "GenericAll",
    "WriteDACL",
    "WriteOwner",
    "GenericWrite",
    "AddMember",
    "ForceChangePassword",
    "MemberOf",
    "AdminTo",
    "HasSession",
}

# ============================================================
# UTILITIES
# ============================================================

def normalize_sid(sid: str) -> str:
    if not sid:
        raise ValueError("Empty SID")
    sid = sid.upper().strip()
    if "-S-1-" in sid and not sid.startswith("S-1-"):
        sid = sid[sid.index("S-1-"):]
    if not SID_PATTERN.match(sid):
        raise ValueError(f"Invalid SID format: {sid}")
    return sid


def extract_domain_from_dn(dn: str) -> str:
    parts = dn.split(",")
    dcs = [p.split("=")[1] for p in parts if p.upper().startswith("DC=")]
    return ".".join(dcs).upper() if dcs else "UNKNOWN.LOCAL"


def timestamp_to_datetime(ts: int) -> Optional[datetime]:
    return None if not ts else datetime.fromtimestamp(ts, tz=timezone.utc)


def _normalize_sid_recursive(value):
    """Normalize SIDs anywhere in nested structures."""
    if isinstance(value, dict):
        return {k: _normalize_sid_recursive(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_sid_recursive(v) for v in value]
    if isinstance(value, str) and value.upper().startswith("S-1-"):
        return normalize_sid(value)
    return value


# ============================================================
# INGESTER
# ============================================================

class SharpHoundIngester:

    def __init__(self, graph: GraphConnector):
        self.graph = graph
        self.stats = {
            "users": 0,
            "computers": 0,
            "groups": 0,
            "domains": 0,
            "containers": 0,
            "ous": 0,
            "gpos": 0,
            "relationships": 0,
        }

    # --------------------------------------------------------
    # Neo4j property sanitizer
    # --------------------------------------------------------

    def _sanitize_properties(self, props: dict) -> dict:
        """
        Neo4j allows only:
        - primitives (str/int/float/bool/None)
        - lists of primitives

        Removes nested dicts or lists of objects.
        Keeps ingestion safe without altering raw data.
        """
        clean = {}

        for k, v in props.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                clean[k] = v
            elif isinstance(v, list):
                if all(isinstance(i, (str, int, float, bool)) for i in v):
                    clean[k] = v
            # silently skip complex structures

        return clean
    
    # --------------------------------------------------------

    def ingest_zip(self, zip_path: Path) -> SnapshotMetadata:

        if not zip_path.exists():
            raise FileNotFoundError(zip_path)

        with open(zip_path, "rb") as f:
            signature = hashlib.sha256(f.read()).hexdigest()

        with zipfile.ZipFile(zip_path) as zf:
            raw = self._read_all_json(zf)

        domain = self._extract_domain_from_domains(raw["domains"])

        parsed = {
            "users": self._parse_entities(raw["users"]),
            "computers": self._parse_entities(raw["computers"]),
            "groups": self._parse_entities(raw["groups"]),
            "domains": self._parse_entities(raw["domains"]),
            "containers": self._parse_entities(raw["containers"]),
            "ous": self._parse_entities(raw["ous"]),
            "gpos": self._parse_entities(raw["gpos"]),
        }

        self.graph.enable_writes()
        try:
            self._ensure_indexes()

            LABEL_MAP = {
                "users": "User",
                "computers": "Computer",
                "groups": "Group",
                "domains": "Domain",
                "containers": "Container",
                "ous": "OU",
                "gpos": "GPO",
            }
            for label, nodes in parsed.items():
                neo4j_label = LABEL_MAP.get(label, label.capitalize())
                self.stats[label] = self._load_nodes(neo4j_label, nodes)

            rels = self._extract_relationships(raw)
            self.stats["relationships"] = self._load_relationships(rels)

        finally:
            self.graph.disable_writes()

        return SnapshotMetadata(
            version="1.0.0",
            collected_at=datetime.now(timezone.utc),
            domain_fqdn=domain,
            collector="sharphound",
            signature=signature,
        )

    # --------------------------------------------------------
    # JSON READING
    # --------------------------------------------------------

    def _read_all_json(self, zf: zipfile.ZipFile) -> dict:
        result = {}
        for key in ["users", "computers", "groups", "domains", "containers", "ous", "gpos"]:
            result[key] = self._read_json_by_keyword(zf, key)
        return result

    def _read_json_by_keyword(self, zf, keyword):
        for name in zf.namelist():
            if keyword in name.lower():
                return json.loads(zf.read(name))
        return {"data": []}

    # --------------------------------------------------------
    # ENTITY PARSING
    # --------------------------------------------------------

    def _parse_entities(self, dataset: dict) -> list[dict]:
        entities = []
        for obj in dataset.get("data", []):
            normalized_obj = _normalize_sid_recursive(obj)
            props = obj.get("Properties", {}) or {}

            detection_flags = {
                # Universal
                "bh_enabled": bool(props.get("enabled", True)),
                "bh_admincount": bool(props.get("admincount", 0)),

                # User-related
                "bh_has_spn": bool(props.get("hasspn", False)),
                "bh_dontreqpreauth": bool(props.get("dontreqpreauth", False)),

                # Computer-related
                "bh_unconstrained_delegation": bool(
                    props.get("unconstraineddelegation", False)
                ),
                "bh_trusted_to_auth": bool(props.get("trustedtoauth", False)),
            }

            merged_props = {**props, **detection_flags}
            entities.append({
                "objectid": normalized_obj.get("ObjectIdentifier"),
                "properties": self._sanitize_properties(merged_props),
                "raw": json.dumps(
                    _normalize_sid_recursive(obj),
                    default=str,
                )
            })
        return entities

    # --------------------------------------------------------
    # NODE LOADING
    # --------------------------------------------------------

    def _load_nodes(self, label: str, nodes: Iterable[dict]) -> int:
        # Filter null objectids and deduplicate — Neo4j MERGE deduplicates by
        # objectid anyway, so counting inputs would overstate the real node count.
        seen: set = set()
        unique_nodes: list = []
        for n in nodes:
            oid = n.get("objectid")
            if oid and oid not in seen:
                seen.add(oid)
                unique_nodes.append(n)
        nodes = unique_nodes

        if not nodes:
            return 0

        batch_size = 500
        total = 0

        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]

            query = f"""
            UNWIND $nodes AS node
            MERGE (n:{label} {{objectid: node.objectid}})
            SET n += node.properties
            SET n._raw = node.raw
            """

            self.graph.run_write_query(query, {"nodes": batch})
            total += len(batch)

        return total

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    def _extract_relationships(self, raw: dict) -> list[dict]:
        rels = []

        for dataset in raw.values():
            for obj in dataset.get("data", []):
                target = _normalize_sid_recursive(obj.get("ObjectIdentifier"))

                for ace in obj.get("Aces", []):
                    rel_type = ace.get("RightName")
                    if rel_type not in ALLOWED_REL_TYPES:
                        continue

                    rels.append({
                        "source": normalize_sid(ace["PrincipalSID"]),
                        "target": target,
                        "type": rel_type,
                        "properties": {
                            "inherited": ace.get("IsInherited", False)
                        }
                    })

                for member in obj.get("Members", []):
                    rels.append({
                        "source": normalize_sid(member["ObjectIdentifier"]),
                        "target": target,
                        "type": "MemberOf",
                        "properties": {}
                    })

        return rels

    # --------------------------------------------------------

    def _load_relationships(self, rels: list[dict]) -> int:
        total = 0

        for rel in rels:
            query = f"""
            MATCH (a {{objectid:$src}})
            MATCH (b {{objectid:$dst}})
            MERGE (a)-[r:{rel['type']} {{ingested:true}}]->(b)
            SET r += $props
            """

            self.graph.run_write_query(query, {
                "src": rel["source"],
                "dst": rel["target"],
                "props": rel["properties"],
            })
            total += 1

        return total

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    def _extract_domain_from_domains(self, dataset: dict) -> str:
        for obj in dataset.get("data", []):
            dn = obj.get("Properties", {}).get("distinguishedname")
            if dn:
                return extract_domain_from_dn(dn)
        return "UNKNOWN.LOCAL"

    # --------------------------------------------------------
    # INDEXES
    # --------------------------------------------------------

    def _ensure_indexes(self):
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (n:User) ON (n.objectid)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Computer) ON (n.objectid)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Group) ON (n.objectid)",
        ]
        for q in indexes:
            self.graph.run_write_query(q)

    # --------------------------------------------------------

    def clear_graph(self):
        self.graph.enable_writes()
        try:
            self.graph.run_write_query("MATCH (n) DETACH DELETE n")
        finally:
            self.graph.disable_writes()

    # --------------------------------------------------------

    def save_snapshot_metadata(self, metadata: SnapshotMetadata, base: Path) -> Path:
        folder = base / metadata.collected_at.strftime("%Y-%m-%d_%H%M%S")
        folder.mkdir(parents=True, exist_ok=True)

        with open(folder / "metadata.json", "w") as f:
            json.dump({
                "version": metadata.version,
                "collected_at": metadata.collected_at.isoformat(),
                "domain_fqdn": metadata.domain_fqdn,
                "signature": metadata.signature,
                "stats": self.stats,
            }, f, indent=2)

        return folder
