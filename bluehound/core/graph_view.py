"""
BlueHound GraphView Layer

Provides a cached, typed, read-only view over the Neo4j graph.

This layer isolates all graph complexity from detection modules.
Detection engines should ONLY use GraphView APIs.
"""

from __future__ import annotations

import logging
from typing import Optional, Dict, List

from bluehound.core.graph import GraphConnector
from bluehound.core.types import (
    ADUser,
    ADComputer,
    ADGroup,
    Edge,
    ACE,
)

# ============================================================
# Tier-0 Constants
# ============================================================

TIER0_GROUP_NAMES = {
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "DOMAIN CONTROLLERS",
    "SCHEMA ADMINS",
    "BACKUP OPERATORS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
}


# ============================================================
# GraphView
# ============================================================

class GraphView:
    """
    Cached, typed read-only view of Active Directory graph.

    Purpose:
    - Load graph once
    - Convert to typed models
    - Provide O(1) lookups
    - Shield detection layer from Neo4j
    """

    def __init__(self, graph_connector: GraphConnector):
        self.graph = graph_connector
        self.logger = logging.getLogger(__name__)

        self._users: Dict[str, ADUser] = {}
        self._computers: Dict[str, ADComputer] = {}
        self._groups: Dict[str, ADGroup] = {}

        self._outgoing_edges: Dict[str, List[Edge]] = {}
        self._incoming_edges: Dict[str, List[Edge]] = {}

        self._tier0_sids: set[str] = set()
        self._loaded = False

    # ========================================================
    # Internal Helpers
    # ========================================================

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            raise RuntimeError("GraphView not loaded. Call load() first.")

    # ========================================================
    # Load
    # ========================================================

    def load(self) -> None:
        if self._loaded:
            self.logger.warning("GraphView already loaded.")
            return

        self.logger.info("Loading graph into GraphView...")

        # Users
        for node in self.graph.get_all_users():
            if not node.id:
                self.logger.warning("Skipping User node with null objectid")
                continue
            user = ADUser.from_node(node)
            self._users[user.sid] = user

        # Computers
        for node in self.graph.get_all_computers():
            if not node.id:
                self.logger.warning("Skipping Computer node with null objectid")
                continue
            comp = ADComputer.from_node(node)
            self._computers[comp.sid] = comp

        # Groups
        for node in self.graph.get_all_groups():
            if not node.id:
                self.logger.warning("Skipping Group node with null objectid")
                continue
            group = ADGroup.from_node(node)
            self._groups[group.sid] = group

        self._load_relationships()
        self._populate_group_memberships()
        self._identify_tier0()

        self._loaded = True

        self.logger.info(
            "GraphView loaded: users=%d computers=%d groups=%d",
            len(self._users),
            len(self._computers),
            len(self._groups),
        )

    # ========================================================
    # Relationship Loading
    # ========================================================

    def _load_relationships(self) -> None:
        cypher = """
        MATCH (s)-[r]->(t)
        RETURN s.objectid AS source,
               t.objectid AS target,
               type(r) AS rel_type,
               properties(r) AS properties
        """

        results = self.graph.run_read_query(cypher)

        for r in results:
            if not r.get("source") or not r.get("target"):
                continue

            edge = Edge(
                source=r["source"],
                target=r["target"],
                relationship_type=r["rel_type"],
                properties=r.get("properties", {}),
            )

            self._outgoing_edges.setdefault(edge.source, []).append(edge)
            self._incoming_edges.setdefault(edge.target, []).append(edge)

    def _populate_group_memberships(self) -> None:
        """Populate direct user group memberships from MemberOf edges."""
        for user in self._users.values():
            groups = [
                e.target
                for e in self._outgoing_edges.get(user.sid, [])
                if e.relationship_type == "MemberOf"
            ]
            user.group_memberships = groups

    # ========================================================
    # Tier-0 Classification
    # ========================================================

    def _identify_tier0(self) -> None:
        self._tier0_sids.clear()

        for group in self._groups.values():
            name = group.sam_account_name.upper()
            if name in TIER0_GROUP_NAMES or group.admin_count > 0:
                self._tier0_sids.add(group.sid)

        for user in self._users.values():
            if user.admin_count > 0:
                self._tier0_sids.add(user.sid)

            if any(g in self._tier0_sids for g in user.group_memberships):
                self._tier0_sids.add(user.sid)

        for comp in self._computers.values():
            if comp.admin_count > 0:
                self._tier0_sids.add(comp.sid)

    # ========================================================
    # Entity Access
    # ========================================================

    def get_users(self) -> list[ADUser]:
        self._ensure_loaded()
        return list(self._users.values())

    def get_computers(self) -> list[ADComputer]:
        self._ensure_loaded()
        return list(self._computers.values())

    def get_groups(self) -> list[ADGroup]:
        self._ensure_loaded()
        return list(self._groups.values())

    def get_user(self, sid: str) -> Optional[ADUser]:
        self._ensure_loaded()
        return self._users.get(sid)

    def get_computer(self, sid: str) -> Optional[ADComputer]:
        self._ensure_loaded()
        return self._computers.get(sid)

    def get_group(self, sid: str) -> Optional[ADGroup]:
        self._ensure_loaded()
        return self._groups.get(sid)

    def get_node(self, sid: str):
        self._ensure_loaded()
        return self._users.get(sid) or self._computers.get(sid) or self._groups.get(sid)

    # ========================================================
    # Tier-0 Public API
    # ========================================================

    def is_tier0(self, sid: str) -> bool:
        self._ensure_loaded()
        return sid in self._tier0_sids

    def get_tier0_groups(self) -> list[ADGroup]:
        self._ensure_loaded()
        return [self._groups[s] for s in self._tier0_sids if s in self._groups]

    def get_tier0_assets(self) -> dict[str, list[str]]:
        self._ensure_loaded()
        return {
            "users": [s for s in self._tier0_sids if s in self._users],
            "computers": [s for s in self._tier0_sids if s in self._computers],
            "groups": [s for s in self._tier0_sids if s in self._groups],
        }

    # ========================================================
    # Relationship Traversal
    # ========================================================

    def get_outgoing_edges(self, sid: str, relationship_type: Optional[str] = None):
        self._ensure_loaded()
        edges = self._outgoing_edges.get(sid, [])
        if relationship_type:
            return [e for e in edges if e.relationship_type == relationship_type]
        return edges

    def get_incoming_edges(self, sid: str, relationship_type: Optional[str] = None):
        self._ensure_loaded()
        edges = self._incoming_edges.get(sid, [])
        if relationship_type:
            return [e for e in edges if e.relationship_type == relationship_type]
        return edges

    def get_group_members(self, group_sid: str) -> list[str]:
        return [e.source for e in self.get_incoming_edges(group_sid, "MemberOf")]

    def get_user_groups(self, user_sid: str) -> list[str]:
        return [e.target for e in self.get_outgoing_edges(user_sid, "MemberOf")]

    def get_admin_computers(self, principal_sid: str) -> list[str]:
        return [e.target for e in self.get_outgoing_edges(principal_sid, "AdminTo")]

    # ========================================================
    # ACL Helpers
    # ========================================================

    def get_aces_on_target(self, target_sid: str, dangerous_only: bool = False):
        aces = []
        for edge in self.get_incoming_edges(target_sid):
            ace = ACE.from_edge(edge)
            if dangerous_only and not ace.is_dangerous():
                continue
            aces.append(ace)
        return aces

    def get_principals_with_right(self, target_sid: str, right_name: str):
        return [e.source for e in self.get_incoming_edges(target_sid, right_name)]

    # ========================================================
    # Stats / Metadata
    # ========================================================

    def get_statistics(self) -> dict:
        self._ensure_loaded()
        total_edges = sum(len(v) for v in self._outgoing_edges.values())
        return {
            "users": len(self._users),
            "computers": len(self._computers),
            "groups": len(self._groups),
            "relationships": total_edges,
            "tier0_assets": len(self._tier0_sids),
        }

    def get_domain_info(self) -> dict:
        return self.graph.get_domain_info()
