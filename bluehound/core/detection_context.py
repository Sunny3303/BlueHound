from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Set

from bluehound.core.graph_view import GraphView
from bluehound.core.types import Edge


class DetectionContext:
    """
    Precomputed intelligence cache for detection engine.

    Built once per analysis run.

    Provides:
    - Fast membership lookup
    - Tier-0 cache
    - ACL indexing
    - Admin relationship lookup

    STRICTLY READ-ONLY after build().
    """

    def __init__(self, view: GraphView):
        self.view = view
        self.logger = logging.getLogger(__name__)

        self._group_membership: Dict[str, Set[str]] = defaultdict(set)
        self._principal_groups: Dict[str, Set[str]] = defaultdict(set)

        self._admin_rights: Dict[str, Set[str]] = defaultdict(set)

        self.admin_to_computers = {}

        self._aces_by_target: Dict[str, List[Edge]] = defaultdict(list)

        self._dangerous_aces_by_principal = {}

        self._tier0_sids: Set[str] = set()

        self._built = False

    def _safe_iter(self, value):
        """
        ENsure iteratble safety for mocked GraphView objects.
        """
        if value is None:
            return []
        
        if isinstance(value, list):
            return value
        
        try:
            return list(value)
        except TypeError:
            return []        


    # =========================================================
    # BUILD
    # =========================================================

    def build(self) -> None:
        if self._built:
            self.logger.warning("DetectionContext already built")
            return

        self.logger.info("Building DetectionContext...")

        self._cache_memberships()
        self._cache_admin_rights()
        self._cache_aces()
        self._cache_tier0()

        self._built = True
        self.logger.info("DetectionContext ready")

    # ---------------------------------------------------------

    def _cache_memberships(self):
        groups = self._safe_iter(self.view.get_groups())

        if not isinstance(groups, list):
            groups = []

        for group in groups:
            members = getattr(group, "group_memberships", []) or []

            for member_sid in members:
                self.membership_cache.setdefault(
                    member_sid, set()
                ).add(group.sid)

    # ---------------------------------------------------------

    def _cache_admin_rights(self):

        users = self._safe_iter(self.view.get_users())
        for user in users:
            comps = self.view.get_admin_computers(user.sid)
            for c in comps:
                self._admin_rights[user.sid].add(c)

        groups = self._safe_iter(self.view.get_groups())
        for group in groups:
            comps = self.view.get_admin_computers(group.sid)
            for c in comps:
                self._admin_rights[group.sid].add(c)
            for principal_sid, computers in self._admin_rights.items():
                self.admin_to_computers[principal_sid] = set(computers)

    # ---------------------------------------------------------

    def _cache_aces(self):

        users = self._safe_iter(self.view.get_users())
        groups = self._safe_iter(self.view.get_groups())
        computers = self._safe_iter(self.view.get_computers())

        all_nodes = users + groups + computers

        for node in all_nodes:
            sid = getattr(node, "sid", None)

            if not sid:
                continue

            edges = self._safe_iter(
                self.view.get_incoming_edges(sid)
            )
            for edge in edges:
                self._aces_by_target[sid].append(edge)

        dangerous_types = {
            "GenericAll",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            }

        for target_sid, edges in self._aces_by_target.items():

            for edge in edges:

                principal = getattr(edge, "source", None)

                if not principal:
                    continue

                if getattr(edge, "relationship", None) in dangerous_types:

                    self._dangerous_aces_by_principal.setdefault(
                        principal, []
                    ).append(edge)

    # ---------------------------------------------------------

    def _cache_tier0(self):
        tier0 = self.view.get_tier0_assets()

        for values in tier0.values():
            self._tier0_sids.update(values)

    # ---------------------------------------------------------

    def _required_build(self):
        if not self._built:
            raise RuntimeError(
                "DetectionContext.build() must be called first."
            )

    # ---------------------------------------------------------

    def get_dangerous_aces_by_principal(self, principal_sid):

        self._required_build()

        return self._dangerous_aces_by_principal.get(principal_sid, [])

    # =========================================================
    # LOOKUPS
    # =========================================================

    def is_tier0(self, sid: str) -> bool:
        self._required_build()
        return sid in self._tier0_sids

    def get_groups_of(self, sid: str) -> Set[str]:
        self._require_build()
        return self._principal_groups.get(sid, set())

    def get_group_members(self, group_sid: str) -> Set[str]:
        self._require_build()
        return self._group_membership.get(group_sid, set())

    def get_admin_targets(self, sid: str) -> Set[str]:
        self._require_build()
        return self._admin_rights.get(sid, set())

    def get_aces(self, target_sid: str) -> List[Edge]:
        self._require_build()
        return self._aces_by_target.get(target_sid, [])
