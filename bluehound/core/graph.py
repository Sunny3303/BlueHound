"""
BlueHound Neo4j Graph Abstraction Layer

Controlled interface for interacting with the BloodHound Neo4j database.
Provides safe graph access, strict query enforcement, and domain object conversion.

Responsibilities:
- Neo4j connection lifecycle management and context handling
- Safe read-only Cypher execution with retry logic
- Explicit, ingestion-only write query execution (disabled by default)
- Convert query results to BlueHound Node and Edge objects
- Domain graph retrieval helpers (users, groups, computers, relationships, metadata)
- Large result monitoring and structured logging

Security Guarantees:
- Read-only access enforced by default
- Write operations blocked unless explicitly enabled
- Cypher write keyword detection via strict regex filtering
- Separate READ and WRITE session enforcement
- Relationship integrity validation before Edge creation
- Transient error retry handling
- No raw Neo4j driver or record objects exposed
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional, Any, Dict, List

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import Neo4jError, ServiceUnavailable, TransientError

from bluehound.core.types import Node, Edge


class GraphConnector:
    """
    Read-only Neo4j connector for BloodHound graph.

    All Cypher queries must pass through this class.
    """

    # Strict word-boundary keyword detection
    WRITE_PATTERN = re.compile(
        r"\b(CREATE|MERGE|DELETE|SET|REMOVE|DETACH|DROP)\b",
        re.IGNORECASE,
    )

    MAX_RETRIES = 3
    RETRY_DELAY = 0.5  # seconds
    LARGE_RESULT_WARNING = 50000

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        max_pool_size: int = 50,
        connection_timeout: int = 30,
    ) -> None:
        self.uri = uri
        self.username = username
        self.password = password
        self.driver: Optional[Driver] = None

        self.max_pool_size = max_pool_size
        self.connection_timeout = connection_timeout

        self.logger = logging.getLogger("bluehound.graph")

        # =========================================================
        # WRITE GUARD (INGESTION CONTROL)
        # =========================================================
        self._write_enabled = False

    # =========================================================
    # WRITE MODE CONTROL (INGESTION ONLY)
    # =========================================================

    def enable_writes(self) -> None:
        """Enable write mode (ingestion only)."""
        self._write_enabled = True

    def disable_writes(self) -> None:
        """Disable write mode."""
        self._write_enabled = False

    def run_write_query(self, cypher: str, parameters: Optional[dict] = None) -> list[dict]:
        """
        Execute write query.

        Only allowed during ingestion.
        """
        if not self.driver:
            raise RuntimeError("Not connected to Neo4j")

        if not self._write_enabled:
            raise RuntimeError("Write operations disabled outside ingestion")

        with self.driver.session(default_access_mode="WRITE") as session:
            result = session.run(cypher, parameters or {})
            return [record.data() for record in result]
        
    # =========================================================
    # Connection Lifecycle
    # =========================================================

    def connect(self) -> None:
        """Establish Neo4j connection."""
        if self.driver:
            return

        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_pool_size=self.max_pool_size,
                connection_timeout=self.connection_timeout,
                max_connection_lifetime=3600,
            )
            self.driver.verify_connectivity()
            self.logger.info("Connected to Neo4j: %s", self.uri)
            
            # Create performance indexes
            from bluehound.core.indexes import create_indexes
            with self.driver.session() as session:
                create_indexes(session)

        except Exception as exc:
            self.logger.error("Neo4j connection failed: %s", exc)
            raise RuntimeError("Failed to connect to Neo4j") from exc

    def disconnect(self) -> None:
        """Close connection safely."""
        if self.driver:
            self.driver.close()
            self.driver = None
            self.logger.info("Neo4j connection closed")

    def _ensure_connected(self) -> None:
        if not self.driver:
            raise RuntimeError("Neo4j not connected. Call connect().")

    # =========================================================
    # Query Safety
    # =========================================================

    def _validate_read_only(self, cypher: str) -> None:
        """Prevent write operations."""
        if self.WRITE_PATTERN.search(cypher):
            raise RuntimeError("Write operations are not allowed")

    # =========================================================
    # Query Execution
    # =========================================================

    def run_read_query(
        self,
        cypher: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute safe read-only query with retry logic."""
        self._ensure_connected()
        self._validate_read_only(cypher)

        last_error = None

        for attempt in range(self.MAX_RETRIES):
            try:
                with self.driver.session(default_access_mode="READ") as session:
                    result = session.run(cypher, parameters or {})
                    data = [record.data() for record in result]

                    if len(data) > self.LARGE_RESULT_WARNING:
                        self.logger.warning(
                            "Large result set returned: %d records", len(data)
                        )

                    return data

            except (ServiceUnavailable, TransientError) as exc:
                last_error = exc
                self.logger.warning("Transient Neo4j error, retrying...")
                time.sleep(self.RETRY_DELAY)

            except Neo4jError as exc:
                self.logger.error("Cypher error: %s", exc)
                raise RuntimeError("Neo4j query failed") from exc

        raise RuntimeError("Neo4j query failed after retries") from last_error

    # =========================================================
    # Record Conversion
    # =========================================================

    @staticmethod
    def _record_to_node(record: Dict[str, Any]) -> Node:
        return Node(
            id=record["id"],
            labels=record["labels"],
            properties=record["properties"],
        )

    @staticmethod
    def _record_to_edge(record: Dict[str, Any]) -> Edge:
        if not record["source"] or not record["target"]:
            raise RuntimeError("Relationship contains null objectid")

        return Edge(
            source=record["source"],
            target=record["target"],
            relationship_type=record["rel_type"],
            properties=record["properties"],
        )

    # =========================================================
    # Node Retrieval
    # =========================================================

    def get_all_users(self) -> List[Node]:
        cypher = """
        MATCH (u:User)
        RETURN u.objectid AS id, labels(u) AS labels, properties(u) AS properties
        """
        return [self._record_to_node(r) for r in self.run_read_query(cypher)]

    def get_all_computers(self) -> List[Node]:
        cypher = """
        MATCH (c:Computer)
        RETURN c.objectid AS id, labels(c) AS labels, properties(c) AS properties
        """
        return [self._record_to_node(r) for r in self.run_read_query(cypher)]

    def get_all_groups(self) -> List[Node]:
        cypher = """
        MATCH (g:Group)
        RETURN g.objectid AS id, labels(g) AS labels, properties(g) AS properties
        """
        return [self._record_to_node(r) for r in self.run_read_query(cypher)]

    def get_node_by_sid(self, sid: str) -> Optional[Node]:
        cypher = """
        MATCH (n {objectid: $sid})
        RETURN n.objectid AS id, labels(n) AS labels, properties(n) AS properties
        LIMIT 1
        """
        results = self.run_read_query(cypher, {"sid": sid})
        return self._record_to_node(results[0]) if results else None

    # =========================================================
    # Relationships
    # =========================================================

    def get_relationships_from_node(
        self,
        sid: str,
        relationship_type: Optional[str] = None,
    ) -> List[Edge]:

        if relationship_type:
            cypher = """
            MATCH (s {objectid:$sid})-[r]->(t)
            WHERE type(r)=$rel
            RETURN s.objectid AS source,
                   t.objectid AS target,
                   type(r) AS rel_type,
                   properties(r) AS properties
            """
            params = {"sid": sid, "rel": relationship_type}
        else:
            cypher = """
            MATCH (s {objectid:$sid})-[r]->(t)
            RETURN s.objectid AS source,
                   t.objectid AS target,
                   type(r) AS rel_type,
                   properties(r) AS properties
            """
            params = {"sid": sid}

        return [self._record_to_edge(r) for r in self.run_read_query(cypher, params)]

    def get_relationships_to_node(
        self,
        sid: str,
        relationship_type: Optional[str] = None,
    ) -> List[Edge]:

        if relationship_type:
            cypher = """
            MATCH (s)-[r]->(t {objectid:$sid})
            WHERE type(r)=$rel
            RETURN s.objectid AS source,
                   t.objectid AS target,
                   type(r) AS rel_type,
                   properties(r) AS properties
            """
            params = {"sid": sid, "rel": relationship_type}
        else:
            cypher = """
            MATCH (s)-[r]->(t {objectid:$sid})
            RETURN s.objectid AS source,
                   t.objectid AS target,
                   type(r) AS rel_type,
                   properties(r) AS properties
            """
            params = {"sid": sid}

        return [self._record_to_edge(r) for r in self.run_read_query(cypher, params)]

    # =========================================================
    # Domain Info
    # =========================================================

    def get_domain_info(self) -> Dict[str, Any]:
        cypher = "MATCH (d:Domain) RETURN properties(d) AS props"
        results = self.run_read_query(cypher)

        if not results:
            return {}

        if len(results) > 1:
            self.logger.warning("Multiple domains detected")

        props = results[0]["props"]

        return {
            "fqdn": props.get("name", "UNKNOWN"),
            "functional_level": props.get("functionallevel", "UNKNOWN"),
            "objectid": props.get("objectid", ""),
        }

    # =========================================================
    # Context Manager
    # =========================================================

    def __enter__(self) -> "GraphConnector":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
