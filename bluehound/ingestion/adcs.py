"""
BlueHound ADCS Ingestion

Loads Active Directory Certificate Services configuration
into Neo4j for later ESC detection.

NO detection logic occurs here.
"""

from pathlib import Path
from typing import Optional
import json
import yaml
import logging

from bluehound.core.graph import GraphConnector
from bluehound.core.types import (
    CertificateTemplate,
    CertificateAuthority,
    ADCSInfrastructure,
)

logger = logging.getLogger(__name__)


class ADCSIngester:
    """Ingest ADCS configuration into Neo4j"""

    def __init__(self, graph_connector: GraphConnector):
        self.graph = graph_connector
        self.logger = logging.getLogger(__name__)

        self.stats = {
            "templates": 0,
            "cas": 0,
            "enrollment_relationships": 0,
        }

    # --------------------------------------------------
    # FILE INGESTION
    # --------------------------------------------------

    def ingest_adcs_file(self, file_path: Path) -> ADCSInfrastructure:

        if not file_path.exists():
            raise FileNotFoundError(f"ADCS file not found: {file_path}")

        suffix = file_path.suffix.lower()

        with open(file_path, "r", encoding="utf-8") as f:
            if suffix == ".json":
                data = json.load(f)
            elif suffix in [".yaml", ".yml"]:
                data = yaml.safe_load(f)
            else:
                raise ValueError(
                    f"Unsupported file format: {suffix}"
                )

        infra = self.parse_adcs_data(data)

        self.stats["templates"] = self.load_templates_to_neo4j(
            infra.certificate_templates
        )

        self.stats["cas"] = self.load_cas_to_neo4j(
            infra.certificate_authorities
        )

        self.stats[
            "enrollment_relationships"
        ] = self.create_enrollment_relationships(
            infra.certificate_templates
        )

        self.logger.info(f"ADCS ingestion complete: {self.stats}")

        return infra

    # --------------------------------------------------
    # PARSING
    # --------------------------------------------------

    def parse_adcs_data(self, data: dict) -> ADCSInfrastructure:

        templates = [
            self._parse_certificate_template(t)
            for t in data.get("certificate_templates", [])
        ]

        cas = [
            self._parse_certificate_authority(c)
            for c in data.get("certificate_authorities", [])
        ]

        return ADCSInfrastructure(
            certificate_templates=templates,
            certificate_authorities=cas,
        )

    def _parse_certificate_template(
        self, data: dict
    ) -> CertificateTemplate:

        policies = data.get("application_policies", [])

        client_auth = any(
            "Client Authentication" in p
            or "1.3.6.1.5.5.7.3.2" in p
            for p in policies
        )

        enroll_perms = data.get("enrollment_permissions", [])
        enrollable = [
            p.get("principal_sid")
            for p in enroll_perms
            if p.get("principal_sid")
        ]

        return CertificateTemplate(
            name=data["name"],
            display_name=data.get(
                "display_name", data["name"]
            ),
            oid=data.get("oid", ""),
            schema_version=data.get("schema_version", 1),
            enrollee_supplies_subject=data.get(
                "enrollee_supplies_subject", False
            ),
            client_authentication=client_auth,
            authorized_signatures_required=data.get(
                "authorized_signatures_required", 0
            ),
            manager_approval_required=data.get(
                "requires_manager_approval", False
            ),
            enrollment_permissions=enrollable,
        )

    def _parse_certificate_authority(
        self, data: dict
    ) -> CertificateAuthority:

        return CertificateAuthority(
            name=data["name"],
            dns_hostname=data.get("dns_hostname", ""),
            web_enrollment_enabled=data.get(
                "web_enrollment_enabled", False
            ),
            web_enrollment_url=data.get(
                "web_enrollment_url"
            ),
            templates=data.get("templates", []),
            ntlm_allowed=data.get(
                "ntlm_authentication_enabled", True
            ),
        )

    # --------------------------------------------------
    # NEO4J LOADERS
    # --------------------------------------------------

    def load_templates_to_neo4j(
        self,
        templates: list[CertificateTemplate],
    ) -> int:

        if not templates:
            return 0

        self.graph.enable_writes()

        count = 0

        for t in templates:

            cypher = """
            MERGE (ct:CertificateTemplate {name:$name})
            SET ct.display_name=$display_name,
                ct.oid=$oid,
                ct.schema_version=$schema_version,
                ct.bh_enrollee_supplies_subject=$ess,
                ct.bh_requires_manager_approval=$mgr,
                ct.bh_authorized_signatures_required=$sig,
                ct.bh_client_authentication=$client_auth
            """

            self.graph.run_write_query(
                cypher,
                {
                    "name": t.name,
                    "display_name": t.display_name,
                    "oid": t.oid,
                    "schema_version": t.schema_version,
                    "ess": t.enrollee_supplies_subject,
                    "mgr": t.manager_approval_required,
                    "sig": t.authorized_signatures_required,
                    "client_auth": t.client_authentication,
                },
            )

            count += 1

        self.graph.disable_writes()
        return count

    def load_cas_to_neo4j(
        self,
        cas: list[CertificateAuthority],
    ) -> int:

        if not cas:
            return 0

        self.graph.enable_writes()
        count = 0

        for ca in cas:

            self.graph.run_write_query(
                """
                MERGE (ca:CertificateAuthority {name:$name})
                SET ca.dns_hostname=$dns,
                    ca.bh_web_enrollment_enabled=$web,
                    ca.bh_web_enrollment_url=$url,
                    ca.bh_ntlm_authentication_enabled=$ntlm
                """,
                {
                    "name": ca.name,
                    "dns": ca.dns_hostname,
                    "web": ca.web_enrollment_enabled,
                    "url": ca.web_enrollment_url,
                    "ntlm": ca.ntlm_allowed,
                },
            )

            for template in ca.templates:
                self.graph.run_write_query(
                    """
                    MATCH (ca:CertificateAuthority {name:$ca})
                    MATCH (t:CertificateTemplate {name:$t})
                    MERGE (ca)-[:Issues]->(t)
                    """,
                    {"ca": ca.name, "t": template},
                )

            count += 1

        self.graph.disable_writes()
        return count

    # --------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------

    def create_enrollment_relationships(
        self,
        templates: list[CertificateTemplate],
    ) -> int:

        if not templates:
            return 0

        self.graph.enable_writes()

        rel_count = 0

        for template in templates:
            for sid in template.enrollment_permissions:

                try:
                    self.graph.run_write_query(
                        """
                        MATCH (p {objectid:$sid})
                        MATCH (t:CertificateTemplate {name:$t})
                        MERGE (p)-[:CanEnroll]->(t)
                        """,
                        {"sid": sid, "t": template.name},
                    )
                    rel_count += 1

                except Exception:
                    self.logger.warning(
                        f"Principal {sid} missing for template {template.name}"
                    )

        self.graph.disable_writes()
        return rel_count

    # --------------------------------------------------

    def get_adcs_stats(self):
        return self.stats.copy()