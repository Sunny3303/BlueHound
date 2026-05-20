import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

from bluehound.ingestion.adcs import ADCSIngester
from bluehound.core.types import CertificateTemplate


def create_mock_graph():
    g = Mock()
    g.enable_writes = Mock()
    g.disable_writes = Mock()
    g.run_write_query = Mock()
    return g


def test_adcs_ingester_initialization():
    ing = ADCSIngester(create_mock_graph())
    assert ing.stats["templates"] == 0


def test_parse_template():
    ing = ADCSIngester(create_mock_graph())

    t = ing._parse_certificate_template({
        "name": "User",
        "application_policies": ["Client Authentication"],
        "enrollment_permissions":[
            {"principal_sid":"S-1"}
        ]
    })

    assert t.client_authentication is True
    assert "S-1" in t.enrollment_permissions


def test_json_ingestion():
    ing = ADCSIngester(create_mock_graph())

    data = {
        "certificate_templates":[{"name":"User"}],
        "certificate_authorities":[{"name":"CA01"}]
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(data, f)
        path = Path(f.name)

    infra = ing.ingest_adcs_file(path)

    assert len(infra.certificate_templates) == 1
    path.unlink()


def test_template_load():
    graph=create_mock_graph()
    ing=ADCSIngester(graph)

    t=[CertificateTemplate(
        name="User",
        display_name="User",
        oid="",
        schema_version=1,
        enrollee_supplies_subject=False,
        client_authentication=True,
        authorized_signatures_required=0,
        manager_approval_required=False,
        enrollment_permissions=[]
    )]

    assert ing.load_templates_to_neo4j(t)==1
    assert graph.enable_writes.called


def test_missing_principal_safe():
    graph=create_mock_graph()

    def fail(*a,**k):
        raise Exception()

    graph.run_write_query.side_effect=fail

    ing=ADCSIngester(graph)

    t=[CertificateTemplate(
        name="User",
        display_name="User",
        oid="",
        schema_version=1,
        enrollee_supplies_subject=False,
        client_authentication=True,
        enrollment_permissions=["S-X"]
    )]

    assert ing.create_enrollment_relationships(t)==0