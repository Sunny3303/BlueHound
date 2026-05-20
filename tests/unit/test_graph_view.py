import pytest
from unittest.mock import Mock

from bluehound.core.graph_view import GraphView
from bluehound.core.types import Node


def create_mock_graph():
    g = Mock()

    g.get_all_users.return_value = [
        Node(
            id="U1",
            labels=["User"],
            properties={
                "samaccountname": "user1",
                "enabled": True,
            },
        )
    ]

    g.get_all_computers.return_value = [
        Node(
            id="C1",
            labels=["Computer"],
            properties={"samaccountname": "WS01$"},
        )
    ]

    g.get_all_groups.return_value = [
        Node(
            id="G1",
            labels=["Group"],
            properties={
                "samaccountname": "Domain Admins",
                "admincount": 1,
            },
        )
    ]

    g.run_read_query.return_value = [
        {
            "source": "U1",
            "target": "G1",
            "rel_type": "MemberOf",
            "properties": {},
        }
    ]

    g.get_domain_info.return_value = {"fqdn": "TEST.LOCAL"}

    return g


def test_load():
    g = create_mock_graph()
    view = GraphView(g)
    view.load()

    assert len(view.get_users()) == 1
    assert len(view.get_groups()) == 1


def test_tier0():
    g = create_mock_graph()
    view = GraphView(g)
    view.load()

    assert view.is_tier0("G1")


def test_edges():
    g = create_mock_graph()
    view = GraphView(g)
    view.load()

    out_edges = view.get_outgoing_edges("U1")
    assert len(out_edges) == 1


def test_requires_load():
    g = create_mock_graph()
    view = GraphView(g)

    with pytest.raises(RuntimeError):
        view.get_users()


def test_statistics():
    g = create_mock_graph()
    view = GraphView(g)
    view.load()

    stats = view.get_statistics()
    assert stats["users"] == 1

