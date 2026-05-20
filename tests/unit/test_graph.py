import pytest
from unittest.mock import Mock, patch, MagicMock

from bluehound.core.graph import GraphConnector
from bluehound.core.types import Node, Edge


def test_not_connected_error():
    connector = GraphConnector("bolt://x", "u", "p")
    with pytest.raises(RuntimeError):
        connector.run_read_query("MATCH (n) RETURN n")


def test_write_detection_regex():
    connector = GraphConnector("bolt://x", "u", "p")
    connector.driver = Mock()

    with pytest.raises(RuntimeError):
        connector.run_read_query("CREATE (n)")

    # Should NOT trigger
    connector.run_read_query = Mock(return_value=[])
    connector.run_read_query('MATCH (n) RETURN "CREATE USER"')


def test_domain_empty():
    connector = GraphConnector("bolt://x", "u", "p")
    with patch.object(connector, "run_read_query", return_value=[]):
        assert connector.get_domain_info() == {}


def test_relationship_null_sid():
    connector = GraphConnector("bolt://x", "u", "p")

    bad_result = [{
        "source": None,
        "target": "B",
        "rel_type": "MemberOf",
        "properties": {}
    }]

    with patch.object(connector, "run_read_query", return_value=bad_result):
        with pytest.raises(RuntimeError):
            connector.get_relationships_from_node("A")

# =========================================================
# BlueHound Write Guard Security Tests (REQUIRED)
# =========================================================

def test_write_query_blocked_by_default():
    connector = GraphConnector("bolt://x", "u", "p")
    connector.driver = MagicMock()

    with pytest.raises(RuntimeError):
        connector.run_write_query("CREATE (n)")


def test_write_query_allowed_when_enabled():
    connector = GraphConnector("bolt://x", "u", "p")

    mock_session = MagicMock()
    mock_session.run.return_value = []
    mock_session.__enter__.return_value = mock_session

    mock_driver = MagicMock()
    mock_driver.session.return_value = mock_session
    connector.driver = mock_driver

    connector.enable_writes()
    connector.run_write_query("CREATE (n)")


def test_write_query_blocked_after_disable():
    connector = GraphConnector("bolt://x", "u", "p")
    connector.driver = MagicMock()

    connector.enable_writes()
    connector.disable_writes()

    with pytest.raises(RuntimeError):
        connector.run_write_query("CREATE (n)")