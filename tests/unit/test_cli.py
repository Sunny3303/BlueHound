import pytest
from click.testing import CliRunner
from pathlib import Path
import json
from unittest.mock import patch

from bluehound.cli.main import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "BlueHound" in result.output


def test_ingest_missing_file():
    runner = CliRunner()
    result = runner.invoke(cli, ["ingest", "missing.zip"])
    assert result.exit_code != 0


@patch("bluehound.cli.main.GraphConnector")
def test_ingest_preflight_mock(mock_graph, tmp_path):
    """Ensure ingest runs without real Neo4j connection."""

    fake_zip = tmp_path / "fake.zip"
    fake_zip.write_text("dummy")

    # Mock connector instance
    mock_instance = mock_graph.return_value
    mock_instance.connect.return_value = None
    mock_instance.enable_writes.return_value = None
    mock_instance.disable_writes.return_value = None
    mock_instance.disconnect.return_value = None

    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["ingest", str(fake_zip), "--neo4j-password", "test"],
    )

    # command should execute (may fail later due to fake zip)
    assert result.exit_code != 2



def test_list_snapshots_empty(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["list-snapshots", "--dir", str(tmp_path)])
    assert "Timestamp" in result.output



def test_list_snapshots_with_data(tmp_path):
    snap = tmp_path / "2025-02-11_143022"
    snap.mkdir()

    metadata = {
        "domain_fqdn": "TEST.LOCAL",
        "statistics": {"users": 100, "computers": 50, "groups": 10},
    }

    with open(snap / "metadata.json", "w") as f:
        json.dump(metadata, f)

    runner = CliRunner()
    result = runner.invoke(cli, ["list-snapshots", "--dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "TEST.LOCAL" in result.output


@pytest.mark.skip(reason="analyze command now fully implemented and tested in test_cli_analyze.py")
def test_analyze_stub():
    pass

@pytest.mark.skip(reason="diff command now fully implemented and tested in test_cli_diff.py")
def test_diff_stub(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()

    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(a), str(b)])
    assert "not yet implemented" in result.output.lower()
