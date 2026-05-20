import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from bluehound.cli.main import cli


def test_analyze_command_exists():
    """
    Ensure the analyze command is registered in the CLI.
    """
    runner = CliRunner()

    result = runner.invoke(cli, ["analyze", "--help"])

    assert result.exit_code == 0
    assert "analyze" in result.output.lower()


def test_analyze_missing_snapshot():
    """
    Running analyze with a missing snapshot directory should fail.
    """

    runner = CliRunner()

    result = runner.invoke(cli, ["analyze", "nonexistent"])

    assert result.exit_code != 0


@patch("bluehound.cli.main.GraphConnector")
@patch("bluehound.cli.main.GraphView")
@patch("bluehound.cli.main.DetectionContext")
@patch("bluehound.cli.main.DetectionEngine")
@patch("bluehound.cli.main.RiskEngine")
@patch("bluehound.cli.main.ThreatModelAssembler")
def test_analyze_full_pipeline(
    mock_assembler_cls,
    mock_risk_engine_cls,
    mock_detection_engine_cls,
    mock_context_cls,
    mock_view_cls,
    mock_graph_cls,
    tmp_path,
):
    """
    Test the full analyze pipeline with all major components mocked.
    """

    # -----------------------------------------------------
    # Create fake snapshot directory
    # -----------------------------------------------------

    snapshot_dir = tmp_path / "snapshot"
    snapshot_dir.mkdir()

    metadata = {
        "version": "1.0.0",
        "collected_at": "2025-02-11T14:30:00+00:00",
        "domain_fqdn": "TEST.LOCAL",
        "collector": "sharphound",
        "signature": "test123",
    }

    with open(snapshot_dir / "metadata.json", "w") as f:
        json.dump(metadata, f)

    # -----------------------------------------------------
    # Mock GraphConnector
    # -----------------------------------------------------

    mock_graph = Mock()
    mock_graph_cls.return_value = mock_graph

    # -----------------------------------------------------
    # Mock GraphView
    # -----------------------------------------------------

    mock_view = Mock()
    mock_view.get_statistics.return_value = {
        "users": 100,
        "computers": 50,
        "groups": 10,
    }

    mock_view_cls.return_value = mock_view

    # -----------------------------------------------------
    # Mock DetectionContext
    # -----------------------------------------------------

    mock_context = Mock()
    mock_context.get_statistics.return_value = {
        "tier0_assets": 15
    }

    mock_context_cls.return_value = mock_context

    # -----------------------------------------------------
    # Mock DetectionEngine
    # -----------------------------------------------------

    mock_engine = Mock()

    mock_engine.run_all_detections.return_value = []

    mock_engine.get_statistics.return_value = {
        "by_category": {
            "A": 0,
            "B": 0,
            "C": 0,
            "D": 0,
            "E": 0,
        }
    }

    mock_detection_engine_cls.return_value = mock_engine

    # -----------------------------------------------------
    # Mock RiskEngine
    # -----------------------------------------------------

    mock_risk_result = Mock()
    mock_risk_result.global_risk_score = 5.5

    mock_risk_engine = Mock()
    mock_risk_engine.compute_risk.return_value = mock_risk_result

    mock_risk_engine_cls.return_value = mock_risk_engine

    # -----------------------------------------------------
    # Mock ThreatModelResult
    # -----------------------------------------------------

    mock_threat_model = Mock()

    mock_threat_model.to_json.return_value = '{"test": true}'

    mock_threat_model.risk_score = 5.5

    mock_threat_model.exposure_level = Mock()
    mock_threat_model.exposure_level.value = "contained"

    mock_threat_model.tier0_reachable = False

    mock_threat_model.primary_kill_path = None

    mock_threat_model.top_fixes = ["Fix 1", "Fix 2"]

    mock_assembler = Mock()
    mock_assembler.assemble.return_value = mock_threat_model

    mock_assembler_cls.return_value = mock_assembler

    # -----------------------------------------------------
    # Run CLI command
    # -----------------------------------------------------

    runner = CliRunner()

    with runner.isolated_filesystem():

        result = runner.invoke(
            cli,
            ["analyze", str(snapshot_dir), "--no-dashboard"],
            input="password\n",
        )

    # -----------------------------------------------------
    # Assertions
    # -----------------------------------------------------

    assert result.exit_code == 0
    assert "BlueHound Analysis Complete" in result.output