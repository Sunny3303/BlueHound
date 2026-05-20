"""
BlueHound configuration management.

Configuration priority:
1. Environment variables
2. User config file (~/.bluehound/config.json)
3. Defaults
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG_PATH = Path.home() / ".bluehound" / "config.json"


def get_neo4j_config() -> Dict[str, Any]:
    """
    Load Neo4j configuration.

    Passwords are expected from interactive prompt — not persisted by default.
    """
    config: Dict[str, Any] = {
        "uri": os.getenv("BLUEHOUND_NEO4J_URI", "bolt://localhost:7687"),
        "username": os.getenv("BLUEHOUND_NEO4J_USER", "neo4j"),
        "password": os.getenv("BLUEHOUND_NEO4J_PASSWORD"),
    }

    if DEFAULT_CONFIG_PATH.exists():
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                file_cfg = json.load(f).get("neo4j", {})
                config["uri"] = file_cfg.get("uri", config["uri"])
                config["username"] = file_cfg.get("username", config["username"])
                # password intentionally ignored unless explicitly set
                if "password" in file_cfg:
                    config["password"] = file_cfg["password"]
        except Exception:
            # Config errors should never break CLI
            pass

    return config


def save_neo4j_config(uri: str, username: str) -> None:
    """
    Save non-sensitive Neo4j configuration.

    Password is NOT stored for security reasons.
    """
    DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "neo4j": {
            "uri": uri,
            "username": username,
        }
    }

    with open(DEFAULT_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
