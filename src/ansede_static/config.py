"""
ansede_static.config
────────────────────
Fast, zero-dependency configuration loader for enterprise workspaces.
Reads an `ansede.json` file to tune scanner rules, set ignore paths, 
and load custom internal taint sources and sinks.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger(__name__)


@dataclass
class AnsedeConfig:
    exclude_paths: list[str] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    custom_sources: list[str] = field(default_factory=list)
    custom_sinks: dict[str, tuple[str, str]] = field(default_factory=dict)


def load_config(workspace_root: Path | None = None) -> AnsedeConfig:
    if not workspace_root:
        workspace_root = Path.cwd()
        
    config_path = workspace_root / "ansede.json"
    if not config_path.is_file():
        return AnsedeConfig()
        
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        custom_sinks = {}
        for sink_name, sink_data in data.get("custom_sinks", {}).items():
            if isinstance(sink_data, list) and len(sink_data) >= 2:
                custom_sinks[sink_name] = (sink_data[0], sink_data[1])
                
        return AnsedeConfig(
            exclude_paths=data.get("exclude_paths", []),
            disable_rules=data.get("disable_rules", []),
            custom_sources=data.get("custom_sources", []),
            custom_sinks=custom_sinks,
        )
    except json.JSONDecodeError as exc:
        _log.warning("ansede.json is not valid JSON — ignoring config: %s", exc)
        return AnsedeConfig()
    except Exception as exc:
        _log.warning("Failed to load ansede.json — ignoring config: %s", exc)
        return AnsedeConfig()
