"""Whole-command developer inspection via the existing bound resident."""

from __future__ import annotations

import os
import shutil
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from . import native_git_execution_safety
from .native_codex_tool_output import _environment_snapshot
from .native_context import _resolve_digest_home
from .native_direct_tool_context import _facts
from .native_runner_authority import native_runner_authority
from .runtime.shell_execution_context import _context_from_report


def _wire(value: Any) -> Any:
    if isinstance(value, (Path, Enum)):
        return value.value if isinstance(value, Enum) else str(value)
    if is_dataclass(value) and not isinstance(value, type):
        return _wire(asdict(value))
    if isinstance(value, dict):
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_wire(item) for item in value]
    return value


def developer_inspection_authority(entry: str, arguments: dict[str, Any]) -> Any:
    home = arguments.get("home_dir") or Path.home()
    request = {
        "entry": entry,
        "arguments": _wire(arguments),
        "facts": {
            "process_cwd": os.getcwd(),
            "home": str(Path.home()),
            "account_home": native_git_execution_safety._account_home_directory(),
            "groups": native_git_execution_safety._process_groups(),
            "environment": _environment_snapshot(),
            "git_executable": shutil.which("git"),
        },
        "direct_facts": _facts(arguments.get("cwd") or home, home),
    }
    result = native_runner_authority("developer_inspection_authority", request, _resolve_digest_home(None))["value"]
    if result is None:
        return None
    if entry in {
        "_low_risk_compound_developer_execution_context",
        "low_risk_compound_developer_execution_context",
        "_bounded_verified_source_edit_execution_context",
    }:
        return _context_from_report(result)
    if entry in {"_compound_developer_effect_graph", "_known_context_effect_graph"}:
        from .runtime.secret_file_request_services.developer_inspection import (
            DeveloperShellEffect,
            DeveloperShellEffectGraph,
            DeveloperShellSegmentEffect,
        )

        graph = DeveloperShellEffectGraph(
            context=_context_from_report(result["context"]),
            segments=tuple(
                DeveloperShellSegmentEffect(item["index"], item["command_name"], DeveloperShellEffect(item["effect"]))
                for item in result["segments"]
            ),
        )
        object.__setattr__(graph, "_native_observation", result["has_observation"])
        return graph
    if entry == "_split_literal_sed_commands":
        return tuple(result)
    return result
