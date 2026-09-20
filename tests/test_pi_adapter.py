"""Tests for the Pi harness adapter."""

from __future__ import annotations

import argparse
import json
import os
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import contract_for
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_support import stable_suffix
from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.cli.commands_support_codex_tool_output_messages import (
    _codex_tool_output_request_summary,
    _codex_tool_output_runtime_reason,
    _codex_tool_output_runtime_summary,
)
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _approval_surface_policy_for_flow
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _codex_post_tool_output_artifact
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.runtime.secret_sensitivity import classify_secret_content
from codex_plugin_scanner.guard.store import GuardStore


def _write_worktree_git_marker(checkout_root: Path) -> None:
    checkout_root.mkdir(parents=True, exist_ok=True)
    (checkout_root / ".git").write_text("gitdir: ../.git/worktrees/test-checkout\n")


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


from .pi_adapter_identity_cases import TestPiAdapterIdentity, TestPiDetect  # noqa: E402
from .pi_adapter_install_cases import TestPiInstall  # noqa: E402
from .pi_adapter_runtime_cases import TestPiRuntime  # noqa: E402

__all__ = [
    "GuardConfig",
    "GuardStore",
    "HarnessContext",
    "HarnessDetection",
    "Path",
    "StringIO",
    "TestPiAdapterIdentity",
    "TestPiDetect",
    "TestPiInstall",
    "TestPiRuntime",
    "_approval_surface_policy_for_flow",
    "_codex_post_tool_output_artifact",
    "_codex_tool_output_request_summary",
    "_codex_tool_output_runtime_reason",
    "_codex_tool_output_runtime_summary",
    "_ctx",
    "_run_hook_generic_payload",
    "_write_json",
    "_write_text",
    "_write_worktree_git_marker",
    "argparse",
    "artifact_hash",
    "classify_secret_content",
    "contract_for",
    "get_adapter",
    "inventory_snapshot_from_detection",
    "json",
    "list_adapters",
    "managed_extension_source",
    "normalize_harness_payload",
    "os",
    "queue_blocked_approvals",
    "redirect_stderr",
    "stable_suffix",
]
