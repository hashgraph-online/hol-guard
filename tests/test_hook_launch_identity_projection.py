"""Unsupported native identity must not erase a decision or permit reuse."""

from __future__ import annotations

import argparse

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_launch_identity import project_hook_launch_identity
from codex_plugin_scanner.guard.cli.commands_hook_native_availability import _native_unavailable_exit_code


def test_complete_native_identity_keeps_exact_projection() -> None:
    identity = {
        "argv_sha256": "a" * 64,
        "launch_cwd": "/workspace",
        "executable": {"status": "verified", "path": "/bin/tool"},
        "entrypoint": {"kind": "not-applicable", "status": "not_applicable"},
    }
    assert project_hook_launch_identity(identity) == {
        "launch_argv_sha256": identity["argv_sha256"],
        "launch_cwd": identity["launch_cwd"],
        "resolved_artifact_command": identity["executable"],
        "resolved_entrypoint": identity["entrypoint"],
    }


@pytest.mark.parametrize("missing", ["argv_sha256", "launch_cwd", "executable", "entrypoint"])
def test_incomplete_identity_is_nonreusable_without_fabricated_proof(missing: str) -> None:
    identity = dict.fromkeys(["argv_sha256", "launch_cwd", "executable", "entrypoint"])
    identity.pop(missing)
    first = project_hook_launch_identity(identity)
    second = project_hook_launch_identity(identity)
    assert first["status"] == "unproven"
    assert first["native_launch_identity"] == identity
    assert first["reuse_nonce"] != second["reuse_nonce"]
    assert "resolved_artifact_command" not in first
    assert "launch_argv_sha256" not in first


def test_windows_stub_remains_nonreusable() -> None:
    identity = {"status": "unsupported_platform", "reuse_nonce": "unsupported_platform"}
    first = project_hook_launch_identity(identity)
    second = project_hook_launch_identity(identity)
    assert first["native_launch_identity"] == identity
    assert first["reuse_nonce"] != second["reuse_nonce"]


@pytest.mark.parametrize("decision,code", [("block", 2), ("deny", 2), ("review", 2), ("allow", 0)])
def test_hermes_unavailable_exit_matches_its_wire_verdict(decision: str, code: int) -> None:
    args = argparse.Namespace(harness="hermes")
    assert _native_unavailable_exit_code(args, {"decision": decision}, "PreToolUse") == code
