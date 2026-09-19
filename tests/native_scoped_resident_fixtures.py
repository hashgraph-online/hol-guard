"""Synthetic signed sources for staged, source-built resident integration proof."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path

from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus, native_runtime_status
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_exact_command_hook_policy import _publish
from tests.test_guard_review_policy_memory_command import _store

HARNESS = "codex"
ARTIFACT = "codex:project:Bash"
COMMAND = "\tprintf 'Synthetic  native policy'\r\n"


def prepare_store(tmp_path: Path) -> tuple[GuardStore, Path]:
    store = _store(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (store.guard_home / "config.toml").write_text(
        'mode = "enforce"\ndefault_action = "review"\n[harnesses]\ncodex = "review"\n',
        encoding="utf-8",
    )
    # The real reader requires the existing local integrity key even for an
    # empty baseline; creating it is normal store setup, not signed authority.
    assert store._policy_integrity_secret_material(create=True)[0] is not None
    return store, workspace


def publish_source(store: GuardStore, source: str) -> None:
    _publish(store, ARTIFACT, source, command=COMMAND, harness=HARNESS)


def raw_payload(command: str = COMMAND) -> dict[str, object]:
    return {"tool_name": "Bash", "tool_input": {"command": command}, "source_scope": "project"}


def explicitly_negotiated_test_status() -> NativeRuntimeStatus:
    """Add only staged capability names to a verified actual native executable.

    This wrapper is deliberately test-only. Passing this component proof does
    not advertise the contract in production or certify the default route.
    """
    assert os.environ.get("HOL_GUARD_NATIVE") == "force", "resident proof requires force mode"
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    assert binary, "resident proof requires an explicitly selected native artifact"
    status = native_runtime_status()
    assert status.available and status.compatible, status.reason
    assert status.identity is not None and status.capabilities is not None
    assert status.identity.path.resolve() == Path(binary).resolve()
    assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == status.identity.sha256
    source_root = Path(__file__).resolve().parents[1]
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
    assert status.capabilities.build_sha == source_sha, "native artifact must match exact checkout"
    return replace(
        status,
        capabilities=replace(
            status.capabilities,
            features=tuple(sorted(set(status.capabilities.features) | SCOPED_PUBLISH_FEATURES)),
        ),
    )
