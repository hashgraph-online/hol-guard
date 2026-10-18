"""Synthetic connectors for the benign false-positive gate.

A connector is a program or server Guard has no allow or block decision for
until the local admin sets it up. Two shapes are written under the fixture HOME,
with synthetic names only:

* a local CLI, ``lanectl``, installed as an executable ``#!/bin/sh`` script in
  ``~/.local/bin`` beside its ``~/.lanectl`` state directory. ``lanectl-ready``
  is a second install of the same shape that the local admin has allowed;
* a harness MCP config naming two stdio servers, ``echo-mcp`` and ``echo-ready`` (the
  one the local admin has allowed), and a remote one, ``https://mcp.example.test/mcp``, in
  the place the Codex adapter reads it. ``tests.benign_fp_gate_mcp`` replays their calls.

The cases pass a path under ``~/.lanectl``. A bare ``lanectl status`` stays in the
workspace, where hosts with a sandbox run it contained and never review it; a command that
reaches the connector's state outside the workspace is the one that needs a decision.
Nothing here runs a connector: the gate only decides on the calls it replays.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

import pytest

from ci.gauntlet.approval_rows import CONNECTOR_GROUP_ID
from codex_plugin_scanner.guard.blocked_request_mode import SAFE_ALTERNATIVE_GUIDANCE, connector_setup_reason
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.native_context import bound_context_digest_home
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_mcp import FORBIDDEN_WORDING, mcp_config, write_server
from tests.benign_fp_gate_projects import _write

UNSET_CLI = "lanectl"
ALLOWED_CLI = "lanectl-ready"
REMOTE_MCP_URL = "https://mcp.example.test/mcp"

# A review held only because Guard does not recognise the command carries this reason on its row.
SETUP_ROW_REASON = "native_command_review_required"


def write_connectors(home: Path) -> None:
    """Install the synthetic CLIs, their state directory and the harness MCP config."""
    for name in (UNSET_CLI, ALLOWED_CLI):
        program = home / ".local" / "bin" / name
        _write(program, f'#!/bin/sh\necho "{name} $*"\n')
        program.chmod(0o755)
    _write(home / ".lanectl" / "state.json", '{"lane": "example", "ready": true}\n')
    _write(home / ".lanectl" / "config.toml", 'endpoint = "local"\n')
    write_server(home)
    _write(home / ".codex" / "config.toml", mcp_config(home, REMOTE_MCP_URL))


def _identify(name: str, home: Path, guard_home: Path) -> UnlistedCliIdentity | None:
    """Identify ``name`` as Guard's own hook does: ``~/.local/bin`` on PATH, no loader overrides, this guard home."""
    with pytest.MonkeyPatch.context() as patch:
        for variable in list(os.environ):
            if variable.upper().startswith(("LD_", "DYLD_")):
                patch.delenv(variable)
        patch.setenv("PATH", os.pathsep.join([str(home / ".local" / "bin"), os.environ.get("PATH", "")]))
        with bound_context_digest_home(guard_home):
            return identify_unlisted_cli(name, cwd=home, home_dir=home)


def allow_ready_cli(store: GuardStore, home: Path) -> None:
    """Record the local admin's allow for ``lanectl-ready`` through the store's grant API."""
    identity = _identify(ALLOWED_CLI, home, store.guard_home)
    assert identity is not None, f"{ALLOWED_CLI} must identify as a local CLI"
    seen_at = utc_now()
    store.record_local_cli_observation(identity, seen_at=seen_at)
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=seen_at,
    )


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _identity_hash(home: Path, guard_home: Path) -> str:
    identity = _identify(UNSET_CLI, home, guard_home)
    assert identity is not None, f"{UNSET_CLI} must identify as a local CLI"
    return identity.identity_hash


def connector_setup_failure(rows: list[dict[str, object]], result: dict[str, object]) -> str | None:
    """Why a result and its new approval rows are not the connector-setup outcome, or None when they are."""
    if result.get("policy_action") != "block":
        return "connector setup must block the call"
    if result.get("prompted") is True:
        return "connector setup must not prompt the agent"
    text = " ".join(_strings(result))
    # A generic per-action review reads "requires review"; setup names the connector and
    # carries the default-mode guidance verbatim.
    if connector_setup_reason(UNSET_CLI, "cli", ask=False) not in text:
        return "not worded as setup"
    if SAFE_ALTERNATIVE_GUIDANCE not in text:
        return "setup lost the safe-alternative guidance"
    leaked = [word for word in FORBIDDEN_WORDING if word in text.lower()]
    if leaked:
        return f"default-mode setup text carries {leaked}"
    if len(rows) != 1:
        return f"setup must queue exactly one approval row, got {len(rows)}"
    if rows[0]["reason_code"] != SETUP_ROW_REASON:
        return "setup row lost its non-recognition reason"
    if CONNECTOR_GROUP_ID.fullmatch(str(rows[0]["queue_group_id"])) is None:
        return "setup row is not under a connector group"
    return None


def assert_connector_setup(
    rows: list[dict[str, object]], result: dict[str, object], description: str, *, home: Path, guard_home: Path
) -> None:
    """A never-decided CLI is held as setup: grouped row, setup wording, no link, no ask."""
    failure = connector_setup_failure(rows, result)
    assert failure is None, f"{failure}: {description}"
    group = CONNECTOR_GROUP_ID.fullmatch(str(rows[0]["queue_group_id"]))
    assert group is not None
    assert group["identity"] == _identity_hash(home, guard_home), f"group names another connector: {description}"


def connector_groups(queue_rows: Iterable[dict[str, object]]) -> dict[str, set[str]]:
    """Connector identity hash to the action digests queued under it."""
    groups: dict[str, set[str]] = {}
    for row in queue_rows:
        match = CONNECTOR_GROUP_ID.fullmatch(str(row.get("queue_group_id") or ""))
        if match is not None:
            groups.setdefault(match["identity"], set()).add(match["action"])
    return groups
