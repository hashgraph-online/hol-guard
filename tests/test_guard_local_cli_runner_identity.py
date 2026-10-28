from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_approval
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_identity import (
    identify_unlisted_cli,
    is_local_cli_id,
)
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident, review_rule_verdict  # noqa: F401


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Parse runner intents through the resident authority."""

    return package_intent_native


def _write_wrangler_workspace(workspace: Path, *, version: str = "4.12.0") -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "package.json").write_text(
        '{"name":"demo","devDependencies":{"wrangler":"^4.12.0"}}\n',
        encoding="utf-8",
    )
    package_dir = workspace / "node_modules" / "wrangler"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "package.json").write_text(
        f'{{"name":"wrangler","version":"{version}","bin":{{"wrangler":"bin/wrangler.js"}}}}\n',
        encoding="utf-8",
    )
    target = package_dir / "bin" / "wrangler.js"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"#!/bin/sh\n# wrangler {version}\nexit 0\n", encoding="utf-8")
    target.chmod(0o755)
    link = workspace / "node_modules" / ".bin" / "wrangler"
    link.parent.mkdir(parents=True, exist_ok=True)
    if not link.exists():
        link.symlink_to(Path("..") / "wrangler" / "bin" / "wrangler.js")
    return target


def _grant_store(tmp_path: Path, identity, state: str) -> GuardStore:
    """A real store: the resident reads grants from ``guard.db`` itself."""

    store = GuardStore(tmp_path / "guard-home")
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(identity=identity, state=state, expected_revision=0, updated_at=utc_now())
    return store


def test_wrangler_upgrade_changes_local_identity_hash(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    target = _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    before = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    target.unlink()
    _write_wrangler_workspace(workspace, version="4.13.0")
    after = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)

    assert before is not None and after is not None
    assert before.cli_id == after.cli_id
    assert before.identity_hash != after.identity_hash


@pytest.mark.parametrize(
    "command",
    ["npx --package evil wrangler", "npx node -e 1", "pnpm wrangler deploy", "npx -c 'wrangler deploy'"],
)
def test_runner_selector_forms_do_not_bind(tmp_path: Path, command: str) -> None:
    workspace = tmp_path / "empty"
    workspace.mkdir()

    assert identify_unlisted_cli(command, cwd=workspace, home_dir=tmp_path / "home") is None


@pytest.mark.parametrize("state", ["allowed", "blocked"])
def test_registry_identity_honors_blocks_only(tmp_path: Path, state: str) -> None:
    workspace = tmp_path / "empty"
    workspace.mkdir()
    home_dir = tmp_path / "home"
    command = "npx -y wrangler@3 deploy"
    identity = identify_unlisted_cli(command, cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _grant_store(tmp_path, identity, state)

    match = review_rule_verdict(store, command=command, cwd=workspace, home_dir=home_dir)

    assert match == (("blocked", identity.name) if state == "blocked" else None)


def test_local_identity_honors_allow_grant(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    identity = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _grant_store(tmp_path, identity, "allowed")

    match = review_rule_verdict(store, command="npx wrangler whoami", cwd=workspace, home_dir=home_dir)

    assert match == ("allowed", None)


def _native_review(
    *,
    minimum_action: str = "review",
    action_type: str = "shell",
    reason_code: str = "native_command_review_required",
) -> dict[str, object]:
    return {
        "decision": "ask",
        "policy_action": "review",
        "minimum_action": minimum_action,
        "reason_code": reason_code,
        "reason": "Review",
        "action": {"action_type": action_type},
    }


@pytest.mark.parametrize(
    ("state", "native_result", "expected"),
    [
        ("blocked", _native_review(), "deny"),
        ("blocked", _native_review(action_type="package"), "deny"),
        ("allowed", _native_review(), "allow"),
        ("allowed", _native_review(action_type="package"), None),
        # A review with a risk signal of its own outlives an allow, not a block.
        ("allowed", _native_review(reason_code="native_network_review"), None),
        ("allowed", _native_review(reason_code="shell_local_secret_read"), None),
        ("blocked", _native_review(reason_code="native_network_review"), "deny"),
    ],
)
def test_native_review_applies_custom_extension_grants(
    tmp_path: Path,
    state: str,
    native_result: dict[str, object],
    expected: str | None,
) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    identity = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _grant_store(tmp_path, identity, state)

    match = review_rule_verdict(
        store, command="npx wrangler whoami", cwd=workspace, home_dir=home_dir, native_result=native_result
    )

    assert (None if match is None else match[0]) == {"deny": "blocked", "allow": "allowed", None: None}[expected]


@pytest.mark.parametrize(("state", "blocked"), [("blocked", True), ("allowed", False)])
@pytest.mark.parametrize("input_key", ["tool_input", "toolInput"])
def test_native_allow_still_honors_custom_extension_block(
    tmp_path: Path, state: str, blocked: bool, input_key: str
) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    identity = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _grant_store(tmp_path, identity, state)

    match = review_rule_verdict(
        store, command="npx wrangler whoami", cwd=workspace, home_dir=home_dir, mode="allowed", input_key=input_key
    )

    assert (match is not None and match[0] == "blocked") is blocked
    if blocked:
        assert match == ("blocked", identity.name)


def test_saved_exact_action_block_wins_over_custom_extension_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved_block = {"decision": "deny", "source": "saved"}
    monkeypatch.setattr(
        hook_native_review_approval, "native_review_evidence", lambda **_kwargs: (True, None, "token", None)
    )
    monkeypatch.setattr(hook_native_review_approval, "native_saved_decision_response", lambda *_a, **_k: saved_block)

    response = hook_native_review_approval.pause_native_pre_tool_for_approval(
        object(),
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "npx wrangler deploy"}, "cwd": str(tmp_path)},
        native_result=_native_review(),
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        local_cli_rule={"blocked": False, "harness_response": {"decision": "allow", "source": "custom"}},
    )

    assert response is saved_block


def test_registry_identity_keeps_valid_id_for_hyphenated_names(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    identity = identify_unlisted_cli("npx -y a-b-c-d-e-f-g-h-i@1.0.0 --help", cwd=workspace, home_dir=tmp_path)

    assert identity is not None
    assert identity.is_registry_package
    assert is_local_cli_id(identity.cli_id)
