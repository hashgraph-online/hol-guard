from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_local_cli, hook_native_review_approval
from codex_plugin_scanner.guard.local_cli_trust import matching_local_cli_grant
from codex_plugin_scanner.guard.runtime.custom_extension_suggestion import is_suggestable_custom_tool
from codex_plugin_scanner.guard.runtime.local_cli_commands import command_tokens_for_invocation
from codex_plugin_scanner.guard.runtime.local_cli_identity import (
    REGISTRY_PACKAGE_CLI_PREFIX,
    identify_unlisted_cli,
    is_local_cli_id,
)


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


class _GrantStore:
    def __init__(self, grants: Mapping[str, Mapping[str, object]]) -> None:
        self._grants = dict(grants)

    def read_local_cli_grant(self, cli_id: str) -> Mapping[str, object] | None:
        return self._grants.get(cli_id)

    def has_local_cli_block_rules(self) -> bool:
        return any(grant.get("state") == "blocked" for grant in self._grants.values())


def test_npx_local_bin_binds_to_project_wrangler(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"

    identity = identify_unlisted_cli("npx wrangler deploy", cwd=workspace, home_dir=home_dir)

    assert identity is not None
    assert identity.name == "wrangler"
    assert identity.runner == "npx"
    assert identity.path_class == "project-tool"
    assert not identity.is_registry_package
    assert not identity.cli_id.startswith(REGISTRY_PACKAGE_CLI_PREFIX)
    assert command_tokens_for_invocation(
        "npx wrangler deploy", cwd=workspace, home_dir=home_dir, identity=identity
    ) == ("deploy",)
    assert is_suggestable_custom_tool(
        name=identity.name,
        kind=identity.kind,
        source_path=identity.path_class,
    )


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


@pytest.mark.parametrize("command", ["npx -y wrangler@3 --version", "bunx wrangler whoami"])
def test_registry_fetch_uses_package_keyed_identity(tmp_path: Path, command: str) -> None:
    workspace = tmp_path / "empty"
    workspace.mkdir()

    identity = identify_unlisted_cli(command, cwd=workspace, home_dir=tmp_path / "home")

    assert identity is not None
    assert identity.is_registry_package
    assert identity.cli_id.startswith(REGISTRY_PACKAGE_CLI_PREFIX)
    assert identity.path_class == "registry-package"


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
    store = _GrantStore({identity.cli_id: {"state": state, "identity_hash": identity.identity_hash}})

    match = matching_local_cli_grant(
        store=store, command=command, cwd=workspace, home_dir=home_dir, current_action="review"
    )

    assert match == ((identity, "blocked") if state == "blocked" else None)


def test_local_identity_honors_allow_grant(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    identity = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _GrantStore({identity.cli_id: {"state": "allowed", "identity_hash": identity.identity_hash}})

    match = matching_local_cli_grant(
        store=store, command="npx wrangler whoami", cwd=workspace, home_dir=home_dir, current_action="review"
    )

    assert match == (identity, "allowed")


def _native_review(*, minimum_action: str = "review", action_type: str = "shell") -> dict[str, object]:
    return {
        "decision": "ask",
        "policy_action": "review",
        "minimum_action": minimum_action,
        "reason_code": "native_review",
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
        ("allowed", _native_review(minimum_action="block"), None),
    ],
)
def test_native_review_applies_custom_extension_grants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    native_result: dict[str, object],
    expected: str | None,
) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    identity = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _GrantStore({identity.cli_id: {"state": state, "identity_hash": identity.identity_hash}})
    rendered: list[Mapping[str, object]] = []
    monkeypatch.setattr(
        hook_native_local_cli,
        "harness_json_from_native_pre_tool",
        lambda harness, result: rendered.append(result) or {"harness": harness},
    )
    monkeypatch.setattr(
        hook_native_local_cli,
        "_saved_block_response",
        lambda harness, result, **kwargs: rendered.append({"decision": "deny", **kwargs}) or {"harness": harness},
    )

    response = hook_native_local_cli.native_local_cli_grant_response(
        store,
        harness="codex",
        payload={"tool_input": {"command": "npx wrangler whoami"}, "cwd": str(workspace)},
        native_result=native_result,
        workspace=workspace,
        home_dir=home_dir,
    )

    if expected is None:
        assert response is None
        return
    assert response is not None
    assert response[0] is (expected == "deny")
    assert rendered[-1]["decision"] == expected


@pytest.mark.parametrize(("state", "blocked"), [("blocked", True), ("allowed", False)])
@pytest.mark.parametrize("input_key", ["tool_input", "toolInput"])
def test_native_allow_still_honors_custom_extension_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str, blocked: bool, input_key: str
) -> None:
    workspace = tmp_path / "workspace"
    _write_wrangler_workspace(workspace)
    home_dir = tmp_path / "home"
    identity = identify_unlisted_cli("npx wrangler whoami", cwd=workspace, home_dir=home_dir)
    assert identity is not None
    store = _GrantStore({identity.cli_id: {"state": state, "identity_hash": identity.identity_hash}})
    monkeypatch.setattr(hook_native_local_cli, "_block_rules_cache", {})
    monkeypatch.setattr(
        hook_native_local_cli,
        "_saved_block_response",
        lambda harness, result, **kwargs: {"decision": "deny", **kwargs},
    )

    response = hook_native_local_cli.native_local_cli_block_response(
        store,
        harness="codex",
        payload={input_key: {"command": "npx wrangler whoami"}, "cwd": str(workspace)},
        native_result={"decision": "allow", "policy_action": "allow", "minimum_action": "allow"},
        workspace=workspace,
        home_dir=home_dir,
    )

    assert (response is not None) is blocked
    if blocked:
        assert response == {
            "decision": "deny",
            "reason_code": "local_cli_extension_blocked",
            "reason": "Your custom extension rules block this wrangler command.",
        }


def test_saved_exact_action_block_wins_over_custom_extension_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved_block = {"decision": "deny", "source": "saved"}
    monkeypatch.setattr(hook_native_review_approval, "native_review_policy_binding", lambda **_kwargs: None)
    monkeypatch.setattr(
        hook_native_review_approval,
        "native_local_cli_grant_response",
        lambda *_args, **_kwargs: (False, {"decision": "allow", "source": "custom"}),
    )
    monkeypatch.setattr(hook_native_review_approval, "native_saved_review_response", lambda *_a, **_k: saved_block)

    response = hook_native_review_approval.pause_native_pre_tool_for_approval(
        object(),
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "npx wrangler deploy"}, "cwd": str(tmp_path)},
        native_result=_native_review(),
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
    )

    assert response is saved_block


def test_registry_identity_keeps_valid_id_for_hyphenated_names(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    identity = identify_unlisted_cli("npx -y a-b-c-d-e-f-g-h-i@1.0.0 --help", cwd=workspace, home_dir=tmp_path)

    assert identity is not None
    assert identity.is_registry_package
    assert is_local_cli_id(identity.cli_id)
