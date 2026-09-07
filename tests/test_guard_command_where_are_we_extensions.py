"""Structured where-are-we command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_where_are_we_extensions import (
    INSTALL_HOOK_FLAGS,
    REPOSITORY_WRITE_FLAGS,
    TRACKER_FETCH_FLAGS,
    WHERE_ARE_WE_COMMAND_RULES,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from tests.command_extension_contracts import assert_safe_command_cases

_EXTENSION_ID = "command.where-are-we"
_REPOSITORY_WRITE_ACTION = "where-are-we repository file write command"
_INSTALL_HOOK_ACTION = "where-are-we agent hook installation command"
_TRACKER_FETCH_ACTION = "where-are-we tracker fetch command"
_REPOSITORY_WRITE_RULE = "command.where-are-we.repository-write"
_INSTALL_HOOK_RULE = "command.where-are-we.install-hook"
_TRACKER_FETCH_RULE = "command.where-are-we.tracker-fetch"

# `where-are-we --effects --json` for 1.5.0, the manifest the rule table is
# written against. Held here so a flag added at writes-repo or above in a later
# release fails this suite instead of silently escaping review.
_EFFECTS_SCHEMA = "where-are-we-effects/1"
_EFFECTS_ORDER: tuple[str, ...] = ("read", "writes-map-dir", "writes-repo", "writes-config", "network")
_EFFECTS_FLAGS: dict[str, str] = {
    "--agent-file": "writes-repo",
    "--also": "read",
    "--ask": "read",
    "--at": "read",
    "--callees": "read",
    "--callers": "read",
    "--context": "read",
    "--corpus": "read",
    "--cost": "read",
    "--ctags": "writes-map-dir",
    "--defines": "read",
    "--diff": "writes-map-dir",
    "--docs": "writes-repo",
    "--dry-run": "read",
    "--effects": "read",
    "--export": "writes-repo",
    "--files": "read",
    "--for": "read",
    "--force": "writes-map-dir",
    "--help": "read",
    "--html": "writes-map-dir",
    "--impact": "read",
    "--impact-depth": "read",
    "--init": "writes-repo",
    "--install-hook": "writes-config",
    "--json": "read",
    "--limit": "read",
    "--lsp": "read",
    "--max-lines": "read",
    "--mcp": "read",
    "--more": "read",
    "--no-semantic": "read",
    "--only": "read",
    "--out": "writes-map-dir",
    "--pointer": "read",
    "--product": "read",
    "--quiet": "read",
    "--rank": "read",
    "--repo": "read",
    "--rules": "read",
    "--runs-api": "network",
    "--sections": "read",
    "--skip": "read",
    "--spec-cmd": "network",
    "--spec-depth": "network",
    "--spec-limit": "network",
    "--spec-source": "network",
    "--specs": "network",
    "--watch": "writes-map-dir",
    "-h": "read",
}
# Carried at network in the manifest because they tune a --specs fetch. Neither
# reaches the network without it, so neither is reviewed on its own.
_BOUNDED_MODIFIERS = frozenset({"--spec-depth", "--spec-limit"})
_SAFE_VARIANT_FLAGS: dict[str, str] = {
    "help": "--help",
    "short-help": "-h",
    "effects": "--effects",
    "dry-run": "--dry-run",
}

WHERE_ARE_WE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("where-are-we --repo . --agent-file AGENTS.md", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --agent-file=CLAUDE.md --repo .", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --repo . --init", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --repo . --docs write", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --repo . --docs", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --ag AGENTS.md", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --ini", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --do write", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --repo . --export map-export.md", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --export=map-export.md --repo .", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    # `--export -` writes to stdout, but the tool's own classifier still calls
    # the line writes-repo, because the class belongs to the flag and not to the
    # value. The rule follows the manifest rather than reading the value.
    ("where-are-we --repo . --export -", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we --ex map-export.md", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    (
        'where-are-we --repo "/tmp/my repo" --agent-file "docs/agent notes.md"',
        _REPOSITORY_WRITE_ACTION,
        _REPOSITORY_WRITE_RULE,
    ),
    ("where-are-we.cmd --repo . --init", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    ("where-are-we.exe --repo . --init", _REPOSITORY_WRITE_ACTION, _REPOSITORY_WRITE_RULE),
    (
        "where-are-we --repo . --ask x && where-are-we --repo . --init",
        _REPOSITORY_WRITE_ACTION,
        _REPOSITORY_WRITE_RULE,
    ),
    ("where-are-we --repo . --out /tmp/map --install-hook git", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("where-are-we --install-hook claude", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("where-are-we --install-hook=codex", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("where-are-we --install git", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("where-are-we --ins gemini", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("where-are-we --install-hook cursor --repo .", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("env WAWE_ASK_LOG=0 where-are-we --repo . --install-hook agent", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("bash -c 'where-are-we --repo . --install-hook git'", _INSTALL_HOOK_ACTION, _INSTALL_HOOK_RULE),
    ("where-are-we --repo . --specs ABC-1 --spec-source github", _TRACKER_FETCH_ACTION, _TRACKER_FETCH_RULE),
    (
        "where-are-we --repo . --specs ABC-1,ABC-2 --spec-cmd 'tracker show {key} --json'",
        _TRACKER_FETCH_ACTION,
        _TRACKER_FETCH_RULE,
    ),
    ("where-are-we --spec-source linear --specs ABC-1", _TRACKER_FETCH_ACTION, _TRACKER_FETCH_RULE),
    ("where-are-we --spec-s github --specs ABC-1", _TRACKER_FETCH_ACTION, _TRACKER_FETCH_RULE),
    ("where-are-we --repo . --runs-api https://runs.example/api", _TRACKER_FETCH_ACTION, _TRACKER_FETCH_RULE),
    ("where-are-we --run https://runs.example/api", _TRACKER_FETCH_ACTION, _TRACKER_FETCH_RULE),
)

WHERE_ARE_WE_SAFE_COMMANDS: tuple[str, ...] = (
    'where-are-we --repo . --ask "where is the retry policy"',
    "where-are-we --repo . --callers build_map",
    "where-are-we --repo . --callees build_map",
    "where-are-we --repo . --impact resolve_target --impact-depth 4",
    "where-are-we --repo . --more h3",
    "where-are-we --repo . --pointer",
    "where-are-we --sections",
    "where-are-we --repo . --mcp",
    "where-are-we --repo . --lsp",
    "where-are-we --repo . --out /tmp/map --html --force",
    "where-are-we --repo . --out /tmp/map --watch 30",
    "where-are-we --repo . --diff",
    "where-are-we --repo . --ctags",
    "where-are-we --repo . --out /tmp/map --ctags --force",
    "where-are-we --repo . --rank",
    "where-are-we --repo . --rank src/a.py,src/b.py --limit 40",
    "where-are-we --repo . --rank --ask x --limit 20",
    "where-are-we --repo . --files src/a.py --ask x",
    "where-are-we --repo . --files - --ask x",
    "where-are-we --repo . --defines build_map",
    "where-are-we --repo . --at src/a.py:120",
    "where-are-we --repo . --context resolve_target",
    "where-are-we --repo . --cost",
    "where-are-we --repo . --cost 2000 --json",
    "where-are-we --repo . --for coder --only Layers --skip Steps --max-lines 400",
    "where-are-we --repo . --spec-depth 3 --spec-limit 40 --ask x",
    "where-are-we --repo . --sections | grep steps",
    "where-are-we --help",
    "where-are-we -h",
    "where-are-we --version",
    "where-are-we --effects",
    "where-are-we --effects --json",
    "where-are-we --effects -- where-are-we --repo . --install-hook git",
    "where-are-we --repo . --install-hook git --dry-run",
    "where-are-we --repo . --install-hook git --help",
    "where-are-we --repo . --install-hook git -h",
    "where-are-we --repo . --install-hook git --effects",
    "where-are-we --repo . --agent-file AGENTS.md --dry-run",
    "where-are-we --dry-run --repo . --init",
    "where-are-we --repo . --docs write --dry-run",
    "where-are-we --repo . --export map-export.md --dry-run",
    "where-are-we --repo . --export - --dry-run",
    "where-are-we --repo . --export map-export.md --help",
    "where-are-we --repo . --specs ABC-1 --spec-source github --dry-run",
    "grep 'where-are-we --repo . --install-hook git' docs",
    "echo where-are-we --init",
)


def _control_layer(state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, _EXTENSION_ID),
                state=state,
            ),
        ),
    )


@pytest.mark.parametrize(("command", "action_class", "rule_id"), WHERE_ARE_WE_REVIEW_CASES)
def test_where_are_we_write_surface_is_inert_until_local_admin_enable(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    inert = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=())

    assert all(item.extension.extension_id != _EXTENSION_ID for item in inert.extension_observations)
    assert all(item.extension.extension_id != _EXTENSION_ID for item in inert.matches)
    assert inert.controlling_rule_id is None

    enabled = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_control_layer(ControlState.ENABLED),),
    )

    assert any(item.extension.extension_id == _EXTENSION_ID for item in enabled.extension_observations)
    assert any(item.extension.extension_id == _EXTENSION_ID for item in enabled.matches)
    assert enabled.controlling_action_class == action_class
    assert enabled.controlling_rule_id == rule_id
    assert enabled.minimum_action == "review"

    disabled = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_control_layer(ControlState.DISABLED),),
    )

    assert all(item.extension.extension_id != _EXTENSION_ID for item in disabled.matches)
    assert disabled.controlling_rule_id is None


def test_where_are_we_read_and_preview_surface_stays_non_reviewable(tmp_path: Path) -> None:
    assert_safe_command_cases(WHERE_ARE_WE_SAFE_COMMANDS, tmp_path)


@pytest.mark.parametrize("command", WHERE_ARE_WE_SAFE_COMMANDS)
def test_where_are_we_safe_surface_stays_non_reviewable_once_enabled(command: str, tmp_path: Path) -> None:
    enabled = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_control_layer(ControlState.ENABLED),),
    )

    assert all(item.extension.extension_id != _EXTENSION_ID for item in enabled.matches)
    assert enabled.controlling_rule_id is None


@pytest.mark.parametrize(
    ("command", "rule_id"),
    (
        ("where-are-we --repo . --install-hook git --unknown --help", _INSTALL_HOOK_RULE),
        ("where-are-we --repo . --init --unknown -h", _REPOSITORY_WRITE_RULE),
        ("where-are-we --repo . --specs ABC-1 --unknown --dry-run", _TRACKER_FETCH_RULE),
    ),
)
def test_where_are_we_unknown_options_cannot_buy_a_safe_exemption(
    command: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    enabled = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_control_layer(ControlState.ENABLED),),
    )

    assert enabled.controlling_rule_id == rule_id
    assert enabled.minimum_action == "review"


def test_where_are_we_unparsable_input_produces_uncertainty_not_safety(tmp_path: Path) -> None:
    evaluation = evaluate_command(
        "where-are-we --repo . --install-hook 'git",
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_control_layer(ControlState.ENABLED),),
    )

    assert evaluation.command.confidence == "fallback"
    assert evaluation.minimum_action == "review"


@pytest.mark.parametrize(
    "command",
    (
        "pipx run where-are-we --repo . --install-hook git",
        "uvx where-are-we --repo . --install-hook git",
        "pip install where-are-we",
        "wawe-readmes --repo . --write",
        "wawe-measure --repo .",
        "wawe-eval --repo . --agent",
    ),
)
def test_where_are_we_extension_does_not_own_launchers_or_sibling_entry_points(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    extension_ids = {extension["extension_id"] for extension in payload["extensions"]}
    rule_ids = {rule["rule_id"] for rule in payload["rules"]}

    assert _EXTENSION_ID not in extension_ids
    assert not any(rule_id.startswith(f"{_EXTENSION_ID}.") for rule_id in rule_ids)


def test_where_are_we_extension_publishes_canonical_reference_and_rules() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/ngavrish/where-are-we#what-writes-and-what-only-reads",)
    assert {rule.rule_id for rule in extension.rules} == {
        _REPOSITORY_WRITE_RULE,
        _INSTALL_HOOK_RULE,
        _TRACKER_FETCH_RULE,
    }
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    for rule in extension.rules:
        assert rule.default_mode == "review"
        assert {variant.variant_id for variant in rule.safe_variants} == set(_SAFE_VARIANT_FLAGS)


def test_where_are_we_actions_publish_runtime_risk_classes() -> None:
    assert risk_classes_for_command_action(_REPOSITORY_WRITE_ACTION) == ("local_secret_read",)
    assert risk_classes_for_command_action(_INSTALL_HOOK_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_TRACKER_FETCH_ACTION) == ("network_egress", "execution")


def _resolved_manifest_flag(flag: str) -> str:
    """Resolve one accepted spelling the way argparse resolves it."""

    if flag in _EFFECTS_FLAGS:
        return flag
    candidates = [name for name in _EFFECTS_FLAGS if name.startswith(flag)]
    assert len(candidates) == 1, f"{flag!r} is not an unambiguous prefix: {sorted(candidates)}"
    return candidates[0]


def test_where_are_we_rule_table_matches_the_published_effects_manifest() -> None:
    assert _EFFECTS_SCHEMA == "where-are-we-effects/1"
    boundary = _EFFECTS_ORDER.index("writes-repo")
    manifest_writes = {
        flag for flag, flag_class in _EFFECTS_FLAGS.items() if _EFFECTS_ORDER.index(flag_class) >= boundary
    }
    reviewed = {
        _resolved_manifest_flag(flag) for flag in REPOSITORY_WRITE_FLAGS + INSTALL_HOOK_FLAGS + TRACKER_FETCH_FLAGS
    }

    assert reviewed == manifest_writes - _BOUNDED_MODIFIERS
    assert {_resolved_manifest_flag(flag) for flag in REPOSITORY_WRITE_FLAGS} == {
        flag for flag, flag_class in _EFFECTS_FLAGS.items() if flag_class == "writes-repo"
    }
    assert {_resolved_manifest_flag(flag) for flag in INSTALL_HOOK_FLAGS} == {
        flag for flag, flag_class in _EFFECTS_FLAGS.items() if flag_class == "writes-config"
    }
    assert all(_EFFECTS_FLAGS[flag] == "read" for flag in _SAFE_VARIANT_FLAGS.values())
    assert all(_EFFECTS_FLAGS[flag] == "network" for flag in _BOUNDED_MODIFIERS)


def test_where_are_we_evidence_carries_no_command_text_paths_or_environment() -> None:
    command = (
        "env WAWE_TOKEN=s3cret where-are-we --repo /srv/private/checkout "
        "--out /tmp/map --install-hook claude --spec-cmd 'tracker show {key}'"
    )
    parsed = parse_shell_command(command)
    secrets = (
        "s3cret",
        "wawe_token",
        "/srv/private/checkout",
        "/tmp/map",
        "tracker show",
        "claude",
        "--install-hook",
    )
    details: list[str] = []
    for rule in WHERE_ARE_WE_COMMAND_RULES:
        assert rule.matcher is not None
        for evidence in rule.matcher.match(parsed):
            assert evidence.executable == "where-are-we"
            details.append(evidence.detail)

    assert details
    for detail in details:
        assert all(secret not in detail.lower() for secret in secrets)

    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    serialized = repr(extension.to_dict()).lower()
    for secret in ("s3cret", "wawe_token", "/srv/private/checkout"):
        assert secret not in serialized
