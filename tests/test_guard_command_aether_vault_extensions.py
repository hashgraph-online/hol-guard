"""Structured Aether-Vault (`av`) command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
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

_EXTENSION_ID = "command.aether-vault"

AETHER_VAULT_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ('av commit -m "epoch 12"', "Aether-Vault commit command", "command.aether-vault.commit"),
    (
        "av commit -m x --tag run:7 --metric val_loss=0.3 --no-upload",
        "Aether-Vault commit command",
        "command.aether-vault.commit",
    ),
    ("av --output json commit -m x", "Aether-Vault commit command", "command.aether-vault.commit"),
    ("av --output=json commit -m x", "Aether-Vault commit command", "command.aether-vault.commit"),
    ("av --verbose --silent commit -m x", "Aether-Vault commit command", "command.aether-vault.commit"),
    ("av commit --unknown-flag -m x", "Aether-Vault commit command", "command.aether-vault.commit"),
    ("av push", "Aether-Vault push command", "command.aether-vault.push"),
    ("av --output json push", "Aether-Vault push command", "command.aether-vault.push"),
    ("av.exe push", "Aether-Vault push command", "command.aether-vault.push"),
    ("av.cmd push", "Aether-Vault push command", "command.aether-vault.push"),
    ("/usr/local/bin/av push", "Aether-Vault push command", "command.aether-vault.push"),
    ("av gc", "Aether-Vault garbage collection command", "command.aether-vault.gc"),
    ("av --silent gc", "Aether-Vault garbage collection command", "command.aether-vault.gc"),
    (
        "av checkout main --force",
        "Aether-Vault forced checkout command",
        "command.aether-vault.checkout-force",
    ),
    (
        "av checkout abc123 -f",
        "Aether-Vault forced checkout command",
        "command.aether-vault.checkout-force",
    ),
    (
        "av checkout -f main",
        "Aether-Vault forced checkout command",
        "command.aether-vault.checkout-force",
    ),
    (
        "av checkout --force main",
        "Aether-Vault forced checkout command",
        "command.aether-vault.checkout-force",
    ),
    (
        'av checkout "release 1" --force',
        "Aether-Vault forced checkout command",
        "command.aether-vault.checkout-force",
    ),
    ("av promote cand-1 --into main", "Aether-Vault promote command", "command.aether-vault.promote"),
    ("av promote cand --force", "Aether-Vault promote command", "command.aether-vault.promote"),
    ("av promote --into staging cand", "Aether-Vault promote command", "command.aether-vault.promote"),
    ("av stash drop", "Aether-Vault stash drop command", "command.aether-vault.stash-drop"),
    ("av stash drop stash-3", "Aether-Vault stash drop command", "command.aether-vault.stash-drop"),
    (
        "av audit prune --before-days 30 --yes",
        "Aether-Vault audit prune command",
        "command.aether-vault.audit-prune",
    ),
    ("av audit prune --yes", "Aether-Vault audit prune command", "command.aether-vault.audit-prune"),
    ("cd repo && av push", "Aether-Vault push command", "command.aether-vault.push"),
    ("av add ckpt/ && av commit -m x", "Aether-Vault commit command", "command.aether-vault.commit"),
    ("av push | tee log.txt", "Aether-Vault push command", "command.aether-vault.push"),
)

AETHER_VAULT_QUIET_COMMANDS: tuple[str, ...] = (
    "av status",
    "av --output json status",
    "av diff v2",
    "av list-meta",
    "av log --limit 5",
    "av log",
    "av fetch checkpoints/",
    "av add checkpoints/",
    "av unstage x",
    "av context show",
    "av run list",
    "av stash",
    "av stash list",
    "av stash push -m wip",
    "av stash apply",
    "av stash pop",
    "av audit list",
    "av policy list",
    "av checkout main",
    "av checkout abc123",
    "av --help",
    "av --version",
    "av doctor",
    "av init",
    "av handoff",
    'grep "av commit" README.md',
    "echo av push",
)

# Safe *variants* of a reviewed rule (--dry-run, --help). Enabling the extension makes it
# observe these (it inspects every `av` command to decide whether a safe variant applies),
# so they are proven quiet via `controlling_rule_id`, not via extension-observation absence.
AETHER_VAULT_SAFE_VARIANT_COMMANDS: tuple[str, ...] = (
    "av audit prune --dry-run",
    "av audit prune --before-days 30 --dry-run",
    "av promote --dry-run cand",
    "av promote cand --into main --dry-run",
    "av commit --help",
    "av push --help",
    "av gc --help",
    "av promote --help",
)

# Commands where `av` is not the executable, or the launcher form is our extension's own
# module dispatch without a subcommand. Our extension never observes these (proven below),
# but each trips an unrelated first-party rule (`git commit ...` owns "git workspace command";
# a bare `python -m <module>` with no recognized subcommand owns "destructive shell command"),
# so they are not globally `no_match` and stay out of `assert_safe_command_cases`.
AETHER_VAULT_QUIET_BUT_OTHERWISE_REVIEWED_COMMANDS: tuple[str, ...] = (
    'git commit -m "av push docs"',
    "python -m av_cli.main status",
)

AETHER_VAULT_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python -m av_cli.main commit -m x", "command.aether-vault.commit"),
    ("python3 -m av_cli.launcher push", "command.aether-vault.push"),
    ("py -m av_cli.main --output json gc", "command.aether-vault.gc"),
    ("exec av push", "command.aether-vault.push"),
    ("xargs av gc", "command.aether-vault.gc"),
    ("xargs -n 1 av push", "command.aether-vault.push"),
)


def _enable_layer(*extension_ids: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=tuple(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.ENABLED,
            )
            for extension_id in extension_ids
        ),
    )


def test_aether_vault_review_and_quiet_split(tmp_path: Path) -> None:
    """Enabled, `commit`/`push`/`gc`/... reach review; read-only commands stay quiet."""

    layers = (_enable_layer(_EXTENSION_ID),)
    review_rule_ids = {rule_id for _command, _action_class, rule_id in AETHER_VAULT_REVIEW_CASES}
    failures: list[str] = []

    for command, action_class, rule_id in AETHER_VAULT_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=layers)
        matched = {
            item.match.rule.rule_id for item in evaluation.matches if item.extension.extension_id == _EXTENSION_ID
        }
        if (
            evaluation.controlling_rule_id != rule_id
            or rule_id not in matched
            or evaluation.controlling_action_class != action_class
        ):
            failures.append(
                f"{command!r}: controlling_rule={evaluation.controlling_rule_id!r}, "
                f"matched={sorted(matched)!r}, action={evaluation.controlling_action_class!r}; "
                f"expected rule={rule_id!r}, action={action_class!r}"
            )

    for command in (*AETHER_VAULT_QUIET_COMMANDS, *AETHER_VAULT_QUIET_BUT_OTHERWISE_REVIEWED_COMMANDS):
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=layers)
        if any(item.extension.extension_id == _EXTENSION_ID for item in evaluation.extension_observations):
            failures.append(f"{command!r}: unexpectedly observed by {_EXTENSION_ID}")
        if evaluation.controlling_rule_id in review_rule_ids:
            failures.append(f"{command!r}: controlling_rule={evaluation.controlling_rule_id!r} unexpectedly")

    for command in AETHER_VAULT_SAFE_VARIANT_COMMANDS:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=layers)
        if evaluation.controlling_rule_id in review_rule_ids:
            failures.append(f"{command!r}: safe variant unexpectedly controlling={evaluation.controlling_rule_id!r}")

    assert not failures, "\n".join(failures)


def test_aether_vault_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in AETHER_VAULT_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id, command
        assert all(item.extension.extension_id != _EXTENSION_ID for item in evaluation.extension_observations), command


def test_aether_vault_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect module and wrapper invocations reach review and attribute to our rules."""

    for command, expected_rule in AETHER_VAULT_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == _EXTENSION_ID}
        assert expected_rule in matched, command


def test_aether_vault_preview_help_and_read_only_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases((*AETHER_VAULT_QUIET_COMMANDS, *AETHER_VAULT_SAFE_VARIANT_COMMANDS), tmp_path)


def test_aether_vault_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/leon1706-lol/Aether-Vault",)
    assert risk_classes_for_command_action("Aether-Vault push command") == ("network_egress",)
    assert risk_classes_for_command_action("Aether-Vault garbage collection command") == ("destructive_shell",)
