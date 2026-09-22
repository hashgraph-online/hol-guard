"""Structured txc vault command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from tests.native_command_test_support import real_native_command_evaluation

EXTENSION_ID = "command.txc"
ENABLED = ((("extension", EXTENSION_ID, "enabled"),))

# txc 0.7.2. clap infers subcommands, so `txc v co` is `txc vault copy`; it does
# not infer long flags, so `--pri` is rejected and flags are matched exactly.
TXC_REVIEW_CASES: tuple[tuple[str, str], ...] = (
    ("txc vault copy github", "command.txc.vault-copy"),
    ("txc vault co github", "command.txc.vault-copy"),
    ("txc v co github", "command.txc.vault-copy"),
    ("txc vault copy visa --field cvv", "command.txc.vault-copy"),
    ("txc vault copy work/openai --print", "command.txc.vault-copy-print"),
    ("txc v co work/openai --print", "command.txc.vault-copy-print"),
    ("txc vault grant work/openai --to age1abc", "command.txc.vault-grant"),
    ("txc vault g work/openai --to age1abc", "command.txc.vault-grant"),
    ("txc vault grant work/openai --to-file", "command.txc.vault-grant"),
    ("txc vault recipients personal --add age1abc", "command.txc.vault-recipients-add"),
    ("txc vault rec personal --add age1abc", "command.txc.vault-recipients-add"),
    ("txc vault create team --recipient age1abc", "command.txc.vault-create-recipient"),
    ("txc vault move github work", "command.txc.vault-move"),
    ("txc vault mv github work", "command.txc.vault-move"),
    ("txc vault m github work", "command.txc.vault-move"),
    ("txc vault delete work --yes", "command.txc.vault-delete"),
    ("txc vault d work", "command.txc.vault-delete"),
    ("txc vault rm github", "command.txc.vault-rm"),
)


def _matched_rules(command: str, tmp_path: Path, *, enabled: bool) -> set[str]:
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=ENABLED if enabled else None,
    ).evaluation
    return {
        item.rule.rule_id
        for item in evaluation.extension_observations
        if item.extension.extension_id == EXTENSION_ID
    }


def test_txc_vault_secret_and_destructive_commands_reach_review(tmp_path: Path) -> None:
    """Every reviewed vault operation attributes to its owning rule."""

    failures: list[str] = []
    for command, expected_rule in TXC_REVIEW_CASES:
        matched = _matched_rules(command, tmp_path, enabled=True)
        if expected_rule not in matched:
            failures.append(f"{command!r}: expected {expected_rule!r}, matched {sorted(matched)!r}")
    assert not failures, "\n".join(failures)


# `show` masks every secret and `list` never decrypts one, so neither is reviewed.
# Entry and vault names are arbitrary operands: a name that looks like an
# abbreviated subcommand must not be mistaken for one.
TXC_SAFE_COMMANDS: tuple[str, ...] = (
    "txc vault show github",
    "txc vault show visa",
    "txc vault list",
    "txc vault list --favourites",
    "txc vault list --recent",
    "txc vault recipients personal",
    "txc vault fingerprint personal",
    "txc vault history personal",
    "txc vault writer",
    "txc vault init",
    "txc vault --help",
    "txc vault copy --help",
    "txc vault grant --help",
    "txc vault delete --help",
    "txc url-encode hello",
    # Operands that collide with abbreviated subcommands.
    "txc vault show d",
    "txc vault show g",
    "txc vault show m",
    "txc vault show rm",
    "txc vault list co",
)


def test_txc_read_only_and_help_commands_remain_safe(tmp_path: Path) -> None:
    """Masked reads, help, and subcommand-shaped operands stay unreviewed."""

    failures: list[str] = []
    for command in TXC_SAFE_COMMANDS:
        matched = _matched_rules(command, tmp_path, enabled=True)
        if matched:
            failures.append(f"{command!r}: unexpectedly matched {sorted(matched)!r}")
    assert not failures, "\n".join(failures)


def test_txc_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Community extensions stay off until a local administrator enables them."""

    for command, rule_id in TXC_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != EXTENSION_ID for item in evaluation.extension_observations)


def test_txc_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(EXTENSION_ID)
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
