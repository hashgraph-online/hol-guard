"""Tests for harness protection contracts (Phase 19)."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.adapters.contracts import (
    HARNESS_CONTRACTS,
    HarnessProtectionContract,
    contract_for,
    harness_contracts_table,
)


class TestHarnessProtectionContract:
    def test_fields_present(self) -> None:
        c = HarnessProtectionContract(
            harness="test",
            install_aliases=("test",),
            config_paths=("~/.test/config.toml",),
            event_surfaces=("shell",),
            native_approval=True,
            browser_fallback=False,
            resume_support=True,
            known_blind_spots="none",
            smoke_command="hol-guard test --version",
        )
        assert c.harness == "test"
        assert c.native_approval is True
        assert "shell" in c.event_surfaces

    def test_frozen(self) -> None:
        c = HarnessProtectionContract(
            harness="test",
            install_aliases=(),
            config_paths=(),
            event_surfaces=(),
            native_approval=False,
            browser_fallback=False,
            resume_support=False,
            known_blind_spots="none",
            smoke_command="",
        )
        with pytest.raises((AttributeError, TypeError)):
            c.harness = "other"  # type: ignore[misc]


class TestHarnessRegistry:
    def test_all_harnesses_present(self) -> None:
        names = {c.harness for c in HARNESS_CONTRACTS}
        assert "codex" in names
        assert "claude-code" in names
        assert "opencode" in names
        assert "copilot" in names
        assert "cursor" in names
        assert "gemini" in names
        assert "hermes" in names
        assert "openclaw" in names

    def test_every_contract_has_smoke_command(self) -> None:
        for c in HARNESS_CONTRACTS:
            assert c.smoke_command.strip(), f"{c.harness} missing smoke_command"

    def test_every_contract_has_known_blind_spots(self) -> None:
        for c in HARNESS_CONTRACTS:
            assert c.known_blind_spots.strip(), f"{c.harness} missing known_blind_spots"

    def test_every_contract_states_native_approval(self) -> None:
        for c in HARNESS_CONTRACTS:
            assert isinstance(c.native_approval, bool), f"{c.harness} native_approval must be bool"

    def test_every_contract_has_at_least_one_alias(self) -> None:
        for c in HARNESS_CONTRACTS:
            assert len(c.install_aliases) > 0, f"{c.harness} must have at least one install alias"

    def test_all_aliases_are_unique(self) -> None:
        from collections import Counter

        all_aliases: list[str] = []
        for c in HARNESS_CONTRACTS:
            all_aliases.extend(c.install_aliases)
        counts = Counter(all_aliases)
        duplicates = {alias: count for alias, count in counts.items() if count > 1}
        assert not duplicates, f"Found duplicate aliases: {duplicates}"


class TestContractFor:
    def test_exact_match(self) -> None:
        c = contract_for("codex")
        assert c is not None
        assert c.harness == "codex"

    def test_alias_match(self) -> None:
        c = contract_for("claude")
        assert c is not None
        assert c.harness == "claude-code"

    def test_codex_cli_alias(self) -> None:
        c = contract_for("codex")
        assert c is not None
        assert "codex" in c.install_aliases

    def test_claude_code_alias(self) -> None:
        c = contract_for("claude-code")
        assert c is not None
        assert "claude" in c.install_aliases and "claude-code" in c.install_aliases

    def test_opencode_alias(self) -> None:
        c = contract_for("opencode")
        assert c is not None

    def test_copilot_alias(self) -> None:
        c = contract_for("copilot")
        assert c is not None

    def test_unknown_returns_none(self) -> None:
        assert contract_for("unknown-harness-xyz") is None


class TestInstallAliases:
    def test_install_codex(self) -> None:
        c = contract_for("codex")
        assert c is not None
        assert "codex" in c.install_aliases

    def test_install_claude_code(self) -> None:
        c = contract_for("claude-code")
        assert c is not None
        assert "claude-code" in c.install_aliases and "claude" in c.install_aliases

    def test_install_opencode(self) -> None:
        c = contract_for("opencode")
        assert c is not None
        assert "opencode" in c.install_aliases

    def test_install_copilot(self) -> None:
        c = contract_for("copilot")
        assert c is not None
        assert "copilot" in c.install_aliases


class TestHarnessContractsTable:
    def test_returns_markdown(self) -> None:
        table = harness_contracts_table()
        assert "| Harness |" in table
        assert "codex" in table
        assert "claude-code" in table

    def test_all_harnesses_in_table(self) -> None:
        table = harness_contracts_table()
        for c in HARNESS_CONTRACTS:
            assert c.harness in table

    def test_columns_present(self) -> None:
        table = harness_contracts_table()
        assert "Native Approval" in table
        assert "Browser Fallback" in table
        assert "Resume" in table


class TestContractAliasesMatchAdapter:
    """All install_aliases in every contract must be accepted by get_adapter()."""

    def test_all_install_aliases_are_resolvable(self) -> None:
        from codex_plugin_scanner.guard.adapters import get_adapter

        for contract in HARNESS_CONTRACTS:
            for alias in contract.install_aliases:
                try:
                    get_adapter(alias)
                except ValueError:
                    pytest.fail(
                        f"Contract '{contract.harness}' lists alias '{alias}' but get_adapter() does not recognize it"
                    )
