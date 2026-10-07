"""Behavior-fixture regression for the declarative command.claude-tmux source."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.native_command_test_support import _resolve_native_binary

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_PATH = ROOT / "contributions/command-sources/command.claude-tmux.json"
_FIXTURE_PATH = ROOT / "tests/fixtures/command-source-claude-tmux.v1.json"
_COMPILER_ENV = "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"
_TEARDOWN_RULE = "command.claude-tmux.session-teardown"
_PRUNE_RULE = "command.claude-tmux.process-prune"


def _run_fixtures(request: dict[str, object]) -> dict[str, object]:
    compiler = _resolve_native_binary(_COMPILER_ENV, "guard-command-source")
    if compiler is None:
        pytest.skip("offline native source compiler is not available (missing guard-command-source)")
    completed = subprocess.run(
        [str(compiler), "test"],
        input=json.dumps(request).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return json.loads(completed.stdout)


def test_claude_tmux_source_is_present_and_declares_its_rules() -> None:
    source = json.loads(_SOURCE_PATH.read_text())
    extension = source["extension"]

    assert source["schema"] == "guard.command-extension-source.v1"
    assert extension["extension_id"] == "command.claude-tmux"
    assert {rule["rule_id"] for rule in extension["rules"]} == {_TEARDOWN_RULE, _PRUNE_RULE}
    assert sorted(extension["executables"]) == ["claude-tmux-cleanup", "ctc"]
    assert extension["risk_classes"] == ["destructive_shell"]
    assert extension["reference_urls"] == ["https://github.com/s403o/claude-code-tmux"]
    assert all(url.startswith("https://") for url in extension["reference_urls"])
    # Every rule owns one permission, and the prune rule carries the higher
    # severity because it reaches processes tmux never held.
    permissions = {permission["permission_id"] for permission in extension["permissions"]}
    assert {rule["permission_id"] for rule in extension["rules"]} == permissions
    severities = {rule["rule_id"]: rule["severity"] for rule in extension["rules"]}
    assert severities == {_TEARDOWN_RULE: "medium", _PRUNE_RULE: "high"}


def test_claude_tmux_source_declares_a_dry_run_counterpart_for_every_rule() -> None:
    """--dry-run prints what would be taken and signals nothing, so it is the
    documented safe variant of both destructive rules."""

    source = json.loads(_SOURCE_PATH.read_text())
    for rule in source["extension"]["rules"]:
        assert [variant["variant_id"] for variant in rule["safe_variants"]] == ["dry-run"], rule["rule_id"]


def test_claude_tmux_portable_fixture_binds_canonical_sources() -> None:
    """The fixture embeds the sources it compiles, so those copies have to stay
    equal to the canonical files: a stale copy would keep passing while proving
    nothing about the source this change ships."""

    fixture = json.loads(_FIXTURE_PATH.read_text())
    assert fixture["schema"] == "guard.command-extension-fixtures.v1"
    sources = fixture["build"]["sources"]
    ids = [source["extension"]["extension_id"] for source in sources]
    assert "command.claude-tmux" in ids
    assert len(ids) == len(set(ids))
    # Native admission also requires the canonical compatibility-rule inventory,
    # so the sources owning those rules travel with this one.
    for source, extension_id in zip(sources, ids, strict=True):
        canonical = ROOT / "contributions/command-sources" / f"{extension_id}.json"
        assert source == json.loads(canonical.read_text()), extension_id

    # The trust map is maintainer-owned and is regenerated when this source
    # lands, so the embedded copy may run ahead of the checked-in one by exactly
    # this extension's external entry, and by nothing else.
    repository_trust = json.loads((ROOT / "contracts/extensions/trust-class-map.v1.json").read_text())
    embedded_trust = fixture["build"]["trust"]
    pending = {"command.claude-tmux"}
    assert set(embedded_trust["classes"]["external"]) - set(repository_trust["classes"]["external"]) <= pending
    assert set(repository_trust["classes"]["external"]) <= set(embedded_trust["classes"]["external"])
    for trust_class, members in embedded_trust["classes"].items():
        if trust_class == "external":
            continue
        assert members == repository_trust["classes"][trust_class], trust_class


def test_claude_tmux_fixture_covers_fed_consent_and_its_safe_counterparts() -> None:
    """The fixture is the behavior contract, so it must keep both destructive
    shapes and the counterparts that must never be attributed to these rules."""

    fixture = json.loads(_FIXTURE_PATH.read_text())
    commands = {case["command"] for case in fixture["cases"]}
    destructive = {case["command"] for case in fixture["cases"] if case["expected_effective_segments"]}
    inert = commands - destructive

    # --force and fed consent are the two ways the confirmation prompt stops
    # being a gate, including consent forwarded through a bare `cat`.
    assert {"ctc --all --force", "ctc --force", "yes | ctc --all", "yes | cat | ctc --all"} <= destructive
    assert {"yes | cat - | ctc --all", "yes | ctc", "yes | ctc --prune"} <= destructive
    # Previews, prompted runs, refusals, unknown piped data and a `yes` that
    # exits before writing consent must claim no segment of these rules.
    assert {"ctc --all --force --dry-run", "ctc --all", "ctc --help"} <= inert
    assert {"yes n | ctc --all", "cat notes | ctc --all", "yes --help | ctc --all"} <= inert


def test_claude_tmux_behavior_fixtures_pass_against_the_native_evaluator() -> None:
    """Runs the fixture cases through the real compiled catalog via
    `guard-command-source test`, so the source is proven without depending on a
    maintainer-owned regeneration of the packaged program."""

    fixture = json.loads(_FIXTURE_PATH.read_text())
    result = _run_fixtures(fixture)
    assert result["target_commands_executed"] == 0
    assert len(result["cases"]) == len(fixture["cases"])
    failures = [case for case in result.get("cases", []) if not case["passed"]]
    assert result.get("ok") is True, f"{len(failures)} fixture case(s) failed: {failures[:5]}"
