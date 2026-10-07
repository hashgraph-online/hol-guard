"""Native behavior of the command.vttforge source."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.native_command_test_support import _resolve_native_binary, real_native_command_evaluation

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_PATH = ROOT / "contributions/command-sources/command.vttforge.json"
_FIXTURE_PATH = ROOT / "tests/fixtures/command-source-vttforge.v1.json"
_COMPILER_ENV = "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"
_ENABLED = (("extension", "command.vttforge", "enabled"),)

# Wrapped lines (exec, xargs) and command or parameter substitution are judged
# by Guard before any extension runs. The rules still declare those launchers,
# so they apply once Guard evaluates the wrapped command; until then each such
# line must report why it is uncertain.
VTTFORGE_REVIEW_CASES: tuple[tuple[str, str], ...] = (
    ("vttforge init my-system", "command.vttforge.init"),
    ("vttforge init my-system --type system --lang ts --yes", "command.vttforge.init"),
    ("vttforge init my-module --type module --no-install --no-git", "command.vttforge.init"),
    ("vttforge lint --fix", "command.vttforge.lint-fix"),
    ("vttforge lint ./packages/my-system --fix --no-audit", "command.vttforge.lint-fix"),
    ("vttforge migrate --write", "command.vttforge.migrate-write"),
    ("vttforge migrate ./my-system --write --strict", "command.vttforge.migrate-write"),
    ("vttforge migrate --data-models --style sdk --lang ts --write", "command.vttforge.migrate-write"),
    ("vttforge migrate --sheets --write --json", "command.vttforge.migrate-write"),
    ("vttforge lint $FLAGS", "command.vttforge.lint-fix"),
    ("vttforge lint ./my-system ${LINT_FLAGS}", "command.vttforge.lint-fix"),
    ("vttforge migrate $(echo --write)", "command.vttforge.migrate-write"),
    ("vttforge migrate ./my-system `cat flags`", "command.vttforge.migrate-write"),
    ("exec vttforge init my-system", "command.vttforge.init"),
    ("xargs -n 1 vttforge lint --fix", "command.vttforge.lint-fix"),
    ("exec vttforge migrate --write", "command.vttforge.migrate-write"),
    ("xargs vttforge migrate ./my-system $FLAGS", "command.vttforge.migrate-write"),
    ("exec -a vtt vttforge lint --fix", "command.vttforge.lint-fix"),
    ("xargs -a targets vttforge migrate --write", "command.vttforge.migrate-write"),
    ("xargs --max-args 1 -a targets vttforge init", "command.vttforge.init"),
    ("xargs -a targets vttforge lint $FLAGS", "command.vttforge.lint-fix"),
    ("exec -a vtt vttforge $ARGS --write", "command.vttforge.migrate-write"),
    ("xargs -0 vttforge migrate --write", "command.vttforge.migrate-write"),
    ("xargs --null -t vttforge lint --fix", "command.vttforge.lint-fix"),
    ("xargs -0rt vttforge lint --fix", "command.vttforge.lint-fix"),
    ("xargs --no-run-if-empty vttforge migrate --write", "command.vttforge.migrate-write"),
    ("exec -c vttforge init my-system", "command.vttforge.init"),
    ("xargs -0 vttforge lint $FLAGS", "command.vttforge.lint-fix"),
    ("xargs --verbose vttforge $ARGS --write", "command.vttforge.migrate-write"),
    ("xargs -r vttforge lint --fix", "command.vttforge.lint-fix"),
    ("xargs -p vttforge init my-system", "command.vttforge.init"),
    ("xargs -R 5 vttforge lint --fix", "command.vttforge.lint-fix"),
    ("xargs -P 4 vttforge migrate --write", "command.vttforge.migrate-write"),
    ("xargs -I {} vttforge init {}", "command.vttforge.init"),
    ("xargs -L 1 vttforge migrate $FLAGS", "command.vttforge.migrate-write"),
    ("xargs -r vttforge.exe lint $FLAGS", "command.vttforge.lint-fix"),
    ("xargs --unknown-option vttforge init my-system", "command.vttforge.init"),
    ("xargs --unknown-option value vttforge lint $FLAGS", "command.vttforge.lint-fix"),
    ("vttforge $SUBCOMMAND --fix", "command.vttforge.lint-fix"),
    ("vttforge $(pick) ./my-system --write --strict", "command.vttforge.migrate-write"),
    ("vttforge $VTTFORGE_ARGS", "command.vttforge.init"),
    ("vttforge ${SUB} my-system --yes", "command.vttforge.init"),
    ("vttforge `cat sub` $FLAGS", "command.vttforge.init"),
    ("exec vttforge $ARGS", "command.vttforge.init"),
    ("vttforge $SUBCOMMAND --write", "command.vttforge.migrate-write"),
    ("vttforge $SUBCOMMAND", "command.vttforge.init"),
    ("exec vttforge.cmd init my-system", "command.vttforge.init"),
    ("exec vttforge.CMD $ARGS", "command.vttforge.init"),
    ("xargs vttforge.exe lint --fix", "command.vttforge.lint-fix"),
    ("xargs vttforge.exe migrate --write", "command.vttforge.migrate-write"),
    ("exec -a vtt vttforge.cmd $ARGS --write", "command.vttforge.migrate-write"),
    ("vttforge.cmd lint $FLAGS", "command.vttforge.lint-fix"),
    ("vttforge.exe lint $FLAGS", "command.vttforge.lint-fix"),
    ("vttforge.CMD lint $FLAGS", "command.vttforge.lint-fix"),
    ("exec vttforge.cmd lint $FLAGS", "command.vttforge.lint-fix"),
    ("xargs -n 1 vttforge.EXE lint $FLAGS", "command.vttforge.lint-fix"),
)

# A literal writing flag is reviewed whatever the subcommand token, since an
# expanded subcommand may be the one that writes.
VTTFORGE_REVIEW_CASES += (
    ("vttforge audit --fix", "command.vttforge.lint-fix"),
    ("vttforge audit --write", "command.vttforge.migrate-write"),
)

VTTFORGE_SAFE_COMMANDS: tuple[str, ...] = (
    "vttforge audit",
    "vttforge audit ./my-system --strict --json",
    "vttforge lint",
    "vttforge lint ./my-system --strict",
    "vttforge lint --no-audit",
    "vttforge migrate",
    "vttforge migrate ./my-system --strict",
    "vttforge migrate --json",
    "vttforge migrate --data-models --style sdk",
    "vttforge migrate --sheets --lang ts",
    "vttforge --help",
    "vttforge init --help",
    "vttforge init -h",
    "vttforge lint --help",
    "vttforge migrate --help",
    "vttforge lint --fix --help",
    "vttforge migrate --write --help",
    "vttforge init my-system --yes -h",
    "vttforge lint $FLAGS --help",
    "vttforge migrate ${FLAGS} --help",
    "vttforge $SUBCOMMAND --help",
    "vttforge $(pick) --write --help",
    "exec vttforge $ARGS --help",
    "xargs -n 1 vttforge lint $FLAGS --help",
    "vttforge audit $FLAGS",
    "xargs vttforge audit ./my-system",
    "xargs -a targets vttforge audit",
    "exec -a vtt vttforge migrate --write --help",
    "exec vttforge.cmd lint --fix --help",
    "xargs vttforge.exe audit ./my-system",
    "xargs -0 vttforge lint",
    "xargs -r vttforge migrate ./my-system",
    "xargs -P 4 vttforge audit",
    "xargs -r vttforge lint --fix --help",
    "xargs -a vttforge lint --fix",
)


def _vttforge_rules(command: str, tmp_path: Path, *, enabled: bool = True) -> tuple[str | None, list[str]]:
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=_ENABLED if enabled else (),
    ).evaluation
    if evaluation.command.confidence != "exact":
        assert evaluation.command.uncertainty_reason is not None, command
        return evaluation.command.uncertainty_reason, []
    rules = sorted(
        item.rule.rule_id
        for item in evaluation.extension_observations
        if item.extension.extension_id == "command.vttforge" and item.effective_evidence
    )
    return None, rules


def test_vttforge_source_declares_three_writing_rules() -> None:
    source = json.loads(_SOURCE_PATH.read_text())
    assert source["schema"] == "guard.command-extension-source.v1"
    extension = source["extension"]
    assert extension["extension_id"] == "command.vttforge"
    assert {rule["rule_id"] for rule in extension["rules"]} == {
        "command.vttforge.init",
        "command.vttforge.lint-fix",
        "command.vttforge.migrate-write",
    }
    assert extension["reference_urls"]
    assert all(url.startswith("https://") for url in extension["reference_urls"])


def _expected_uncertainty(command: str) -> str | None:
    if command.startswith(("exec ", "xargs ")):
        return "nested_command_executor_not_yet_supported"
    if "$(" in command or "`" in command:
        return "command_substitution_not_yet_supported"
    if "${" in command:
        return "parameter_expansion_not_yet_supported"
    return None


def test_vttforge_writing_commands_reach_one_rule(tmp_path: Path) -> None:
    for command, expected_rule in VTTFORGE_REVIEW_CASES:
        uncertainty, rules = _vttforge_rules(command, tmp_path)
        # Guard settles these lines before extensions run. Pin the reason, so
        # the case turns into rule coverage the day Guard evaluates it exactly.
        assert uncertainty == _expected_uncertainty(command), command
        if uncertainty is None:
            assert rules == [expected_rule], command


def test_vttforge_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _expected_rule in VTTFORGE_REVIEW_CASES:
        _uncertainty, rules = _vttforge_rules(command, tmp_path, enabled=False)
        assert rules == [], command


def test_vttforge_read_only_preview_and_help_commands_match_no_rule(tmp_path: Path) -> None:
    for command in VTTFORGE_SAFE_COMMANDS:
        uncertainty, rules = _vttforge_rules(command, tmp_path)
        assert uncertainty == _expected_uncertainty(command), command
        assert rules == [], command


def _trust_classes(trust: dict, extension_id: str) -> tuple[str, ...]:
    classes = tuple(name for name, ids in trust["classes"].items() if extension_id in ids)
    assert len(classes) == 1, "each fixture source needs exactly one reviewed trust class"
    return classes


def test_vttforge_portable_fixture_binds_canonical_sources() -> None:
    fixture = json.loads(_FIXTURE_PATH.read_text())
    assert fixture["schema"] == "guard.command-extension-fixtures.v1"
    assert _FIXTURE_PATH.stat().st_size <= 1_048_576
    build = fixture["build"]
    assert build["schema"] == "guard.command-extension-build.v1"
    ids = [source["extension"]["extension_id"] for source in build["sources"]]
    assert "command.vttforge" in ids
    assert len(ids) == len(set(ids))
    for source, extension_id in zip(build["sources"], ids, strict=True):
        assert source == json.loads((ROOT / "contributions/command-sources" / f"{extension_id}.json").read_text())
    canonical_trust = json.loads((ROOT / "contracts/extensions/trust-class-map.v1.json").read_text())
    assert build["trust"]["schemaVersion"] == canonical_trust["schemaVersion"]
    assert build["trust"]["publishers"] == canonical_trust["publishers"]
    for extension_id in ids:
        assert _trust_classes(build["trust"], extension_id) == _trust_classes(canonical_trust, extension_id)
    assert _trust_classes(build["trust"], "command.vttforge") == ("external",)


def test_vttforge_behavior_fixtures_pass_against_the_native_evaluator() -> None:
    compiler = _resolve_native_binary(_COMPILER_ENV, "guard-command-source")
    if compiler is None:
        pytest.skip("offline native source compiler is not available (missing guard-command-source)")
    fixture = json.loads(_FIXTURE_PATH.read_text())
    completed = subprocess.run(
        [str(compiler), "test"],
        input=json.dumps(fixture).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    result = json.loads(completed.stdout)
    assert result["target_commands_executed"] == 0
    assert len(result["cases"]) == len(fixture["cases"])
    failures = [case for case in result["cases"] if not case["passed"]]
    assert result["ok"] is True, f"{len(failures)} fixture case(s) failed: {failures[:5]}"
