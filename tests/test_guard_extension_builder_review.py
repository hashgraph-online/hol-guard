"""Human-review bindings and rule-local literal evidence never widen other rules."""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import build_kit
from codex_plugin_scanner.guard.extension_builder.models import Discovery
from codex_plugin_scanner.guard.extension_builder.review import default_review, load_review
from codex_plugin_scanner.guard.runtime.command_extension_observations import observe_command_extensions
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_reviewed_literal_matcher import (
    ReviewedLiteralCommandMatcher,
    validate_reviewed_literal_argv,
)
from codex_plugin_scanner.guard.runtime.command_rules import CommandSafetyRule, CommandSafeVariant, ExecutableMatcher
from tests.extension_builder_support import make_discovery, make_kit


def reviewed_entry(discovery: Discovery, path: tuple[str, ...]) -> tuple[dict[str, object], dict[str, object]]:
    payload = default_review(discovery).to_dict()
    entries = payload["entries"]
    assert isinstance(entries, dict)
    operation = next(row for row in discovery.operations if row.path == path)
    entry = entries[operation.operation_id]
    assert isinstance(entry, dict)
    entry.update(
        {
            "reviewed": True,
            "rationale": "Checked this exact fixture operation.",
            "evidenceUrl": discovery.metadata.homepage,
        }
    )
    return payload, entry


@pytest.mark.parametrize("kind,state", [("cli", "review"), ("mcp", "inherit")])
def test_default_review_never_uses_name_or_annotation_to_allow(tmp_path: Path, kind: str, state: str) -> None:
    discovery = make_discovery(tmp_path, kind)
    review = default_review(discovery)
    assert all(
        decision.state == state and not decision.reviewed and not decision.safe_argv for _, decision in review.entries
    )
    assert load_review(review.to_dict(), discovery) == review


def test_source_drift_invalidates_prior_review(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    payload = default_review(discovery).to_dict()
    payload["discoveryDigest"] = "0" * 64
    with pytest.raises(BuilderError, match="Discovery changed"):
        load_review(payload, discovery)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_review_requires_exact_inventory_membership(tmp_path: Path, mutation: str) -> None:
    discovery = make_discovery(tmp_path)
    payload = default_review(discovery).to_dict()
    entries = payload["entries"]
    assert isinstance(entries, dict)
    key = next(iter(entries))
    if mutation == "missing":
        entries.pop(key)
    else:
        entries["op-" + "f" * 16] = copy.deepcopy(entries[key])
    with pytest.raises(BuilderError, match="exactly the operations"):
        load_review(payload, discovery)


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "block"),
        ("rationale", "Incomplete review"),
        ("riskClasses", ["execution", "network_egress"]),
        ("saferAlternative", "Use a dry run"),
    ],
)
def test_behavior_edits_cannot_be_labeled_unreviewed(tmp_path: Path, field: str, value: object) -> None:
    discovery = make_discovery(tmp_path)
    payload = default_review(discovery).to_dict()
    entries = payload["entries"]
    assert isinstance(entries, dict)
    next(iter(entries.values()))[field] = value
    with pytest.raises(BuilderError, match="explicit completed review"):
        load_review(payload, discovery)


@pytest.mark.parametrize(
    "field,value", [("rationale", ""), ("evidenceUrl", ""), ("evidenceUrl", "http://example.test")]
)
def test_reviewed_decisions_require_rationale_and_publishable_evidence(tmp_path: Path, field: str, value: str) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry[field] = value
    with pytest.raises(BuilderError):
        load_review(payload, discovery)


@pytest.mark.parametrize("state", ["allow", "inherit"])
def test_cli_does_not_generate_broad_allow_decisions(tmp_path: Path, state: str) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry["state"] = state
    with pytest.raises(BuilderError, match="incompatible"):
        load_review(payload, discovery)


def test_review_cannot_drop_execution_risk(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry["riskClasses"] = ["network_egress"]
    with pytest.raises(BuilderError, match="execution risk"):
        load_review(payload, discovery)


def test_exact_reviewed_cli_and_mcp_decisions_compile(tmp_path: Path) -> None:
    cli = make_kit(tmp_path, reviewed=True)
    mcp = make_kit(tmp_path, "mcp", reviewed=True)
    assert cli.summary()["exactSafeInvocations"] == 1
    assert cli.summary()["explicitBlocks"] == 1
    assert mcp.summary()["explicitBlocks"] == 1
    assert cli.summary()["activeProtectionChanged"] is False


@pytest.mark.parametrize(
    "argv",
    [
        ["items", "list", "&&", "echo"],
        ["items", "list", "$(id)"],
        ["items", "list", "*"],
        ["items", "list", "$HOME"],
        ["items", "list", ">out"],
        ["items", "list", "a b"],
        ["items", "list", "x\ny"],
        ["items", "list", "`id`"],
        ["items", "list", "KEY=value"],
    ],
)
def test_safe_vectors_reject_shell_syntax_and_expansions(tmp_path: Path, argv: list[str]) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry["safeArgv"] = [argv]
    with pytest.raises(BuilderError):
        load_review(payload, discovery)


@pytest.mark.parametrize("argv", [["items", "delete"], ["status"], ["--help"]])
def test_safe_vectors_are_bound_to_their_exact_operation(tmp_path: Path, argv: list[str]) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry["safeArgv"] = [argv]
    with pytest.raises(BuilderError, match="operation path"):
        load_review(payload, discovery)


@pytest.mark.parametrize(
    "argv", [["items", "list", "--not-discovered"], ["items", "list", "--profile"], ["items", "list", "--json=yes"]]
)
def test_safe_vectors_require_known_option_arity(tmp_path: Path, argv: list[str]) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry["safeArgv"] = [argv]
    with pytest.raises(BuilderError, match="option"):
        load_review(payload, discovery)


def test_blocked_operation_cannot_gain_a_safe_variant(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ("items", "delete"))
    entry.update({"state": "block", "safeArgv": [["items", "delete", "--help"]]})
    with pytest.raises(BuilderError, match="nonblocked"):
        load_review(payload, discovery)


def test_root_safe_variants_cannot_preapprove_unknown_commands(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    payload, entry = reviewed_entry(discovery, ())
    entry["safeArgv"] = [["undiscovered"]]
    with pytest.raises(BuilderError, match="Root safe variants"):
        load_review(payload, discovery)
    entry["safeArgv"] = [["--undiscovered"]]
    with pytest.raises(BuilderError, match="option"):
        load_review(payload, discovery)
    entry["safeArgv"] = [["--help"]]
    assert load_review(payload, discovery)


def test_rule_revision_changes_with_review_not_only_source(tmp_path: Path) -> None:
    discovery = make_discovery(tmp_path)
    before = build_kit(discovery, default_review(discovery))
    payload, entry = reviewed_entry(discovery, ("items", "list"))
    entry["safeArgv"] = [["items", "list", "--json"]]
    after = build_kit(discovery, load_review(payload, discovery))
    assert before.revision != after.revision
    assert before.discovery.binding == after.discovery.binding
    before_detector = next(content for path, content in before.files if path.endswith("extensions.py"))
    after_detector = next(content for path, content in after.files if path.endswith("extensions.py"))
    before_revision = next(line for line in before_detector.splitlines() if line.startswith("_RULE_REVISION"))
    after_revision = next(line for line in after_detector.splitlines() if line.startswith("_RULE_REVISION"))
    assert before_revision != after_revision
    assert '"state": "allow"' not in canonical_json(after.review.to_dict())


@pytest.mark.parametrize(
    "command",
    [
        "builder-demo items list --json --force",
        "builder-demo items list --json extra",
        "builder-demo items list --json; builder-demo items delete",
        "builder-demo items list --json && echo done",
        "builder-demo items list --json | tee out",
        "builder-demo items list --json >out",
        "builder-demo items list --json 2>/dev/null",
        "builder-demo items list --json $(echo extra)",
        "env builder-demo items list --json",
        "sudo builder-demo items list --json",
        "command builder-demo items list --json",
        "PATH=/tmp builder-demo items list --json",
        "FOO=bar builder-demo items list --json",
        "/usr/bin/builder-demo items list --json",
        "Builder-Demo items list --json",
        "builder-demo ITEMS list --json",
        'builder-demo "items" list --json',
        "builder-demo items\tlist --json",
        "builder-demo items list --json\necho next",
    ],
)
def test_literal_matcher_rejects_changed_context(command: str) -> None:
    matcher = ReviewedLiteralCommandMatcher("builder-demo", ("items", "list", "--json"))
    assert not matcher.match(parse_shell_command(command))


def test_literal_matcher_requires_exact_canonical_boundary() -> None:
    matcher = ReviewedLiteralCommandMatcher("builder-demo", ("items", "list", "--json"))
    command = parse_shell_command("builder-demo items list --json")
    assert matcher.match(command)
    for changed in (
        replace(command, dialect="powershell"),
        replace(command, transport="argv"),
        replace(command, confidence="uncertain"),
        replace(command, wrapper_chain=("env",)),
    ):
        assert not matcher.match(changed)
    segment = replace(command.segments[0], environment_names=("CUSTOM_CONFIG",))
    assert not matcher.match(replace(command, segments=(segment,)))


@pytest.mark.parametrize(
    "executable,argv",
    [("../demo", ("status",)), ("demo", ()), ("demo", ("x" * 65,)), ("demo", ("long-value" * 5,) * 3)],
)
def test_literal_matcher_constructor_enforces_its_own_bounds(executable: str, argv: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        validate_reviewed_literal_argv(executable, argv)


def test_owned_safe_evidence_does_not_suppress_an_independent_floor() -> None:
    base = ExecutableMatcher(executables=frozenset({"builder-demo"}))
    safe = CommandSafeVariant("literal", "Reviewed literal", ReviewedLiteralCommandMatcher("builder-demo", ("status",)))
    own = CommandSafetyRule(
        "command.builder-demo.review",
        "Review",
        "Review invocation",
        "medium",
        ("execution",),
        ("builder-demo invocation",),
        ("Inspect target",),
        matcher=base,
        safe_variants=(safe,),
    )
    floor = replace(own, rule_id="command.independent.floor", safe_variants=(), default_mode="enforce")

    @dataclass(frozen=True)
    class Extension:
        extension_id: str
        version: str
        rules: tuple[CommandSafetyRule, ...]

    extensions = (
        Extension("command.builder-demo", "1.0.0", (own,)),
        Extension("command.independent", "1.0.0", (floor,)),
    )
    observations = observe_command_extensions(
        parse_shell_command("builder-demo status"), extensions, (own.rule_id, floor.rule_id)
    )
    assert not observations[0].effective_evidence
    assert observations[1].effective_evidence
    assert observations[1].rule.default_mode == "enforce"
