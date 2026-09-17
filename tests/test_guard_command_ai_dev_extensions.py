"""Structured ai-dev command extension tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_structured_matchers as csm
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_matcher_contracts import MatcherEvidence
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import (
    IndexedCommandMatcher,
    matcher_index_hints,
)
from codex_plugin_scanner.guard.runtime.extension_contribution import load_contribution_payloads
from codex_plugin_scanner.guard.runtime.extension_trust import ids_for_class
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

_INSTALL_FORCE_ACTION = "ai-dev forced integration config overwrite command"
_INDEX_DAEMON_ACTION = "ai-dev index daemon lifecycle command"
_AGENT_MUTATION_ACTION = "ai-dev agent coordination mutation command"

AI_DEV_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    # --- Integrations install --force (and long option prefixes) ---
    (
        "ai-dev integrations install --force",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --forc",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --for",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --fo",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --f",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev --verbose integrations install --force",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install claude --force",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install $FORCE_FLAG",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        'ai-dev integrations install "$FORCE_FLAG"',
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install ${FORCE_FLAG}",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install $(echo --force)",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install `echo --force`",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    # --- Index daemon start ---
    (
        "ai-dev index daemon start",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev --json index daemon start",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon start --foreground",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon start --workers 4",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon $ACTION",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        'ai-dev index daemon "$ACTION"',
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon ${ACTION}",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon $(echo start)",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon `echo start`",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    # --- Index daemon stop ---
    (
        "ai-dev index daemon stop",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop --force",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop -f",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop --timeout 30",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop -t 30",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev --quiet index daemon stop",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    # --- Agents claim ---
    (
        "ai-dev agents claim task-123",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents claim task-123 --agent bot-1",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents --agent bot-1 claim task-123",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents claim 'task with spaces'",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        'ai-dev agents claim "task with spaces"',
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents claim $TASK_ID",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    # --- Agents release ---
    (
        "ai-dev agents release task-123",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release task-123 --agent bot-1",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release task-123 --reason 'blocked on external api'",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        'ai-dev agents release task-123 --reason "blocked on external api"',
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release 'task with spaces'",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release $TASK_ID",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
)


AI_DEV_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    # Executable suffixes
    ("ai-dev.exe integrations install --force", "command.ai-dev.integrations-install-force"),
    ("ai-dev.exe integrations install $FORCE", "command.ai-dev.integrations-install-force"),
    ("ai-dev.exe index daemon start", "command.ai-dev.index-daemon-start"),
    ("ai-dev.exe index daemon", "command.ai-dev.index-daemon-start"),
    ("ai-dev.exe index daemon $ACTION", "command.ai-dev.index-daemon-start"),
    ("ai-dev.exe index daemon stop", "command.ai-dev.index-daemon-stop"),
    ("ai-dev.exe agents claim task-123", "command.ai-dev.agents-claim"),
    ("ai-dev.exe agents release task-123", "command.ai-dev.agents-release"),
    # Python launcher variants (verified module: ai_dev_tools)
    ("python -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("python3 -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("py -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("python -m ai_dev_tools index daemon start", "command.ai-dev.index-daemon-start"),
    ("python3 -m ai_dev_tools index daemon stop", "command.ai-dev.index-daemon-stop"),
    ("py -m ai_dev_tools agents claim task-123", "command.ai-dev.agents-claim"),
    ("python -m ai_dev_tools agents release task-123", "command.ai-dev.agents-release"),
    # Common wrappers: sudo, exec, env, xargs
    ("sudo ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("exec ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("env FOO=bar ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("xargs ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("xargs -n 1 ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("xargs -n 1 python -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("sudo ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("exec ai-dev index daemon stop", "command.ai-dev.index-daemon-stop"),
    ("sudo ai-dev agents claim task-123", "command.ai-dev.agents-claim"),
    ("exec ai-dev agents release task-123", "command.ai-dev.agents-release"),
)


AI_DEV_PIPELINE_AND_CHAINED_CASES: tuple[tuple[str, str], ...] = (
    ("echo yes | ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("ai-dev index daemon status && ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("ai-dev index daemon stop; ai-dev index daemon start", "command.ai-dev.index-daemon-stop"),
    ("ai-dev index daemon stop; ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("ai-dev agents list || ai-dev agents claim task-123", "command.ai-dev.agents-claim"),
    ("ai-dev agents claim task-1; ai-dev agents release task-2", "command.ai-dev.agents-claim"),
    ("ai-dev agents claim task-1; ai-dev agents release task-2", "command.ai-dev.agents-release"),
)


AI_DEV_SAFE_COMMANDS: tuple[str, ...] = (
    # integrations without --force
    "ai-dev integrations install",
    "ai-dev integrations install claude",
    "ai-dev integrations install --help",
    "ai-dev integrations list",
    # index daemon read/status queries
    "ai-dev index daemon status",
    "ai-dev index daemon status --json",
    "ai-dev index daemon status -v",
    "ai-dev index daemon --help",
    "ai-dev index query 'test search'",
    "ai-dev index stats",
    # agents read queries
    "ai-dev agents list",
    "ai-dev agents show task-123",
    "ai-dev agents status",
    "ai-dev agents --help",
    "ai-dev agents claim --help",
    "ai-dev agents release --help",
    # global help & version
    "ai-dev --help",
    "ai-dev -h",
    "ai-dev --version",
    "ai-dev -V",
    # unrelated commands & strings
    "grep 'ai-dev integrations install --force' docs.md",
    "echo ai-dev integrations install --force",
    "cat ai-dev.log",
)


def test_ai_dev_review_cases_match_rules(tmp_path: Path) -> None:
    """All v1 mutation commands match their designated rule in the built-in catalog."""
    for command, _action_class, expected_rule in AI_DEV_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"


def test_ai_dev_wrapper_and_launcher_invocations_match_rules(tmp_path: Path) -> None:
    """Indirect wrappers and launchers properly attribute to ai-dev rules."""
    for command, expected_rule in AI_DEV_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"


def test_ai_dev_pipeline_and_chained_commands_match_rules(tmp_path: Path) -> None:
    """Pipelines, semicolons, and boolean chains evaluate individual commands."""
    for command, expected_rule in AI_DEV_PIPELINE_AND_CHAINED_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"


def test_ai_dev_force_flag_prefixes_and_short_f_contract(tmp_path: Path) -> None:
    """Verify long --force prefixes match, but short -f is not recognized as ai-dev force flag."""
    for flag in ("--force", "--forc", "--for", "--fo", "--f"):
        command = f"ai-dev integrations install {flag}"
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert "command.ai-dev.integrations-install-force" in matched, (
            f"Flag {flag!r} should be recognized as force in {command!r}"
        )

    # -f is an unrecognized short option in ai-dev (not an alias for --force)
    for command in (
        "ai-dev integrations install -f",
        "ai-dev integrations install codex -f",
    ):
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert "command.ai-dev.integrations-install-force" not in matched, (
            f"Short flag -f must not be recognized as ai-dev force flag in {command!r}"
        )


def test_ai_dev_help_with_expansion_arguments_remains_safe(tmp_path: Path) -> None:
    """Explicit help requests override and suppress unresolved shell expansion matching."""
    safe_help_expansion_cases = (
        "ai-dev integrations install --help $ARG",
        'ai-dev integrations install --help "$ARG"',
        "ai-dev integrations install -h ${ARG}",
        "python -m ai_dev_tools integrations install --help $(echo --force)",
        "ai-dev index daemon start --help $ACTION",
        "ai-dev index daemon --help $ACTION",
        "ai-dev index daemon $ACTION --help",
        "ai-dev index daemon ${ACTION} -h",
        "python -m ai_dev_tools index daemon $ACTION --help",
        "exec ai-dev index daemon ${ACTION} -h",
        "xargs ai-dev index daemon $ACTION --help",
    )
    for command in safe_help_expansion_cases:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        ai_dev_rules = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        unsafe_matches = [
            item.rule.rule_id
            for item in observations
            if item.extension.extension_id == "command.ai-dev"
            and not (
                item.safe_variants and {e.segment_index for e in item.matcher_evidence} <= item.safe_segment_indexes
            )
        ]
        assert not unsafe_matches, f"Expected no unsafe ai-dev rule matches for {command!r}, got {unsafe_matches!r}"

    # Normal fail-secure behavior for non-help expansion must remain intact
    non_help_expansions = (
        ("ai-dev integrations install codex $FORCE_FLAG", "command.ai-dev.integrations-install-force"),
        ("ai-dev integrations install $FORCE_FLAG", "command.ai-dev.integrations-install-force"),
        ("ai-dev index daemon $ACTION", "command.ai-dev.index-daemon-start"),
        ("ai-dev index daemon ${ACTION}", "command.ai-dev.index-daemon-start"),
        ("python -m ai_dev_tools index daemon $ACTION", "command.ai-dev.index-daemon-start"),
        ("exec ai-dev index daemon $ACTION", "command.ai-dev.index-daemon-start"),
        ("xargs ai-dev index daemon $ACTION", "command.ai-dev.index-daemon-start"),
    )
    for command, expected_rule in non_help_expansions:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        ai_dev_rules = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in ai_dev_rules, (
            f"Expansion without help must be reviewed: {command!r} expected {expected_rule}"
        )


def test_ai_dev_candidate_rule_ids_indexing() -> None:
    """Registry indexing excludes ai-dev rules from completely unrelated commands."""
    assert not any("ai-dev" in r for r in BUILT_IN_COMMAND_EXTENSION_REGISTRY._unindexed_rule_ids)

    unrelated_commands = (
        "git status",
        "npm test",
        "cargo build",
        "echo hello world",
    )
    for command in unrelated_commands:
        candidates = BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(parse_shell_command(command))
        ai_dev_candidates = [r for r in candidates if "ai-dev" in r]
        assert not ai_dev_candidates, (
            f"Unrelated command {command!r} should not index ai-dev candidate rules, got: {ai_dev_candidates!r}"
        )


def test_ai_dev_xargs_option_variants(tmp_path: Path) -> None:
    """Xargs invocations with value-consuming options properly match sensitive commands."""
    xargs_review_cases = (
        ("xargs --max-procs 2 ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
        ("xargs -P 2 ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
        ("xargs --arg-file input ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
        ("xargs -a input ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
        ("xargs -n 1 ai-dev agents claim task-1 --agent bot", "command.ai-dev.agents-claim"),
    )
    for command, expected_rule in xargs_review_cases:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"

    xargs_safe_cases = (
        "xargs --max-procs 2 ai-dev integrations install",
        "xargs -a input ai-dev index daemon status",
        "xargs -n 1 ai-dev agents list",
    )
    for command in xargs_safe_cases:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        unsafe_matches = [
            item.rule.rule_id
            for item in observations
            if item.extension.extension_id == "command.ai-dev"
            and not (
                item.safe_variants and {e.segment_index for e in item.matcher_evidence} <= item.safe_segment_indexes
            )
        ]
        assert not unsafe_matches, (
            f"Expected no unsafe ai-dev rule matches for safe xargs {command!r}, got {unsafe_matches!r}"
        )


def test_ai_dev_safe_commands_remain_safe(tmp_path: Path) -> None:
    """Read-only and benign commands remain unflagged in policy review."""
    assert_safe_command_cases(AI_DEV_SAFE_COMMANDS, tmp_path)
    for command in AI_DEV_SAFE_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        unsafe_matches = [
            item.rule.rule_id
            for item in observations
            if item.extension.extension_id == "command.ai-dev"
            and not (
                item.safe_variants and {e.segment_index for e in item.matcher_evidence} <= item.safe_segment_indexes
            )
        ]
        assert not unsafe_matches, f"Expected no unsafe ai-dev rule matches for {command!r}, got {unsafe_matches!r}"


def test_ai_dev_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Opt-in extension remains inert in baseline evaluation when not activated."""
    for command, _action_class, rule_id in AI_DEV_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.ai-dev" for item in evaluation.extension_observations)


def test_ai_dev_matcher_evidence_preserves_privacy(tmp_path: Path) -> None:
    """Evidence emitted by ai-dev matchers does not leak sensitive arguments or secrets."""
    for command, _action_class, _expected_rule in AI_DEV_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        for observation in observations:
            if observation.extension.extension_id == "command.ai-dev":
                for evidence in observation.matcher_evidence:
                    assert evidence.detail
                    assert "token" not in evidence.detail.lower()
                    assert "secret" not in evidence.detail.lower()
                    assert "password" not in evidence.detail.lower()


def test_ai_dev_extension_metadata_and_risk_classes() -> None:
    """Extension metadata, references, and risk mappings conform to spec."""
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.ai-dev")
    assert extension is not None
    assert extension.extension_id == "command.ai-dev"
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)

    assert "command.ai-dev" in ids_for_class("external")
    payload = next(item for item in load_contribution_payloads() if item.get("id") == "command.ai-dev")
    assert payload["activation"] == "opt-in"
    assert payload["trustClass"] == "external"
    assert payload["publisher"]["displayName"] == "ai-dev community"
    assert payload["icon"]["background"] == "#2563EB"

    assert risk_classes_for_command_action(_INSTALL_FORCE_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_INDEX_DAEMON_ACTION) == ("destructive_shell", "execution")
    assert risk_classes_for_command_action(_AGENT_MUTATION_ACTION) == ("destructive_shell",)

    # Verify presence in generated public catalog
    catalog_path = Path(__file__).resolve().parents[1] / "docs/guard/extensions/catalog.v1.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog_entry = next((e for e in catalog["entries"] if e["id"] == "command.ai-dev"), None)
    assert catalog_entry is not None
    assert catalog_entry["protectionModel"] == "external-opt-in"
    assert len(catalog_entry["operations"]) == 5


def test_command_structured_matchers_does_not_import_ai_dev() -> None:
    """Architecture test: core structured matchers must not import external extensions."""
    source_path = Path(csm.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "ai_dev" not in alias.name, f"Forbidden import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert "ai_dev" not in module, f"Forbidden import from: {module}"
            for alias in node.names:
                assert "ai_dev" not in alias.name, f"Forbidden import name: {alias.name}"


def test_indexed_command_matcher_contract() -> None:
    """Generic IndexedCommandMatcher provides explicit hints and delegates matching."""

    class _DummyMatcher:
        def match(self, command):
            return (MatcherEvidence(segment_index=0, executable=command.segments[0].executable, detail="dummy"),)

    dummy = _DummyMatcher()
    indexed = IndexedCommandMatcher(
        matcher=dummy,
        executables=frozenset({" Tool-A ", "TOOL-B"}),
        keywords=frozenset({" Key-1 ", "KEY-2"}),
    )

    assert indexed.executables == frozenset({"tool-a", "tool-b"})
    assert indexed.keywords == frozenset({"key-1", "key-2"})

    hints = matcher_index_hints(indexed)
    assert hints.complete is True
    assert hints.executables == frozenset({"tool-a", "tool-b"})
    assert hints.keywords == frozenset({"key-1", "key-2"})

    cmd = parse_shell_command("tool-a key-1")
    evidence = indexed.match(cmd)
    assert len(evidence) == 1
    assert evidence[0].detail == "dummy"


def test_ai_dev_candidate_indexing_filters_unrelated_commands() -> None:
    """Registry candidate indexing filters out ai-dev rules for unrelated commands."""
    for cmd in ("git status", "npm test", "cargo build", "docker ps"):
        candidate_ids = BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(parse_shell_command(cmd))
        ai_dev_candidates = [rid for rid in candidate_ids if rid.startswith("command.ai-dev.")]
        assert not ai_dev_candidates, f"Unexpected ai-dev candidates for {cmd!r}: {ai_dev_candidates}"

    # Relevant ai-dev commands ARE indexed as candidates
    daemon_candidates = BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(
        parse_shell_command("ai-dev index daemon start")
    )
    assert "command.ai-dev.index-daemon-start" in daemon_candidates

    install_candidates = BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(
        parse_shell_command("ai-dev integrations install --force")
    )
    assert "command.ai-dev.integrations-install-force" in install_candidates


def test_ai_dev_frozen_packaging_parity() -> None:
    """Ensure command.ai-dev contribution manifest is included in frozen artifact staging."""
    import importlib.util

    script_path = Path(__file__).resolve().parents[1] / "scripts/release/stage_guard_cloud_review_artifacts.py"
    spec = importlib.util.spec_from_file_location("stage_guard_cloud_review_artifacts", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert "contributions/extensions/command.ai-dev.json" in module._ARTIFACTS
    assert (
        module._ARTIFACTS["contributions/extensions/command.ai-dev.json"]
        == "extensions/contributions/command.ai-dev.json"
    )
