"""Structured claude-tmux cleanup command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_claude_tmux_extensions import (
    _CTC_DRY_RUN,
    _CTC_PROCESS_PRUNE,
    _CTC_SESSION_TEARDOWN,
)
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

CLAUDE_TMUX_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "ctc --all --force",
        "claude tmux session teardown command",
        "command.claude-tmux.session-teardown",
    ),
    (
        "claude-tmux-cleanup --all --force",
        "claude tmux session teardown command",
        "command.claude-tmux.session-teardown",
    ),
    (
        "ctc --all --force --prune",
        "claude tmux process prune command",
        "command.claude-tmux.process-prune",
    ),
    # No target and no selection flag is the widest form: the interactive sweep
    # with every prompt answered for you.
    (
        "ctc --force",
        "claude tmux session teardown command",
        "command.claude-tmux.session-teardown",
    ),
    (
        "yes | ctc --all",
        "claude tmux session teardown command",
        "command.claude-tmux.session-teardown",
    ),
    (
        "yes | ctc --all --prune",
        "claude tmux process prune command",
        "command.claude-tmux.process-prune",
    ),
)


def test_claude_tmux_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in CLAUDE_TMUX_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.claude-tmux" for item in evaluation.extension_observations)


def _enabled_layer() -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.claude-tmux"),
                state=ControlState.ENABLED,
            ),
        ),
    )


def test_enabled_extension_controls_the_documented_shapes(tmp_path: Path) -> None:
    """Once enabled, each unattended shape is owned by its rule and the preview by neither."""
    layer = _enabled_layer()
    failures: list[str] = []
    for command, _action_class, rule_id in CLAUDE_TMUX_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(layer,),
        )
        if evaluation.controlling_rule_id != rule_id:
            failures.append(f"{command!r}: controlling={evaluation.controlling_rule_id!r}, expected {rule_id!r}")
    assert not failures, "\n".join(failures)


def test_enabled_prune_outranks_the_teardown_it_contains(tmp_path: Path) -> None:
    """A full sweep is both actions, and the one reaching past tmux controls the decision."""
    evaluation = evaluate_command(
        "ctc --all --force --prune",
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_enabled_layer(),),
    )
    observed = {
        observation.rule.rule_id
        for observation in evaluation.extension_observations
        if observation.extension.extension_id == "command.claude-tmux"
    }

    assert observed == {
        "command.claude-tmux.session-teardown",
        "command.claude-tmux.process-prune",
    }
    assert evaluation.controlling_rule_id == "command.claude-tmux.process-prune"


def test_enabled_preview_keeps_evidence_but_controls_nothing(tmp_path: Path) -> None:
    """--dry-run is observed as the safe counterpart of the rules it previews."""
    evaluation = evaluate_command(
        "ctc --all --force --prune --dry-run",
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_enabled_layer(),),
    )
    variants = {
        variant.variant_id
        for observation in evaluation.extension_observations
        if observation.extension.extension_id == "command.claude-tmux"
        for variant in observation.safe_variants
    }

    assert variants == {"dry-run"}
    assert evaluation.controlling_rule_id is None


CLAUDE_TMUX_SAFE_COMMANDS: tuple[str, ...] = (
    # The preview lists sessions and pids and signals nothing.
    "ctc --dry-run",
    "ctc --all --force --dry-run",
    "ctc --all --force --prune --dry-run",
    "ctc -a -f -p -n",
    # Without --force the command stops on its confirmation prompt.
    "ctc",
    "ctc api",
    "ctc --all",
    "ctc --prune",
    "ctc --help",
    "claude-tmux-cleanup --help",
    # The launcher is a different program and starts nothing destructive.
    "claude-tmux",
    "ct api",
    # Neither a mention of the command nor a grep for it is an invocation.
    "grep 'ctc --all --force --prune' docs",
    "echo ctc --all --force",
)


def test_claude_tmux_previews_and_prompted_runs_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(CLAUDE_TMUX_SAFE_COMMANDS, tmp_path)


def test_claude_tmux_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.claude-tmux")

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/s403o/claude-code-tmux",)
    assert all(url.startswith("https://") for url in extension.reference_urls)
    assert risk_classes_for_command_action("claude tmux session teardown command") == ("destructive_shell",)
    assert risk_classes_for_command_action("claude tmux process prune command") == ("destructive_shell",)


def test_session_teardown_turns_on_force_not_on_selection(tmp_path: Path) -> None:
    """--force alone is the widest kill: with no target it sweeps every session."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --force"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc api --force"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --all --force"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --every --force"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("claude-tmux-cleanup --all --force"))
    # Without --force every one of these stops on a prompt.
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --all")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc api")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc")) == ()


def test_help_exits_before_anything_is_killed(tmp_path: Path) -> None:
    """Help prints and returns, so the flags on the same line describe no risk."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --help")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --force --help")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc -h -f")) == ()
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --force --prune --help")) == ()


def test_a_piped_yes_answers_the_prompt_the_same_way_force_does(tmp_path: Path) -> None:
    """The prompt reads one line of stdin, so a feed of consent is unattended too."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_SESSION_TEARDOWN.match(parsed("yes | ctc"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("yes | ctc --all"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("yes y | ctc --all"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("echo y | ctc api"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("printf 'y\\n' | ctc --all"))
    assert _CTC_PROCESS_PRUNE.match(parsed("yes | ctc --prune"))
    assert _CTC_PROCESS_PRUNE.match(parsed("yes yes | ctc --all --prune"))
    # A refusal is not consent, and neither is arbitrary piped data.
    assert _CTC_SESSION_TEARDOWN.match(parsed("yes n | ctc --all")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("cat notes | ctc --all")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("echo | ctc --all")) == ()
    # `&&` and `;` start their own execution context and share no stdin.
    assert _CTC_SESSION_TEARDOWN.match(parsed("yes && ctc --all")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("yes ; ctc --all")) == ()
    # The feed has to come before the cleanup, not after it.
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --all | yes")) == ()


def test_process_prune_is_matched_independently_of_session_selection(tmp_path: Path) -> None:
    """--prune reaches processes tmux never owned, so it stands on its own flag."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --prune --force"))
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --all --force --prune"))
    # The full teardown does both things, and each rule keeps its own evidence.
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --all --force --prune"))
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --prune")) == ()
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --all --force")) == ()


def test_short_flags_and_clusters_carry_the_same_meaning(tmp_path: Path) -> None:
    """`ctc -afp` is the documented short spelling of the same unattended run."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc -f"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc -a -f"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc -af"))
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc -afp"))
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc -fp"))
    # Arguments are lower-cased before matching, so -A (--every) and -a (--all)
    # are one token here. Neither selects anything the force flag has not
    # already claimed, so the collapse changes nothing for these rules.
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc -A -f"))


def test_flag_order_and_session_operands_do_not_change_the_match(tmp_path: Path) -> None:
    """Session names are operands; they narrow the blast radius, not the risk."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc --force --all"))
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --prune --force --all"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc api --all --force"))
    assert _CTC_PROCESS_PRUNE.match(parsed("ctc --force api --prune"))


def test_dry_run_variant_matches_every_destructive_spelling(tmp_path: Path) -> None:
    """The preview flag is what makes a run safe, wherever it appears."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_DRY_RUN.match(parsed("ctc --dry-run"))
    assert _CTC_DRY_RUN.match(parsed("ctc --all --force --prune --dry-run"))
    assert _CTC_DRY_RUN.match(parsed("ctc --dry-run --all --force --prune"))
    assert _CTC_DRY_RUN.match(parsed("ctc -afpn"))
    assert _CTC_DRY_RUN.match(parsed("ctc --all --force --prune")) == ()


def test_other_executables_named_like_the_cleanup_are_not_matched(tmp_path: Path) -> None:
    """Only the cleanup launchers own these flags; a lookalike name does not."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_SESSION_TEARDOWN.match(parsed("claude-tmux --all --force")) == ()
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctcx --all --force")) == ()
    assert _CTC_PROCESS_PRUNE.match(parsed("tmux kill-server --force --prune")) == ()
    # Portable launcher names are the same program.
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc.exe --all --force"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("ctc.cmd --all --force"))


def test_wrappers_and_pipelines_preserve_the_match(tmp_path: Path) -> None:
    """A wrapped or chained run kills exactly what a bare one does."""

    def parsed(command: str):
        return parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert _CTC_PROCESS_PRUNE.match(parsed("yes | ctc --all --force --prune"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("tmux detach && ctc --all --force"))
    assert _CTC_SESSION_TEARDOWN.match(parsed("env TMUX= ctc --all --force"))
