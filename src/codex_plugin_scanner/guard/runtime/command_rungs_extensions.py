"""Structured rules and metadata for the rungs command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Argument handling verified against @rungs/cli 0.4.0 — git tag v0.4.0, commit
# f7b6aa08466da08f5b0d495f9c9d62cf900cd8a7, the version published to npm on
# 2026-09-05 — and re-read at 3339065170f8cddb83c276f7044bdf22e95b9eb8 (48
# commits later, 2026-09-06), where the dispatch of these four commands is the
# same. rungs parses argv itself (src/cli.ts, the loop after
# `const [, , cmd, ...rest] = process.argv`):
#
# - argv[2] is the command and nothing precedes it: `rungs --dry-run add x` is
#   an unknown command that prints help and exits 1.
# - After the command, every token starting with `--` is a switch wherever it
#   appears, and `--name=value` registers the bare `--name`. Only `--set`
#   consumes the token after it (VALUE_FLAGS). Single-dash tokens are
#   positionals.
# - `--help` and `-h` are recognised only in the command slot. `rungs check
#   --help` runs the gates, so no rule below declares a help variant.
#
# What each command does, from the same sources:
#
# - `doctor [path] [--explain]` (cli.ts cmdDoctor) reads the tree, the install
#   record and the gate ledger. `--explain` runs the engine table in-process,
#   skips every `command` gate (explain.ts isRunnable and skipped.command) and
#   issues only read-only git queries. That is repository inspection, and it is
#   deliberately unmatched here: Guard expresses "reads, never writes" as the
#   absence of review evidence — `blitcp ls`, `repo2nb reverse` without
#   --force — and the test suite pins doctor to that classification, stray
#   switches included, because doctor ignores every switch but --explain.
# - `check [path] [tier] [--fast|--full]` (check.ts runGates and appendLedger)
#   executes every registered `kind = "command"` gate with execSync — commands
#   the repository owns, not rungs — and appends one line per gate to
#   .ai/.gate-ledger.jsonl unless the registry sets `[runner] ledger = false`.
#   There is no preview form: check never reads --dry-run.
# - `add <module…> [--dry-run] [--into path] [--set m.p=v] [--confirm-*]`
#   (cli.ts cmdAdd; add.ts addModule and registerGates) writes module files,
#   the gate registry, the install record and the rendered harness files, in
#   that order. Under --dry-run every write site is skipped: addModule returns
#   before mkdirSync/writeFileSync, registerGates skips, and the record and
#   render phase sits behind `if (!dryRun)`. The preview is therefore a
#   verified safe variant. A bare `rungs add` still writes the record and the
#   render report.
# - `upgrade [path] [--apply]` (cli.ts cmdUpgrade; lifecycle.ts planUpgrade and
#   applyUpgrade) only plans without --apply — reads and path validation — and
#   writes files, gate blocks and the record with it. upgrade never reads
#   --dry-run, so `rungs upgrade --apply --dry-run` writes.
#
# What this extension does not claim: rungs writes in phases with no journal,
# so a failed `add` or `upgrade --apply` can leave the earlier files written.
# These rules classify what an invocation can do before it runs. They do not
# detect a partial write, roll one back, or repair an installation.

# The switches rungs honours (help.ts FLAGS) other than --dry-run, which the
# safe variant owns. Declaring them lets the fail-secure parse tell a documented
# switch from an unknown option that might swallow the token after it, so
# `rungs add backlog --into ../repo --dry-run` stays a preview while
# `rungs add backlog --mystery --dry-run` reviews. This mirrors 0.4.0 exactly:
# --into is a bare switch there and the target is the last positional.
_RUNGS_SWITCHES = frozenset(
    {
        "--apply",
        "--confirm-conflict",
        "--confirm-paradigm",
        "--confirm-threshold",
        "--copilot",
        "--explain",
        "--fast",
        "--full",
        "--into",
        "--params",
    }
)
_RUNGS_OPTIONS_WITH_VALUES = frozenset({"--set"})
_EMPTY: frozenset[str] = frozenset()


def _rungs(
    subcommand: str,
    *,
    required_flags: frozenset[str] = _EMPTY,
    options_with_values: frozenset[str] = _RUNGS_OPTIONS_WITH_VALUES,
    switches: frozenset[str] = _RUNGS_SWITCHES,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "rungs",
                subcommand,
                required_flags=required_flags,
                global_flags=switches,
                options_with_values=options_with_values,
                fail_secure_unknown_options=True,
            ),
        )
    )


_RUNGS_CHECK = _rungs("check")
_RUNGS_ADD = _rungs("add")
# rungs registers the bare name of every `--apply...` spelling, so
# `--apply=false` still applies. Guard's flag semantics would read that
# assignment as disabled, so --apply is declared as value-taking here: every
# spelling then counts as present, and the token it may consume matters to
# nothing else on upgrade, which reads no other switch. No switches are
# declared for the same reason: Guard strips every fully-known interspersed
# `--name=value` token before it checks required flags, which would hide the
# assigned spelling again.
_RUNGS_UPGRADE_APPLY = _rungs(
    "upgrade",
    required_flags=frozenset({"--apply"}),
    options_with_values=_RUNGS_OPTIONS_WITH_VALUES | {"--apply"},
    switches=_EMPTY,
)

# The action-class risk map merges this the same way it merges blitcp's, so the
# risk declarations stay next to the rules that emit them. Guard's vocabulary
# has no lighter local-write class than destructive_shell, which is why the
# ledger append and the module writes both carry it.
RUNGS_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "rungs gate execution command": ("execution", "destructive_shell"),
    "rungs module install command": ("destructive_shell",),
    "rungs module upgrade command": ("destructive_shell",),
}

RUNGS_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.rungs.check",
        title="rungs gate execution",
        description=(
            "Identifies `rungs check`, which executes every command gate registered in .ai/gates.toml — "
            "commands the repository owns, not rungs — and appends one line per gate to the local "
            ".ai/.gate-ledger.jsonl. check has no preview form; --dry-run is not read."
        ),
        severity="high",
        risk_classes=("execution", "destructive_shell"),
        action_classes=("rungs gate execution command",),
        safer_alternatives=(
            'Read .ai/gates.toml first; each `kind = "command"` gate is a repository-owned command that will run.',
            "Use `rungs doctor --explain` to run the in-process detectors without executing any command gate.",
        ),
        matcher=_RUNGS_CHECK,
        default_mode="review",
        example_command="rungs check",
    ),
    CommandSafetyRule(
        rule_id="command.rungs.add",
        title="rungs module install",
        description=(
            "Identifies `rungs add`, which writes module files, the gate registry, the install record "
            "and the rendered harness instruction files into the target repository. `--dry-run` reports "
            "the same plan and writes nothing, and is the only preview form."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("rungs module install command",),
        safer_alternatives=(
            "Run `rungs add <module> --dry-run` first: it prints every file, gate and record it would write.",
            "Run `rungs doctor` to see what the repository already has before installing over it.",
        ),
        matcher=_RUNGS_ADD,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _RUNGS_ADD,
                variant_id="dry-run",
                title="rungs add dry run",
                flag="--dry-run",
            ),
        ),
        example_command="rungs add backlog",
    ),
    CommandSafetyRule(
        rule_id="command.rungs.upgrade",
        title="rungs module upgrade",
        description=(
            "Identifies `rungs upgrade --apply`, which rewrites stale and missing module files, replaces "
            "gate registry blocks and updates the install record. Without --apply, upgrade only prints the "
            "plan; it never reads --dry-run, so `--apply --dry-run` still writes."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("rungs module upgrade command",),
        safer_alternatives=(
            "Run `rungs upgrade` without --apply: it prints the stale, missing and diverged files and writes nothing.",
        ),
        matcher=_RUNGS_UPGRADE_APPLY,
        default_mode="review",
        example_command="rungs upgrade --apply",
    ),
)

RUNGS_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.rungs",
        name="rungs command protection",
        description=(
            "Reviews rungs runs that execute registered gates or write module files, gates and records "
            "into a repository, and keeps doctor and the documented previews unreviewed."
        ),
        action_classes=(
            "rungs gate execution command",
            "rungs module install command",
            "rungs module upgrade command",
        ),
        risk_classes=("destructive_shell", "execution"),
        safer_alternatives=(
            "Inspect with `rungs doctor`, preview with `rungs add --dry-run` or `rungs upgrade` without --apply, "
            "and read .ai/gates.toml before `rungs check`.",
        ),
        reference_urls=(
            "https://docs.rungscli.com/",
            "https://github.com/ThroughTheWind/rungs/blob/v0.4.0/src/cli.ts",
        ),
    ),
)
