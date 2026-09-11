"""Structured rules and metadata for the VTTForge command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    _after_leading_options,
    _segment_matches_executable,
)

# Flag surface verified against @vttforge/cli 0.15.0 (src/cli.ts). The CLI is
# split by flag: `audit`, `lint` and `migrate` read by default; `init` writes a
# project, `lint --fix` rewrites source and `migrate --write` rewrites a
# project in place. Only the writing forms are reviewed here. `--help` on any
# subcommand prints the help and exits before anything runs, whatever else is
# on the line, so a help invocation is safe regardless of its other flags.
#
# Conservative matching covers:
# - Direct invocation and the exec / xargs shell wrappers.
# - Unresolved shell expansions ($VAR, ${VAR}, $(...), backticks) after a
#   literal `lint` or `migrate`, which may supply --fix or --write.
# - An unresolved expansion in the subcommand position itself. With a literal
#   --fix or --write beside it the line is attributed to that rule; with
#   neither it may still expand into an init argument list, so it is reviewed
#   under the init rule.
#
# The npm/npx/pnpm launcher is intentionally not an extension target: Guard's
# package firewall owns launcher policy, while this matcher owns the installed
# CLI.

_VTTFORGE_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("vttforge",),
    ("exec", "vttforge"),
    ("xargs", "vttforge"),
)
# Wrapper options that consume the next token. Missing one here would let its
# operand pass for the wrapped executable and hide the command; `exec -a name`
# and `xargs -a file` are the ones a shared set tends to forget.
_WRAPPER_LEADING_OPTIONS_WITH_VALUES: dict[str, frozenset[str]] = {
    "exec": frozenset({"-a"}),
    "xargs": frozenset(
        {
            "-a",
            "--arg-file",
            "-d",
            "--delimiter",
            "-E",
            "--eof",
            "-I",
            "--replace",
            "-J",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-R",
            "-S",
            "-s",
            "--max-chars",
        }
    ),
}
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})
_INIT_OPTIONS_WITH_VALUES = frozenset({"--type", "--lang", "--id", "--title", "--description", "--author", "--license"})
_MIGRATE_OPTIONS_WITH_VALUES = frozenset({"--style", "--lang"})


def _is_wrapper(launcher: tuple[str, ...]) -> bool:
    return launcher[0] in _WRAPPER_LEADING_OPTIONS_WITH_VALUES


def _wrapper_options(launcher: tuple[str, ...]) -> frozenset[str]:
    return _WRAPPER_LEADING_OPTIONS_WITH_VALUES.get(launcher[0], frozenset())


def _launcher_matcher(
    launcher: tuple[str, ...],
    *subcommands: str,
    required_flags: frozenset[str] = frozenset(),
    options_with_values: frozenset[str] = frozenset(),
):
    return executable_matcher(
        *launcher,
        *subcommands,
        required_flags=required_flags,
        options_with_values=options_with_values,
        allow_leading_options=_is_wrapper(launcher),
        leading_options_with_values=_wrapper_options(launcher),
    )


def _literal_matcher(
    subcommand: str,
    *,
    required_flags: frozenset[str] = frozenset(),
    options_with_values: frozenset[str] = frozenset(),
) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            _launcher_matcher(
                launcher,
                subcommand,
                required_flags=required_flags,
                options_with_values=options_with_values,
            )
            for launcher in _VTTFORGE_LAUNCHERS
        )
    )


@dataclass(frozen=True, slots=True)
class VttforgeUnresolvedExpansionMatcher:
    """Match a vttforge invocation whose writing flag or subcommand may come from shell expansion.

    With `literal_flag` set (the lint and migrate rules), the match is a
    literal subcommand followed by an expansion, or an expanded subcommand
    followed by the literal flag. Without it (the init rule), the match is an
    expanded subcommand with neither writing flag in sight: the line may still
    expand into `init` and its arguments.
    """

    subcommand: str
    literal_flag: str | None = None
    other_literal_flags: frozenset[str] = frozenset()
    launchers: tuple[tuple[str, ...], ...] = _VTTFORGE_LAUNCHERS
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def _has_expansion(self, argument: str) -> bool:
        return any(marker in argument for marker in self.expansion_markers)

    def _matches_arguments(self, arguments: tuple[str, ...]) -> bool:
        if not arguments:
            return False
        first, rest = arguments[0], arguments[1:]
        if first == self.subcommand:
            return self.literal_flag is not None and any(self._has_expansion(argument) for argument in rest)
        if not self._has_expansion(first):
            return False
        if self.literal_flag is not None:
            return self.literal_flag in rest
        return not any(flag in rest for flag in self.other_literal_flags)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                candidate_arguments = lowered_arguments
                if _is_wrapper(launcher):
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        _wrapper_options(launcher),
                        frozenset(),
                    )
                prefix = launcher[1:]
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                if self._matches_arguments(candidate_arguments[len(prefix) :]):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail=(
                                f"Matched vttforge arguments that may expand to {self.subcommand} or its writing flag."
                            ),
                        )
                    )
                break
        return tuple(evidence)


# The literal-flag matchers stay free of custom children; the rules use them
# with the unresolved-expansion overlay on top.
_VTTFORGE_INIT = _literal_matcher("init", options_with_values=_INIT_OPTIONS_WITH_VALUES)
_VTTFORGE_LINT_FIX = _literal_matcher("lint", required_flags=frozenset({"--fix"}))
_VTTFORGE_MIGRATE_WRITE = _literal_matcher(
    "migrate",
    required_flags=frozenset({"--write"}),
    options_with_values=_MIGRATE_OPTIONS_WITH_VALUES,
)

_VTTFORGE_INIT_WITH_EXPANSIONS = AnyMatcher(
    matchers=(
        *_VTTFORGE_INIT.matchers,
        VttforgeUnresolvedExpansionMatcher("init", other_literal_flags=frozenset({"--fix", "--write"})),
    ),
)
_VTTFORGE_LINT_FIX_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_VTTFORGE_LINT_FIX.matchers, VttforgeUnresolvedExpansionMatcher("lint", "--fix")),
)
_VTTFORGE_MIGRATE_WRITE_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_VTTFORGE_MIGRATE_WRITE.matchers, VttforgeUnresolvedExpansionMatcher("migrate", "--write")),
)

# `--help` (and `-h` on init) ends the command before anything runs, so the
# safe variants require only the help flag, on any subcommand, literal or
# expanded, and never the writing flag the rule itself looks for.
_VTTFORGE_HELP = AnyMatcher(
    matchers=tuple(
        _launcher_matcher(launcher, required_flags=frozenset({"--help"})) for launcher in _VTTFORGE_LAUNCHERS
    )
)
_VTTFORGE_SHORT_HELP = AnyMatcher(
    matchers=tuple(_launcher_matcher(launcher, required_flags=frozenset({"-h"})) for launcher in _VTTFORGE_LAUNCHERS)
)


def _help_variants(title: str, *, short: bool = False) -> tuple[CommandSafeVariant, ...]:
    variants = [CommandSafeVariant(variant_id="help", title=title, matcher=_VTTFORGE_HELP)]
    if short:
        variants.append(CommandSafeVariant(variant_id="short-help", title=title, matcher=_VTTFORGE_SHORT_HELP))
    return tuple(variants)


VTTFORGE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.vttforge.init",
        title="VTTForge project scaffold",
        description=(
            "Identifies `vttforge init`, which writes a new Foundry VTT system or "
            "module tree into the working directory, then runs the package "
            "manager install and `git init` unless --no-install and --no-git "
            "are present. A vttforge invocation whose subcommand is an "
            "unresolved shell expansion, with no literal --fix or --write beside "
            "it, is reviewed here too, since it may expand into init."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("VTTForge project scaffold command",),
        safer_alternatives=(
            "Confirm the target directory does not already hold a project before scaffolding.",
            "Pass --no-install and --no-git to write the files only, then review them before installing.",
            "Expand shell variables and command substitutions before running vttforge.",
        ),
        matcher=_VTTFORGE_INIT_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=_help_variants("VTTForge init command help", short=True),
    ),
    CommandSafetyRule(
        rule_id="command.vttforge.lint-fix",
        title="VTTForge lint with fixes written",
        description=(
            "Identifies `vttforge lint --fix`, which rewrites source files in "
            "place with the bundled formatter and linter fixes. Without --fix the "
            "command only reports. A lint invocation carrying an unresolved shell "
            "expansion is reviewed too, since it may expand to --fix."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("VTTForge lint fix command",),
        safer_alternatives=(
            "Run `vttforge lint` without --fix to see the findings first.",
            "Run --fix on a clean git tree so the rewrite is one reviewable diff.",
            "Expand shell variables and command substitutions before running vttforge lint.",
        ),
        matcher=_VTTFORGE_LINT_FIX_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=_help_variants("VTTForge lint command help"),
    ),
    CommandSafetyRule(
        rule_id="command.vttforge.migrate-write",
        title="VTTForge migration written to the project",
        description=(
            "Identifies `vttforge migrate --write`, which rewrites a v13 Foundry "
            "VTT project for v14 in place, and with --data-models or --sheets "
            "also writes generated files next to the originals. Without --write "
            "the command previews the same edits and writes nothing. A migrate "
            "invocation carrying an unresolved shell expansion is reviewed too, "
            "since it may expand to --write."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("VTTForge migration write command",),
        safer_alternatives=(
            "Run `vttforge migrate` without --write first and read the report.",
            "Run --write on a clean git tree, then `vttforge audit`, and review the diff before committing.",
            "Add --strict so the command exits non-zero when it leaves anything that needs a decision.",
            "Expand shell variables and command substitutions before running vttforge migrate.",
        ),
        matcher=_VTTFORGE_MIGRATE_WRITE_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=_help_variants("VTTForge migrate command help"),
    ),
)

VTTFORGE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.vttforge",
        name="VTTForge command protection",
        description=(
            "Reviews VTTForge CLI commands that write a project: the scaffold, "
            "lint fixes, and the v14 migration written in place. The audit, the "
            "lint report and the migration preview stay unreviewed."
        ),
        action_classes=(
            "VTTForge project scaffold command",
            "VTTForge lint fix command",
            "VTTForge migration write command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Run the preview forms first: `vttforge migrate` and `vttforge lint` without --write or --fix.",
            "Run the writing forms on a clean git tree and review the diff.",
        ),
        reference_urls=("https://github.com/vttforge/vttforge", "https://vttforge.dev/docs/guide/cli"),
    ),
)
