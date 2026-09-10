"""Structured rules and metadata for the VTTForge command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandSafetyRule, _segment_matches_executable

# Flag surface verified against @vttforge/cli 0.15.0 (src/cli.ts). The CLI is
# split by flag: `audit`, `lint` and `migrate` read by default; `init` writes a
# project, `lint --fix` rewrites source and `migrate --write` rewrites a
# project in place. Only the writing forms are reviewed here.
#
# The npm/npx/pnpm launcher is intentionally not an extension target: Guard's
# package firewall owns launcher policy, while this matcher owns the installed
# CLI.
#
# Guard parses without shell expansion, so a `$VAR`, `${VAR}`, `$(...)` or
# backtick token after `lint` or `migrate` may turn into --fix or --write at
# execution time. Those invocations are reviewed too; the flag cannot be
# proven absent.

_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})


@dataclass(frozen=True, slots=True)
class VttforgeUnresolvedExpansionMatcher:
    """Match a `vttforge <subcommand>` whose flags may come from shell expansion."""

    subcommand: str
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None or not _segment_matches_executable(segment, frozenset({"vttforge"})):
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            if lowered_arguments[:1] != (self.subcommand,):
                continue
            remaining_arguments = lowered_arguments[1:]
            if any(any(marker in argument for marker in self.expansion_markers) for argument in remaining_arguments):
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable,
                        detail=f"Matched vttforge {self.subcommand} arguments that may expand to a writing flag.",
                    )
                )
        return tuple(evidence)


_VTTFORGE_INIT = AnyMatcher(
    matchers=(
        executable_matcher(
            "vttforge",
            "init",
            options_with_values=frozenset(
                {"--type", "--lang", "--id", "--title", "--description", "--author", "--license"}
            ),
        ),
    )
)

_VTTFORGE_LINT_FIX = AnyMatcher(
    matchers=(
        executable_matcher(
            "vttforge",
            "lint",
            required_flags=frozenset({"--fix"}),
        ),
    )
)

_VTTFORGE_MIGRATE_WRITE = AnyMatcher(
    matchers=(
        executable_matcher(
            "vttforge",
            "migrate",
            required_flags=frozenset({"--write"}),
            options_with_values=frozenset({"--style", "--lang"}),
        ),
    )
)

# The literal-flag matchers stay free of custom children so the `--help` safe
# variants keep working; the rules use these, with the expansion overlay.
_VTTFORGE_LINT_FIX_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_VTTFORGE_LINT_FIX.matchers, VttforgeUnresolvedExpansionMatcher("lint")),
)

_VTTFORGE_MIGRATE_WRITE_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_VTTFORGE_MIGRATE_WRITE.matchers, VttforgeUnresolvedExpansionMatcher("migrate")),
)


VTTFORGE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.vttforge.init",
        title="VTTForge project scaffold",
        description=(
            "Identifies `vttforge init`, which writes a new Foundry VTT system or "
            "module tree into the working directory, then runs the package "
            "manager install and `git init` unless --no-install and --no-git "
            "are present."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("VTTForge project scaffold command",),
        safer_alternatives=(
            "Confirm the target directory does not already hold a project before scaffolding.",
            "Pass --no-install and --no-git to write the files only, then review them before installing.",
        ),
        matcher=_VTTFORGE_INIT,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _VTTFORGE_INIT,
                variant_id="help",
                title="VTTForge init command help",
                flag="--help",
            ),
            safe_flag_variant(
                _VTTFORGE_INIT,
                variant_id="short-help",
                title="VTTForge init command help",
                flag="-h",
            ),
        ),
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
        safe_variants=(
            safe_flag_variant(
                _VTTFORGE_LINT_FIX,
                variant_id="help",
                title="VTTForge lint command help",
                flag="--help",
            ),
        ),
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
        safe_variants=(
            safe_flag_variant(
                _VTTFORGE_MIGRATE_WRITE,
                variant_id="help",
                title="VTTForge migrate command help",
                flag="--help",
            ),
        ),
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
