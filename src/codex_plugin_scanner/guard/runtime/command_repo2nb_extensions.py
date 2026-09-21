"""Structured rules and metadata for the repo2nb command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    _after_leading_options,
    _segment_matches_executable,
)

# Flag surface verified against repo2nb 0.2.1 (PyPI wheel, cli.py): `reverse`
# accepts --force (store_true, no -f alias) and --output/-o; `sync` accepts
# --notebook and --dry-run. Dispatch requires the literal subcommand as
# argv[0], so no global options can precede it. Module invocation
# (`python/-m repo2nb ...`) enforces the module name as literal subcommand
# tokens because option-value tracking does not retain `-m` values.
#
# Conservative matching covers:
# - Standard launcher variants: repo2nb, python -m repo2nb, python3 -m repo2nb, py -m repo2nb
# - Shell wrappers: exec repo2nb ..., xargs repo2nb ...
# - Flag abbreviations: Python argparse accepts unambiguous prefixes (--f, --fo, ..., --force)
# - Unresolved shell expansions ($VAR, ${VAR}, $(...), backticks) that may supply --force
# - Fail-secure option parsing: unknown options prevent unsafe dry-run bypasses

_REPO2NB_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("repo2nb",),
    ("python", "-m", "repo2nb"),
    ("python3", "-m", "repo2nb"),
    ("py", "-m", "repo2nb"),
    ("exec", "repo2nb"),
    ("exec", "python", "-m", "repo2nb"),
    ("exec", "python3", "-m", "repo2nb"),
    ("exec", "py", "-m", "repo2nb"),
    ("xargs", "repo2nb"),
    ("xargs", "python", "-m", "repo2nb"),
    ("xargs", "python3", "-m", "repo2nb"),
    ("xargs", "py", "-m", "repo2nb"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
# argparse resolves any unambiguous long-option prefix, so every prefix of
# --force is the destructive flag itself.
_FORCE_FLAGS: tuple[str, ...] = ("--force", "--forc", "--for", "--fo", "--f")
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})

_REPO2NB_REVERSE_FORCE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "reverse",
            required_flags=frozenset({force_flag}),
            options_with_values=frozenset({"--output", "-o"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _REPO2NB_LAUNCHERS
        for force_flag in _FORCE_FLAGS
    )
)

_REPO2NB_SYNC = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "sync",
            options_with_values=frozenset({"--notebook"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _REPO2NB_LAUNCHERS
    )
)


@dataclass(frozen=True, slots=True)
class Repo2nbUnresolvedExpansionMatcher:
    """Match repo2nb commands whose flags may be supplied by shell expansion.

    A `$VAR`, `${VAR}`, `$(...)`, or backtick token can expand to `--force` at
    execution time, so its presence in a `reverse` invocation means the
    destructive flag cannot be proven absent.
    """

    subcommand: str = "reverse"
    launchers: tuple[tuple[str, ...], ...] = _REPO2NB_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

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
                if launcher[0] in ("exec", "xargs"):
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                prefix = (*launcher[1:], self.subcommand)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                remaining_arguments = candidate_arguments[len(prefix) :]
                if any(
                    any(marker in argument for marker in self.expansion_markers) for argument in remaining_arguments
                ):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched repo2nb arguments that may expand to destructive flags.",
                        )
                    )
                break
        return tuple(evidence)


# The literal-flag matcher stays free of custom children so `--help` safe
# variants keep cloning pure executable matchers; the rule itself adds the
# unresolved-expansion overlay on top.
_REPO2NB_REVERSE_FORCE_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_REPO2NB_REVERSE_FORCE.matchers, Repo2nbUnresolvedExpansionMatcher()),
)

REPO2NB_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.repo2nb.reverse-force",
        title="repo2nb forced notebook reversal",
        description=(
            "Identifies `repo2nb reverse --force`, which can overwrite an "
            "existing non-empty destination directory. A symlink inside the "
            "destination can cause writes to land outside the intended root "
            "even with --force's existing non-empty-directory check. Reverse "
            "invocations carrying unresolved shell expansions are reviewed "
            "because they cannot prove --force absent."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("repo2nb forced directory overwrite command",),
        safer_alternatives=(
            "Run repo2nb reverse without --force first and review what it reports about the existing directory.",
            "Confirm the destination path is not a sensitive system or home directory before forcing.",
            "Expand shell variables and command substitutions before running repo2nb reverse.",
        ),
        matcher=_REPO2NB_REVERSE_FORCE_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _REPO2NB_REVERSE_FORCE,
                variant_id="help",
                title="repo2nb reverse command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.repo2nb.sync",
        title="repo2nb notebook sync",
        description=(
            "Identifies `repo2nb sync`, a one-directional repo-to-notebook "
            "sync that can silently drop manually-added notebook cells not "
            "tracked in .repo2nb/manifest.json."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("repo2nb notebook sync command",),
        safer_alternatives=(
            "Review .repo2nb/manifest.json to see which cells are tracked before syncing.",
            "Back up or export manually-added cells before running sync.",
        ),
        matcher=_REPO2NB_SYNC,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _REPO2NB_SYNC,
                variant_id="dry-run",
                title="repo2nb sync dry run",
                flag="--dry-run",
            ),
            safe_flag_variant(
                _REPO2NB_SYNC,
                variant_id="help",
                title="repo2nb sync command help",
                flag="--help",
            ),
        ),
    ),
)

REPO2NB_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.repo2nb",
        name="repo2nb command protection",
        description=(
            "Reviews repo2nb commands that can overwrite an existing "
            "destination directory or silently drop untracked notebook "
            "cells."
        ),
        action_classes=(
            "repo2nb forced directory overwrite command",
            "repo2nb notebook sync command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Run repo2nb reverse without --force first to see what it reports.",
            "Review the manifest before syncing to catch untracked manual edits.",
        ),
        reference_urls=("https://github.com/David-Magdy/repo2nb",),
    ),
)
