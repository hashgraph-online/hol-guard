"""Structured rules and metadata for the apex command safety extension."""

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

_APEX_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("apex",),
    ("apexcompress",),
    ("python", "-m", "apex"),
    ("python3", "-m", "apex"),
    ("py", "-m", "apex"),
    ("python", "-m", "apexcompress"),
    ("python3", "-m", "apexcompress"),
    ("py", "-m", "apexcompress"),
    ("exec", "apex"),
    ("exec", "apexcompress"),
    ("exec", "python", "-m", "apex"),
    ("exec", "python3", "-m", "apex"),
    ("exec", "py", "-m", "apex"),
    ("exec", "python", "-m", "apexcompress"),
    ("exec", "python3", "-m", "apexcompress"),
    ("exec", "py", "-m", "apexcompress"),
    ("xargs", "apex"),
    ("xargs", "apexcompress"),
    ("xargs", "python", "-m", "apex"),
    ("xargs", "python3", "-m", "apex"),
    ("xargs", "py", "-m", "apex"),
    ("xargs", "python", "-m", "apexcompress"),
    ("xargs", "python3", "-m", "apexcompress"),
    ("xargs", "py", "-m", "apexcompress"),
)

_APEX_OPTIONS_WITH_VALUES = frozenset({
    "-o", "--output", "-m", "--mode", "-e", "--exclude",
    "-b", "--block-size", "-p", "--password", "-d", "--dest", "-i", "--include"
})

_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

_EXPANSION_MARKERS = frozenset({"$", "`"})

@dataclass(frozen=True, slots=True)
class ApexUnresolvedExpansionMatcher:
    """Match apex commands whose action may be supplied by shell expansion.

    A `$VAR`, `${VAR}`, `$(...)`, or backtick token can expand to a mutating
    subcommand (like `compress`, `decompress`, `repair`) at execution time.
    """

    launchers: tuple[tuple[str, ...], ...] = _APEX_LAUNCHERS
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
                prefix_len = len(launcher) - 1
                if len(candidate_arguments) <= prefix_len:
                    continue
                launcher_args = launcher[1:]
                if candidate_arguments[:prefix_len] != launcher_args:
                    continue
                
                action_token = candidate_arguments[prefix_len]
                if any(marker in action_token for marker in self.expansion_markers):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched apex command with unresolved expansion in the subcommand position.",
                        )
                    )
                break
        return tuple(evidence)


_APEX_COMPRESS = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            subcmd,
            options_with_values=_APEX_OPTIONS_WITH_VALUES,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _APEX_LAUNCHERS
        for subcmd in ("compress", "c")
    )
)

_APEX_DECOMPRESS = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            subcmd,
            options_with_values=_APEX_OPTIONS_WITH_VALUES,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _APEX_LAUNCHERS
        for subcmd in ("decompress", "x", "extract")
    )
)

_APEX_REPAIR = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            subcmd,
            options_with_values=_APEX_OPTIONS_WITH_VALUES,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _APEX_LAUNCHERS
        for subcmd in ("repair", "fix", "heal")
    )
)


_APEX_COMPRESS_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_APEX_COMPRESS.matchers, ApexUnresolvedExpansionMatcher()),
)

APEX_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.apex.compress",
        title="apex file compression",
        description=(
            "Identifies `apex compress` commands, which can overwrite existing "
            "files or archives. Invocations carrying unresolved shell expansions "
            "in the action position are reviewed because they cannot prove mutating actions absent."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("apex compress command",),
        safer_alternatives=(
            "Confirm the destination path is not an existing critical file.",
        ),
        matcher=_APEX_COMPRESS_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _APEX_COMPRESS,
                variant_id="help",
                title="apex compress command help",
                flag="--help",
            ),
            safe_flag_variant(
                _APEX_COMPRESS,
                variant_id="help-short",
                title="apex compress command help",
                flag="-h",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.apex.decompress",
        title="apex archive decompression",
        description=(
            "Identifies `apex decompress` commands, which can extract files and "
            "potentially overwrite existing contents in the destination directory."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("apex decompress command",),
        safer_alternatives=(
            "Confirm the destination directory is safe for extraction.",
        ),
        matcher=_APEX_DECOMPRESS,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _APEX_DECOMPRESS,
                variant_id="help",
                title="apex decompress command help",
                flag="--help",
            ),
            safe_flag_variant(
                _APEX_DECOMPRESS,
                variant_id="help-short",
                title="apex decompress command help",
                flag="-h",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.apex.repair",
        title="apex archive repair",
        description=(
            "Identifies `apex repair` commands, which can modify or overwrite "
            "existing archives during the repair process."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("apex repair command",),
        safer_alternatives=(
            "Ensure you have a backup of the archive before repairing.",
        ),
        matcher=_APEX_REPAIR,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _APEX_REPAIR,
                variant_id="help",
                title="apex repair command help",
                flag="--help",
            ),
            safe_flag_variant(
                _APEX_REPAIR,
                variant_id="help-short",
                title="apex repair command help",
                flag="-h",
            ),
        ),
    ),
)

APEX_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.apex",
        name="apex command protection",
        description=(
            "Reviews apex commands that can overwrite files during compression, "
            "decompression, or archive repair."
        ),
        action_classes=(
            "apex compress command",
            "apex decompress command",
            "apex repair command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Check destinations before compressing or decompressing.",
            "Backup archives before attempting to repair them.",
        ),
        reference_urls=("https://github.com/qxmcu/apex",),
    ),
)
