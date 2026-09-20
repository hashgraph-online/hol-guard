"""Structured rules and metadata for PromptBranch CLI commands."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import final

from .command_extension_matchers import executable_matcher, executable_names, with_required_flag
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import argument_semantics, flags_present_in_all_option_parses
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
    _after_leading_options,
    _without_options,
)

# CLI surface verified against PromptBranch CLI 0.2.x (apps/cli/src/index.ts):
# publish, import, add-note, report-run, and suggest mutate local records or
# exchange data with the sharing portal. Suggest's --file form additionally
# reads caller-selected local content. `publish --preview` is the documented
# side-effect-free counterpart. Read, search, and suggestion-listing commands
# intentionally have no rules. The public npx/bunx launch forms cover the
# documented package name and aliases. Version-qualified package launches are
# matched structurally so a pinned version or dist-tag cannot bypass review.

_COMMON_FLAGS = frozenset({"--json"})
_NO_FLAGS: frozenset[str] = frozenset()
_PUBLISH_OPTIONS_WITH_VALUES = frozenset({"--description", "--portal"})
_IMPORT_OPTIONS_WITH_VALUES = frozenset({"--portal"})
_ADD_NOTE_OPTIONS_WITH_VALUES = frozenset({"--prompt", "--body", "--version-id"})
_REPORT_RUN_OPTIONS_WITH_VALUES = frozenset(
    {"--prompt", "--version-id", "--version", "--tool", "--model", "--outcome", "--summary"}
)
_SUGGEST_OPTIONS_WITH_VALUES = frozenset(
    {"--prompt", "--file", "--content", "--rationale", "--base-version-id", "--base-version"}
)
_PUBLISH_FLAGS = frozenset({"--full-history", "--preview", "--yes"})
_NPX_LEADING_FLAGS = frozenset({"-y", "--yes"})
_XARGS_LEADING_OPTIONS_WITH_VALUES = frozenset({"-I", "-L", "-n", "-P", "-s"})
_PROMPTBRANCH_PACKAGE_LAUNCHERS = executable_names("npx") | executable_names("bunx")
_PROMPTBRANCH_WRAPPER_EXECUTABLES = executable_names("exec") | executable_names("xargs")
_PROMPTBRANCH_XARGS_EXECUTABLES = executable_names("xargs")


@final
@dataclass(frozen=True, slots=True)
class PromptBranchVersionedPackageMatcher:
    """Match a version- or tag-qualified PromptBranch package launch.

    The package token is intentionally checked as a complete structured
    operand. A prefix such as ``@promptbranch/cli-helper@...`` therefore does
    not become a PromptBranch match, while arbitrary non-empty npm versions
    and dist-tags remain covered without enumerating them in the catalog.
    """

    subcommand: str
    package_launchers: frozenset[str]
    wrapper_executables: frozenset[str]
    wrapper_options_with_values: frozenset[str]
    package_prefix: str = "@promptbranch/cli@"
    excluded_qualifiers: frozenset[str] = frozenset({"latest"})
    required_flags: frozenset[str] = frozenset()
    options_with_values: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        package_launchers = frozenset(value.strip().lower() for value in self.package_launchers if value.strip())
        wrapper_executables = frozenset(value.strip().lower() for value in self.wrapper_executables if value.strip())
        package_prefix = self.package_prefix.strip().lower()
        subcommand = self.subcommand.strip().lower()
        excluded_qualifiers = frozenset(value.strip().lower() for value in self.excluded_qualifiers if value.strip())
        required_flags = frozenset(value.strip().lower() for value in self.required_flags if value.strip())
        options_with_values = frozenset(value.strip().lower() for value in self.options_with_values if value.strip())
        flags = frozenset(value.strip().lower() for value in self.flags if value.strip())
        wrapper_options_with_values = frozenset(
            value.strip().lower() for value in self.wrapper_options_with_values if value.strip()
        )
        if not package_launchers or not wrapper_executables:
            raise ValueError("PromptBranchVersionedPackageMatcher requires launchers")
        if not subcommand or not package_prefix.endswith("@"):
            raise ValueError("PromptBranchVersionedPackageMatcher requires a subcommand and package prefix")
        object.__setattr__(self, "package_launchers", package_launchers)
        object.__setattr__(self, "wrapper_executables", wrapper_executables)
        object.__setattr__(self, "package_prefix", package_prefix)
        object.__setattr__(self, "subcommand", subcommand)
        object.__setattr__(self, "excluded_qualifiers", excluded_qualifiers)
        object.__setattr__(self, "required_flags", required_flags)
        object.__setattr__(self, "options_with_values", options_with_values)
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "wrapper_options_with_values", wrapper_options_with_values)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        all_options_with_values = self.options_with_values | self.wrapper_options_with_values
        known_flags = self.flags | self.required_flags
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            executable = segment.executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if executable not in self.package_launchers and executable not in self.wrapper_executables:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            package_arguments = _without_options(
                lowered_arguments,
                self.options_with_values,
                self.flags | _NPX_LEADING_FLAGS,
            )
            if executable in self.wrapper_executables:
                package_arguments = _after_leading_options(
                    package_arguments,
                    self.wrapper_options_with_values if executable in _PROMPTBRANCH_XARGS_EXECUTABLES else frozenset(),
                    self.flags | _NPX_LEADING_FLAGS,
                )
                if not package_arguments or package_arguments[0] not in self.package_launchers:
                    continue
                package_arguments = package_arguments[1:]
            if len(package_arguments) < 2:
                continue
            package, subcommand = package_arguments[:2]
            if not package.startswith(self.package_prefix):
                continue
            qualifier = package[len(self.package_prefix) :]
            if not qualifier or qualifier in self.excluded_qualifiers or subcommand != self.subcommand:
                continue
            if self.required_flags:
                semantics = argument_semantics(lowered_arguments, options_with_values=all_options_with_values)
                if not self.required_flags <= semantics.present_flags:
                    continue
                if not flags_present_in_all_option_parses(
                    lowered_arguments,
                    self.required_flags,
                    options_with_values=all_options_with_values,
                    known_flags=known_flags,
                ):
                    continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a version-qualified PromptBranch package launcher and structured subcommand.",
                )
            )
        return tuple(evidence)


def _promptbranch_versioned_package_matcher(
    subcommand: str,
    options_with_values: frozenset[str],
    flags: frozenset[str],
) -> PromptBranchVersionedPackageMatcher:
    return PromptBranchVersionedPackageMatcher(
        subcommand=subcommand,
        package_launchers=_PROMPTBRANCH_PACKAGE_LAUNCHERS,
        wrapper_executables=_PROMPTBRANCH_WRAPPER_EXECUTABLES,
        wrapper_options_with_values=_XARGS_LEADING_OPTIONS_WITH_VALUES,
        options_with_values=options_with_values,
        flags=flags,
    )


def _promptbranch_with_required_flag(matcher: AnyMatcher, flag: str) -> AnyMatcher:
    """Clone literal and version-qualified launchers for a safe flag variant."""

    literal_children = tuple(child for child in matcher.matchers if isinstance(child, ExecutableMatcher))
    versioned_children = tuple(
        replace(child, required_flags=child.required_flags | {flag})
        for child in matcher.matchers
        if isinstance(child, PromptBranchVersionedPackageMatcher)
    )
    if len(literal_children) + len(versioned_children) != len(matcher.matchers):
        raise ValueError("PromptBranch safe variants require supported matcher children")
    return AnyMatcher(
        matchers=(
            *with_required_flag(AnyMatcher(matchers=literal_children), flag).matchers,
            *versioned_children,
        )
    )


def _promptbranch_matcher(
    subcommand: str,
    options_with_values: frozenset[str],
    flags: frozenset[str] | None = None,
) -> AnyMatcher:
    command_flags = _COMMON_FLAGS | (flags if flags is not None else _NO_FLAGS)
    versioned_package_matcher = _promptbranch_versioned_package_matcher(
        subcommand,
        options_with_values,
        command_flags | _NPX_LEADING_FLAGS,
    )
    package_arguments = (
        ("@promptbranch/cli", subcommand),
        ("@promptbranch/cli@latest", subcommand),
    )
    launcher_arguments = (
        *((launcher, subcommand) for launcher in sorted(executable_names("promptbranch"))),
        *(
            (launcher, *package)
            for launcher in sorted(executable_names("npx") | executable_names("bunx"))
            for package in package_arguments
        ),
    )

    def _wrapped_matcher(prefix: tuple[str, ...]) -> tuple[ExecutableMatcher, ...]:
        return (
            ExecutableMatcher(
                executables=executable_names("exec"),
                subcommands=prefix,
                interspersed_options_with_values=options_with_values,
                interspersed_flags=command_flags | _NPX_LEADING_FLAGS,
                fail_secure_unknown_options=True,
            ),
            ExecutableMatcher(
                executables=executable_names("xargs"),
                subcommands=prefix,
                allow_leading_options=True,
                leading_options_with_values=_XARGS_LEADING_OPTIONS_WITH_VALUES,
                interspersed_options_with_values=options_with_values,
                interspersed_flags=command_flags | _NPX_LEADING_FLAGS,
                fail_secure_unknown_options=True,
            ),
        )

    return AnyMatcher(
        matchers=(
            executable_matcher(
                "promptbranch",
                subcommand,
                global_options_with_values=options_with_values,
                global_flags=command_flags,
                fail_secure_unknown_options=True,
            ),
            *(
                ExecutableMatcher(
                    executables=executable_names("npx") | executable_names("bunx"),
                    subcommands=package_argument,
                    interspersed_options_with_values=options_with_values,
                    interspersed_flags=command_flags | _NPX_LEADING_FLAGS,
                    allow_leading_options=True,
                    fail_secure_unknown_options=True,
                )
                for package_argument in package_arguments
            ),
            *(matcher for prefix in launcher_arguments for matcher in _wrapped_matcher(prefix)),
            versioned_package_matcher,
        )
    )


_PROMPTBRANCH_PUBLISH = _promptbranch_matcher("publish", _PUBLISH_OPTIONS_WITH_VALUES, _PUBLISH_FLAGS)
_PROMPTBRANCH_IMPORT = _promptbranch_matcher("import", _IMPORT_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_ADD_NOTE = _promptbranch_matcher("add-note", _ADD_NOTE_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_REPORT_RUN = _promptbranch_matcher("report-run", _REPORT_RUN_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_SUGGEST = _promptbranch_matcher("suggest", _SUGGEST_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_SUGGEST_FILE = _promptbranch_with_required_flag(_PROMPTBRANCH_SUGGEST, "--file")

PROMPTBRANCH_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "promptbranch prompt publication command": ("network_egress",),
    "promptbranch shared prompt import command": ("network_egress",),
    "promptbranch prompt note write command": ("destructive_shell",),
    "promptbranch prompt run report command": ("destructive_shell",),
    "promptbranch prompt suggestion write command": ("destructive_shell",),
    "promptbranch prompt suggestion local file read command": ("local_secret_read",),
}

PROMPTBRANCH_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.promptbranch.publish",
        title="PromptBranch prompt publication",
        description=(
            "Identifies PromptBranch CLI publication, which sends an immutable prompt "
            "snapshot to the configured sharing portal. PromptBranch also performs its "
            "own confirmation and secret scan; this rule supplies the outer agent-launch "
            "boundary, including non-interactive `--yes` execution."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("PromptBranch prompt publication command",),
        safer_alternatives=(
            "Run promptbranch publish --preview and review the exact payload and destination first.",
            "Approve the exact prompt and portal in an interactive terminal before publishing.",
        ),
        matcher=_PROMPTBRANCH_PUBLISH,
        default_mode="review",
        safe_variants=(
            CommandSafeVariant(
                variant_id="preview",
                title="PromptBranch publish preview",
                matcher=_promptbranch_with_required_flag(_PROMPTBRANCH_PUBLISH, "--preview"),
            ),
        ),
        example_command="promptbranch publish",
    ),
    CommandSafetyRule(
        rule_id="command.promptbranch.import",
        title="PromptBranch shared prompt import",
        description=(
            "Identifies PromptBranch CLI import, which fetches a shared snapshot from "
            "a portal and creates a new local prompt from that untrusted content."
        ),
        severity="medium",
        risk_classes=("network_egress",),
        action_classes=("PromptBranch shared prompt import command",),
        safer_alternatives=(
            "Open the share URL in a browser and review its prompt, tags, and history before importing.",
            "Import into an isolated PromptBranch database first when testing an untrusted share.",
        ),
        matcher=_PROMPTBRANCH_IMPORT,
        default_mode="review",
        example_command="promptbranch import",
    ),
    CommandSafetyRule(
        rule_id="command.promptbranch.add-note",
        title="PromptBranch prompt note write",
        description="Identifies PromptBranch CLI add-note, which persists a note on a local prompt or prompt version.",
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("PromptBranch prompt note write command",),
        safer_alternatives=(
            "Review the target prompt and exact note body before writing them to the shared local library.",
        ),
        matcher=_PROMPTBRANCH_ADD_NOTE,
        default_mode="review",
        example_command="promptbranch add-note",
    ),
    CommandSafetyRule(
        rule_id="command.promptbranch.report-run",
        title="PromptBranch prompt run report",
        description=(
            "Identifies PromptBranch CLI report-run, which persists run metadata and evaluation results locally."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("PromptBranch prompt run report command",),
        safer_alternatives=("Confirm the prompt version, tool, model, rating, and summary before recording the run.",),
        matcher=_PROMPTBRANCH_REPORT_RUN,
        default_mode="review",
        example_command="promptbranch report-run",
    ),
    CommandSafetyRule(
        rule_id="command.promptbranch.suggest",
        title="PromptBranch prompt suggestion write",
        description=(
            "Identifies PromptBranch CLI suggest, which creates a local branch and pending prompt version "
            "for later human review."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("PromptBranch prompt suggestion write command",),
        safer_alternatives=(
            "Review the target prompt, complete rewritten content, and rationale before creating the suggestion.",
        ),
        matcher=_PROMPTBRANCH_SUGGEST,
        default_mode="review",
        example_command="promptbranch suggest",
    ),
    CommandSafetyRule(
        rule_id="command.promptbranch.suggest-file",
        title="PromptBranch prompt suggestion file read",
        description=(
            "Identifies PromptBranch CLI suggest --file, which reads caller-selected local file content "
            "before storing it in a pending prompt version."
        ),
        severity="medium",
        risk_classes=("local_secret_read",),
        action_classes=("PromptBranch prompt suggestion local file read command",),
        safer_alternatives=("Review the selected file path and its complete contents before creating the suggestion.",),
        matcher=_PROMPTBRANCH_SUGGEST_FILE,
        default_mode="review",
        example_command="promptbranch suggest --file prompt.md",
    ),
)

PROMPTBRANCH_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.promptbranch",
        name="PromptBranch command protection",
        description=(
            "Reviews PromptBranch CLI sharing operations and persistent agent-written "
            "library records while leaving read, search, and suggestion listing commands automatic."
        ),
        action_classes=(
            "PromptBranch prompt publication command",
            "PromptBranch shared prompt import command",
            "PromptBranch prompt note write command",
            "PromptBranch prompt run report command",
            "PromptBranch prompt suggestion write command",
            "PromptBranch prompt suggestion local file read command",
        ),
        risk_classes=("network_egress", "destructive_shell", "local_secret_read"),
        safer_alternatives=(
            "Use promptbranch publish --preview to inspect the exact payload and destination first.",
            "Review imported prompts and agent-written notes before saving them to the shared local library.",
            "Review suggestion content and any selected local file before creating a pending version.",
        ),
        reference_urls=("https://promptbranch.app/docs/integrations/cli",),
        executables=("promptbranch", "npx", "bunx"),
        ecosystem_ids=("promptbranch",),
    ),
)
