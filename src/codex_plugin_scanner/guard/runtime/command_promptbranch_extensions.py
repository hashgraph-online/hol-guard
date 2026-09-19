"""Structured rules and metadata for PromptBranch CLI commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant, with_required_flag
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, ExecutableMatcher

# CLI surface verified against PromptBranch CLI 0.2.x (apps/cli/src/index.ts):
# publish, import, add-note, report-run, and suggest mutate local records or
# exchange data with the sharing portal. Suggest's --file form additionally
# reads caller-selected local content. `publish --preview` is the documented
# side-effect-free counterpart. Read, search, and suggestion-listing commands
# intentionally have no rules. The public npx/bunx launch forms cover the
# documented package name and @latest alias; other version pins remain outside
# this v1 boundary.

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


def _promptbranch_matcher(
    subcommand: str,
    options_with_values: frozenset[str],
    flags: frozenset[str] | None = None,
) -> AnyMatcher:
    command_flags = _COMMON_FLAGS | (flags if flags is not None else _NO_FLAGS)
    package_arguments = (
        ("@promptbranch/cli", subcommand),
        ("@promptbranch/cli@latest", subcommand),
    )
    launcher_arguments = (("promptbranch", subcommand), *(("npx", *package) for package in package_arguments))

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
        )
    )


_PROMPTBRANCH_PUBLISH = _promptbranch_matcher("publish", _PUBLISH_OPTIONS_WITH_VALUES, _PUBLISH_FLAGS)
_PROMPTBRANCH_IMPORT = _promptbranch_matcher("import", _IMPORT_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_ADD_NOTE = _promptbranch_matcher("add-note", _ADD_NOTE_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_REPORT_RUN = _promptbranch_matcher("report-run", _REPORT_RUN_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_SUGGEST = _promptbranch_matcher("suggest", _SUGGEST_OPTIONS_WITH_VALUES)
_PROMPTBRANCH_SUGGEST_FILE = with_required_flag(_PROMPTBRANCH_SUGGEST, "--file")

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
            safe_flag_variant(
                _PROMPTBRANCH_PUBLISH,
                variant_id="preview",
                title="PromptBranch publish preview",
                flag="--preview",
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
