"""Structured rules and metadata for Storage Clearer commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandSafetyRule


@final
@dataclass(frozen=True, slots=True)
class _ShellScriptInvocationMatcher:
    """Match cleanup subcommands passed to a supported shell interpreter."""

    interpreters: frozenset[str]
    script_name: str
    subcommands: frozenset[str]

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            executable = segment.executable
            if executable is None or executable.replace("\\", "/").rsplit("/", 1)[-1].lower() not in self.interpreters:
                continue
            arguments = segment.arguments
            script_index = 1 if arguments[:1] == ("--",) else 0
            if len(arguments) <= script_index + 1:
                continue
            script_name = arguments[script_index].replace("\\", "/").rsplit("/", 1)[-1].lower()
            subcommand = arguments[script_index + 1].lower()
            if script_name != self.script_name or subcommand not in self.subcommands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=executable,
                    detail="Matched a shell-interpreted Storage Clearer cleanup command.",
                )
            )
        return tuple(evidence)


_STORAGE_CLEARER_CLEANUP = AnyMatcher(
    matchers=(
        executable_matcher("storage-clearer.sh", "run"),
        executable_matcher("storage-clearer.sh", "app-run"),
        _ShellScriptInvocationMatcher(
            interpreters=frozenset({"bash", "sh"}),
            script_name="storage-clearer.sh",
            subcommands=frozenset({"app-run", "run"}),
        ),
    )
)

STORAGE_CLEARER_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.storage-clearer.cleanup",
        title="Storage Clearer cleanup execution",
        description=(
            "Identifies Storage Clearer run and app-run cleanup sessions, which can invoke Docker prune commands, "
            "xcrun simctl deletion, or tmutil snapshot thinning."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Storage Clearer cleanup command",),
        safer_alternatives=(
            "Run audit and review the generated plan before starting cleanup.",
            "Keep Storage Clearer's approval and target-revalidation gates in place.",
        ),
        matcher=_STORAGE_CLEARER_CLEANUP,
        default_mode="review",
        example_command="./storage-clearer.sh run B",
    ),
)

STORAGE_CLEARER_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.storage-clearer",
        name="Storage Clearer command protection",
        description=(
            "Reviews Storage Clearer's run and app-run cleanup entry points while leaving audit, explain, reason, "
            "and plan read-only."
        ),
        action_classes=("Storage Clearer cleanup command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Run audit and review the generated plan before starting cleanup.",),
        reference_urls=("https://github.com/khiemnd777/storage-clearer/blob/main/storage-clearer.sh",),
        executables=("storage-clearer.sh",),
    ),
)
