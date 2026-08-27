"""Structured rules and metadata for the errd command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import CommandSafetyRule


_ERRD_ANALYZE = executable_matcher(
    "errd",
    "analyze",
    options_with_values=frozenset(
        {
            "--budget",
            "-b",
            "--output",
            "-o",
            "--repo",
            "-r",
        }
    ),
)


ERRD_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.errd.analyze",
        title="errd traceback analysis",
        description=(
            "Identifies the `errd analyze` command, which reads a traceback or log "
            "and local source files and writes an errd-context.md analysis package."
        ),
        severity="low",
        risk_classes=("local_secret_read",),
        action_classes=("errd local analysis command",),
        safer_alternatives=(
            "Review the traceback and repository scope before generating the context package.",
            "Use the smallest practical token budget and an explicit output path when needed.",
        ),
        matcher=_ERRD_ANALYZE,
        default_mode="review",
    ),
)


ERRD_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.errd",
        name="errd traceback analysis",
        description=(
            "Recognizes errd's local traceback analysis command and documents its "
            "bounded local filesystem read/write behavior."
        ),
        action_classes=("errd local analysis command",),
        risk_classes=("local_secret_read",),
        safer_alternatives=(
            "Review the traceback and repository scope before generating the context package.",
            "Use the smallest practical token budget and an explicit output path when needed.",
        ),
        reference_urls=(
            "https://pypi.org/project/errd/",
            "https://github.com/Das-R10/errd",
        ),
        executables=("errd",),
    ),
)
