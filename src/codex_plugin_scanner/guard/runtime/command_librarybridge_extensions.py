"""Structured rules and metadata for LibraryBridge command protection."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--data-dir", "--steam-root"})
_GLOBAL_FLAGS = frozenset(
    {
        "--dry-run",
        "--force",
        "--json",
        "--keep-destination",
        "--replace-destination",
        "--yes",
        "-n",
    }
)


def _librarybridge_matcher(
    *subcommands: str,
    options_with_values: frozenset[str] = frozenset(),
) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "librarybridge",
                *subcommands,
                allow_leading_options=True,
                leading_options_with_values=_GLOBAL_OPTIONS_WITH_VALUES,
                global_options_with_values=_GLOBAL_OPTIONS_WITH_VALUES,
                global_flags=_GLOBAL_FLAGS,
                options_with_values=options_with_values,
                fail_secure_unknown_options=True,
            ),
        )
    )


_FIX = _librarybridge_matcher("fix", options_with_values=frozenset({"--expect"}))
_UNDO = _librarybridge_matcher("undo")
_BACKUP = _librarybridge_matcher("backup")
_LUTRIS_IMPORT = _librarybridge_matcher("lutris", "import", options_with_values=frozenset({"--plan"}))


def _safe_variants(matcher: AnyMatcher, name: str) -> tuple[CommandSafeVariant, ...]:
    return (
        safe_flag_variant(
            matcher,
            variant_id="dry-run",
            title=f"LibraryBridge {name} dry run",
            flag="--dry-run",
        ),
        safe_flag_variant(
            matcher,
            variant_id="no-act",
            title=f"LibraryBridge {name} no-act",
            flag="-n",
        ),
        safe_flag_variant(
            matcher,
            variant_id="help",
            title=f"LibraryBridge {name} help",
            flag="--help",
        ),
    )


LIBRARYBRIDGE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.librarybridge.fix",
        title="LibraryBridge repair",
        description=(
            "Identifies LibraryBridge repairs, which copy Proton compatdata, "
            "retain the original, and change the Steam library path."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("LibraryBridge fix command",),
        safer_alternatives=("Run `librarybridge fix` with `--dry-run` and review the complete plan first.",),
        matcher=_FIX,
        safe_variants=_safe_variants(_FIX, "fix"),
    ),
    CommandSafetyRule(
        rule_id="command.librarybridge.undo",
        title="LibraryBridge repair undo",
        description=(
            "Identifies LibraryBridge undo operations, which restore Proton "
            "compatdata to the Steam library and remove its routing link."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("LibraryBridge undo command",),
        safer_alternatives=("Run `librarybridge undo` with `--dry-run` and review the restore plan first.",),
        matcher=_UNDO,
        safe_variants=_safe_variants(_UNDO, "undo"),
    ),
    CommandSafetyRule(
        rule_id="command.librarybridge.backup",
        title="LibraryBridge backup removal",
        description=(
            "Identifies LibraryBridge backup cleanup, which permanently removes "
            "the retained original compatdata after its recovery checks."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("LibraryBridge backup command",),
        safer_alternatives=("Run `librarybridge backup` with `--dry-run` and confirm the original is recoverable.",),
        matcher=_BACKUP,
        safe_variants=_safe_variants(_BACKUP, "backup"),
    ),
    CommandSafetyRule(
        rule_id="command.librarybridge.lutris-import",
        title="LibraryBridge Lutris import",
        description=(
            "Identifies LibraryBridge Lutris imports, which write selected "
            "game definitions and import records into Lutris state."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("LibraryBridge Lutris import command",),
        safer_alternatives=("Run `librarybridge lutris import` with `--dry-run` and review the selected games first.",),
        matcher=_LUTRIS_IMPORT,
        safe_variants=_safe_variants(_LUTRIS_IMPORT, "Lutris import"),
    ),
)


LIBRARYBRIDGE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.librarybridge",
        name="LibraryBridge command protection",
        description=(
            "Reviews LibraryBridge commands that move Steam Proton data, restore it, "
            "remove retained originals, or write Lutris definitions."
        ),
        action_classes=(
            "LibraryBridge fix command",
            "LibraryBridge undo command",
            "LibraryBridge backup command",
            "LibraryBridge Lutris import command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Use the matching LibraryBridge `--dry-run` command and review it before applying changes.",
        ),
        executables=("librarybridge",),
        reference_urls=(
            "https://github.com/amcdev7/LibraryBridge",
            "https://github.com/amcdev7/LibraryBridge#usage",
        ),
    ),
)
