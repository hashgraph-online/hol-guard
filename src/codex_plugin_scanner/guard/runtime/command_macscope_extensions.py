"""Structured rules and metadata for the MacScope MCP command extension."""

from __future__ import annotations

from .command_extension_matchers import safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant, ExecutableMatcher

# Startup surface verified against MacScopeMCPServer 1.0.0 at
# rsm23/macscope@a3056e7de62b88c1021b1ccbad04711c34eaf00b. MacScope is
# macOS-only, so this extension intentionally recognizes only the app-bundled
# executable instead of inventing portable .cmd or .exe launcher variants.
_MACSCOPE_EXECUTABLES = frozenset({"macscopemcpserver"})


def _write_gate(flag: str) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            ExecutableMatcher(
                executables=_MACSCOPE_EXECUTABLES,
                required_flags=frozenset({flag}),
            ),
        )
    )


def _nonstarting_variants(matcher: AnyMatcher) -> tuple[CommandSafeVariant, ...]:
    """Return informational exits that prevent the MCP server from starting."""

    return tuple(
        safe_flag_variant(
            matcher,
            variant_id=variant_id,
            title=title,
            flag=flag,
        )
        for variant_id, title, flag in (
            ("help", "MacScope MCP server help", "--help"),
            ("short-help", "MacScope MCP server help", "-h"),
            ("version", "MacScope MCP server version", "--version"),
            ("short-version", "MacScope MCP server version", "-v"),
        )
    )


_FEATURE_WRITES = _write_gate("--allow-feature-writes")
_EXPERIMENTAL_FEATURE_WRITES = _write_gate("--allow-experimental-feature-writes")
_UTILITY_WRITES = _write_gate("--allow-utility-writes")


MACSCOPE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.macscope.feature-writes",
        title="MacScope feature-write capability",
        description=(
            "Identifies a MacScopeMCPServer launch that enables the preflight, apply, and undo workflow for "
            "allowlisted recommended and advanced macOS feature changes."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("MacScope feature-write capability command",),
        safer_alternatives=(
            "Start MacScopeMCPServer without write flags and enable feature writes only for a specific task.",
            "Inspect the exact feature and retain MacScope's expiring undo token before applying the change.",
        ),
        matcher=_FEATURE_WRITES,
        default_mode="review",
        safe_variants=_nonstarting_variants(_FEATURE_WRITES),
        example_command="MacScopeMCPServer --allow-feature-writes",
    ),
    CommandSafetyRule(
        rule_id="command.macscope.experimental-feature-writes",
        title="MacScope experimental feature-write capability",
        description=(
            "Identifies a MacScopeMCPServer launch that separately enables experimental feature changes and "
            "also implies the established feature-write gate."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("MacScope experimental feature-write capability command",),
        safer_alternatives=(
            "Use --allow-feature-writes when the requested feature is recommended or advanced.",
            "Enable experimental writes only after reviewing the exact feature, restart effect, and undo path.",
        ),
        matcher=_EXPERIMENTAL_FEATURE_WRITES,
        default_mode="review",
        safe_variants=_nonstarting_variants(_EXPERIMENTAL_FEATURE_WRITES),
        example_command="MacScopeMCPServer --allow-experimental-feature-writes",
    ),
    CommandSafetyRule(
        rule_id="command.macscope.utility-writes",
        title="MacScope utility-write capability",
        description=(
            "Identifies a MacScopeMCPServer launch that enables exact actions from MacScope's compiled utility "
            "catalog, including local state changes and explicitly marked destructive actions."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("MacScope utility-write capability command",),
        safer_alternatives=(
            "Start MacScopeMCPServer without utility writes until an allowlisted action is required.",
            "Inspect macscope_list_utilities and keep the MCP client's write-tool approval policy enabled.",
        ),
        matcher=_UTILITY_WRITES,
        default_mode="review",
        safe_variants=_nonstarting_variants(_UTILITY_WRITES),
        example_command="MacScopeMCPServer --allow-utility-writes",
    ),
)


MACSCOPE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.macscope",
        name="MacScope MCP command protection",
        description=(
            "Reviews MacScopeMCPServer launches that opt into established feature writes, separately gated "
            "experimental feature writes, or allowlisted utility execution."
        ),
        action_classes=(
            "MacScope feature-write capability command",
            "MacScope experimental feature-write capability command",
            "MacScope utility-write capability command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Use MacScope's read-only default and add only the narrowest write gate required for the task.",
            "Keep experimental feature writes disabled unless a reviewed experimental catalog entry is needed.",
        ),
        reference_urls=(
            "https://github.com/rsm23/macscope/blob/a3056e7de62b88c1021b1ccbad04711c34eaf00b/Sources/MacScopeMCPServer/ServerMain.swift",
            "https://github.com/rsm23/macscope/blob/a3056e7de62b88c1021b1ccbad04711c34eaf00b/docs/MCP_SERVER.md",
        ),
        executables=("MacScopeMCPServer",),
    ),
)
