"""Structured rules and metadata for the where-are-we command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

# Flag surface verified against where-are-we 1.4.1 (PyPI), which publishes its
# own effects manifest: `where-are-we --effects --json`, schema
# "where-are-we-effects/1", installed beside the code as effects.json. It
# classes every flag read < writes-map-dir < writes-repo < writes-config <
# network, and a command line carries the highest class any of its flags does.
#
# The reviewed boundary is writes-repo and above. Reads and the map-directory
# writes the caller already named in --out stay non-reviewable: coding agents
# run the read flags on nearly every turn, and a read invocation carries no
# reviewed flag, so no matcher emits evidence and the command never enters the
# review pipeline. --spec-depth and --spec-limit carry the network class in the
# manifest but only tune a --specs fetch and cannot reach the network alone, so
# they are not reviewed on their own.
#
# The tool has no subcommands: the whole surface is argparse flags on the bare
# executable, so each rule is a required-flag constraint.

# Every value-taking option, so a reviewed flag spelled inside another option's
# value cannot be mistaken for the option itself. --docs is deliberately absent:
# it takes an optional argument, and treating it as value-taking would let it
# swallow a following reviewed flag.
_OPTIONS_WITH_VALUES: frozenset[str] = frozenset(
    {
        "--agent-file",
        "--also",
        "--ask",
        "--callees",
        "--callers",
        "--corpus",
        "--for",
        "--impact",
        "--impact-depth",
        "--install-hook",
        "--max-lines",
        "--more",
        "--only",
        "--out",
        "--product",
        "--repo",
        "--rules",
        "--runs-api",
        "--skip",
        "--spec-cmd",
        "--spec-depth",
        "--spec-limit",
        "--spec-source",
        "--specs",
        "--watch",
    }
)

# argparse resolves any unambiguous long-option prefix, so every prefix below is
# the flag itself, the way command.repo2nb enumerates the prefixes of --force.
# Prefixes are accepted for the flags that cause review and never for the flags
# that cancel it, so an abbreviation can only broaden detection.
_AGENT_FILE_FLAGS: tuple[str, ...] = (
    "--agent-file",
    "--agent-fil",
    "--agent-fi",
    "--agent-f",
    "--agent-",
    "--agent",
    "--agen",
    "--age",
    "--ag",
)
_INIT_FLAGS: tuple[str, ...] = ("--init", "--ini")
_DOCS_FLAGS: tuple[str, ...] = ("--docs", "--doc", "--do")
_INSTALL_HOOK_FLAGS: tuple[str, ...] = (
    "--install-hook",
    "--install-hoo",
    "--install-ho",
    "--install-h",
    "--install-",
    "--install",
    "--instal",
    "--insta",
    "--inst",
    "--ins",
)
_SPECS_FLAGS: tuple[str, ...] = ("--specs",)
_SPEC_CMD_FLAGS: tuple[str, ...] = ("--spec-cmd", "--spec-cm", "--spec-c")
_SPEC_SOURCE_FLAGS: tuple[str, ...] = (
    "--spec-source",
    "--spec-sourc",
    "--spec-sour",
    "--spec-sou",
    "--spec-so",
    "--spec-s",
)
_RUNS_API_FLAGS: tuple[str, ...] = (
    "--runs-api",
    "--runs-ap",
    "--runs-a",
    "--runs-",
    "--runs",
    "--run",
)

REPOSITORY_WRITE_FLAGS: tuple[str, ...] = _AGENT_FILE_FLAGS + _INIT_FLAGS + _DOCS_FLAGS
INSTALL_HOOK_FLAGS: tuple[str, ...] = _INSTALL_HOOK_FLAGS
TRACKER_FETCH_FLAGS: tuple[str, ...] = _SPECS_FLAGS + _SPEC_CMD_FLAGS + _SPEC_SOURCE_FLAGS + _RUNS_API_FLAGS

# --effects is resolved before anything else in the tool's main() and exits, and
# --dry-run returns from the answer path and the build path before any write,
# printing the paths it would have written. Both are documented, side-effect
# free, and spelled in full: an unknown option before one of them leaves its
# presence unprovable in every bounded parse, so fail-secure option parsing
# keeps the command reviewable rather than selling a help exemption.
_SAFE_FLAGS: tuple[tuple[str, str], ...] = (
    ("help", "--help"),
    ("short-help", "-h"),
    ("effects", "--effects"),
    ("dry-run", "--dry-run"),
)


def _flag_matcher(flags: tuple[str, ...]) -> AnyMatcher:
    """Match where-are-we invocations carrying any one accepted flag spelling."""

    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                "where-are-we",
                required_flags=frozenset({flag}),
                options_with_values=_OPTIONS_WITH_VALUES,
                fail_secure_unknown_options=True,
            )
            for flag in flags
        )
    )


def _safe_variants(matcher: AnyMatcher, title: str) -> tuple[CommandSafeVariant, ...]:
    """Build the side-effect-free variants shared by every where-are-we rule."""

    return tuple(
        safe_flag_variant(matcher, variant_id=variant_id, title=title, flag=flag) for variant_id, flag in _SAFE_FLAGS
    )


_WHERE_ARE_WE_REPOSITORY_WRITE = _flag_matcher(REPOSITORY_WRITE_FLAGS)
_WHERE_ARE_WE_INSTALL_HOOK = _flag_matcher(INSTALL_HOOK_FLAGS)
_WHERE_ARE_WE_TRACKER_FETCH = _flag_matcher(TRACKER_FETCH_FLAGS)


WHERE_ARE_WE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.where-are-we.repository-write",
        title="where-are-we repository file write",
        description=(
            "Identifies the where-are-we flags that write into the repository being mapped rather than into the "
            "map directory: --agent-file writes the brief into an agent file such as AGENTS.md or CLAUDE.md, "
            "--init writes a starter .framework-map.json, and --docs write creates the READMEs, manifest and "
            "architecture page a repository lacks."
        ),
        severity="medium",
        risk_classes=("local_secret_read",),
        action_classes=("where-are-we repository file write command",),
        safer_alternatives=(
            "Run the same command line with --dry-run first and read the paths it prints.",
            "Confirm which agent file is being written before writing it; the map lands between markers and the "
            "rest of the file survives, but the target is chosen by the caller.",
            "Use --docs without an argument, which only reports what it would write.",
        ),
        matcher=_WHERE_ARE_WE_REPOSITORY_WRITE,
        default_mode="review",
        safe_variants=_safe_variants(_WHERE_ARE_WE_REPOSITORY_WRITE, "where-are-we side-effect-free invocation"),
        example_command="where-are-we --repo . --agent-file AGENTS.md",
    ),
    CommandSafetyRule(
        rule_id="command.where-are-we.install-hook",
        title="where-are-we agent hook installation",
        description=(
            "Identifies `where-are-we --install-hook`, which writes where a tool other than this one reads: git "
            "hooks (post-checkout, post-merge, post-commit), ~/.claude/settings.json, ~/.codex/config.toml, a "
            "Cursor rule or a Gemini setting. After it runs, a checkout or a session start re-runs the tool."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("where-are-we agent hook installation command",),
        safer_alternatives=(
            "Run the same command line with --dry-run first; it prints every hook or config path it would write.",
            "Confirm the hook target, because git installs into the repository while claude, codex, cursor and "
            "gemini write user-level configuration outside it.",
            "Review the existing hook or configuration file before letting the tool wire itself into it.",
        ),
        matcher=_WHERE_ARE_WE_INSTALL_HOOK,
        default_mode="review",
        safe_variants=_safe_variants(_WHERE_ARE_WE_INSTALL_HOOK, "where-are-we side-effect-free invocation"),
        example_command="where-are-we --repo . --install-hook git",
    ),
    CommandSafetyRule(
        rule_id="command.where-are-we.tracker-fetch",
        title="where-are-we tracker fetch",
        description=(
            "Identifies the where-are-we flags that leave the machine: --specs walks a ticket tracker into a "
            "specification map, --spec-source selects github or linear, --spec-cmd supplies the command line run "
            "once per ticket to fetch it, and --runs-api reads a runs database endpoint."
        ),
        severity="medium",
        risk_classes=("network_egress", "execution"),
        action_classes=("where-are-we tracker fetch command",),
        safer_alternatives=(
            "Confirm the ticket keys and the fetch depth before a walk; a tracker is a graph and will hand over "
            "far more than the roots named.",
            "Read the --spec-cmd command line before it runs, because it executes once per ticket.",
            "Prefer a tracker endpoint and credentials scoped to the project being mapped.",
        ),
        matcher=_WHERE_ARE_WE_TRACKER_FETCH,
        default_mode="review",
        safe_variants=_safe_variants(_WHERE_ARE_WE_TRACKER_FETCH, "where-are-we side-effect-free invocation"),
        example_command="where-are-we --repo . --specs ABC-1 --spec-source github",
    ),
)


WHERE_ARE_WE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.where-are-we",
        name="where-are-we command protection",
        description=(
            "Reviews the where-are-we repository-map CLI where it writes outside its own map directory: an agent "
            "file or manifest in the repository, a git hook or agent configuration file, and the tracker walk "
            "that leaves the machine. Map queries and map-directory writes stay non-reviewable."
        ),
        action_classes=(
            "where-are-we repository file write command",
            "where-are-we agent hook installation command",
            "where-are-we tracker fetch command",
        ),
        risk_classes=("local_secret_read", "destructive_shell", "network_egress", "execution"),
        safer_alternatives=(
            "Run the same command line with --dry-run first and read the paths it prints.",
            "Ask the tool what a command line does before running it: `where-are-we --effects -- <command line>`.",
        ),
        reference_urls=("https://github.com/ngavrish/where-are-we#what-writes-and-what-only-reads",),
    ),
)
