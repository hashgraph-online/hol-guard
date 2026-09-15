"""Structured rules and metadata for the Blaizio CLI command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

# Flag surface verified against Blaizio.Cli 0.3.3 (Spectre.Console.Cli, src/Blaizio.Cli/Commands).
# `add`, `update`, `remove` and `uninstall` are the only commands that rewrite project files
# (component sources, the csproj package set, blaizio.json, host wiring). Every one of them
# accepts --dry-run, which runs the same resolution and local-edit conflict scan as a real run
# but writes nothing: no NuGet bump, no blaizio.json save, no CSS or host wiring, and the
# trust-host confirm for unrecorded URLs is skipped as well. `add --diff` (compare installed
# files against upstream, exit 1 on drift) and `add --view` (print an item's files) are the
# other read-only entry points on the mutating command.
#
# Blaizio ships as a .NET tool, so the launcher forms are:
# - blaizio ...                       (global tool, also blaizio.exe / blaizio.cmd shims)
# - dotnet blaizio ...                (local tool manifest)
# - dotnet tool run blaizio ...       (explicit local tool invocation)
# - exec / xargs wrappers around the first two
#
# Spectre accepts options anywhere after the command name, and an unattended run (-y, --json,
# --silent) keeps every locally edited file; the "take upstream" flags are --force on update
# and --force-overwrite on add (plain --overwrite still prompts). Those flags do not change the
# review outcome: a rewrite is a rewrite, only --dry-run/--diff/--view make it a preview.
#
# Option parsing is fail-secure: every boolean flag the four commands accept is declared so
# `--dry-run` can be proven present in every bounded parse, and an unknown option keeps the
# command in review instead of letting an unrecognised value-taking option swallow the flag.

_BLAIZIO_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("blaizio",),
    ("dotnet", "blaizio"),
    ("dotnet", "tool", "run", "blaizio"),
    ("exec", "blaizio"),
    ("exec", "dotnet", "blaizio"),
    ("xargs", "blaizio"),
    ("xargs", "dotnet", "blaizio"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

# GlobalSettings / ConfirmRegistrySettings: shared by all four commands.
_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"-c", "--cwd", "--registry"})
_GLOBAL_FLAGS = frozenset({"-s", "--silent", "--json", "-y", "--yes", "-h", "--help"})

# AddSettings.
_ADD_OPTIONS_WITH_VALUES = frozenset({"--namespace", "--css", "--style", "--tailwind", "--icons", "-p", "--preset"})
_ADD_FLAGS = frozenset(
    {
        "-a",
        "--all",
        "--overwrite",
        "--prune",
        "--rtl",
        "--pointer",
        "--scrollbar",
        "-d",
        "--defaults",
        "-f",
        "--force",
        "--force-overwrite",
        "--dry-run",
        "--no-deps",
        "--no-nuget",
    }
)
# `--diff [path]` and `--view [path]` take an optional value, so they are declared as
# value-taking options: a bare `--diff`, `--diff ./path` and `--diff=./path` all keep the
# flag present, and a swallowed following token can only ever be a filter path.
_ADD_READ_ONLY_OPTIONS = frozenset({"--diff", "--view"})

# UpdateSettings and RemoveSettings share -f|--force and --dry-run; UninstallSettings has --dry-run.
_FORCE_FLAGS = frozenset({"-f", "--force"})
_DRY_RUN_FLAG = frozenset({"--dry-run"})


def _blaizio_matcher(
    subcommand: str,
    *,
    options_with_values: frozenset[str],
    flags: frozenset[str],
) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                subcommand,
                global_options_with_values=_GLOBAL_OPTIONS_WITH_VALUES | options_with_values,
                global_flags=_GLOBAL_FLAGS | flags,
                allow_leading_options=launcher[0] in ("exec", "xargs"),
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
                ),
                fail_secure_unknown_options=True,
            )
            for launcher in _BLAIZIO_LAUNCHERS
        )
    )


_BLAIZIO_ADD = _blaizio_matcher(
    "add",
    options_with_values=_ADD_OPTIONS_WITH_VALUES | _ADD_READ_ONLY_OPTIONS,
    flags=_ADD_FLAGS,
)
_BLAIZIO_UPDATE = _blaizio_matcher("update", options_with_values=frozenset(), flags=_FORCE_FLAGS | _DRY_RUN_FLAG)
_BLAIZIO_REMOVE = _blaizio_matcher("remove", options_with_values=frozenset(), flags=_FORCE_FLAGS | _DRY_RUN_FLAG)
_BLAIZIO_REMOVE_ALIAS = _blaizio_matcher("rm", options_with_values=frozenset(), flags=_FORCE_FLAGS | _DRY_RUN_FLAG)
_BLAIZIO_UNINSTALL = _blaizio_matcher("uninstall", options_with_values=frozenset(), flags=_DRY_RUN_FLAG)
_BLAIZIO_UNINSTALL_ALIAS = _blaizio_matcher("un", options_with_values=frozenset(), flags=_DRY_RUN_FLAG)

_BLAIZIO_REMOVE_ANY = AnyMatcher(matchers=(*_BLAIZIO_REMOVE.matchers, *_BLAIZIO_REMOVE_ALIAS.matchers))
_BLAIZIO_UNINSTALL_ANY = AnyMatcher(matchers=(*_BLAIZIO_UNINSTALL.matchers, *_BLAIZIO_UNINSTALL_ALIAS.matchers))


def _preview_variants(matcher: AnyMatcher, *, noun: str) -> tuple[CommandSafeVariant, ...]:
    return (
        safe_flag_variant(
            matcher,
            variant_id="dry-run",
            title=f"Blaizio {noun} dry run",
            flag="--dry-run",
        ),
        safe_flag_variant(
            matcher,
            variant_id="help",
            title=f"Blaizio {noun} command help",
            flag="--help",
        ),
        # Spectre.Console.Cli registers -h as the short form of --help on every command.
        safe_flag_variant(
            matcher,
            variant_id="short-help",
            title=f"Blaizio {noun} command help (short flag)",
            flag="-h",
        ),
    )


BLAIZIO_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.blaizio.add",
        title="Blaizio component install",
        description=(
            "Identifies `blaizio add`, which writes component source files into the "
            "project, adds NuGet package references to the csproj, records the install "
            "in blaizio.json and wires the CSS host on first use. With --overwrite or "
            "--force-overwrite it replaces files the user has edited locally."
        ),
        severity="medium",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("Blaizio component install command",),
        safer_alternatives=(
            "Preview the exact files, packages and local-edit decisions with blaizio add <item> --dry-run.",
            "Compare installed components against upstream without writing using blaizio add --diff.",
            "Inspect an item's files before installing with blaizio add --view <item> or blaizio view <item>.",
        ),
        matcher=_BLAIZIO_ADD,
        default_mode="review",
        safe_variants=(
            *_preview_variants(_BLAIZIO_ADD, noun="add"),
            safe_flag_variant(
                _BLAIZIO_ADD,
                variant_id="diff",
                title="Blaizio add upstream diff",
                flag="--diff",
            ),
            safe_flag_variant(
                _BLAIZIO_ADD,
                variant_id="view",
                title="Blaizio add item view",
                flag="--view",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.blaizio.update",
        title="Blaizio component update",
        description=(
            "Identifies `blaizio update`, which bumps the Blaizio NuGet packages and "
            "re-pulls every installed component from the registry. Files the user "
            "edited are kept under -y and replaced under --force, so an unattended "
            "run silently decides which local edits survive."
        ),
        severity="medium",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=("Blaizio component update command",),
        safer_alternatives=(
            "Run blaizio update --dry-run first: it runs the same local-edit conflict scan and lists every kept file.",
            "Use --dry-run --json to script the per-file decision list before committing to a real run.",
        ),
        matcher=_BLAIZIO_UPDATE,
        default_mode="review",
        safe_variants=_preview_variants(_BLAIZIO_UPDATE, noun="update"),
    ),
    CommandSafetyRule(
        rule_id="command.blaizio.remove",
        title="Blaizio component removal",
        description=(
            "Identifies `blaizio remove` (alias `rm`), which deletes the files a "
            "component installed and drops it from blaizio.json. With --force it "
            "removes a component other installed components still depend on."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Blaizio component remove command",),
        safer_alternatives=(
            "List the files that would be deleted with blaizio remove <item> --dry-run.",
            "Check dependants first: without --force the command refuses to remove a component something else needs.",
        ),
        matcher=_BLAIZIO_REMOVE_ANY,
        default_mode="review",
        safe_variants=_preview_variants(_BLAIZIO_REMOVE_ANY, noun="remove"),
    ),
    CommandSafetyRule(
        rule_id="command.blaizio.uninstall",
        title="Blaizio uninstall",
        description=(
            "Identifies `blaizio uninstall` (alias `un`), which undoes the Blaizio "
            "wiring: every tracked component file, the Blaizio NuGet packages, the "
            "CSS host entries and blaizio.json itself are removed from the project."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Blaizio uninstall command",),
        safer_alternatives=(
            "Review the full removal list with blaizio uninstall --dry-run.",
            "Remove individual components with blaizio remove <item> instead of undoing the whole install.",
        ),
        matcher=_BLAIZIO_UNINSTALL_ANY,
        default_mode="review",
        safe_variants=_preview_variants(_BLAIZIO_UNINSTALL_ANY, noun="uninstall"),
    ),
)

BLAIZIO_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.blaizio",
        name="Blaizio CLI command protection",
        description=(
            "Reviews Blaizio CLI commands that rewrite project files: component "
            "installs, updates, removals and uninstall. Dry runs, upstream diffs and "
            "item views stay unreviewed."
        ),
        action_classes=(
            "Blaizio component install command",
            "Blaizio component update command",
            "Blaizio component remove command",
            "Blaizio uninstall command",
        ),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=(
            "Preview any add, update, remove or uninstall with --dry-run; it runs the conflict scan without writing.",
            "Compare installed components against upstream with blaizio add --diff before updating.",
        ),
        reference_urls=("https://github.com/blaizio/blaizio", "https://blaiz.io"),
    ),
)
