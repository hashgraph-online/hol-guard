"""Structured rules and metadata for aparta identity-scope commands."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

# CLI surface verified against lucascarvalhal/aparta 0.9.x (`src/aparta/cli.py`).
# aparta binds one Git, GitHub CLI, gcloud and AWS identity to each project
# folder and injects it into terminal AI agents. Three command families leave
# the read-only surface:
#
# * `apply`, `remove` and `fallback --secure|--restore` write identity files on
#   the host (gitconfig includes, the gh config dir, the isolated gcloud dir,
#   agent config files, the global ADC), always with backups. `--dry-run` is
#   the documented side-effect-free preview and `--help` exits immediately.
# * `run --profile <name>` / `run -p <name>` executes an arbitrary command with
#   another profile's credentials, which is the one deliberate way to cross
#   the identity scope of the current folder.
# * `--with-gh-token` (on `run` and `env`) reads the GitHub token out of the OS
#   keyring and materializes it as GITHUB_TOKEN in a child process or on
#   stdout; it is strictly opt-in for that reason.
#
# `scan`, `doctor`, `status`, `check`, `list`, `env` without the token flag,
# `run` without `--profile`, `login` (interactive, opens a browser) and the
# bare `fallback` report are not reviewed. Global options (`--dry-run`,
# `--verbose`/`-v`) may precede the subcommand.
# https://github.com/lucascarvalhal/aparta

_APARTA_GLOBAL_FLAGS = frozenset({"--dry-run", "--verbose", "-v"})
_APARTA_RUN_OPTIONS = frozenset({"--profile", "-p"})

_IDENTITY_WRITE_ACTION = "aparta identity write command"
_SCOPE_CROSSING_ACTION = "aparta identity scope crossing command"
_TOKEN_EXPORT_ACTION = "aparta credential export command"

APARTA_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    _IDENTITY_WRITE_ACTION: ("destructive_shell",),
    _SCOPE_CROSSING_ACTION: ("execution",),
    _TOKEN_EXPORT_ACTION: ("local_secret_read",),
}


def _aparta(*subcommands: str, **kwargs: object) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            executable_matcher(
                "aparta",
                *subcommands,
                global_flags=_APARTA_GLOBAL_FLAGS,
                allow_leading_options=True,
                fail_secure_unknown_options=True,
                **kwargs,  # type: ignore[arg-type]
            ),
        )
    )


_APARTA_APPLY = _aparta("apply")
_APARTA_REMOVE = _aparta("remove")
_APARTA_FALLBACK_SECURE = _aparta("fallback", required_flags=frozenset({"--secure"}))
_APARTA_FALLBACK_RESTORE = _aparta("fallback", required_flags=frozenset({"--restore"}))
_APARTA_IDENTITY_WRITE = AnyMatcher(
    matchers=(
        *_APARTA_APPLY.matchers,
        *_APARTA_REMOVE.matchers,
        *_APARTA_FALLBACK_SECURE.matchers,
        *_APARTA_FALLBACK_RESTORE.matchers,
    )
)

_APARTA_RUN_PROFILE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "aparta",
            "run",
            required_flags=frozenset({option}),
            options_with_values=_APARTA_RUN_OPTIONS,
            global_flags=_APARTA_GLOBAL_FLAGS,
            allow_leading_options=True,
            fail_secure_unknown_options=True,
        )
        for option in sorted(_APARTA_RUN_OPTIONS)
    )
)

_APARTA_TOKEN_EXPORT = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "aparta",
            subcommand,
            required_flags=frozenset({"--with-gh-token"}),
            options_with_values=_APARTA_RUN_OPTIONS,
            global_flags=_APARTA_GLOBAL_FLAGS,
            allow_leading_options=True,
            fail_secure_unknown_options=True,
        )
        for subcommand in ("run", "env")
    )
)


def _help_variants(matcher: AnyMatcher, *, title: str) -> tuple[CommandSafeVariant, ...]:
    return (
        safe_flag_variant(matcher, variant_id="help", title=title, flag="--help"),
        safe_flag_variant(matcher, variant_id="short-help", title=title, flag="-h"),
    )


APARTA_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.aparta.identity-write",
        title="aparta identity file write",
        description=(
            "Identifies aparta apply, remove, and fallback --secure/--restore invocations that rewrite "
            "Git, GitHub CLI, gcloud, AWS and agent identity files on the host."
        ),
        severity="high",
        risk_classes=APARTA_ACTION_RISK_CLASSES[_IDENTITY_WRITE_ACTION],
        action_classes=(_IDENTITY_WRITE_ACTION,),
        safer_alternatives=(
            "Preview the exact diff with the same command plus --dry-run, and inspect the current state with "
            "aparta doctor before writing anything.",
        ),
        matcher=_APARTA_IDENTITY_WRITE,
        safe_variants=(
            safe_flag_variant(
                _APARTA_IDENTITY_WRITE,
                variant_id="dry-run",
                title="Diff preview without writing",
                flag="--dry-run",
            ),
            *_help_variants(_APARTA_IDENTITY_WRITE, title="Command help"),
        ),
        example_command="aparta apply client-a",
    ),
    CommandSafetyRule(
        rule_id="command.aparta.scope-crossing",
        title="aparta cross-profile execution",
        description=(
            "Identifies aparta run --profile invocations that execute a command with another profile's "
            "credentials instead of the identity bound to the current folder."
        ),
        severity="critical",
        risk_classes=APARTA_ACTION_RISK_CLASSES[_SCOPE_CROSSING_ACTION],
        action_classes=(_SCOPE_CROSSING_ACTION,),
        safer_alternatives=(
            "Run the command from a folder that belongs to the intended profile, so the identity comes from "
            "the folder binding instead of an explicit override.",
        ),
        matcher=_APARTA_RUN_PROFILE,
        safe_variants=_help_variants(_APARTA_RUN_PROFILE, title="Command help"),
        example_command="aparta run --profile client-a -- terraform apply",
    ),
    CommandSafetyRule(
        rule_id="command.aparta.token-export",
        title="aparta GitHub token export",
        description=(
            "Identifies aparta run and env invocations with --with-gh-token, which read the GitHub token "
            "from the OS keyring and expose it as GITHUB_TOKEN to a child process or on stdout."
        ),
        severity="critical",
        risk_classes=APARTA_ACTION_RISK_CLASSES[_TOKEN_EXPORT_ACTION],
        action_classes=(_TOKEN_EXPORT_ACTION,),
        safer_alternatives=(
            "Let the tool read the token through the GitHub CLI's own config dir (GH_CONFIG_DIR is already "
            "injected) instead of materializing it into the environment.",
        ),
        matcher=_APARTA_TOKEN_EXPORT,
        safe_variants=_help_variants(_APARTA_TOKEN_EXPORT, title="Command help"),
        example_command="aparta env --with-gh-token",
    ),
)

APARTA_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.aparta",
        name="aparta identity scope protection",
        description=(
            "Reviews aparta commands that rewrite identity files, run with another profile's credentials, "
            "or export the GitHub token into the environment."
        ),
        action_classes=(_IDENTITY_WRITE_ACTION, _SCOPE_CROSSING_ACTION, _TOKEN_EXPORT_ACTION),
        risk_classes=("destructive_shell", "execution", "local_secret_read"),
        safer_alternatives=(
            "Preview writes with --dry-run, keep commands inside the folder of the intended profile, "
            "and avoid materializing tokens into the environment.",
        ),
        reference_urls=("https://github.com/lucascarvalhal/aparta",),
    ),
)
