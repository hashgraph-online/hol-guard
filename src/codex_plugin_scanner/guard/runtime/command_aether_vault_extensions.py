"""Structured rules and metadata for the Aether-Vault (`av`) command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Flag surface verified against aether-vault 1.4.1 (python/av_cli/main.py, cmd_history.py,
# cmd_maintenance.py, cmd_policy.py, cmd_audit.py). Global click options precede the
# subcommand (`av --output json commit ...`), so they are declared as interspersed options
# on every matcher; otherwise `json` would be read as the subcommand and the rule would miss.

_AV_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("av",),
    ("python", "-m", "av_cli.main"),
    ("python3", "-m", "av_cli.main"),
    ("py", "-m", "av_cli.main"),
    ("python", "-m", "av_cli.launcher"),
    ("python3", "-m", "av_cli.launcher"),
    ("py", "-m", "av_cli.launcher"),
    ("exec", "av"),
    ("xargs", "av"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_AV_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--output"})
_AV_GLOBAL_FLAGS = frozenset({"--verbose", "--silent", "--version"})


def _av_matcher(
    *subcommands: str,
    required_flags: frozenset[str] = frozenset(),
    options_with_values: frozenset[str] = frozenset(),
) -> AnyMatcher:
    """Build an AnyMatcher covering every launcher/wrapper form for one `av` subcommand."""

    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                *subcommands,
                required_flags=required_flags,
                options_with_values=options_with_values,
                global_options_with_values=_AV_GLOBAL_OPTIONS_WITH_VALUES,
                global_flags=_AV_GLOBAL_FLAGS,
                allow_leading_options=launcher[0] in ("exec", "xargs"),
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
                ),
                fail_secure_unknown_options=True,
            )
            for launcher in _AV_LAUNCHERS
        )
    )


_AV_COMMIT = _av_matcher(
    "commit",
    options_with_values=frozenset({"-m", "--message", "--tag", "--metric", "--metric-sharpe", "--metric-drawdown"}),
)
_AV_PUSH = _av_matcher("push")
_AV_GC = _av_matcher("gc")
# `-f` and `--force` are independent single-flag matchers, OR-ed together: a matcher's
# required_flags is a conjunction, so `checkout --force` and `checkout -f` need two matchers.
_AV_CHECKOUT_FORCE = AnyMatcher(
    matchers=(
        *_av_matcher("checkout", required_flags=frozenset({"--force"})).matchers,
        *_av_matcher("checkout", required_flags=frozenset({"-f"})).matchers,
    )
)
_AV_PROMOTE = _av_matcher("promote", options_with_values=frozenset({"--into"}))
_AV_STASH_DROP = _av_matcher("stash", "drop")
_AV_AUDIT_PRUNE = _av_matcher("audit", "prune", options_with_values=frozenset({"--before-days"}))


def _help_variant(matcher: AnyMatcher, what: str) -> object:
    return safe_flag_variant(matcher, variant_id="help", title=f"{what} command help", flag="--help")


AETHER_VAULT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.aether-vault.commit",
        title="Aether-Vault commit",
        description=(
            "Identifies `av commit`, which persists staged model or dataset state as a new "
            "version and uploads it to the registry unless --no-upload is given. Agents should "
            "checkpoint deliberately, not on every loop iteration."
        ),
        severity="medium",
        risk_classes=("network_egress",),
        action_classes=("Aether-Vault commit command",),
        safer_alternatives=(
            "Run `av status` and `av diff` first to confirm what will be committed.",
            "Use `av commit --no-upload` to persist locally and defer the upload to a reviewed `av push`.",
        ),
        matcher=_AV_COMMIT,
        default_mode="review",
        safe_variants=(_help_variant(_AV_COMMIT, "Aether-Vault commit"),),
        example_command='av commit -m "epoch 12"',
    ),
    CommandSafetyRule(
        rule_id="command.aether-vault.push",
        title="Aether-Vault push",
        description=(
            "Identifies `av push`, which retries uploading locally committed model or dataset "
            "state to the remote registry, making it visible to every other client of that "
            "repository."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("Aether-Vault push command",),
        safer_alternatives=("Confirm with `av log` which local commits are still unpushed before running.",),
        matcher=_AV_PUSH,
        default_mode="review",
        safe_variants=(_help_variant(_AV_PUSH, "Aether-Vault push"),),
        example_command="av push",
    ),
    CommandSafetyRule(
        rule_id="command.aether-vault.gc",
        title="Aether-Vault garbage collection",
        description=(
            "Identifies `av gc`, which triggers garbage collection on the remote "
            "content-addressed store and can permanently delete unreferenced model and "
            "dataset objects."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("Aether-Vault garbage collection command",),
        safer_alternatives=(
            "Confirm every branch and tag that should retain its history has been pushed before running gc.",
        ),
        matcher=_AV_GC,
        default_mode="review",
        safe_variants=(_help_variant(_AV_GC, "Aether-Vault gc"),),
        example_command="av gc",
    ),
    CommandSafetyRule(
        rule_id="command.aether-vault.checkout-force",
        title="Aether-Vault forced checkout",
        description=(
            "Identifies `av checkout --force` (or `-f`), which discards uncommitted local "
            "changes while materializing another branch or commit instead of aborting."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Aether-Vault forced checkout command",),
        safer_alternatives=(
            "Run `av status` first and stash or commit any changes worth keeping.",
            "Use `av stash push` instead of discarding local changes outright.",
        ),
        matcher=_AV_CHECKOUT_FORCE,
        default_mode="review",
        safe_variants=(_help_variant(_AV_CHECKOUT_FORCE, "Aether-Vault checkout"),),
        example_command="av checkout main --force",
    ),
    CommandSafetyRule(
        rule_id="command.aether-vault.promote",
        title="Aether-Vault promote",
        description=(
            "Identifies `av promote`, which lands a candidate commit into a protected branch; "
            "`--force` bypasses the armed policy gate entirely. Autonomous loops must not "
            "self-promote blindly."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Aether-Vault promote command",),
        safer_alternatives=(
            "Run `av promote --dry-run` first to see which policy rule would decide the outcome.",
            "Keep an `av policy set` guardrail armed on the target branch instead of using `--force`.",
        ),
        matcher=_AV_PROMOTE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AV_PROMOTE, variant_id="dry-run", title="Aether-Vault promote dry run", flag="--dry-run"
            ),
            _help_variant(_AV_PROMOTE, "Aether-Vault promote"),
        ),
        example_command="av promote candidate-1 --into main",
    ),
    CommandSafetyRule(
        rule_id="command.aether-vault.stash-drop",
        title="Aether-Vault stash drop",
        description="Identifies `av stash drop`, which deletes a stash without ever applying it.",
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("Aether-Vault stash drop command",),
        safer_alternatives=("Run `av stash list` and `av stash apply` first to confirm the stash isn't needed.",),
        matcher=_AV_STASH_DROP,
        default_mode="review",
        safe_variants=(_help_variant(_AV_STASH_DROP, "Aether-Vault stash drop"),),
        example_command="av stash drop",
    ),
    CommandSafetyRule(
        rule_id="command.aether-vault.audit-prune",
        title="Aether-Vault audit prune",
        description=(
            "Identifies `av audit prune`, which permanently deletes audit-log entries from the "
            "registry older than a cutoff."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Aether-Vault audit prune command",),
        safer_alternatives=(
            "Run `av audit prune --dry-run` first to see what would be deleted.",
            "Export the audit log (`av audit export`) before pruning if retention may be needed later.",
        ),
        matcher=_AV_AUDIT_PRUNE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AV_AUDIT_PRUNE, variant_id="dry-run", title="Aether-Vault audit prune dry run", flag="--dry-run"
            ),
            _help_variant(_AV_AUDIT_PRUNE, "Aether-Vault audit prune"),
        ),
        example_command="av audit prune --before-days 30",
    ),
)

AETHER_VAULT_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.aether-vault",
        name="Aether-Vault command protection",
        description=(
            "Reviews Aether-Vault commands that publish, promote, or delete model and dataset "
            "state; read-only commands stay quiet."
        ),
        action_classes=(
            "Aether-Vault commit command",
            "Aether-Vault push command",
            "Aether-Vault garbage collection command",
            "Aether-Vault forced checkout command",
            "Aether-Vault promote command",
            "Aether-Vault stash drop command",
            "Aether-Vault audit prune command",
        ),
        risk_classes=("network_egress", "destructive_shell"),
        safer_alternatives=(
            "Inspect with `av status` / `av diff` before committing or pushing.",
            "Use `--dry-run` where the command offers it (`promote`, `audit prune`).",
            "Prefer an armed `av policy set` guardrail over `av promote --force`.",
        ),
        reference_urls=("https://github.com/leon1706-lol/Aether-Vault",),
        executables=("av",),
        ecosystem_ids=("aether-vault",),
        example_command="av push",
    ),
)
