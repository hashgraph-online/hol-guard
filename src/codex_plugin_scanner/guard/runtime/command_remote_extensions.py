"""Structured rules and metadata for remote administration commands."""

from __future__ import annotations

from .command_extension_matchers import executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import (
    AnyMatcher,
    CommandMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
    LeadingOperandCountMatcher,
)

_SSH_OPTIONS_WITH_VALUES = frozenset(
    {
        "-B",
        "-b",
        "-c",
        "-D",
        "-E",
        "-e",
        "-F",
        "-I",
        "-i",
        "-J",
        "-L",
        "-l",
        "-m",
        "-O",
        "-o",
        "-P",
        "-p",
        "-Q",
        "-R",
        "-S",
        "-W",
        "-w",
    }
)
_SCP_OPTIONS_WITH_VALUES = frozenset({"-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"})
_SSH_REMOTE_EXECUTION = LeadingOperandCountMatcher(
    executables=executable_names("ssh"),
    minimum_operands=2,
    options_with_values=_SSH_OPTIONS_WITH_VALUES,
    forbidden_flags=frozenset({"-G"}),
)
_SCP_TRANSFER = LeadingOperandCountMatcher(
    executables=executable_names("scp"),
    minimum_operands=2,
    options_with_values=_SCP_OPTIONS_WITH_VALUES,
)
_RSYNC_DESTRUCTIVE_FLAGS = (
    "--del",
    "--delete",
    "--delete-after",
    "--delete-before",
    "--delete-delay",
    "--delete-during",
    "--delete-excluded",
    "--delete-missing-args",
    "--remove-source-files",
)
_RSYNC_MUTATION = AnyMatcher(
    matchers=tuple(
        ExecutableMatcher(
            executables=executable_names("rsync"),
            required_flags=frozenset({flag}),
            required_flags_in_all_arguments=True,
        )
        for flag in _RSYNC_DESTRUCTIVE_FLAGS
    )
)


def _remote_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: CommandMatcher,
    action_class: str,
    safer_alternative: str,
    severity: CommandRuleSeverity,
    risk_classes: tuple[str, ...] = ("destructive_shell", "network_egress"),
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=risk_classes,
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


REMOTE_COMMAND_RULES = (
    _remote_rule(
        rule_id="command.remote.ssh.execution",
        title="Explicit SSH remote execution",
        description="Identifies SSH commands that provide an explicit command to execute after the destination.",
        matcher=_SSH_REMOTE_EXECUTION,
        action_class="SSH remote execution command",
        safer_alternative="Connect interactively first or inspect the resolved SSH configuration with ssh -G.",
        severity="high",
        risk_classes=("execution", "network_egress"),
    ),
    _remote_rule(
        rule_id="command.remote.scp.transfer",
        title="SCP file transfer",
        description="Identifies SCP transfers that can overwrite files at a local or remote destination.",
        matcher=_SCP_TRANSFER,
        action_class="SCP overwrite command",
        safer_alternative="Inspect both endpoints and copy to a new destination path before replacing existing data.",
        severity="high",
    ),
    _remote_rule(
        rule_id="command.remote.rsync.deletion",
        title="Rsync destructive synchronization",
        description="Identifies rsync deletion and source-removal options that can remove synchronized data.",
        matcher=_RSYNC_MUTATION,
        action_class="Rsync destructive command",
        safer_alternative="Run the same rsync command with --dry-run and inspect every deletion first.",
        severity="critical",
        safe_variants=(
            safe_flag_variant(_RSYNC_MUTATION, variant_id="dry-run", title="Rsync dry run", flag="--dry-run"),
            safe_flag_variant(_RSYNC_MUTATION, variant_id="short-dry-run", title="Rsync short dry run", flag="-n"),
        ),
    ),
)


REMOTE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.remote.ssh",
        name="SSH remote execution protection",
        description="Reviews SSH invocations that explicitly execute a remote command.",
        action_classes=("SSH remote execution command",),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Connect interactively or inspect resolved connection settings with ssh -G first.",),
        reference_urls=("https://man.openbsd.org/ssh",),
    ),
    CommandExtensionSpec(
        extension_id="command.remote.scp",
        name="SCP transfer protection",
        description="Reviews SCP transfers that can overwrite local or remote destination files.",
        action_classes=("SCP overwrite command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Transfer to a new path and verify both endpoints before replacing data.",),
        reference_urls=("https://man.openbsd.org/scp",),
    ),
    CommandExtensionSpec(
        extension_id="command.remote.rsync",
        name="Rsync deletion protection",
        description="Reviews rsync options that delete destination data or remove synchronized source files.",
        action_classes=("Rsync destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Use --dry-run and inspect the itemized change list before applying deletions.",),
        reference_urls=("https://rsync.samba.org/ftp/rsync/rsync.1.html",),
    ),
)
