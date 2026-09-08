"""Structured rules and metadata for blitcp copy commands."""

from __future__ import annotations

from dataclasses import replace

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_operand_matchers import (
    OperandGatedFlagMatcher,
    TrailingOperandHostTargetMatcher,
    TrailingOperandPrefixMatcher,
    TrailingOperandRemoteAliasMatcher,
)
from .command_remote_extensions import _remote_rule
from .command_rules import (
    AnyMatcher,
    CommandSafeVariant,
    ExecutableMatcher,
)

# blitcp takes `SOURCE... DESTINATION`, so the final operand decides whether a
# run reads remote data or writes it: `blitcp /data s3://bucket` sends data off
# the host, while `blitcp s3://bucket/data /restore` pulls it down. Matching any
# operand would prompt on both, which teaches people to approve the one that
# matters.
#
# Options may appear anywhere, so the ones that consume a following value have
# to be declared or that value is mistaken for the destination.
_BLITCP_OPTIONS_WITH_VALUES = frozenset(
    {
        "--az-account",
        "--az-connection-string",
        "--az-key",
        "--buffer",
        "--chunk-size",
        "--cloud-concurrency",
        "--credentials-file",
        "--endpoint-url",
        "--exclude",
        "--gcs-credentials",
        "--gcs-project",
        "--hash",
        "--index-existing",
        "--lang",
        "--log-file",
        "--preserve",
        "--s3-profile",
        "--s3-region",
        "--small-files",
        "--smb-domain",
        "--smb-password-env",
        "--smb-port",
        "--smb-user",
        "--ssh-dst-key",
        "--ssh-dst-password-env",
        "--ssh-dst-port",
        "--ssh-src-key",
        "--ssh-src-password-env",
        "--ssh-src-port",
        "--threads",
        "--update-sha256",
    }
)
# blitcp writes to two kinds of remote destination and both mean egress, so one
# rule covers both syntaxes rather than teaching people that only object stores
# are worth a prompt.
#
# Case-sensitive prefixes on purpose: blitcp itself only accepts lower-case
# schemes, so matching "S3://bucket" would flag a command blitcp refuses to run.
# blitcp dispatches on its literal first argument before argparse ever runs:
# `blitcp creds ...` manages the credential store, `blitcp ls`/`list-objects`
# lists a remote, and `blitcp deps`/`check-deps`/`doctor` report on the
# environment. None of them is a copy, and `ls` in particular is a read — so a
# listing of a remote must not prompt as egress. The dispatch is case-sensitive
# and looks only at argv[1], which is exactly what the matchers mirror.
_BLITCP_SUBCOMMANDS = frozenset({"creds", "ls", "list-objects", "deps", "check-deps", "doctor"})
_BLITCP_SCHEME_DESTINATION = TrailingOperandPrefixMatcher(
    executables=executable_names("blitcp"),
    operand_prefixes=frozenset({"s3://", "az://", "gs://", "smb://"}),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
    excluded_first_arguments=_BLITCP_SUBCOMMANDS,
)
# SSH is blitcp's oldest remote transport: it streams tar over one channel to
# `[user@]host:path`. Without this an upload over SSH would leave the host with
# no prompt at all, which is the same egress as an object-store write.
_BLITCP_SSH_DESTINATION = TrailingOperandHostTargetMatcher(
    executables=executable_names("blitcp"),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
    excluded_first_arguments=_BLITCP_SUBCOMMANDS,
)
# The third destination syntax: a saved connection, referenced as `NAME:subpath`
# (`azure-prod:backups`) or as a bare `NAME`. The colon form is structurally
# recognizable and follows blitcp's own parser — a head with `@`, a path
# separator, or a single character is not a connection reference. A bare name is
# not: nothing distinguishes `blitcp /data azure-prod` from a copy into a local
# `azure-prod/` directory without reading the user's credentials file, and
# prompting on every bare-word destination would recreate exactly the
# any-operand noise this rule exists to avoid. So the bare form is only matched
# when --credentials-file names a connections file on the command itself, which
# is the one static signal that saved connections are in play. The residual gap
# — a bare name resolved through the *implicit* default credentials file — is
# documented rather than closed, because closing it costs a prompt on every
# local copy to a fresh directory.
_BLITCP_ALIAS_DESTINATION = TrailingOperandRemoteAliasMatcher(
    executables=executable_names("blitcp"),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
    excluded_first_arguments=_BLITCP_SUBCOMMANDS,
)
# Bare operands only: a colon operand is already owned by the ungated alias
# matcher above, so restricting this one keeps a single evidence row per hit.
_BLITCP_BARE_ALIAS_DESTINATION = TrailingOperandRemoteAliasMatcher(
    executables=executable_names("blitcp"),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
    required_flags=frozenset({"--credentials-file"}),
    allow_bare_names=True,
    bare_names_only=True,
    excluded_first_arguments=_BLITCP_SUBCOMMANDS,
)
_BLITCP_REMOTE_DESTINATION_MATCHERS: tuple[
    TrailingOperandPrefixMatcher | TrailingOperandHostTargetMatcher | TrailingOperandRemoteAliasMatcher,
    ...,
] = (
    _BLITCP_SCHEME_DESTINATION,
    _BLITCP_SSH_DESTINATION,
    _BLITCP_ALIAS_DESTINATION,
    _BLITCP_BARE_ALIAS_DESTINATION,
)
_BLITCP_REMOTE_DESTINATION = AnyMatcher(matchers=_BLITCP_REMOTE_DESTINATION_MATCHERS)
# safe_flag_variant() expects an AnyMatcher of executable children, so it cannot
# build this one; the variant is the same matchers with --dry-run required on
# top of whatever each already requires, which is what that helper produces for
# the others.
_BLITCP_REMOTE_DESTINATION_DRY_RUN = AnyMatcher(
    matchers=tuple(
        replace(matcher, required_flags=matcher.required_flags | frozenset({"--dry-run"}))
        for matcher in _BLITCP_REMOTE_DESTINATION_MATCHERS
    ),
)
_BLITCP_SELF_UPDATE = ExecutableMatcher(
    executables=executable_names("blitcp"),
    required_flags=frozenset({"--update"}),
)
# Both flag rules are gated on the shape of an actual copy — at least a source
# and a destination once option values are stripped. The flags describe how a
# copy runs, so `blitcp --use-sudo` alone (help output, an aborted command line)
# elevates nothing and must not prompt; prompting there is what teaches people
# to approve the elevation that matters.
_BLITCP_SUDO_COPY = OperandGatedFlagMatcher(
    executables=executable_names("blitcp"),
    required_flags=frozenset({"--use-sudo"}),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
    excluded_first_arguments=_BLITCP_SUBCOMMANDS,
)
# `creds lock` / `creds unlock` are the documented sudo re-execs outside copy
# mode: with --use-sudo the tool re-runs itself under root to set or clear OS
# immutability on the credentials file. The dispatch token that keeps `creds`
# out of the copy matchers is present here too, so these are matched on their
# literal subcommand pair instead of a copy shape.
_BLITCP_SUDO_CREDS = AnyMatcher(
    matchers=(
        ExecutableMatcher(
            executables=executable_names("blitcp"),
            subcommands=("creds", "lock"),
            required_flags=frozenset({"--use-sudo"}),
        ),
        ExecutableMatcher(
            executables=executable_names("blitcp"),
            subcommands=("creds", "unlock"),
            required_flags=frozenset({"--use-sudo"}),
        ),
    )
)
_BLITCP_PRIVILEGE_ESCALATION = AnyMatcher(
    matchers=(_BLITCP_SUDO_COPY, _BLITCP_SUDO_CREDS),
)
# A dry run copies nothing, so there is nothing for verification to check and
# --no-verify says nothing about the outcome. Excluding it keeps previews
# distinct from real copies here too, not only on the destination rule.
_BLITCP_UNVERIFIED_COPY = OperandGatedFlagMatcher(
    executables=executable_names("blitcp"),
    required_flags=frozenset({"--no-verify"}),
    forbidden_flags=frozenset({"--dry-run"}),
    options_with_values=_BLITCP_OPTIONS_WITH_VALUES,
    excluded_first_arguments=_BLITCP_SUBCOMMANDS,
)


# The action-class risk map in the builtin rules registry merges this the same
# way it merges the GitHub action classes, so blitcp's risk declarations stay
# next to its rules.
BLITCP_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "blitcp remote destination command": ("network_egress",),
    "blitcp privilege escalation command": ("execution",),
    "blitcp self-update command": ("execution", "network_egress"),
    "blitcp unverified copy command": ("destructive_shell",),
}

BLITCP_COMMAND_RULES = (
    _remote_rule(
        rule_id="command.blitcp.remote-destination",
        example_command="blitcp /data s3://backups/nightly",
        title="Blitcp copy to a remote destination",
        description=(
            "Identifies blitcp copies whose final operand is a remote destination — an "
            "object-store or SMB endpoint, an scp-style [user@]host:path target, or a saved "
            "connection referenced as NAME:subpath (or as a bare NAME when --credentials-file "
            "is on the command) — which sends local data off the host. The same endpoint in "
            "an earlier position is a source and reads data instead."
        ),
        matcher=_BLITCP_REMOTE_DESTINATION,
        action_class="Blitcp remote destination command",
        safer_alternative="Run the same command with --dry-run and confirm the destination before copying.",
        severity="high",
        risk_classes=("network_egress",),
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Blitcp dry run",
                matcher=_BLITCP_REMOTE_DESTINATION_DRY_RUN,
            ),
        ),
    ),
    _remote_rule(
        rule_id="command.blitcp.privilege-escalation",
        example_command="blitcp --use-sudo /var/lib/data /mnt/backup",
        title="Blitcp privilege escalation",
        description=(
            "Identifies blitcp runs that re-execute the tool under sudo — copies elevated "
            "with --use-sudo, and `creds lock`/`creds unlock --use-sudo`, which needs root "
            "to set or clear credentials-file immutability."
        ),
        matcher=_BLITCP_PRIVILEGE_ESCALATION,
        action_class="Blitcp privilege escalation command",
        safer_alternative="Copy as a user that already reaches both paths rather than elevating the copier.",
        severity="critical",
        risk_classes=("execution",),
    ),
    _remote_rule(
        rule_id="command.blitcp.self-update",
        example_command="blitcp --update",
        title="Blitcp self-update",
        description=(
            "Identifies blitcp self-update runs, which download a release over the network and "
            "replace the running executable in place."
        ),
        matcher=_BLITCP_SELF_UPDATE,
        action_class="Blitcp self-update command",
        safer_alternative="Update through the package manager that installed blitcp instead of rewriting the binary.",
        severity="high",
        risk_classes=("execution", "network_egress"),
    ),
    _remote_rule(
        rule_id="command.blitcp.unverified-copy",
        example_command="blitcp --no-verify /data /mnt/backup",
        title="Blitcp copy without verification",
        description=(
            "Identifies blitcp runs that skip the whole post-copy verification phase, so the run "
            "reports success without reading anything back and the destination can silently "
            "diverge from the source — data loss once the source is cleaned up on the strength "
            "of that success report."
        ),
        matcher=_BLITCP_UNVERIFIED_COPY,
        action_class="Blitcp unverified copy command",
        safer_alternative="Drop --no-verify so every copied file is read back and compared against the source.",
        severity="medium",
        risk_classes=("destructive_shell",),
    ),
)

BLITCP_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.blitcp",
        name="Blitcp transfer protection",
        description="Reviews blitcp copies that leave the host, elevate privileges, or skip verification.",
        action_classes=(
            "Blitcp remote destination command",
            "Blitcp privilege escalation command",
            "Blitcp self-update command",
            "Blitcp unverified copy command",
        ),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=("Use --dry-run to print the plan, and keep verification enabled on real copies.",),
        reference_urls=("https://blitcp.dev/docs/", "https://github.com/gekap/blitcp"),
    ),
)
