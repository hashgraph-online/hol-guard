"""Structured rules and metadata for remote administration commands."""

from __future__ import annotations

from .command_database_matchers import LeadingSubcommandMatcher
from .command_extension_matchers import executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import (
    AnyMatcher,
    CommandMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)
from .command_structured_matchers import EnvironmentNameMatcher, LeadingOperandCountMatcher, OptionValueKeyMatcher

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
    forbidden_flags=frozenset({"-G", "-N", "-O", "-Q", "-V", "-W"}),
)
_SCP_TRANSFER = LeadingOperandCountMatcher(
    executables=executable_names("scp"),
    minimum_operands=2,
    options_with_values=_SCP_OPTIONS_WITH_VALUES,
)
_SSH_CONFIGURED_EXECUTION = AnyMatcher(
    matchers=(
        OptionValueKeyMatcher(
            executables=executable_names("ssh"),
            option_names=frozenset({"-o"}),
            value_keys=frozenset({"knownhostscommand", "proxycommand", "remotecommand"}),
            forbidden_flags=frozenset({"-G", "-O", "-Q", "-V"}),
            ignored_values=frozenset({"none"}),
            cluster_options_with_values=_SSH_OPTIONS_WITH_VALUES,
        ),
        OptionValueKeyMatcher(
            executables=executable_names("ssh"),
            option_names=frozenset({"-o"}),
            value_keys=frozenset({"localcommand"}),
            forbidden_flags=frozenset({"-G", "-O", "-Q", "-V"}),
            ignored_values=frozenset({"none"}),
            required_key_values=(("permitlocalcommand", "yes"),),
            cluster_options_with_values=_SSH_OPTIONS_WITH_VALUES,
        ),
    )
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
_RSYNC_OPTIONS_WITH_VALUES = frozenset(
    {
        "--backup-dir",
        "--address",
        "--block-size",
        "--bwlimit",
        "--checksum-choice",
        "--checksum-seed",
        "--chmod",
        "--chown",
        "--compare-dest",
        "--compress-choice",
        "--compress-level",
        "--compress-threads",
        "--config",
        "--contimeout",
        "--copy-as",
        "--copy-dest",
        "--debug",
        "--dparam",
        "--early-input",
        "--exclude",
        "--exclude-from",
        "--files-from",
        "--filter",
        "--groupmap",
        "--iconv",
        "--include",
        "--include-from",
        "--info",
        "--log-file",
        "--log-file-format",
        "--log-format",
        "--link-dest",
        "--max-alloc",
        "--max-delete",
        "--max-size",
        "--min-size",
        "--modify-window",
        "--only-write-batch",
        "--outbuf",
        "--out-format",
        "--partial-dir",
        "--password-file",
        "--port",
        "--protocol",
        "--read-batch",
        "--remote-option",
        "--rsh",
        "--rsync-path",
        "--skip-compress",
        "--sockopts",
        "--stderr",
        "--stop-after",
        "--stop-at",
        "--suffix",
        "--timeout",
        "--temp-dir",
        "--usermap",
        "--write-batch",
        "--cc",
        "--zc",
        "--zl",
        "--zt",
        "-B",
        "-e",
        "-f",
        "-M",
        "-T",
    }
)
_RSYNC_MUTATION = AnyMatcher(
    matchers=tuple(
        ExecutableMatcher(
            executables=executable_names("rsync"),
            required_flags=frozenset({flag}),
            options_with_values=_RSYNC_OPTIONS_WITH_VALUES,
            required_flags_in_all_arguments=True,
        )
        for flag in _RSYNC_DESTRUCTIVE_FLAGS
    )
)
_RSYNC_REMOTE_SHELL = AnyMatcher(
    matchers=(
        *(
            ExecutableMatcher(
                executables=executable_names("rsync"),
                required_flags=frozenset({flag}),
                options_with_values=_RSYNC_OPTIONS_WITH_VALUES,
                required_flags_in_all_arguments=True,
            )
            for flag in ("--rsync-path", "--rsh", "-e")
        ),
        EnvironmentNameMatcher(
            executables=executable_names("rsync"),
            environment_names=frozenset({"RSYNC_RSH"}),
        ),
    )
)


_ESSH_GLOBAL_OPTIONS = frozenset({"--theme"})
_ESSH_EXIT_ONLY_FLAGS = frozenset({"-h", "--help", "-V", "--version"})
_ESSH_GROUP_EXECUTION = LeadingSubcommandMatcher(
    executables=executable_names("essh"),
    subcommands=("run",),
    options_with_values=_ESSH_GLOBAL_OPTIONS,
    interleaved_options_with_values=_ESSH_GLOBAL_OPTIONS,
    forbidden_flags_before_delimiter=_ESSH_EXIT_ONLY_FLAGS,
)
_ESSH_CACHE_REMOVAL = AnyMatcher(
    matchers=tuple(
        LeadingSubcommandMatcher(
            executables=executable_names("essh"),
            subcommands=subcommands,
            options_with_values=_ESSH_GLOBAL_OPTIONS,
            interleaved_options_with_values=_ESSH_GLOBAL_OPTIONS,
            forbidden_flags_before_delimiter=_ESSH_EXIT_ONLY_FLAGS,
        )
        for subcommands in (("hosts", "remove"), ("keys", "remove"), ("workspace", "remove"))
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
    example_command: str | None = None,
    compatibility_fallback: bool = False,
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
        compatibility_fallback=compatibility_fallback,
        example_command=example_command,
    )


REMOTE_COMMAND_RULES = (
    _remote_rule(
        rule_id="command.remote.ssh.execution",
        example_command="ssh web-1 'sudo rm -rf /var/log/app'",
        title="Explicit SSH remote execution",
        description="Identifies SSH commands that provide an explicit command to execute after the destination.",
        matcher=_SSH_REMOTE_EXECUTION,
        action_class="SSH remote execution command",
        safer_alternative="Connect interactively first or inspect the resolved SSH configuration with ssh -G.",
        severity="high",
        risk_classes=("execution", "network_egress"),
    ),
    _remote_rule(
        rule_id="command.remote.ssh.configured-execution",
        example_command="ssh -o BatchMode=yes web-1 'uptime'",
        title="SSH configured command execution",
        description="Identifies SSH options that configure local, host-key, proxy, or remote shell commands.",
        matcher=_SSH_CONFIGURED_EXECUTION,
        action_class="SSH configured execution command",
        safer_alternative=(
            "Move connection-only settings into reviewed SSH configuration and omit command-bearing options."
        ),
        severity="high",
        risk_classes=("execution", "network_egress"),
    ),
    _remote_rule(
        rule_id="command.remote.scp.transfer",
        example_command="scp secrets.tar.gz backup-host:/srv/backup/",
        title="SCP file transfer",
        description="Identifies SCP transfers that can overwrite files at a local or remote destination.",
        matcher=_SCP_TRANSFER,
        action_class="SCP overwrite command",
        safer_alternative="Inspect both endpoints and copy to a new destination path before replacing existing data.",
        severity="high",
    ),
    _remote_rule(
        rule_id="command.remote.rsync.remote-shell",
        title="Rsync remote shell command",
        description="Identifies rsync commands that override the remote-side command executed through the shell.",
        matcher=_RSYNC_REMOTE_SHELL,
        action_class="Rsync remote shell command",
        safer_alternative=(
            "Use the default remote rsync command or inspect the remote command override before execution."
        ),
        severity="high",
        risk_classes=("execution", "network_egress"),
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
            safe_flag_variant(
                _RSYNC_MUTATION,
                variant_id="dry-run",
                title="Rsync dry run",
                flag="--dry-run",
                inverse_flag="--no-dry-run",
            ),
            safe_flag_variant(
                _RSYNC_MUTATION,
                variant_id="short-dry-run",
                title="Rsync short dry run",
                flag="-n",
                inverse_flag="--no-dry-run",
            ),
        ),
    ),
    _remote_rule(
        rule_id="command.remote.essh.group-execution",
        example_command="essh run web -- sudo systemctl restart api",
        title="essh host group execution",
        description="Identifies essh run invocations that execute a command across every host in a group.",
        matcher=_ESSH_GROUP_EXECUTION,
        action_class="essh group execution command",
        safer_alternative=(
            "Inspect the group membership with essh hosts list and run the command against a single host first."
        ),
        severity="critical",
        risk_classes=("execution", "network_egress"),
        compatibility_fallback=True,
    ),
    _remote_rule(
        rule_id="command.remote.essh.cache-removal",
        example_command="essh keys remove deploy-key",
        title="essh cached credential and host removal",
        description="Identifies essh remove verbs that delete cached hosts, keys, or saved workspaces.",
        matcher=_ESSH_CACHE_REMOVAL,
        action_class="essh cache removal command",
        safer_alternative=(
            "List the cached entry first with essh hosts list, essh keys list, or essh workspace list "
            "and confirm the name before removing it."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        compatibility_fallback=True,
    ),
)


REMOTE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.remote.ssh",
        name="SSH remote execution protection",
        description="Reviews SSH invocations that explicitly execute a remote command.",
        action_classes=("SSH remote execution command", "SSH configured execution command"),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Connect interactively or inspect resolved connection settings with ssh -G first.",),
        reference_urls=("https://man.openbsd.org/ssh", "https://man.openbsd.org/ssh_config"),
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
        action_classes=("Rsync destructive command", "Rsync remote shell command"),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=("Use --dry-run and inspect the itemized change list before applying deletions.",),
        reference_urls=("https://rsync.samba.org/ftp/rsync/rsync.1.html",),
    ),
    CommandExtensionSpec(
        extension_id="command.remote.essh",
        name="essh group execution and cache removal protection",
        description=(
            "Reviews essh invocations that execute commands across a host group or delete cached "
            "hosts, keys, and workspaces."
        ),
        action_classes=("essh group execution command", "essh cache removal command"),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=("Inspect group membership and cached entries before running or removing anything.",),
        reference_urls=("https://github.com/matthart1983/essh",),
    ),
)
