"""Built-in compatibility rules for existing Guard command action classes."""

from __future__ import annotations

from .command_backup_extensions import BACKUP_COMMAND_RULES
from .command_cloud_extensions import CLOUD_COMMAND_RULES
from .command_database_extensions import DATABASE_COMMAND_RULES
from .command_domain_extensions import DOMAIN_COMMAND_RULES
from .command_remote_extensions import REMOTE_COMMAND_RULES
from .command_rules import (
    AnyMatcher,
    ArgumentMatcher,
    CommandMatcher,
    CommandRuleSeverity,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
    PipelineMatcher,
)
from .command_search_messaging_extensions import SEARCH_MESSAGING_COMMAND_RULES
from .command_storage_extensions import STORAGE_COMMAND_RULES

COMMAND_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "credential exfiltration shell command": (
        "data_flow_exfiltration",
        "credential_exfiltration",
        "network_egress",
    ),
    "guard-managed config write": ("destructive_shell",),
    "docker-sensitive command": ("network_egress", "destructive_shell"),
    "docker client config access": ("local_secret_read",),
    "encoded or encrypted shell command": ("encoded_execution",),
    "kubernetes secret read command": ("local_secret_read",),
    "shell file upload command": ("credential_exfiltration", "network_egress"),
    "sensitive local file write": ("destructive_shell", "local_secret_read"),
    "destructive shell command": ("destructive_shell",),
    "guard approval self-authorization command": ("policy_bypass",),
    "github pr body shell substitution": ("execution",),
    "filesystem destructive command": ("destructive_shell",),
    "git destructive command": ("destructive_shell",),
    "system destructive command": ("destructive_shell",),
    "windows destructive command": ("destructive_shell",),
    "kubernetes destructive command": ("destructive_shell", "network_egress"),
    "infrastructure destructive command": ("destructive_shell", "network_egress"),
    "aws destructive command": ("destructive_shell", "network_egress"),
    "google cloud destructive command": ("destructive_shell", "network_egress"),
    "azure destructive command": ("destructive_shell", "network_egress"),
    "aws storage destructive command": ("destructive_shell", "network_egress"),
    "google storage destructive command": ("destructive_shell", "network_egress"),
    "azure storage destructive command": ("destructive_shell", "network_egress"),
    "minio storage destructive command": ("destructive_shell", "network_egress"),
    "rclone destructive command": ("destructive_shell", "network_egress"),
    "restic destructive command": ("destructive_shell", "network_egress"),
    "borg destructive command": ("destructive_shell", "network_egress"),
    "velero destructive command": ("destructive_shell", "network_egress"),
    "ssh remote execution command": ("execution", "network_egress"),
    "ssh configured execution command": ("execution", "network_egress"),
    "scp overwrite command": ("destructive_shell", "network_egress"),
    "rsync destructive command": ("destructive_shell", "network_egress"),
    "postgresql destructive command": ("destructive_shell", "network_egress"),
    "mysql destructive command": ("destructive_shell", "network_egress"),
    "mongodb destructive command": ("destructive_shell", "network_egress"),
    "redis destructive command": ("destructive_shell", "network_egress"),
    "sqlite destructive command": ("destructive_shell",),
    "supabase destructive command": ("destructive_shell", "network_egress"),
    "rsync remote shell command": ("execution", "network_egress"),
}
_GIT_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {"-c", "-C", "--config-env", "--exec-path", "--git-dir", "--namespace", "--super-prefix", "--work-tree"}
)
_GIT_SUBCOMMAND_OPTIONS_WITH_VALUES = {
    "clean": frozenset({"-e", "--exclude"}),
    "push": frozenset({"--exec", "--push-option", "--receive-pack", "--repo", "-o"}),
    "reset": frozenset({"--pathspec-from-file"}),
}


def _git_matcher(
    subcommand: str,
    *,
    required_flags: frozenset[str],
    inverse_flag_pairs: frozenset[tuple[str, str]] = frozenset(),
) -> ExecutableMatcher:
    return ExecutableMatcher(
        executables=frozenset({"git"}),
        subcommands=(subcommand,),
        required_flags=required_flags,
        allow_leading_options=True,
        leading_options_with_values=_GIT_GLOBAL_OPTIONS_WITH_VALUES,
        options_with_values=_GIT_SUBCOMMAND_OPTIONS_WITH_VALUES.get(subcommand, frozenset()),
        inverse_flag_pairs=inverse_flag_pairs,
    )


def _compatibility_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    action_class: str,
    safer_alternative: str,
    matcher: CommandMatcher | None = None,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="high",
        risk_classes=COMMAND_ACTION_RISK_CLASSES[action_class.lower()],
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        compatibility_fallback=True,
    )


def _structured_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: CommandMatcher,
    action_class: str,
    safer_alternative: str,
    severity: CommandRuleSeverity = "high",
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        risk_classes=("destructive_shell",),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


BUILT_IN_COMMAND_RULES = (
    _compatibility_rule(
        rule_id="command.container-runtime.docker-sensitive",
        title="Sensitive container operation",
        description="Identifies container operations that can expose credentials or mutate protected state.",
        action_class="docker-sensitive command",
        safer_alternative="Use a pinned image, minimal privileges, and a preview where the command supports one.",
    ),
    _compatibility_rule(
        rule_id="command.container-runtime.docker-config-access",
        title="Container credential access",
        description="Identifies reads of local container client authentication configuration.",
        action_class="Docker client config access",
        safer_alternative="Pass only the specific credential material required by the operation.",
    ),
    _compatibility_rule(
        rule_id="command.data-protection.credential-exfiltration",
        title="Credential data transfer",
        description="Identifies shell flows that can send credential material to a network destination.",
        action_class="credential exfiltration shell command",
        safer_alternative="Send an explicit non-secret value and review the exact destination and payload.",
    ),
    _compatibility_rule(
        rule_id="command.data-protection.file-upload",
        title="Local file upload",
        description="Identifies shell upload flows that read local files or standard input.",
        action_class="shell file upload command",
        safer_alternative="Upload a reviewed non-secret artifact through an allowlisted destination.",
    ),
    _compatibility_rule(
        rule_id="command.encoded-execution.decode-and-execute",
        title="Encoded execution",
        description="Identifies decode or decrypt chains that immediately execute their output.",
        action_class="encoded or encrypted shell command",
        safer_alternative="Decode to a file, inspect the result, then invoke the reviewed file directly.",
        matcher=PipelineMatcher(
            producer=ArgumentMatcher(
                executables=frozenset({"base64", "openssl", "gpg"}),
                required_arguments=frozenset({"-d"}),
            ),
            consumer=ExecutableMatcher(executables=frozenset({"sh", "bash", "zsh", "pwsh", "powershell"})),
        ),
    ),
    _compatibility_rule(
        rule_id="command.guard-self-protection.self-authorization",
        title="Guard self-authorization",
        description="Identifies commands that attempt to approve or weaken their own Guard decision.",
        action_class="Guard approval self-authorization command",
        safer_alternative="Approve the request through Guard's authenticated approval surface.",
        matcher=ExecutableMatcher(
            executables=frozenset({"hol-guard"}),
            subcommands=("approvals", "approve"),
        ),
    ),
    _compatibility_rule(
        rule_id="command.kubernetes-secrets.secret-read",
        title="Cluster secret read",
        description="Identifies cluster CLI operations that can reveal Secret payloads.",
        action_class="Kubernetes secret read command",
        safer_alternative="Request non-secret metadata or only the specific field required.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.destructive-shell",
        title="Destructive shell mutation",
        description="Identifies destructive shell, filesystem, and version-control mutations.",
        action_class="destructive shell command",
        safer_alternative="Use a dry run or narrow preview before applying the mutation.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.managed-config-write",
        title="Guard-managed configuration write",
        description="Identifies direct writes to configuration managed by Guard.",
        action_class="guard-managed config write",
        safer_alternative="Use Guard's setup or repair command to update managed configuration.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.sensitive-file-write",
        title="Sensitive local file write",
        description="Identifies writes that can replace or expose sensitive local state.",
        action_class="sensitive local file write",
        safer_alternative="Write to a scoped temporary path and review the final destination.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.github-body-substitution",
        title="Command substitution in remote body",
        description="Identifies shell substitution used to construct a remote request body.",
        action_class="GitHub PR body shell substitution",
        safer_alternative="Use a literal body file whose contents can be reviewed before submission.",
    ),
    _structured_rule(
        rule_id="command.filesystem.recursive-delete",
        title="Recursive filesystem deletion",
        description="Identifies recursive deletion that can remove a directory tree in one operation.",
        matcher=ArgumentMatcher(
            executables=frozenset({"rm"}),
            required_arguments=frozenset({"-r"}),
        ),
        action_class="filesystem destructive command",
        safer_alternative="List the exact target tree first, then remove only reviewed paths.",
    ),
    _structured_rule(
        rule_id="command.filesystem.recursive-permission-change",
        title="Recursive permission or ownership change",
        description="Identifies recursive access-control changes across a filesystem tree.",
        matcher=ArgumentMatcher(
            executables=frozenset({"chmod", "chown", "chgrp"}),
            required_arguments=frozenset({"-r"}),
        ),
        action_class="filesystem destructive command",
        safer_alternative="Preview affected paths and apply the change to the narrowest directory possible.",
    ),
    _structured_rule(
        rule_id="command.git.hard-reset",
        title="Destructive Git reset",
        description="Identifies hard resets that discard tracked working-tree and index changes.",
        matcher=_git_matcher("reset", required_flags=frozenset({"--hard"})),
        action_class="git destructive command",
        safer_alternative="Inspect the diff and create a temporary branch or stash before resetting.",
    ),
    _structured_rule(
        rule_id="command.git.force-clean",
        title="Forced Git clean",
        description="Identifies forced removal of untracked files from a repository.",
        matcher=_git_matcher("clean", required_flags=frozenset({"-f"})),
        action_class="git destructive command",
        safer_alternative="Run `git clean -ndx` first and review every path before forced cleanup.",
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Git clean preview",
                matcher=AnyMatcher(
                    matchers=(
                        _git_matcher(
                            "clean",
                            required_flags=frozenset({"-n"}),
                            inverse_flag_pairs=frozenset({("-n", "--no-dry-run")}),
                        ),
                        _git_matcher(
                            "clean",
                            required_flags=frozenset({"--dry-run"}),
                            inverse_flag_pairs=frozenset({("--dry-run", "--no-dry-run")}),
                        ),
                    )
                ),
            ),
        ),
    ),
    _structured_rule(
        rule_id="command.git.force-push",
        title="Forced Git push",
        description="Identifies remote history replacement through a forced push.",
        matcher=AnyMatcher(
            matchers=(
                _git_matcher("push", required_flags=frozenset({"--force"})),
                _git_matcher("push", required_flags=frozenset({"-f"})),
            )
        ),
        action_class="git destructive command",
        safer_alternative="Use `--force-with-lease` after fetching and reviewing the remote ref.",
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Git push preview",
                matcher=_git_matcher(
                    "push",
                    required_flags=frozenset({"--dry-run"}),
                    inverse_flag_pairs=frozenset({("--dry-run", "--no-dry-run")}),
                ),
            ),
        ),
    ),
    _structured_rule(
        rule_id="command.system.disk-or-power-mutation",
        title="Disk or power-state mutation",
        description="Identifies commands that format storage or stop the operating system.",
        matcher=AnyMatcher(
            matchers=(
                ExecutableMatcher(
                    executables=frozenset({"shutdown", "reboot", "halt", "poweroff", "mkfs", "mkfs.ext4", "mkfs.xfs"})
                ),
                ExecutableMatcher(
                    executables=frozenset({"diskutil"}),
                    subcommands=("erasedisk",),
                ),
            )
        ),
        action_class="system destructive command",
        safer_alternative="Inspect the selected device or host state and use a non-mutating status command first.",
        severity="critical",
        safe_variants=(
            CommandSafeVariant(
                variant_id="help",
                title="System command help",
                matcher=AnyMatcher(
                    matchers=(
                        ExecutableMatcher(
                            executables=frozenset(
                                {"shutdown", "reboot", "halt", "poweroff", "mkfs", "mkfs.ext4", "mkfs.xfs"}
                            ),
                            required_flags=frozenset({"--help"}),
                        ),
                        ExecutableMatcher(
                            executables=frozenset(
                                {"shutdown", "reboot", "halt", "poweroff", "mkfs", "mkfs.ext4", "mkfs.xfs"}
                            ),
                            required_flags=frozenset({"--version"}),
                        ),
                    )
                ),
            ),
        ),
    ),
    _structured_rule(
        rule_id="command.windows.destructive-storage",
        title="Destructive Windows storage operation",
        description="Identifies Windows commands that clear, format, or remove storage volumes.",
        matcher=ExecutableMatcher(
            executables=frozenset({"clear-disk", "format-volume", "remove-partition"}),
        ),
        action_class="windows destructive command",
        safer_alternative="Inspect the disk and partition identifiers with read-only PowerShell commands first.",
        severity="critical",
        safe_variants=(
            CommandSafeVariant(
                variant_id="what-if",
                title="PowerShell operation preview",
                matcher=ExecutableMatcher(
                    executables=frozenset({"clear-disk", "format-volume", "remove-partition"}),
                    required_flags=frozenset({"-whatif"}),
                ),
            ),
        ),
    ),
    *DOMAIN_COMMAND_RULES,
    *CLOUD_COMMAND_RULES,
    *STORAGE_COMMAND_RULES,
    *BACKUP_COMMAND_RULES,
    *REMOTE_COMMAND_RULES,
    *DATABASE_COMMAND_RULES,
    *SEARCH_MESSAGING_COMMAND_RULES,
)

_RULES_BY_EXTENSION: dict[str, tuple[CommandSafetyRule, ...]] = {}
for _rule_definition in BUILT_IN_COMMAND_RULES:
    _extension_id, _separator, _rule_name = _rule_definition.rule_id.rpartition(".")
    _RULES_BY_EXTENSION[_extension_id] = (*_RULES_BY_EXTENSION.get(_extension_id, ()), _rule_definition)


def rules_for_extension(extension_id: str) -> tuple[CommandSafetyRule, ...]:
    """Return deterministic built-in rules owned by one extension."""

    return _RULES_BY_EXTENSION.get(extension_id, ())
