"""Structured rules and metadata for backup command extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant

_RCLONE_GLOBAL_OPTIONS = frozenset({"--config", "--log-file", "--password-command", "--rc-addr"})
_RESTIC_GLOBAL_OPTIONS = frozenset({"-r", "--repo", "--password-file", "--cache-dir", "-o", "--option"})
_BORG_GLOBAL_OPTIONS = frozenset(
    {
        "-r",
        "--repo",
        "--debug-profile",
        "--debug-topic",
        "--lock-wait",
        "--remote-path",
        "--rsh",
        "--socket",
        "--umask",
        "--upload-buffer",
        "--upload-ratelimit",
    }
)
_VELERO_GLOBAL_OPTIONS = frozenset(
    {
        "--features",
        "--kubeconfig",
        "--kubecontext",
        "--log_backtrace_at",
        "--log_dir",
        "--log_file",
        "--log_file_max_size",
        "--log-backtrace-at",
        "--log-dir",
        "--log-file",
        "--log-file-max-size",
        "--namespace",
        "--stderrthreshold",
        "--v",
        "--vmodule",
        "-n",
        "-v",
    }
)
_VELERO_GLOBAL_FLAGS = frozenset(
    {
        "--add-dir-header",
        "--add_dir_header",
        "--alsologtostderr",
        "--colorized",
        "--logtostderr",
        "--one_output",
        "--skip_headers",
        "--skip_log_headers",
        "--skip-headers",
        "--skip-log-headers",
    }
)
_RCLONE_MUTATION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "rclone",
            command,
            allow_leading_options=True,
            leading_options_with_values=_RCLONE_GLOBAL_OPTIONS,
        )
        for command in ("delete", "deletefile", "purge", "rmdirs", "sync", "move", "moveto", "bisync")
    )
)
_RESTIC_MUTATION = AnyMatcher(
    matchers=(
        executable_matcher(
            "restic",
            "forget",
            allow_leading_options=True,
            leading_options_with_values=_RESTIC_GLOBAL_OPTIONS,
        ),
        executable_matcher(
            "restic",
            "prune",
            allow_leading_options=True,
            leading_options_with_values=_RESTIC_GLOBAL_OPTIONS,
        ),
        executable_matcher(
            "restic",
            "rewrite",
            required_flags=frozenset({"--forget"}),
            allow_leading_options=True,
            leading_options_with_values=_RESTIC_GLOBAL_OPTIONS,
        ),
    )
)
_BORG_MUTATION = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "borg",
            command,
            allow_leading_options=True,
            leading_options_with_values=_BORG_GLOBAL_OPTIONS,
        )
        for command in ("delete", "prune", "recreate")
    )
)
_BORG_DRY_RUN = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "borg",
            command,
            allow_leading_options=True,
            leading_options_with_values=_BORG_GLOBAL_OPTIONS,
        )
        for command in ("prune", "recreate")
    )
)
_VELERO_DELETE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "velero",
            resource,
            "delete",
            global_options_with_values=_VELERO_GLOBAL_OPTIONS,
            global_flags=_VELERO_GLOBAL_FLAGS,
        )
        for resource in ("backup", "schedule", "restore")
    )
)


def _backup_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: AnyMatcher,
    action_class: str,
    safe_variants: tuple[CommandSafeVariant, ...],
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="critical",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=("List retained backups and run the documented preview before changing backup data.",),
        matcher=matcher,
        safe_variants=safe_variants,
    )


BACKUP_COMMAND_RULES = (
    _backup_rule(
        rule_id="command.backup.rclone.mutation",
        title="Rclone destructive synchronization",
        description="Identifies deletion, purge, move, and synchronization operations that can remove data.",
        matcher=_RCLONE_MUTATION,
        action_class="Rclone destructive command",
        safe_variants=(
            safe_flag_variant(_RCLONE_MUTATION, variant_id="help", title="Rclone command help", flag="--help"),
            safe_flag_variant(_RCLONE_MUTATION, variant_id="dry-run", title="Rclone dry run", flag="--dry-run"),
            safe_flag_variant(_RCLONE_MUTATION, variant_id="no-act", title="Rclone no-act", flag="-n"),
        ),
    ),
    _backup_rule(
        rule_id="command.backup.restic.mutation",
        title="Restic backup removal",
        description="Identifies snapshot forgetting, repository pruning, and rewrite operations that remove originals.",
        matcher=_RESTIC_MUTATION,
        action_class="Restic destructive command",
        safe_variants=(
            safe_flag_variant(_RESTIC_MUTATION, variant_id="help", title="Restic command help", flag="--help"),
            safe_flag_variant(_RESTIC_MUTATION, variant_id="dry-run", title="Restic dry run", flag="--dry-run"),
        ),
    ),
    _backup_rule(
        rule_id="command.backup.borg.mutation",
        title="Borg backup mutation",
        description="Identifies archive deletion, retention pruning, and archive recreation operations.",
        matcher=_BORG_MUTATION,
        action_class="Borg destructive command",
        safe_variants=(
            safe_flag_variant(_BORG_MUTATION, variant_id="help", title="Borg command help", flag="--help"),
            safe_flag_variant(_BORG_DRY_RUN, variant_id="dry-run", title="Borg dry run", flag="--dry-run"),
            safe_flag_variant(_BORG_DRY_RUN, variant_id="no-act", title="Borg no-act", flag="-n"),
        ),
    ),
    _backup_rule(
        rule_id="command.backup.velero.deletion",
        title="Velero backup deletion",
        description="Identifies deletion of backups, schedules, and restore records through Velero CLI.",
        matcher=_VELERO_DELETE,
        action_class="Velero destructive command",
        safe_variants=(
            safe_flag_variant(_VELERO_DELETE, variant_id="help", title="Velero command help", flag="--help"),
        ),
    ),
)


BACKUP_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.backup.rclone",
        name="Rclone command protection",
        description="Reviews rclone operations that delete, move, purge, or synchronize data.",
        action_classes=("Rclone destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Run the same command with --dry-run and inspect every affected path first.",),
        reference_urls=("https://rclone.org/commands/", "https://rclone.org/commands/rclone_delete/"),
    ),
    CommandExtensionSpec(
        extension_id="command.backup.restic",
        name="Restic command protection",
        description="Reviews restic operations that remove snapshots or repository data.",
        action_classes=("Restic destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Run forget, prune, or rewrite with --dry-run and inspect retained snapshots.",),
        reference_urls=(
            "https://restic.readthedocs.io/en/stable/060_forget.html",
            "https://restic.readthedocs.io/en/stable/045_working_with_repos.html",
        ),
    ),
    CommandExtensionSpec(
        extension_id="command.backup.borg",
        name="Borg command protection",
        description="Reviews Borg operations that delete, prune, or recreate archives.",
        action_classes=("Borg destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Use --dry-run where documented and inspect the selected archive set.",),
        reference_urls=("https://borgbackup.readthedocs.io/en/stable/usage/prune.html",),
    ),
    CommandExtensionSpec(
        extension_id="command.backup.velero",
        name="Velero command protection",
        description="Reviews Velero operations that delete backup data or recovery records.",
        action_classes=("Velero destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Describe the backup and confirm object-storage and snapshot retention first.",),
        reference_urls=("https://velero.io/docs/main/backup-reference/",),
    ),
)
