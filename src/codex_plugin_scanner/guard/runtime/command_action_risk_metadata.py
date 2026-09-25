"""Matcher-free risk metadata for command action classes.

The action-class map is consumed by metadata, inspection, and policy
projection paths. Keep it independent from the legacy Python matcher modules;
semantic command observations are supplied by the native catalog.
"""

from __future__ import annotations

from typing import Final

_BASE_COMMAND_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    "local secret read shell command": ("local_secret_read",),
    "local script execution shell command": ("execution",),
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
    "process environment secret read": ("local_secret_read",),
    "shell file upload command": ("credential_exfiltration", "network_egress"),
    "sensitive local file write": ("destructive_shell", "local_secret_read"),
    "destructive shell command": ("destructive_shell",),
    "pytest repository-code execution": ("execution",),
    "untrusted python interpreter": ("execution",),
    "guard approval self-authorization command": ("policy_bypass",),
    "github pr body shell substitution": ("execution",),
    "filesystem destructive command": ("destructive_shell",),
    "git destructive command": ("destructive_shell",),
    "git origin refresh": ("network_egress",),
    "git index inspection": ("local_secret_read",),
    "git workspace command": ("destructive_shell", "network_egress"),
    "git read command": ("local_secret_read",),
    "skill sunset configuration audit command": ("local_secret_read",),
    "system destructive command": ("destructive_shell",),
    "windows destructive command": ("destructive_shell",),
    "kubernetes destructive command": ("destructive_shell", "network_egress"),
    "infrastructure destructive command": ("destructive_shell", "network_egress"),
    "aws destructive command": ("destructive_shell", "network_egress"),
    "google cloud destructive command": ("destructive_shell", "network_egress"),
    "azure destructive command": ("destructive_shell", "network_egress"),
    "aws dns destructive command": ("destructive_shell", "network_egress"),
    "google dns destructive command": ("destructive_shell", "network_egress"),
    "azure dns destructive command": ("destructive_shell", "network_egress"),
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
    "essh group execution command": ("execution", "network_egress"),
    "essh cache removal command": ("destructive_shell",),
    "noodle request execution command": ("execution", "network_egress"),
    "probe request execution command": ("execution", "network_egress"),
    "probe workspace mutation command": ("destructive_shell",),
    "probe destructive command": ("destructive_shell",),
}

BLITCP_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    "blitcp remote destination command": ("network_egress",),
    "blitcp privilege escalation command": ("execution",),
    "blitcp self-update command": ("execution", "network_egress"),
    "blitcp unverified copy command": ("destructive_shell",),
}

GITHUB_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    "github routine pull-request merge command": ("destructive_shell", "network_egress"),
    "github workflow rerun": ("destructive_shell", "network_egress"),
    "github local configuration write": ("destructive_shell",),
    "github bounded maintenance command": ("destructive_shell", "network_egress"),
    "github content mutation command": ("destructive_shell", "network_egress"),
    "github merge command": ("destructive_shell", "network_egress"),
    "github administrator pull-request merge command": ("destructive_shell", "network_egress"),
    "github release publication command": ("destructive_shell", "network_egress"),
    "github workflow mutation command": ("destructive_shell", "network_egress"),
    "github force mutation command": ("destructive_shell", "network_egress"),
    "github delete command": ("destructive_shell", "network_egress"),
    "github secret mutation command": ("destructive_shell", "network_egress"),
    "github access mutation command": ("destructive_shell", "network_egress"),
    "github remote mutation command": ("destructive_shell", "network_egress"),
    "unverified github command capability": ("destructive_shell", "network_egress"),
}

OLLAMA_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    "ollama model publication command": ("network_egress",),
    "ollama model removal command": ("destructive_shell",),
}

COMMAND_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    **_BASE_COMMAND_ACTION_RISK_CLASSES,
    **BLITCP_ACTION_RISK_CLASSES,
    **GITHUB_ACTION_RISK_CLASSES,
    **OLLAMA_ACTION_RISK_CLASSES,
}

__all__ = [
    "BLITCP_ACTION_RISK_CLASSES",
    "COMMAND_ACTION_RISK_CLASSES",
    "GITHUB_ACTION_RISK_CLASSES",
    "OLLAMA_ACTION_RISK_CLASSES",
]
