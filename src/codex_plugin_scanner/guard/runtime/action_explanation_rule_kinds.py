"""Presentation-only mapping from Guard command rules to Everyday action kinds."""

from __future__ import annotations

from .command_rules import CommandSafetyRule


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def _git_rule_kind(rule_id: str) -> str:
    if _contains_any(rule_id, ("force-push", "push", "remote", "fetch")):
        return "git_remote_change"
    if _contains_any(rule_id, ("reset", "rebase", "history", "branch-delete")):
        return "git_history_rewrite"
    if _contains_any(rule_id, ("read", "inspect", "status", "diff", "log", "show")):
        return "git_read"
    return "git_local_change"


def _package_rule_kind(rule_id: str) -> str:
    if _contains_any(rule_id, ("remove", "uninstall")):
        return "package_remove"
    if "update" in rule_id or "upgrade" in rule_id:
        return "package_update"
    return "package_install"


def _filesystem_or_git_kind(
    extension_id: str,
    rule_id: str,
    _action_text: str,
) -> str | None:
    if extension_id == "command.filesystem":
        return "permission_change" if "permission" in rule_id or "ownership" in rule_id else "file_delete"
    if extension_id == "command.git":
        return _git_rule_kind(rule_id)
    return None


def _sensitive_or_transfer_kind(
    extension_id: str,
    rule_id: str,
    action_text: str,
) -> str | None:
    if _contains_any(rule_id, ("secret", "credential")) or _contains_any(action_text, ("secret", "credential")):
        return "secret_send" if _contains_any(rule_id, ("send", "upload", "exfil")) else "secret_read"
    if "download" in rule_id:
        return "download_and_execute" if _contains_any(rule_id, ("execute", "script", "pipe")) else "download"
    if "package" in extension_id or "package" in rule_id:
        return _package_rule_kind(rule_id)
    return None


def _infrastructure_rule_kind(
    extension_id: str,
    rule_id: str,
    action_text: str,
) -> str | None:
    if "container" in extension_id or "docker" in rule_id or "podman" in rule_id:
        return "container_change"
    if "kubernetes" in extension_id or "kubectl" in rule_id or "cluster" in action_text:
        return "cluster_change"
    if _contains_any(extension_id, ("cloud", "terraform", "aws", "azure", "gcp")):
        return "cloud_change"
    if "database" in extension_id or "database" in action_text or "sql" in rule_id:
        return "database_read" if "read" in rule_id else "database_change"
    return None


def _system_or_network_rule_kind(
    extension_id: str,
    rule_id: str,
    action_text: str,
) -> str | None:
    if "guard" in extension_id or "guard" in action_text:
        return "guard_control_change"
    if "windows" in extension_id or "system" in extension_id:
        return "disk_change" if _contains_any(rule_id, ("disk", "partition", "format")) else "system_change"
    if _contains_any(rule_id, ("upload", "egress", "remote-body", "publish")):
        return "network_send"
    return None


def kind_for_rule(extension_id: str, rule: CommandSafetyRule) -> str:
    rule_id = rule.rule_id.lower()
    action_text = " ".join(rule.action_classes).lower()
    classifiers = (
        _filesystem_or_git_kind,
        _sensitive_or_transfer_kind,
        _infrastructure_rule_kind,
        _system_or_network_rule_kind,
    )
    for classifier in classifiers:
        kind = classifier(extension_id, rule_id, action_text)
        if kind is not None:
            return kind
    return "system_change"
