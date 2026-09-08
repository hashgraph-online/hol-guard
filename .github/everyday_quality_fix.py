from pathlib import Path

SEMANTICS = Path("src/codex_plugin_scanner/guard/runtime/action_explanation_semantics.py")
PROJECTION = Path("src/codex_plugin_scanner/guard/runtime/action_explanation_projection.py")

semantics = SEMANTICS.read_text()
old_classifier = '''def _kind_for_rule(extension_id: str, rule: CommandSafetyRule) -> str:
    rule_id = rule.rule_id.lower()
    action_text = " ".join(rule.action_classes).lower()
    if extension_id == "command.filesystem":
        return "permission_change" if "permission" in rule_id or "ownership" in rule_id else "file_delete"
    if extension_id == "command.git":
        if any(token in rule_id for token in ("force-push", "push", "remote", "fetch")):
            return "git_remote_change"
        if any(token in rule_id for token in ("reset", "rebase", "history", "branch-delete")):
            return "git_history_rewrite"
        if any(token in rule_id for token in ("read", "inspect", "status", "diff", "log", "show")):
            return "git_read"
        return "git_local_change"
    if "secret" in rule_id or "credential" in rule_id or "secret" in action_text or "credential" in action_text:
        return "secret_send" if any(token in rule_id for token in ("send", "upload", "exfil")) else "secret_read"
    if "download" in rule_id and any(token in rule_id for token in ("execute", "script", "pipe")):
        return "download_and_execute"
    if "download" in rule_id:
        return "download"
    if "package" in extension_id or "package" in rule_id:
        if any(token in rule_id for token in ("remove", "uninstall")):
            return "package_remove"
        if "update" in rule_id or "upgrade" in rule_id:
            return "package_update"
        return "package_install"
    if "container" in extension_id or "docker" in rule_id or "podman" in rule_id:
        return "container_change"
    if "kubernetes" in extension_id or "kubectl" in rule_id or "cluster" in action_text:
        return "cluster_change"
    if any(token in extension_id for token in ("cloud", "terraform", "aws", "azure", "gcp")):
        return "cloud_change"
    if "database" in extension_id or "database" in action_text or "sql" in rule_id:
        return "database_read" if "read" in rule_id else "database_change"
    if "guard" in extension_id or "guard" in action_text:
        return "guard_control_change"
    if "windows" in extension_id or "system" in extension_id:
        return "disk_change" if any(token in rule_id for token in ("disk", "partition", "format")) else "system_change"
    if any(token in rule_id for token in ("upload", "egress", "remote-body", "publish")):
        return "network_send"
    return "system_change"
'''
new_classifier = '''def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
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


def _filesystem_or_git_kind(extension_id: str, rule_id: str, action_text: str) -> str | None:
    del action_text
    if extension_id == "command.filesystem":
        return (
            "permission_change"
            if "permission" in rule_id or "ownership" in rule_id
            else "file_delete"
        )
    if extension_id == "command.git":
        return _git_rule_kind(rule_id)
    return None


def _sensitive_or_transfer_kind(extension_id: str, rule_id: str, action_text: str) -> str | None:
    if _contains_any(rule_id, ("secret", "credential")) or _contains_any(
        action_text, ("secret", "credential")
    ):
        return (
            "secret_send"
            if _contains_any(rule_id, ("send", "upload", "exfil"))
            else "secret_read"
        )
    if "download" in rule_id:
        return (
            "download_and_execute"
            if _contains_any(rule_id, ("execute", "script", "pipe"))
            else "download"
        )
    if "package" in extension_id or "package" in rule_id:
        return _package_rule_kind(rule_id)
    return None


def _infrastructure_rule_kind(extension_id: str, rule_id: str, action_text: str) -> str | None:
    if "container" in extension_id or "docker" in rule_id or "podman" in rule_id:
        return "container_change"
    if "kubernetes" in extension_id or "kubectl" in rule_id or "cluster" in action_text:
        return "cluster_change"
    if _contains_any(extension_id, ("cloud", "terraform", "aws", "azure", "gcp")):
        return "cloud_change"
    if "database" in extension_id or "database" in action_text or "sql" in rule_id:
        return "database_read" if "read" in rule_id else "database_change"
    return None


def _system_or_network_rule_kind(extension_id: str, rule_id: str, action_text: str) -> str | None:
    if "guard" in extension_id or "guard" in action_text:
        return "guard_control_change"
    if "windows" in extension_id or "system" in extension_id:
        return (
            "disk_change"
            if _contains_any(rule_id, ("disk", "partition", "format"))
            else "system_change"
        )
    if _contains_any(rule_id, ("upload", "egress", "remote-body", "publish")):
        return "network_send"
    return None


def _kind_for_rule(extension_id: str, rule: CommandSafetyRule) -> str:
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
'''
if semantics.count(old_classifier) != 1:
    raise SystemExit("expected exactly one Everyday classifier block")
semantics = semantics.replace(old_classifier, new_classifier)
semantics = semantics.replace(
    '_strings(envelope.get("target_paths"))',
    'normalized_string_sequence(envelope.get("target_paths"))',
)
semantics = semantics.replace(
    '_strings(envelope.get("network_hosts"))',
    'normalized_string_sequence(envelope.get("network_hosts"))',
)
old_sequence = '''def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]
'''
new_sequence = '''def normalized_string_sequence(value: object) -> tuple[str, ...]:
    """Normalize a bounded sequence of non-empty string values."""

    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]
'''
if semantics.count(old_sequence) != 1:
    raise SystemExit("expected exactly one semantics sequence helper")
SEMANTICS.write_text(semantics.replace(old_sequence, new_sequence))

projection = PROJECTION.read_text()
old_import = "from .action_explanation_semantics import ActionExplanationSemantics, derive_action_semantics\n"
new_import = '''from .action_explanation_semantics import (
    ActionExplanationSemantics,
    derive_action_semantics,
    normalized_string_sequence,
)
'''
if projection.count(old_import) != 1:
    raise SystemExit("expected exactly one semantics import")
projection = projection.replace(old_import, new_import)
projection = projection.replace("_string_sequence(", "normalized_string_sequence(")
old_projection_sequence = '''def normalized_string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]


'''
if projection.count(old_projection_sequence) != 1:
    raise SystemExit("expected exactly one projection sequence helper after rename")
PROJECTION.write_text(projection.replace(old_projection_sequence, ""))
