"""Privacy-safe, side-effect-free command evaluation for Protection Center Test Lab."""

from __future__ import annotations

from typing import cast

from ..runtime.command_evaluation import evaluate_command
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_runtime import ExtensionControlRuntime
from .extension_control_errors import ExtensionControlApiError

_TEST_SCHEMA = "guard.daemon.extension-control-test.v1"
_MAX_TEST_COMMAND_CHARS = 4096
_MAX_TEST_EXTENSION_ID_CHARS = 256
_MAX_TEST_MATCHES = 32
_MAX_SAFER_ALTERNATIVES = 8
_MAX_TEXT_CHARS = 320


def _bounded_text(value: str, *, limit: int = _MAX_TEXT_CHARS) -> str:
    normalized = " ".join(value.split())
    return normalized[:limit]


def _decision(minimum_action: str) -> str:
    if minimum_action == "block":
        return "blocked"
    if minimum_action == "review":
        return "ask-first"
    return "allowed"


def evaluate_extension_control_test(
    *,
    registry: CommandSafetyExtensionRegistry,
    runtime: ExtensionControlRuntime,
    payload: dict[str, object],
) -> dict[str, object]:
    """Evaluate a command without executing it, persisting it, or returning it."""

    raw_command = payload.get("command")
    if not isinstance(raw_command, str):
        raise ExtensionControlApiError(400, "invalid_test_command")
    command = raw_command.strip()
    if not command or len(command) > _MAX_TEST_COMMAND_CHARS or "\x00" in command:
        raise ExtensionControlApiError(400, "invalid_test_command")

    raw_extension_id = payload.get("extension_id")
    extension_id: str | None = None
    if raw_extension_id is not None:
        if not isinstance(raw_extension_id, str):
            raise ExtensionControlApiError(400, "invalid_extension")
        requested = raw_extension_id.strip().lower()
        if not requested or len(requested) > _MAX_TEST_EXTENSION_ID_CHARS:
            raise ExtensionControlApiError(400, "invalid_extension")
        extension = registry.get(requested)
        if extension is None:
            raise ExtensionControlApiError(404, "unknown_extension")
        extension_id = extension.extension_id

    evaluation = evaluate_command(
        command,
        registry=registry,
        extension_control_snapshot=runtime.current(),
    )
    relevant = [
        owned for owned in evaluation.matches if extension_id is None or owned.extension.extension_id == extension_id
    ][:_MAX_TEST_MATCHES]

    safer: list[str] = []
    for owned in relevant:
        for candidate in (*owned.match.rule.safer_alternatives, *owned.extension.safer_alternatives):
            value = _bounded_text(candidate)
            if value and value not in safer:
                safer.append(value)
            if len(safer) >= _MAX_SAFER_ALTERNATIVES:
                break
        if len(safer) >= _MAX_SAFER_ALTERNATIVES:
            break

    match_payloads: list[dict[str, object]] = []
    for owned in relevant:
        rule = owned.match.rule
        permission = registry.permission_for_rule_id(rule.rule_id)
        match_payloads.append(
            {
                "extension_id": owned.extension.extension_id,
                "extension_name": _bounded_text(owned.extension.name, limit=120),
                "rule_id": rule.rule_id,
                "rule_title": _bounded_text(rule.title, limit=160),
                "permission_id": permission.permission_id if permission is not None else None,
                "description": _bounded_text(rule.description),
                "severity": rule.severity,
                "risk_classes": list(rule.risk_classes[:16]),
            }
        )

    module_matched = bool(relevant) if extension_id is not None else evaluation.matched
    if relevant:
        explanation = _bounded_text(relevant[0].match.rule.description)
    elif extension_id is not None and evaluation.matched:
        explanation = "This protection module did not match, but another Guard protection would handle the action."
    elif extension_id is not None:
        explanation = "This protection module did not match the command under the current local protection state."
    else:
        explanation = "No command protection rule matched under the current local protection state."

    snapshot = runtime.current()
    return {
        "schema_version": _TEST_SCHEMA,
        "decision": _decision(evaluation.minimum_action),
        "minimum_action": evaluation.minimum_action,
        "matched": evaluation.matched,
        "module_matched": module_matched,
        "other_protection_matched": bool(extension_id is not None and evaluation.matched and not relevant),
        "explanation": explanation,
        "matches": cast(list[object], match_payloads),
        "safer_alternatives": safer,
        "authority_health": snapshot.health.value,
        "revision": snapshot.revision,
        "catalog_digest": snapshot.catalog_digest,
    }
