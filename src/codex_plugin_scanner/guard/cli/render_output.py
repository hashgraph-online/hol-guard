"""output presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, PayloadDict
    from .render_context import RenderContext


def emit_guard_payload(view: RenderContext, command: str, payload: PayloadDict, as_json: bool) -> None:
    """Render Guard payloads as JSON or human-friendly rich output."""

    if as_json:
        redacted_output = view.redact_text(view._safe_json_output_text(command, payload))
        view.sys.stdout.write(redacted_output.text)
        view.sys.stdout.write("\n")
        return

    redacted_payload = view._coerce_object_dict(view._sanitize_payload_for_output(payload, command=command))
    if not view._RICH_AVAILABLE:
        plain_renderer = view._PLAIN_TEXT_RENDERERS.get(command)
        if plain_renderer is None:
            redacted_output = view.redact_text(view._safe_json_output_text(command, payload))
            view.sys.stdout.write(redacted_output.text)
        else:
            view.sys.stdout.write(plain_renderer(redacted_payload))
        view.sys.stdout.write("\n")
        return

    console = view.Console(file=view.sys.stdout, soft_wrap=True)
    renderer = view._RENDERERS.get(command, view._render_fallback)
    renderer(console, redacted_payload)


def _redact_payload(
    view: RenderContext,
    value: object,
    *,
    key: str | None = None,
    command: str | None = None,
) -> object:
    if key in view._NON_SECRET_STRUCTURED_KEYS and isinstance(value, dict):
        return {
            item_key: view._redact_payload(item_value, key=item_key, command=command)
            for item_key, item_value in value.items()
        }
    if (
        key is not None
        and key not in view._NON_SECRET_STRUCTURED_KEYS
        and key not in view._NON_SECRET_DIAGNOSTIC_KEYS
        and any(token in key.lower() for token in view._SENSITIVE_KEY_TOKENS)
    ):
        if isinstance(value, str) and value.lower() in view._SAFE_POLICY_LITERALS:
            return value
        return "*****"
    if isinstance(value, dict):
        return {
            item_key: view._redact_payload(item_value, key=item_key, command=command)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [view._redact_payload(item, command=command) for item in value]
    if isinstance(value, str):
        redacted = value
        patterns = (
            view._TRUST_SENSITIVE_STRING_PATTERNS
            if isinstance(command, str) and command.startswith("trust.")
            else view._SENSITIVE_STRING_PATTERNS
        )
        for pattern, replacement in patterns:
            redacted = pattern.sub(replacement, redacted)
        return view.redact_local_path(redacted)
    return value


def _render_redacted_json_payload(view: RenderContext, redacted_payload: object) -> str:
    if not isinstance(redacted_payload, dict):
        return "{}"
    return view._serialize_redacted_json(redacted_payload, indent=0)


def _safe_json_output_text(view: RenderContext, command: str, payload: PayloadDict) -> str:
    json_payload = view._json_payload_for_command(command, payload)
    sanitized_payload = view._coerce_object_dict(view._sanitize_payload_for_output(json_payload, command=command))
    return view._render_redacted_json_payload(sanitized_payload)


def _plain_text_protect(view: RenderContext, payload: PayloadDict) -> str:
    if str(payload.get("mode") or "") == "status":
        lines = ["HOL Guard install protection is active."]
        supply_chain = payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            status = str(supply_chain.get("status") or "").strip()
            detail = str(supply_chain.get("detail") or "").strip()
            if status:
                lines.append(f"Status: {status}")
            if detail:
                lines.append(detail)
        return "\n".join(lines)

    verdict = payload.get("verdict")
    verdict_map = view._coerce_object_dict(verdict)
    action = str(verdict_map.get("action") or "review").strip() or "review"
    action_line = {
        "allow": "HOL Guard allowed this install.",
        "block": "HOL Guard blocked this install before it ran.",
        "review": "HOL Guard paused this install for review before it ran.",
        "require-reapproval": "HOL Guard paused this install for review before it ran.",
        "warn": "HOL Guard warned about this install.",
    }.get(action, f"HOL Guard decision: {action}.")
    lines = [action_line]

    request = payload.get("request")
    if isinstance(request, dict):
        command_text = view._command_text(request.get("command")).strip()
        if command_text and command_text != "none":
            lines.append(f"Command: {command_text}")

    reason = str(verdict_map.get("reason") or "").strip()
    if reason:
        lines.append(f"Reason: {reason}")

    supply_chain_evaluation = payload.get("supply_chain_evaluation")
    user_copy = supply_chain_evaluation.get("user_copy") if isinstance(supply_chain_evaluation, dict) else None
    user_copy_map = view._coerce_object_dict(user_copy)
    harness_message = str(user_copy_map.get("harness_message") or "").strip()
    if harness_message:
        lines.append(harness_message)

    next_step = str(user_copy_map.get("next_step") or "").strip()
    if next_step and next_step not in harness_message:
        lines.append(f"Next step: {next_step}")

    dashboard_url = str(user_copy_map.get("dashboard_url") or "").strip()
    if dashboard_url and dashboard_url not in harness_message:
        lines.append(f"Review: {dashboard_url}")

    return "\n".join(lines)


def _sanitize_payload_for_output(view: RenderContext, value: object, *, command: str | None = None) -> object:
    return view._redact_payload(value, command=command)


def _json_payload_for_command(view: RenderContext, command: str, payload: PayloadDict) -> PayloadDict:
    json_renderer = view._JSON_RENDERERS.get(command)
    if json_renderer is None:
        return dict(payload)
    return json_renderer(dict(payload))


def _render_settings_json_payload(view: RenderContext, redacted_payload: PayloadDict) -> PayloadDict:
    settings = redacted_payload.get("settings")
    safe_keys = (
        "mode",
        "security_level",
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
        "risk_actions",
        "risk_action_overrides",
        "harness_risk_actions",
        "approval_wait_timeout_seconds",
        "approval_surface_policy",
        "telemetry",
        "sync",
    )
    safe_settings = {key: settings[key] for key in safe_keys if isinstance(settings, dict) and key in settings}
    return {
        "generated_at": redacted_payload.get("generated_at"),
        "guard_home": redacted_payload.get("guard_home"),
        "config_path": redacted_payload.get("config_path"),
        "settings": safe_settings,
    }


def _serialize_redacted_json(view: RenderContext, value: object, *, indent: int) -> str:
    if isinstance(value, dict):
        if not value:
            return "{}"
        child_indent = indent + 2
        entries = [
            (
                f"{' ' * child_indent}{view.json.dumps(str(item_key))}: "
                f"{view._serialize_redacted_json(item_value, indent=child_indent)}"
            )
            for item_key, item_value in value.items()
        ]
        return "{\n" + ",\n".join(entries) + "\n" + (" " * indent) + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        child_indent = indent + 2
        items = [f"{' ' * child_indent}{view._serialize_redacted_json(item, indent=child_indent)}" for item in value]
        return "[\n" + ",\n".join(items) + "\n" + (" " * indent) + "]"
    try:
        return view.json.dumps(value)
    except TypeError:
        return view.json.dumps(str(value))


def _render_fallback(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    console.print(
        view.Syntax(
            view._render_redacted_json_payload(payload),
            "json",
            theme="ansi_dark",
            word_wrap=True,
        )
    )
