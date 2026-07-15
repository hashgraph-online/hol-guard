"""Side-effect-free command inspection using Guard's runtime command parser."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.risk import artifact_risk_signals_v2
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    COMMAND_EXTENSION_SCHEMA_VERSION,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def inspect_command(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> dict[str, object]:
    """Classify one command without executing it or persisting Guard state."""

    command_text = command.strip()
    if not command_text:
        raise ValueError("Command text cannot be empty")
    workspace = (cwd or Path.cwd()).resolve()
    home = (home_dir or Path.home()).resolve()
    arguments = {"command": command_text}
    benign = is_explicitly_benign_tool_action_request("Shell", arguments, cwd=workspace, home_dir=home)
    match = extract_sensitive_tool_action_request("Shell", arguments, cwd=workspace, home_dir=home)
    trace: list[dict[str, object]] = [
        {
            "step": "normalize",
            "result": "completed",
            "detail": "Applied Guard's transparent shell-wrapper normalization.",
        },
        {
            "step": "benign-classification",
            "result": "matched" if benign else "not-matched",
            "detail": "Checked Guard's explicit read-only and observer command classifications.",
        },
        {
            "step": "sensitive-action-classification",
            "result": "matched" if match is not None else "not-matched",
            "detail": "Ran the same sensitive command parser used by Guard harness hooks.",
        },
    ]
    if match is None:
        return {
            "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
            "status": "no_match",
            "command": command_text,
            "classification": {
                "matched": False,
                "explicitly_benign": benign,
                "action_class": None,
                "reason": (
                    "No built-in command safety extension matched. Other Guard protections and final policy were not "
                    "evaluated."
                ),
                "normalized_command": command_text,
                "wrapper_chain": [],
            },
            "risk_classes": [],
            "signals": [],
            "extensions": [],
            "trace": trace,
            "policy_evaluation": "not_run",
            "side_effects": "none",
        }

    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class(match.action_class)
    artifact = build_tool_action_request_artifact(
        "guard-cli",
        match,
        config_path="command-inspection",
        source_scope="inspection",
    )
    signals = artifact_risk_signals_v2(artifact)
    trace.extend(
        (
            {
                "step": "extension-ownership",
                "result": extension.extension_id if extension is not None else "unowned",
                "detail": "Mapped the existing action class to a versioned command safety extension.",
            },
            {
                "step": "risk-signal-derivation",
                "result": "completed",
                "detail": f"Derived {len(signals)} existing Guard risk signal(s) from the classified artifact.",
            },
        )
    )
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "status": "review",
        "command": command_text,
        "classification": {
            "matched": True,
            "explicitly_benign": benign,
            "action_class": match.action_class,
            "reason": match.reason,
            "normalized_command": match.command_text,
            "wrapper_chain": list(match.wrapper_chain),
        },
        "risk_classes": list(risk_classes_for_command_action(match.action_class)),
        "signals": [signal.to_dict() for signal in signals],
        "extensions": [extension.to_dict()] if extension is not None else [],
        "trace": trace,
        "policy_evaluation": "not_run",
        "side_effects": "none",
    }


def command_extensions_payload(extension_id: str | None = None) -> dict[str, object]:
    """Return deterministic metadata for built-in command safety extensions."""

    if extension_id is not None:
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
        if extension is None:
            raise ValueError(f"Unknown command safety extension: {extension_id}")
        extensions = (extension,)
    else:
        extensions = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    return {
        "schema_version": COMMAND_EXTENSION_SCHEMA_VERSION,
        "source": "built-in",
        "count": len(extensions),
        "extensions": [extension.to_dict() for extension in extensions],
    }
