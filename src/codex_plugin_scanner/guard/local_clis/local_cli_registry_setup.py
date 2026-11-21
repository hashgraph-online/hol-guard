"""Reviewed registry setup and Undo routing for the local CLI API."""

from __future__ import annotations

from _thread import LockType
from typing import TYPE_CHECKING

from ..approval_gate import (
    ApprovalGateError,
    consume_local_cli_trust_grant,
    input_from_mapping,
    require_local_cli_trust,
)
from .local_cli_api_contract import LOCAL_CLI_API_SCHEMA as _LOCAL_CLI_API_SCHEMA
from .local_cli_api_contract import LocalCliApiError
from .mcp_registry_undo import RegistrySetupUndo, RegistryUndoError

if TYPE_CHECKING:
    from ..runtime.codex_mcp_setup import CodexMcpSetupReceipt
    from ..store import GuardStore


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LocalCliApiError(400, f"missing_{key}")
    return value.strip()


def registry_setup(
    store: GuardStore, undo: RegistrySetupUndo, setup_lock: LockType, payload: dict[str, object]
) -> dict[str, object]:
    from ..runtime.mcp_registry_setup import (
        install_codex_package_mcp,
        install_codex_remote_mcp,
        reviewed_codex_package_candidate,
        reviewed_codex_setup_candidate,
    )

    operation = payload.get("operation")
    if operation == "recent":
        return {"schema_version": _LOCAL_CLI_API_SCHEMA, "setups": undo.recent()}
    if operation in {"rollback-preview", "rollback"}:
        try:
            if operation == "rollback-preview":
                response = undo.preview(payload)
            else:
                with setup_lock:
                    response = undo.rollback(payload)
        except RegistryUndoError as error:
            raise LocalCliApiError(error.status, error.code, str(error)) from error
        return {"schema_version": _LOCAL_CLI_API_SCHEMA, **response}
    if operation not in {"preview", "apply"}:
        raise LocalCliApiError(400, "invalid_registry_setup_operation")
    kind = payload.get("kind", "remote")
    if kind not in ("remote", "package"):
        raise LocalCliApiError(400, "invalid_registry_setup_kind")
    package_setup = kind == "package"
    try:
        candidate = (
            reviewed_codex_package_candidate(payload) if package_setup else reviewed_codex_setup_candidate(payload)
        )
    except ValueError as error:
        raise LocalCliApiError(
            409, str(error), "Registry listing changed or cannot be used for Codex setup."
        ) from error
    if operation == "preview":
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            **candidate,
            "permissions_granted": False,
            "host_change_applied": False,
            "next_action": "Review the exact Codex launch recipe and confirm setup.",
        }
    if (
        payload.get("selection_digest") != candidate["selection_digest"]
        or payload.get("confirm_host_change") is not True
    ):
        raise LocalCliApiError(409, "registry_setup_review_changed", "Review this connection again before setup.")
    session_nonce = _required_string(payload, "session_nonce")
    action = "codex-mcp-package-setup" if package_setup else "codex-mcp-remote-setup"
    subject = action + ":" + str(candidate["selection_digest"])
    try:
        grant = require_local_cli_trust(
            store.guard_home,
            approval_gate_input=input_from_mapping(payload),
            action=action,
            subject=subject,
            session_nonce=session_nonce,
        )
        consume_local_cli_trust_grant(
            store.guard_home,
            grant,
            action=action,
            subject=subject,
            session_nonce=session_nonce,
        )
    except ApprovalGateError as error:
        raise LocalCliApiError(error.status, error.code, str(error)) from error
    try:
        rollback_handle: str | None = None

        def remember(receipt: CodexMcpSetupReceipt) -> None:
            nonlocal rollback_handle
            rollback_handle = undo.remember(receipt, candidate)

        with setup_lock:
            undo.ensure_capacity()
            configured = (
                install_codex_package_mcp(
                    candidate,
                    on_installed=remember,
                    on_version_chain=undo.advance_version_chain,
                )
                if package_setup
                else install_codex_remote_mcp(
                    candidate,
                    on_installed=remember,
                    on_version_chain=undo.advance_version_chain,
                )
            )
            if rollback_handle is None or configured != candidate["setup_name"]:
                raise ValueError("codex_setup_outcome_uncertain")
    except ValueError as error:
        if str(error) == "codex_setup_outcome_uncertain":
            message = "Codex may have changed its connection. Check the host configuration before retrying."
        elif str(error) == "codex_setup_rolled_back":
            message = "Setup did not verify and its new connection was removed. Review setup and retry."
        elif str(error) == "codex_config_changed":
            message = "Codex configuration changed. Review it before retrying setup."
        elif str(error) == "codex_setup_receipt_limit":
            message = (
                "Recent setup history is full. Wait for an older setup to expire before adding another connection."
            )
        else:
            message = "Codex could not add this connection. Update or review its host configuration and retry."
        raise LocalCliApiError(409, str(error), message) from error
    return {
        "schema_version": _LOCAL_CLI_API_SCHEMA,
        "host": "codex",
        "kind": "package" if package_setup else "remote",
        "setup_name": configured,
        "rollback_handle": rollback_handle,
        "rollback_available_seconds": 3600,
        "host_change_applied": True,
        "permissions_granted": False,
        "next_action": (
            "Restart Codex. On first use, Codex may download and run the pinned package. "
            "Complete provider-owned sign-in if prompted, then check host connections in Guard."
            if package_setup
            else "Restart Codex, complete provider-owned sign-in if prompted, then check host connections in Guard."
        ),
    }
