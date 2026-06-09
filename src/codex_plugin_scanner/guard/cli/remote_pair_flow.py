"""Browserless remote agent pairing for hosted OpenClaw and Hermes."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from ..adapters.base import HarnessContext
from ..redaction import redact_sensitive_text
from ..remote_pairing_constants import REMOTE_PAIRING_CODE_ALPHABET, REMOTE_PAIRING_CODE_PREFIX
from ..store import GuardStore
from .connect_flow import (
    CONNECT_REPAIR_COMMAND,
    CONNECT_STATUS_COMMAND,
    DEFAULT_GUARD_CONNECT_URL,
    _load_error_payload,
    _oauth_sync_url_from_issuer,
    _parse_guard_token_exchange_payload,
    _persist_oauth_local_credentials,
    resolve_connect_url,
)
from .install_commands import apply_managed_install, build_harness_verification
from .oauth_client import generate_dpop_key_pair, resolve_guard_oauth_client_config

REMOTE_PAIRING_OAUTH_CLIENT_ID = "guard-local-daemon"
REMOTE_PAIRING_RUNTIMES = frozenset({"openclaw", "hermes"})
REMOTE_PAIRING_CODE_PATTERN = re.compile(
    rf"^{REMOTE_PAIRING_CODE_PREFIX}-[{REMOTE_PAIRING_CODE_ALPHABET}]{{6}}$",
    re.IGNORECASE,
)
REMOTE_PAIRING_CODE_REDACTION_PATTERN = re.compile(
    rf"\b{REMOTE_PAIRING_CODE_PREFIX}-[{REMOTE_PAIRING_CODE_ALPHABET}]{{6}}\b",
    re.IGNORECASE,
)
REMOTE_PAIR_COMMAND = "hol-guard remote-pair"
REMOTE_PAIR_STATUS_COMMAND = "hol-guard remote-pair status"
RUNTIME_LABELS: dict[str, str] = {
    "openclaw": "OpenClaw",
    "hermes": "Hermes",
}
GuardRemotePairingRuntime = Literal["openclaw", "hermes"]


def normalize_remote_pairing_code(value: str) -> str:
    return value.strip().upper()


def is_remote_pairing_code_shape(value: str) -> bool:
    return bool(REMOTE_PAIRING_CODE_PATTERN.match(normalize_remote_pairing_code(value)))


def redact_remote_pairing_text(value: str) -> str:
    redacted = REMOTE_PAIRING_CODE_REDACTION_PATTERN.sub("HLG-******", value)
    return redact_sensitive_text(redacted)


def remote_pairing_claim_url(*, issuer: str) -> str:
    return f"{issuer.rstrip('/')}/api/guard/remote-pairing/claim"


def _assert_no_root_install_allowed(*, no_root: bool) -> None:
    if not no_root:
        return
    if hasattr(os, "geteuid") and callable(os.geteuid) and os.geteuid() == 0:
        raise ValueError("Remote pairing --no-root refuses to run as root.")
    if os.name == "nt":
        import ctypes

        if bool(ctypes.windll.shell32.IsUserAnAdmin()):
            raise ValueError("Remote pairing --no-root refuses elevated Administrator sessions.")
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user:
        raise ValueError("Remote pairing --no-root refuses sudo sessions.")


def _assert_user_space_paths_writable(home_dir: Path) -> None:
    if not home_dir.is_dir():
        raise ValueError("Remote pairing requires a writable home directory.")
    if not os.access(home_dir, os.W_OK):
        raise ValueError("Remote pairing requires a writable home directory.")

    required_paths = (
        home_dir / ".local" / "bin",
        home_dir / ".hol-guard" / "bin",
    )
    for path in required_paths:
        parent = path.parent
        writable_parent = parent if parent.exists() else home_dir
        if not os.access(writable_parent, os.W_OK):
            raise ValueError(f"Remote pairing requires a writable user-space install path at {path}.")
        if path.exists() and not os.access(path, os.W_OK):
            raise ValueError(f"Remote pairing requires a writable user-space install path at {path}.")


def _runtime_label(runtime: str) -> str:
    return RUNTIME_LABELS.get(runtime, runtime)


def _build_capability_summary(
    *,
    runtime: str,
    context: HarnessContext,
    no_root: bool,
) -> dict[str, object]:
    from ..adapters import get_adapter

    adapter = get_adapter(runtime)
    contract = adapter.setup_contract()
    contract_payload = contract.to_dict()
    return {
        "runtime": runtime,
        "runtimeLabel": _runtime_label(runtime),
        "userSpaceInstall": no_root,
        "nativeHookWritable": bool(contract_payload.get("native_hooks")),
        "pretoolAvailable": bool(contract_payload.get("pretool_available")),
        "mcpProxyAvailable": bool(contract_payload.get("mcp_proxy_available")),
        "wrapperFallbackAvailable": bool(contract_payload.get("wrapper_fallback")),
        "homeDir": str(context.home_dir),
        "guardHome": str(context.guard_home),
    }


def claim_remote_pairing_intent(
    *,
    claim_url: str,
    pair_code: str,
    runtime: str,
    installation_id: str,
    label: str | None,
    public_dpop_jwk: dict[str, str],
    capability_summary: dict[str, object] | None = None,
    urlopen=urllib.request.urlopen,
) -> dict[str, object]:
    normalized_code = normalize_remote_pairing_code(pair_code)
    if not is_remote_pairing_code_shape(normalized_code):
        raise ValueError("Pairing code format is invalid.")

    if runtime not in REMOTE_PAIRING_RUNTIMES:
        raise ValueError("Runtime must be openclaw or hermes for remote pairing.")

    body: dict[str, object] = {
        "pairCode": normalized_code,
        "runtime": runtime,
        "installationId": installation_id,
        "publicDpopJwk": public_dpop_jwk,
    }
    if isinstance(label, str) and label.strip():
        body["label"] = label.strip()
    if capability_summary:
        body["capabilitySummary"] = capability_summary

    request = urllib.request.Request(
        claim_url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "hol-guard-remote-pair",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        error_payload = _load_error_payload(error)
        if isinstance(error_payload, dict):
            message = str(
                error_payload.get("error") or error_payload.get("message") or "Remote pairing claim failed."
            ).strip()
            code = str(error_payload.get("code") or "").strip()
        else:
            message = "Remote pairing claim failed."
            code = ""
        detail = f"{code}: {message}" if code else message
        raise RuntimeError(redact_remote_pairing_text(detail)) from error
    except urllib.error.URLError as error:
        raise RuntimeError(redact_remote_pairing_text(str(error.reason))) from error

    if not isinstance(payload, dict):
        raise RuntimeError("Remote pairing claim failed: invalid response.")
    return payload


def _sanitize_remote_pair_payload(payload: dict[str, object]) -> dict[str, object]:
    sanitized = dict(payload)
    for key in ("access_token", "refresh_token", "pair_code", "pairCode"):
        sanitized.pop(key, None)
    return sanitized


def build_remote_pair_status_payload(
    *,
    store: GuardStore,
    context: HarnessContext,
) -> dict[str, object]:
    credentials = store.get_oauth_local_credentials()
    cloud_profile = store.get_cloud_sync_profile()
    runtime_id = None
    if isinstance(credentials, dict):
        runtime_value = credentials.get("runtime_id")
        if isinstance(runtime_value, str) and runtime_value.strip():
            runtime_id = runtime_value.strip()

    pairing_state = "disconnected"
    if cloud_profile is not None:
        pairing_state = "connected"
    elif credentials is not None:
        pairing_state = "paired_local_only"

    protection_status = "unknown"
    protection_reason = None
    if runtime_id in REMOTE_PAIRING_RUNTIMES:
        verification = build_harness_verification(runtime_id, context, store)
        protection_status = "active" if bool(verification.get("safe")) else "paired_not_protected"
        verification_block = verification.get("verification", {})
        if isinstance(verification_block, dict):
            warning_items = verification_block.get("warnings")
            if isinstance(warning_items, list) and warning_items:
                protection_reason = str(warning_items[0])

    return _sanitize_remote_pair_payload(
        {
            "status": pairing_state,
            "pairing": pairing_state,
            "protection": protection_status,
            "protection_reason": protection_reason,
            "runtime": runtime_id,
            "workspace_id": store.get_cloud_workspace_id(),
            "machine_id": (
                str(credentials.get("machine_id"))
                if isinstance(credentials, dict) and isinstance(credentials.get("machine_id"), str)
                else None
            ),
            "remote_pair_status_command": REMOTE_PAIR_STATUS_COMMAND,
        }
    )


def run_guard_remote_pair_command(
    *,
    store: GuardStore,
    context: HarnessContext,
    connect_url: str,
    runtime: str,
    pair_code: str,
    label: str | None,
    no_root: bool,
    now: str | None = None,
    urlopen=urllib.request.urlopen,
) -> dict[str, object]:
    store.repair_oauth_local_credential_storage_from_primary()
    _assert_no_root_install_allowed(no_root=no_root)
    if no_root:
        _assert_user_space_paths_writable(context.home_dir)

    if runtime not in REMOTE_PAIRING_RUNTIMES:
        raise ValueError("Runtime must be openclaw or hermes for remote pairing.")

    normalized_connect_url, allowed_origin = resolve_connect_url(connect_url or DEFAULT_GUARD_CONNECT_URL)
    oauth_client = resolve_guard_oauth_client_config(allowed_origin)
    claim_url = remote_pairing_claim_url(issuer=oauth_client.issuer)

    dpop_key_material = generate_dpop_key_pair()
    installation_id = store.get_or_create_installation_id()
    resolved_label = label.strip() if isinstance(label, str) and label.strip() else _runtime_label(runtime)

    claim_payload = claim_remote_pairing_intent(
        claim_url=claim_url,
        pair_code=pair_code,
        runtime=runtime,
        installation_id=installation_id,
        label=resolved_label,
        public_dpop_jwk=dpop_key_material.public_jwk,
        capability_summary=_build_capability_summary(
            runtime=runtime,
            context=context,
            no_root=no_root,
        ),
        urlopen=urlopen,
    )

    token_payload = claim_payload.get("tokens")
    if not isinstance(token_payload, dict):
        raise RuntimeError("Remote pairing claim succeeded but token payload is missing.")

    token_result = _parse_guard_token_exchange_payload(token_payload)
    if token_result.refresh_token is None:
        raise RuntimeError("Remote pairing claim succeeded but refresh token is missing.")

    timestamp = now or datetime.now(timezone.utc).isoformat()
    _persist_oauth_local_credentials(
        store=store,
        issuer=oauth_client.issuer,
        client_id=REMOTE_PAIRING_OAUTH_CLIENT_ID,
        refresh_token=token_result.refresh_token,
        dpop_key_material=dpop_key_material,
        grant_id=token_result.grant_id,
        machine_id=token_result.machine_id or installation_id,
        supply_chain_entitlement=token_result.supply_chain_entitlement,
        workspace_id=token_result.workspace_id,
        runtime_id=runtime,
        runtime_label=resolved_label,
        now=timestamp,
    )

    install_payload = apply_managed_install(
        "install",
        runtime,
        False,
        context,
        store,
        str(context.workspace_dir) if context.workspace_dir is not None else None,
        timestamp,
    )
    verification = build_harness_verification(runtime, context, store)
    protection_status = "active" if bool(verification.get("safe")) else "paired_not_protected"
    protection_reason = None
    verification_block = verification.get("verification")
    if isinstance(verification_block, dict):
        warnings = verification_block.get("warnings")
        if isinstance(warnings, list) and warnings:
            protection_reason = str(warnings[0])

    sync_url = _oauth_sync_url_from_issuer(oauth_client.issuer)
    return _sanitize_remote_pair_payload(
        {
            "status": "connected",
            "pairing": "connected",
            "connect_mode": "remote_pairing",
            "intent_id": claim_payload.get("intentId"),
            "runtime": runtime,
            "runtime_label": resolved_label,
            "machine_id": token_result.machine_id or installation_id,
            "workspace_id": token_result.workspace_id,
            "grant_id": token_result.grant_id,
            "protection": protection_status,
            "protection_reason": protection_reason,
            "no_root": no_root,
            "connect_url": normalized_connect_url,
            "sync_url": sync_url,
            "remote_pair_command": REMOTE_PAIR_COMMAND,
            "remote_pair_status_command": REMOTE_PAIR_STATUS_COMMAND,
            "connect_status_command": CONNECT_STATUS_COMMAND,
            "connect_repair_command": CONNECT_REPAIR_COMMAND,
            "managed_install": install_payload.get("managed_install"),
            "managed_installs": install_payload.get("managed_installs"),
            "completed_at": timestamp,
        }
    )


def dispatch_guard_remote_pair_command(
    *,
    args: object,
    store: GuardStore,
    context: HarnessContext,
    emit: Callable[[str, dict[str, object], bool], None],
    finalize_connect_payload: Callable[..., dict[str, object]],
    now: str,
) -> int:
    if getattr(args, "remote_pair_command", None) == "status":
        payload = build_remote_pair_status_payload(store=store, context=context)
        emit("remote-pair", payload, bool(getattr(args, "json", False)))
        return 0

    runtime = getattr(args, "runtime", None)
    pair_code = getattr(args, "pair_code", None)
    if not isinstance(runtime, str) or not runtime.strip():
        print("remote-pair requires --runtime openclaw|hermes.", file=sys.stderr)
        return 2
    if not isinstance(pair_code, str) or not pair_code.strip():
        print("remote-pair requires --pair-code.", file=sys.stderr)
        return 2

    try:
        payload = run_guard_remote_pair_command(
            store=store,
            context=context,
            connect_url=str(getattr(args, "connect_url", DEFAULT_GUARD_CONNECT_URL)),
            runtime=runtime.strip(),
            pair_code=pair_code,
            label=getattr(args, "label", None),
            no_root=bool(getattr(args, "no_root", False)),
            now=now,
        )
    except ValueError as error:
        print(redact_remote_pairing_text(str(error)), file=sys.stderr)
        return 2
    except RuntimeError as error:
        print(redact_remote_pairing_text(str(error)), file=sys.stderr)
        return 1

    if bool(getattr(args, "verify", False)):
        payload = finalize_connect_payload(
            store=store,
            connect_url=str(getattr(args, "connect_url", DEFAULT_GUARD_CONNECT_URL)),
            payload=payload,
            now=now,
        )
    emit("remote-pair", payload, bool(getattr(args, "json", False)))
    return 0


__all__ = [
    "REMOTE_PAIR_COMMAND",
    "REMOTE_PAIR_STATUS_COMMAND",
    "build_remote_pair_status_payload",
    "claim_remote_pairing_intent",
    "dispatch_guard_remote_pair_command",
    "is_remote_pairing_code_shape",
    "normalize_remote_pairing_code",
    "redact_remote_pairing_text",
    "remote_pairing_claim_url",
    "run_guard_remote_pair_command",
]
