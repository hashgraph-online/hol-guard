"""Exercise the authenticated recovery HTTP surface without granting shell access."""

from __future__ import annotations

import copy
import secrets
from collections.abc import Callable

from ci.native_runtime.probe_installed_scoped_policy import present, require
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore

_PERMISSION = "command.git.permission.force-push"


def _restricted(payload: dict[str, object]) -> None:
    require(payload.get("health") == "protected", "recovery_authority_not_protected")
    require(payload.get("global_lockdown") is True, "recovery_removed_lockdown")
    controls = payload.get("controls")
    require(
        isinstance(controls, list)
        and {"target": {"kind": "permission", "target_id": _PERMISSION}, "state": "disabled"} in controls,
        "recovery_removed_managed_disable",
    )


def _refused(call: Callable[[], object], status: int, code: str) -> None:
    try:
        call()
    except GuardDaemonRequestError as error:
        require(error.status == status and error.code == code, "recovery_refusal_mismatch")
    else:
        require(False, "recovery_refusal_missing")


def repair_local_authority(daemon: GuardDaemonServer, store: GuardStore, password: str) -> int:
    """Damage only local authentication, then require a fresh protected repair.

    The signed activation is checked byte-for-byte throughout. Native callers
    must separately verify ordinary commands remain blocked after this returns.
    """
    token = present(load_guard_daemon_auth_token(store.guard_home), "recovery_token_missing")
    url = f"http://127.0.0.1:{daemon.port}"
    client = GuardSurfaceDaemonClient(url, token)
    _restricted(client.refresh_extension_controls())
    _refused(
        lambda: client.recover_extension_control_authority({"session_nonce": secrets.token_hex(16)}),
        409,
        "authority_not_recoverable",
    )
    retained = copy.deepcopy(store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY))
    require(retained is not None, "recovery_signed_source_missing")
    with store._extension_control_authority_lock(), store._connect() as connection:
        changed = connection.execute("update extension_control_authority_snapshot set snapshot_mac = 'invalid'")
        require(changed.rowcount == 1, "recovery_tamper_fixture_missing")
    require(client.refresh_extension_controls().get("health") == "tampered", "recovery_tamper_not_detected")
    unauthorized = GuardSurfaceDaemonClient(url, "synthetic-invalid-token")
    _refused(
        lambda: unauthorized.recover_extension_control_authority(
            {"session_nonce": secrets.token_hex(16), "approval_password": password}
        ),
        401,
        "unauthorized",
    )
    _refused(
        lambda: client.recover_extension_control_authority({"session_nonce": secrets.token_hex(16)}),
        403,
        "approval_gate_required",
    )
    require(client.refresh_extension_controls().get("health") == "tampered", "unauthorized_recovery_changed_state")
    require(store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == retained, "recovery_changed_signed_source")
    repaired = client.recover_extension_control_authority(
        {"session_nonce": secrets.token_hex(16), "approval_password": password}
    )
    _restricted(repaired)
    _restricted(client.effective_extension_controls())
    require(store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == retained, "recovery_changed_signed_source")
    revision = repaired.get("revision")
    require(type(revision) is int and revision >= 0, "recovery_revision_missing")
    assert isinstance(revision, int)
    return revision
