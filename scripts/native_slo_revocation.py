"""Withdraw accepted authority in a private fixture and witness native rejection.

This is a filesystem authority-withdrawal fault, not a new administrative
revocation API. Publication is stopped first. The old in-memory generation must
be rejected by the running native authority after its accepted record is removed.
The fixture never removes a generation floor from a user's installation.
"""

from __future__ import annotations

import json
import stat
import time
from typing import Any


def revoke_acknowledged_authority(session: Any) -> dict[str, bool]:
    from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope
    from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        _RUST_SNAPSHOT_STATE_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )
    from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
    from codex_plugin_scanner.guard.native_runtime import _isolated_environment, native_runtime_status
    from scripts.native_benchmark_oracle import synthetic_payload

    root = session.root.resolve()
    home = session.guard_home.resolve()
    if home == root or not home.is_relative_to(root):
        raise RuntimeError("revocation fixture requires a private child home")
    authority = home / NATIVE_RUNTIME_STATE_DIRECTORY / _RUST_SNAPSHOT_STATE_NAME
    if authority.parent.is_symlink() or authority.is_symlink() or not stat.S_ISREG(authority.lstat().st_mode):
        raise RuntimeError("revocation fixture authority is not a regular private file")
    worker = session.daemon._server.hook_worker
    publisher = worker.policy_snapshot_publisher
    binding = acked_snapshot_binding_for_store(session.store)
    status = native_runtime_status()
    if binding is None or not publisher.is_ready() or status.identity is None:
        raise RuntimeError("revocation fixture requires acknowledged native authority")
    encoded = _encode_hook_envelope(
        payload=synthetic_payload(0),
        harness="claude-code",
        event="PostToolUse",
        guard_home=home,
        home_dir=root,
        cwd=session.workspace,
        source_ref_external_allowed=False,
        deadline_budget_ms=1000,
        snapshot=binding,
    )
    if encoded is None:
        raise RuntimeError("revocation probe envelope unavailable")
    publisher.close()
    if not publisher.closed or (publisher._thread is not None and publisher._thread.is_alive()):
        raise RuntimeError("revocation fixture could not suspend publication")
    # Keep the old private bytes for disposable fixture cleanup. Do not rewrite
    # them, manufacture an unauthenticated lower generation, or restart a daemon.
    retired = authority.with_name(authority.name + ".revoked-fixture")
    if retired.exists() or retired.is_symlink():
        raise RuntimeError("revocation fixture destination already exists")
    authority.rename(retired)
    if acked_snapshot_binding_for_store(session.store) is not None:
        raise RuntimeError("withdrawn resident authority remained acknowledged")
    rejected = native_resident_client_request(
        executable=status.identity.path,
        guard_home=home,
        environment=_isolated_environment(),
        payload=encoded,
        raw_hook_envelope=True,
        deadline_monotonic=time.monotonic() + 1.0,
    )
    response = json.loads(rejected) if rejected else None
    if not isinstance(response, dict) or response.get("error") != "native_policy_snapshot_context_mismatch":
        raise RuntimeError("resident did not reject the withdrawn generation")
    prepared = worker.prepare_workspace_policy(session.workspace, deadline=time.monotonic() + 0.4)
    if prepared is not None:
        raise RuntimeError("withdrawn generation passed the hook readiness barrier")
    return {"revoked_generation": True, "policy_prepare_rejected": True, "refresh_suspended": True}
