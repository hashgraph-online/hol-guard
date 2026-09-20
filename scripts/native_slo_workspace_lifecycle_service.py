"""Replace an actually contained service while retaining its owned home.

This fixture proves two Python service instances in one process. It never
reports a Python process restart or substitutes a resident-only restart.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from scripts.native_slo_workspace_lifecycle_clocks import LifecycleClocks
from scripts.native_slo_workspace_startup import prepare_owned_publisher


def _stopped_thread(thread: Any) -> bool:
    return thread is None or not thread.is_alive()


def require_owned_paths(session: Any, workspaces: tuple[Path, ...]) -> None:
    root = session.root
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or root.resolve(strict=True) != root
        or len(workspaces) not in {1, 10, 100}
        or len(set(workspaces)) != len(workspaces)
        or session.guard_home.parent != root
        or session.guard_home.resolve(strict=True) != session.guard_home
        or any(path.parent != root or path.resolve(strict=True) != path or not path.is_dir() for path in workspaces)
    ):
        raise RuntimeError("workspace lifecycle requires one owned canonical home")


def replace_service(
    session: Any,
    workspaces: tuple[Path, ...],
    *,
    prepare: Callable[[Any], None] | None = None,
    clocks: LifecycleClocks | None = None,
) -> dict[str, object]:
    """Construct the next cold service only after actual old-owner containment."""
    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
    from codex_plugin_scanner.guard.store import GuardStore
    from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
    from scripts.native_slo_command_fixture import verify_empty_command_authority

    require_owned_paths(session, workspaces)
    home = session.guard_home
    before_home = home.stat()
    previous = session.daemon
    publisher = previous._server.hook_worker.policy_snapshot_publisher
    previous_session = previous._server.runtime_session_id
    publisher.close()
    if not publisher.closed or not _stopped_thread(publisher._thread):
        raise RuntimeError("workspace old publisher did not stop")
    if session.stop_resident() is not True:
        raise RuntimeError("workspace resident containment failed before service replacement")
    if session._connection is not None:
        session._connection.close()
        session._connection = None
    previous.stop()
    if not (
        previous._finish_service_completed is True
        and _stopped_thread(previous._thread)
        and previous._owner_lock is None
        and previous._server.active_hook_requests == 0
    ):
        raise RuntimeError("workspace old service containment incomplete")
    # A fresh store and server are essential; changing only the publisher or
    # restarting the Rust resident cannot satisfy the service lifecycle cell.
    if clocks is not None:
        clocks.mark("store_constructor_enter")
    store = GuardStore(home)
    if clocks is not None:
        clocks.mark("store_constructor_return")
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(home)
    verify_empty_command_authority(store)

    def before_start(cold: Any) -> None:
        if cold._workspace_paths or cold.current_snapshot_binding() is not None:
            raise RuntimeError("workspace replacement publisher was not cold before startup")
        if prepare is not None:
            prepare(cold)

    with prepare_owned_publisher(store, before_start) as captured:
        if clocks is not None:
            clocks.mark("server_constructor_enter")
        current = GuardDaemonServer(store, host="127.0.0.1", port=0)
        if clocks is not None:
            clocks.mark("server_constructor_return")
    session.store, session.daemon = store, current
    after_home = home.stat()
    cold = current._server.hook_worker.policy_snapshot_publisher
    if (
        current is previous
        or current._server.runtime_session_id == previous_session
        or cold is publisher
        or cold is not captured[0]
        or (before_home.st_dev, before_home.st_ino) != (after_home.st_dev, after_home.st_ino)
    ):
        raise RuntimeError("workspace replacement was not cold on the same owned home")
    return {
        "scope": "two_python_service_instances_same_process_same_owned_home",
        "python_process_restarted": False,
        "service_instances": 2,
        "old_publisher_stopped": True,
        "old_resident_contained": True,
        "old_service_contained": True,
        "old_owner_lock_released": True,
        "same_owned_home_identity": True,
        "fresh_store_and_service": True,
        "cold_publisher_without_ack": True,
        "cold_observation_boundary": "before_real_constructor_start",
        "empty_command_authority_reloaded": True,
    }


def replace_expired_publisher(session: Any, workspaces: tuple[Path, ...]) -> Any:
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher

    require_owned_paths(session, workspaces)
    worker = session.daemon._server.hook_worker
    previous = worker.policy_snapshot_publisher
    if not previous.closed or not _stopped_thread(previous._thread) or previous.current_snapshot_binding() is not None:
        raise RuntimeError("workspace expiry publisher was not contained")
    current = NativePolicySnapshotPublisher(store=session.store, config_capture=previous.config_capture)
    worker.policy_snapshot_publisher = current
    return current


def register_scopes(publisher: Any, workspaces: tuple[Path, ...]) -> None:
    for workspace in workspaces:
        if publisher.register_workspace(workspace) is not True:
            raise RuntimeError("workspace replacement did not accept every scope")
    if publisher._workspace_paths != set(workspaces) or publisher.current_snapshot_binding() is not None:
        raise RuntimeError("workspace replacement registration or acknowledgment invalid")
