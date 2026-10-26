"""Best-effort janitor for guard daemons leaked by ephemeral (test) homes.

Runs on a background thread and never participates in request handling.  State
and collaborators stay owned by ``manager``; every reference resolves through
that module at call time so the manager remains the single patch surface.
"""

from __future__ import annotations

import threading
from pathlib import Path


class _ManagerProxy:
    """Late-bound view of ``manager`` that avoids an import cycle."""

    def __getattr__(self, name: str):
        from . import manager

        return getattr(manager, name)

    def __setattr__(self, name: str, value: object) -> None:
        from . import manager

        setattr(manager, name, value)


m = _ManagerProxy()


def _schedule_stale_ephemeral_guard_daemon_reap(*, exclude_guard_home: Path | None = None) -> None:
    with m._EPHEMERAL_REAP_SCHEDULE_LOCK:
        if m._EPHEMERAL_REAP_IN_FLIGHT is True:
            return
        now = m.time.monotonic()
        last_reap_at = m._LAST_EPHEMERAL_REAP_AT
        if not isinstance(last_reap_at, (int, float)):
            last_reap_at = 0.0
        if now - float(last_reap_at) < m._EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS:
            return
        previous_reap_at = float(last_reap_at)
        m._EPHEMERAL_REAP_IN_FLIGHT = True
        m._LAST_EPHEMERAL_REAP_AT = now

    reaper = m._reap_stale_ephemeral_guard_daemons

    def reap() -> None:
        try:
            reaper(
                exclude_guard_home=exclude_guard_home,
                force=True,
            )
        except Exception:
            # A later interval can retry this best-effort cleanup.
            pass
        finally:
            with m._EPHEMERAL_REAP_SCHEDULE_LOCK:
                m._EPHEMERAL_REAP_IN_FLIGHT = False

    thread = threading.Thread(
        target=reap,
        name="guard-daemon-stale-reaper",
        daemon=True,
    )
    try:
        thread.start()
    except RuntimeError:
        with m._EPHEMERAL_REAP_SCHEDULE_LOCK:
            m._EPHEMERAL_REAP_IN_FLIGHT = False
            m._LAST_EPHEMERAL_REAP_AT = previous_reap_at


def _reap_stale_ephemeral_guard_daemons(
    *,
    exclude_guard_home: Path | None = None,
    force: bool = False,
) -> None:
    now = m.time.monotonic()
    last_reap_at = m._LAST_EPHEMERAL_REAP_AT
    if not isinstance(last_reap_at, (int, float)):
        last_reap_at = 0.0
    if not force and now - float(last_reap_at) < m._EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS:
        return
    if not force:
        m._LAST_EPHEMERAL_REAP_AT = now
    temp_root = Path(m.tempfile.gettempdir())
    candidate_paths = list(m._ephemeral_guard_daemon_state_paths(temp_root))
    exclude_resolved = exclude_guard_home.resolve() if exclude_guard_home is not None else None
    for state_path in candidate_paths[: m._EPHEMERAL_GUARD_DAEMON_MAX_STATES]:
        try:
            m._reap_one_stale_ephemeral_state_file(state_path, exclude_resolved=exclude_resolved)
        except Exception:
            # A missing verdict leaves that home untouched and must not skip
            # the process inventory, which still requires its own inactive verdict.
            continue
    for pid, guard_home, elapsed_seconds in m._running_ephemeral_guard_daemon_processes():
        if elapsed_seconds < m._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
            continue
        try:
            resolved_guard_home = guard_home.resolve()
        except OSError:
            continue
        if exclude_resolved is not None and resolved_guard_home == exclude_resolved:
            continue
        if not m._ephemeral_guard_home_is_inactive(guard_home, fallback_age_seconds=elapsed_seconds):
            continue
        if m._retire_guard_daemon_pid(pid, expected_guard_home=guard_home):
            m.clear_guard_daemon_state(guard_home)


def _reap_one_stale_ephemeral_state_file(state_path: Path, *, exclude_resolved: Path | None) -> None:
    guard_home = state_path.parent
    try:
        resolved_guard_home = guard_home.resolve()
    except OSError:
        return
    if exclude_resolved is not None and resolved_guard_home == exclude_resolved:
        return
    if not m._guard_home_is_ephemeral(resolved_guard_home):
        return
    state_age_seconds = m._state_path_age_seconds(state_path)
    if state_age_seconds < m._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
        return
    payload = m._load_state(guard_home)
    if not m._ephemeral_guard_home_is_inactive(
        guard_home,
        fallback_age_seconds=state_age_seconds,
        state_payload=payload,
    ):
        return
    if not isinstance(payload, dict) or not m._looks_like_guard_daemon_state(payload, guard_home=guard_home):
        return
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return
    # Live daemons are handled by the single bounded process inventory below.
    # Probing every stale state independently creates an unbounded process
    # query fan-out when a temp root contains many prior test runs.
    if not m._guard_daemon_pid_is_running(pid):
        m.clear_guard_daemon_state(guard_home)


def _ephemeral_guard_daemon_state_paths(temp_root: Path) -> list[Path]:
    results: list[Path] = []
    for root in m._pytest_temp_roots(temp_root):
        m._collect_daemon_state_paths(root, results, limit=m._EPHEMERAL_GUARD_DAEMON_MAX_STATES)
        if len(results) >= m._EPHEMERAL_GUARD_DAEMON_MAX_STATES:
            break
    return sorted(results)


def _pytest_temp_roots(temp_root: Path) -> list[Path]:
    roots: list[Path] = []
    try:
        if m._path_name_looks_like_pytest_temp_root(temp_root.name):
            roots.append(temp_root)
        with m.os.scandir(temp_root) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if m._path_name_looks_like_pytest_temp_root(entry.name):
                    roots.append(Path(entry.path))
    except OSError:
        return []
    return sorted(roots)


def _path_name_looks_like_pytest_temp_root(name: str) -> bool:
    return name.startswith("pytest-") or "pytest-of-" in name


def _collect_daemon_state_paths(root: Path, results: list[Path], *, limit: int) -> None:
    pending: list[Path] = [root]
    while pending and len(results) < limit:
        current = pending.pop()
        try:
            with m.os.scandir(current) as entries:
                directories: list[Path] = []
                files: list[Path] = []
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and entry.name == "daemon-state.json":
                        files.append(Path(entry.path))
        except OSError:
            continue
        for path in sorted(files):
            results.append(path)
            if len(results) >= limit:
                return
        pending.extend(reversed(sorted(directories)))


def _state_path_age_seconds(state_path: Path) -> float:
    try:
        return max(0.0, m.time.time() - state_path.stat().st_mtime)
    except OSError:
        return 0.0


def _ephemeral_guard_home_is_inactive(
    guard_home: Path,
    *,
    fallback_age_seconds: float,
    state_payload: dict[str, object] | None = None,
) -> bool:
    payload = state_payload if isinstance(state_payload, dict) else m._load_state(guard_home)
    state = None if not isinstance(payload, dict) else {"pid": m._native_int(payload.get("pid"))}
    query = {"state": state, "fallback_age_seconds": float(fallback_age_seconds)}
    return bool(m._lifecycle("ephemeral_inactive", query, facts_home=guard_home)["inactive"])


def _running_ephemeral_guard_daemon_processes() -> list[tuple[int, Path, float]]:
    if m.os.name == "nt":
        return []
    ps_path = m._trusted_posix_ps_path()
    if ps_path is None:
        return []
    output = m._bounded_process_query_stdout([ps_path, "-axo", "pid=,etime=,command="])
    if output is None:
        return []
    verdict = m._lifecycle("ephemeral_processes", {"ps_output": output})
    if "raises" in verdict:
        raise ValueError("unparseable process elapsed time")
    return [(int(pid), Path(home), float(elapsed)) for pid, home, elapsed in verdict["processes"]]
