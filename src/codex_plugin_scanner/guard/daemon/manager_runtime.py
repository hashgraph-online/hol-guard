"""Guard daemon runtime helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def _guard_daemon_state_matches_current_runtime(payload: dict[str, object]) -> bool:
    from .runtime_peer import daemon_state_matches_current_runtime

    return daemon_state_matches_current_runtime(payload)


def _current_guard_daemon_source_root() -> str:
    return str(_manager.Path(_manager.__file__).resolve().parents[3])


def _runtime_identity_paths(source_root: _manager.Path) -> list[_manager.Path]:
    package_root = source_root / "codex_plugin_scanner"
    static_root = package_root / "guard" / "daemon" / "static"
    paths = [*package_root.rglob("*.py")]
    if static_root.is_dir():
        paths.extend(path for path in static_root.rglob("*") if path.is_file())
    return paths


def _runtime_tree_signature(source_root: _manager.Path, paths: list[_manager.Path]) -> str:
    digest = _manager.hashlib.sha256()
    digest.update(_manager.__version__.encode("utf-8"))
    for path in sorted(paths):
        try:
            stat_result = path.stat()
        except OSError:
            continue
        digest.update(str(path.relative_to(source_root)).encode("utf-8"))
        digest.update(str(stat_result.st_size).encode("utf-8"))
        digest.update(str(stat_result.st_mtime_ns).encode("utf-8"))
    return digest.hexdigest()


def _hash_runtime_contents(source_root: _manager.Path, paths: list[_manager.Path]) -> str:
    digest = _manager.hashlib.sha256()
    digest.update(_manager.__version__.encode("utf-8"))
    for path in sorted(paths):
        try:
            stat_result = path.stat()
        except OSError:
            continue
        digest.update(str(path.relative_to(source_root)).encode("utf-8"))
        digest.update(str(stat_result.st_size).encode("utf-8"))
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(65536):
                    digest.update(chunk)
        except OSError:
            continue
    return digest.hexdigest()


def _runtime_fingerprint_cache_path(source_root: _manager.Path) -> _manager.Path:
    digest = _manager.hashlib.sha256(_manager.os.fsencode(str(source_root))).hexdigest()
    return _manager.Path.home() / ".hol-guard" / "runtime-fingerprint-cache" / f"{digest}.json"


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _manager._RUNTIME_FINGERPRINT_HEX_LENGTH
        and not set(value) - set("0123456789abcdef")
    )


def _load_runtime_fingerprint_cache(source_root: _manager.Path, tree_sig: str) -> str | None:
    raw_payload = _manager.read_private_regular_text(
        _manager._runtime_fingerprint_cache_path(source_root),
        max_bytes=_manager._RUNTIME_FINGERPRINT_CACHE_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = _manager.json.loads(raw_payload)
    except _manager.json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("source_root") != str(source_root):
        return None
    cached_tree_sig = payload.get("tree_sig")
    cached_fingerprint = payload.get("content_fingerprint")
    if cached_tree_sig != tree_sig or not isinstance(cached_fingerprint, str):
        return None
    if not _manager._is_sha256_hex(cached_fingerprint):
        return None
    return cached_fingerprint


def _store_runtime_fingerprint_cache(source_root: _manager.Path, tree_sig: str, fingerprint: str) -> None:
    cache_path = _manager._runtime_fingerprint_cache_path(source_root)
    try:
        _manager._ensure_private_directory(cache_path.parent)
        _manager._write_private_atomic_text(
            cache_path,
            _manager.json.dumps(
                {
                    "content_fingerprint": fingerprint,
                    "source_root": str(source_root),
                    "tree_sig": tree_sig,
                },
                sort_keys=True,
            ),
        )
    except (OSError, RuntimeError, ValueError):
        return


def _current_guard_daemon_runtime_fingerprint() -> str:
    if _manager._runtime_fingerprint_cache is not None:
        return _manager._runtime_fingerprint_cache[1]
    source_root = _manager.Path(_manager._current_guard_daemon_source_root())
    paths = _manager._runtime_identity_paths(source_root)
    tree_sig = _manager._runtime_tree_signature(source_root, paths)
    cached = _manager._load_runtime_fingerprint_cache(source_root, tree_sig)
    if cached is not None:
        _manager._runtime_fingerprint_cache = (tree_sig, cached)
        return cached
    fingerprint = _manager._hash_runtime_contents(source_root, paths)
    _manager._store_runtime_fingerprint_cache(source_root, tree_sig, fingerprint)
    _manager._runtime_fingerprint_cache = (tree_sig, fingerprint)
    return fingerprint


def current_guard_daemon_runtime_fingerprint() -> str:
    """Return the installed runtime identity used for daemon compatibility."""

    return _manager._current_guard_daemon_runtime_fingerprint()


def _configured_port(guard_home: _manager.Path) -> int | None:
    raw_port = _manager.os.environ.get("GUARD_DAEMON_PORT")
    if raw_port is None or not raw_port.strip():
        return _manager._stable_port_for_guard_home(guard_home)
    try:
        port = int(raw_port)
    except ValueError:
        return _manager._stable_port_for_guard_home(guard_home)
    return port if port > 0 else _manager._stable_port_for_guard_home(guard_home)


def _stable_port_for_guard_home(guard_home: _manager.Path) -> int:
    encoded_path = str(guard_home.resolve()).encode("utf-8")
    digest = _manager.hashlib.sha256(encoded_path).hexdigest()
    offset = int(digest[:8], 16) % _manager.GUARD_DAEMON_PORT_RANGE
    return _manager.DEFAULT_GUARD_DAEMON_PORT + offset


def _prepend_preferred_port(ports: list[int], preferred_port: int | None) -> list[int]:
    if not isinstance(preferred_port, int) or preferred_port <= 0:
        return ports
    ordered: list[int] = [preferred_port]
    seen = {preferred_port}
    for port in ports:
        if port in seen:
            continue
        seen.add(port)
        ordered.append(port)
    return ordered


def _candidate_ports(guard_home: _manager.Path, *, preferred_port: int | None = None) -> list[int]:
    configured_port = _manager._configured_port(guard_home)
    if configured_port is None:
        return _manager._prepend_preferred_port([], preferred_port)
    raw_port = _manager.os.environ.get("GUARD_DAEMON_PORT")
    if raw_port is not None and raw_port.strip():
        return _manager._prepend_preferred_port([configured_port], preferred_port)
    offset = configured_port - _manager.DEFAULT_GUARD_DAEMON_PORT
    ports: list[int] = []
    for step in range(min(25, _manager.GUARD_DAEMON_PORT_RANGE)):
        candidate_offset = (offset + step) % _manager.GUARD_DAEMON_PORT_RANGE
        ports.append(_manager.DEFAULT_GUARD_DAEMON_PORT + candidate_offset)
    return _manager._prepend_preferred_port(ports, preferred_port)


def _healthz_payload_is_current(raw_payload: str) -> bool:
    payload = _manager.json.loads(raw_payload)
    if not isinstance(payload, dict):
        return False
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != _manager.GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    tables = payload.get("tables")
    if tables is None:
        return True
    if not isinstance(tables, list):
        return False
    table_names = {table for table in tables if isinstance(table, str)}
    return _manager.REQUIRED_DAEMON_TABLES.issubset(table_names)


def _healthz_payload_matches_guard_home(raw_payload: str, guard_home: _manager.Path) -> bool:
    payload = _manager.json.loads(raw_payload)
    if not isinstance(payload, dict):
        return False
    payload_guard_home = payload.get("guard_home")
    if not isinstance(payload_guard_home, str) or not payload_guard_home.strip():
        return False
    try:
        return _manager.Path(payload_guard_home).resolve() == guard_home.resolve()
    except OSError:
        return _manager.Path(payload_guard_home) == guard_home


def _live_or_newer_daemon_url(
    guard_home: _manager.Path, *, executable: _manager.Path | None, preferred_port: int | None
) -> str | None:
    from .runtime_peer import live_or_newer_daemon_url as resolve_live

    return resolve_live(
        guard_home, executable=executable, preferred_port=preferred_port, current_version=_manager.__version__
    )
