"""PyInstaller entrypoint for the machine-owned HOL Guard runtime."""

from __future__ import annotations

import ast
import hashlib
import hmac
import http.client
import json
import os
import stat
import sys
from multiprocessing import freeze_support
from pathlib import Path

_FROZEN_DAEMON_SERVE_ARG = "--_hol-guard-daemon-serve"


def _packaged_version() -> str:
    """Read the stamped version without importing Guard.

    Desktop's update check runs ``--version`` with a 90s budget. Importing the
    frozen daemon runtime before that probe extracts and loads the whole
    command surface, so the check times out and the current CLI stays in place.
    """

    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if isinstance(meipass, str) and meipass:
        candidates.append(Path(meipass) / "version.py")
    if not getattr(sys, "frozen", False):
        candidates.append(
            Path(__file__).resolve().parents[2] / "src" / "codex_plugin_scanner" / "version.py"
        )
    for path in candidates:
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets):
                continue
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                version = node.value.value.strip()
                if version:
                    return version
    raise SystemExit(1)


def _consume_frozen_daemon_serve_gate() -> bool:
    """Read the parent gate before importing any Guard package code."""

    if len(sys.argv) != 3 or sys.argv[1] != _FROZEN_DAEMON_SERVE_ARG:
        return False
    try:
        payload = json.loads(sys.argv[2])
        if not isinstance(payload, dict) or set(payload) != {"guard_home", "home_dir", "port"}:
            raise ValueError
        guard_home = Path(payload["guard_home"])
        home_dir = Path(payload["home_dir"])
        port = payload["port"]
        if (
            not isinstance(payload["guard_home"], str)
            or not isinstance(payload["home_dir"], str)
            or not guard_home.is_absolute()
            or not home_dir.is_absolute()
            or guard_home != guard_home.resolve(strict=False)
            or home_dir != home_dir.resolve(strict=False)
            or type(port) is not int
            or not 1 <= port <= 65_535
            or Path(sys.argv[0]).expanduser().resolve(strict=True)
            != Path(sys.executable).expanduser().resolve(strict=True)
        ):
            raise ValueError
        gate_stream = getattr(sys.stdin, "buffer", sys.stdin)
        if gate_stream.read(1) != b"1":
            raise SystemExit(70)
    except SystemExit:
        raise
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
        raise SystemExit(70) from None
    return True


_DESKTOP_BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
_BOOTSTRAP_PROXY_TIMEOUT_SECONDS = 5.0
_BOOTSTRAP_STATE_MAX_BYTES = 65_536
_BOOTSTRAP_TOKEN_MAX_BYTES = 4_096
_BOOTSTRAP_BODY_MAX_BYTES = 1_000_000


def _argv_is_desktop_bootstrap() -> bool:
    command = sys.argv[1:]
    return command == ["desktop", "bootstrap"] or command == ["desktop", "bootstrap", "--json"]


def _metadata_is_private_file(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o077


def _private_file_text(path: Path, *, root: Path, max_bytes: int) -> str | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if not _metadata_is_private_file(metadata):
        return None
    try:
        if path.resolve(strict=True).parent != root.resolve(strict=True):
            return None
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not _metadata_is_private_file(opened)
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size > max_bytes
        ):
            return None
        payload = os.read(descriptor, max_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > max_bytes:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _daemon_state_is_authentic(state: dict[str, object], discovery_key: str) -> bool:
    signature = state.get("state_signature")
    if not isinstance(signature, str) or len(discovery_key) != 64:
        return False
    unsigned = {key: value for key, value in state.items() if key != "state_signature"}
    if unsigned.get("discovery_protocol_version") != 1:
        return False
    try:
        key = bytes.fromhex(discovery_key)
    except ValueError:
        return False
    if unsigned.get("discovery_key_id") != hashlib.sha256(key).hexdigest():
        return False
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def _running_desktop_bootstrap_body() -> str | None:
    """Read bootstrap JSON from the loopback daemon without importing Guard."""

    guard_home = Path.home() / ".hol-guard"
    state_text = _private_file_text(
        guard_home / "daemon-state.json",
        root=guard_home,
        max_bytes=_BOOTSTRAP_STATE_MAX_BYTES,
    )
    token = _private_file_text(
        guard_home / "daemon-auth-token",
        root=guard_home,
        max_bytes=_BOOTSTRAP_TOKEN_MAX_BYTES,
    )
    discovery_key = _private_file_text(
        guard_home / "daemon-discovery-key",
        root=guard_home,
        max_bytes=256,
    )
    if state_text is None or token is None or discovery_key is None:
        return None
    token = token.strip()
    discovery_key = discovery_key.strip().lower()
    if not token or "\n" in token or "\r" in token:
        return None
    try:
        state = json.loads(state_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(state, dict) or not _daemon_state_is_authentic(state, discovery_key):
        return None
    if not _daemon_state_matches_this_binary(state):
        return None
    host = state.get("host")
    port = state.get("port")
    if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
        return None
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=_BOOTSTRAP_PROXY_TIMEOUT_SECONDS,
    )
    try:
        connection.request(
            "GET",
            "/v1/desktop/bootstrap",
            headers={"X-Guard-Token": token, "Host": "127.0.0.1"},
        )
        response = connection.getresponse()
        if response.status != 200:
            return None
        body = response.read(_BOOTSTRAP_BODY_MAX_BYTES + 1)
    except (OSError, http.client.HTTPException, TimeoutError, ValueError):
        return None
    finally:
        connection.close()
    if len(body) > _BOOTSTRAP_BODY_MAX_BYTES:
        return None
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or document.get("schema") != _DESKTOP_BOOTSTRAP_SCHEMA:
        return None
    return json.dumps(document, sort_keys=True)


def _running_executable() -> str:
    try:
        return str(Path(sys.executable).resolve(strict=True))
    except OSError:
        return sys.executable


def _daemon_state_matches_this_binary(state: dict[str, object]) -> bool:
    """Proxy only a daemon running this same package and executable.

    The signed state records ``package_version`` and ``executable``. A candidate
    preflight never reaches this check. An older daemon without ``executable``
    falls through so Desktop still runs the binary it selected.
    """

    executable = state.get("executable")
    return (
        state.get("package_version") == _packaged_version()
        and isinstance(executable, str)
        and executable == _running_executable()
    )


def _desktop_preflight_requested() -> bool:
    return os.environ.get("HOL_GUARD_DESKTOP_PREFLIGHT", "").strip().lower() in {"1", "true", "yes"}


def _try_proxy_running_desktop_bootstrap() -> bool:
    """Print a live daemon's bootstrap JSON and skip the frozen runtime import.

    Desktop runs this command on every open. Importing the frozen runtime first
    dlopens the whole native graph, and after a crash that import exceeds
    Desktop's startup budget while the daemon is already serving. Candidate
    preflight must still execute this binary, so that flag falls through.
    Any other failure falls through to the existing command.
    """

    if not _argv_is_desktop_bootstrap() or _desktop_preflight_requested():
        return False
    try:
        body = _running_desktop_bootstrap_body()
    except Exception:
        return False
    if body is None:
        return False
    print(body)
    return True


if __name__ == "__main__":
    # Dispatch PyInstaller multiprocessing children before importing Guard.
    # Otherwise private resource-tracker argv is parsed as a public CLI command.
    freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        print(f"{Path(sys.argv[0]).name} {_packaged_version()}")
        raise SystemExit(0)
    if _try_proxy_running_desktop_bootstrap():
        raise SystemExit(0)

    daemon_gate_released = _consume_frozen_daemon_serve_gate()

    from codex_plugin_scanner.guard.frozen_daemon_runtime import install_frozen_daemon_runtime

    install_frozen_daemon_runtime()

    from codex_plugin_scanner.guard.frozen_codex_runtime import (
        install_frozen_codex_runtime,
        run_frozen_internal_command,
    )

    install_frozen_codex_runtime()
    if daemon_gate_released:
        internal_exit_code = run_frozen_internal_command(gate_already_released=True)
    else:
        internal_exit_code = run_frozen_internal_command()
    if internal_exit_code is not None:
        raise SystemExit(internal_exit_code)

    from codex_plugin_scanner.cli import main

    raise SystemExit(main())
