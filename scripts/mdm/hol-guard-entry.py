"""PyInstaller entrypoint for the machine-owned HOL Guard runtime."""

from __future__ import annotations

import ast
import hashlib
import hmac
import http.client
import io
import json
import os
import secrets
import stat
import subprocess
import sys
import time
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
        candidates.append(Path(__file__).resolve().parents[2] / "src" / "codex_plugin_scanner" / "version.py")
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


_CODEX_BRIDGE_ARG = "--_hol-guard-codex-bridge"
_CODEX_HOOK_MAX_INPUT_BYTES = 1_000_000
_CODEX_HOOK_TIMEOUT_GRACE_SECONDS = 2
_CODEX_MAX_APPROVAL_WAIT_TIMEOUT_SECONDS = 600
_CODEX_MAX_DAEMON_RESPONSE_BYTES = 1_000_000
_CODEX_CHALLENGE_TTL_MS = 5_000
_CODEX_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_CODEX_WAIT_PROCESS_KEY = "guard_codex_browser_wait_process"
_CODEX_WAIT_TIMEOUT_KEY = "guard_codex_browser_wait_timeout_seconds"
_CODEX_TRUSTED_PS_PATHS = ("/bin/ps", "/usr/bin/ps")
_CODEX_DISCOVERY_PROTOCOL_VERSION = 1


def _codex_bridge_request_config() -> dict[str, object] | None:
    """Parse the managed bridge argv contract without importing Guard."""

    if len(sys.argv) != 3 or sys.argv[1] != _CODEX_BRIDGE_ARG:
        return None
    try:
        payload = json.loads(sys.argv[2])
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    state_path = payload.get("state_path")
    query = payload.get("query")
    hook_timeouts = payload.get("hook_timeouts")
    if (
        not isinstance(state_path, str)
        or not state_path
        or not isinstance(query, str)
        or not isinstance(hook_timeouts, dict)
    ):
        return None
    timeouts = {
        key: value
        for key, value in hook_timeouts.items()
        if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool) and value > 0
    }
    if not timeouts:
        return None
    return {"state_path": state_path, "query": query, "hook_timeouts": timeouts}


def _codex_hook_event_name(payload: object) -> str:
    if not isinstance(payload, dict):
        return "PreToolUse"
    value = payload.get("hook_event_name", payload.get("event", "PreToolUse"))
    return value.strip() if isinstance(value, str) and value.strip() else "PreToolUse"


def _codex_process_start_token(pid: int) -> str | None:
    """Mirror live_process_identity.process_start_token without importing Guard."""

    if os.name == "nt":
        return None
    try:
        raw = os.path.join("/proc", str(pid), "stat")
        with open(raw, encoding="ascii") as handle:
            value = handle.read(4096)
        _name, separator, suffix = value.rpartition(")")
        if separator:
            fields = suffix.split()
            if len(fields) > 19 and fields[19].isdigit():
                return f"linux:{fields[19]}"
    except (OSError, UnicodeError):
        pass
    for raw_path in _CODEX_TRUSTED_PS_PATHS:
        candidate = Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            continue
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            continue
        try:
            result = subprocess.run(
                [str(resolved), "-p", str(pid), "-o", "lstart="],
                check=False,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C"},
                text=True,
                timeout=0.5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        started_at = result.stdout.strip()
        return f"posix:{started_at}" if result.returncode == 0 and started_at else None
    return None


def _codex_hint_hook_data(data: str, *, event_name: str, deadline: float) -> str:
    """Attach the wait-process identity and remaining budget the daemon expects."""

    try:
        payload = json.loads(data)
    except ValueError:
        return data
    if not isinstance(payload, dict):
        return data
    payload["guard_remaining_ms"] = min(60_000, max(1, int((deadline - time.monotonic()) * 1000)))
    if event_name == "PreToolUse":
        start_token = _codex_process_start_token(os.getpid())
        if start_token is None:
            payload.pop(_CODEX_WAIT_PROCESS_KEY, None)
            payload.pop(_CODEX_WAIT_TIMEOUT_KEY, None)
        else:
            payload[_CODEX_WAIT_PROCESS_KEY] = {"pid": os.getpid(), "startToken": start_token}
            payload[_CODEX_WAIT_TIMEOUT_KEY] = min(
                _CODEX_MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
                max(1, int(deadline - time.monotonic())),
            )
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _codex_daemon_identity(state_path: str) -> tuple[dict[str, object], str, str] | None:
    """Load the signed daemon state, discovery key, and auth token."""

    path = Path(state_path)
    guard_home = path.parent
    try:
        home_metadata = guard_home.lstat()
    except OSError:
        return None
    if os.name != "nt" and (
        stat.S_ISLNK(home_metadata.st_mode)
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
        or stat.S_IMODE(home_metadata.st_mode) & 0o077
    ):
        return None
    state_text = _private_file_text(path, root=guard_home, max_bytes=_BOOTSTRAP_STATE_MAX_BYTES)
    discovery_key = _private_file_text(guard_home / "daemon-discovery-key", root=guard_home, max_bytes=256)
    token = _private_file_text(guard_home / "daemon-auth-token", root=guard_home, max_bytes=_BOOTSTRAP_TOKEN_MAX_BYTES)
    if state_text is None or discovery_key is None or token is None:
        return None
    discovery_key = discovery_key.strip().lower()
    token = token.strip()
    try:
        state = json.loads(state_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(state, dict) or not _daemon_state_is_authentic(state, discovery_key):
        return None
    host = state.get("host")
    port = state.get("port")
    if (
        not isinstance(host, str)
        or host.lower() not in _CODEX_LOOPBACK_HOSTS
        or type(port) is not int
        or not 0 < port <= 65535
        or type(state.get("pid")) is not int
        or not isinstance(state.get("state_id"), str)
        or not state.get("state_id")
        or not isinstance(state.get("started_at"), str)
        or not state.get("started_at")
        or not isinstance(state.get("auth_token_id"), str)
    ):
        return None
    try:
        if str(Path(state["guard_home"]).resolve()) != str(guard_home.resolve()):
            return None
        unsigned_token = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if not secrets.compare_digest(unsigned_token, state["auth_token_id"]):
            return None
    except (KeyError, OSError, RuntimeError, TypeError):
        return None
    return state, discovery_key, token


def _codex_daemon_identity_tuple(state: dict[str, object]) -> tuple[object, ...]:
    return tuple(state.get(field) for field in ("state_id", "auth_token_id", "host", "port", "pid", "started_at"))


def _codex_daemon_challenge_proof(
    challenge: dict[str, object],
    *,
    state: dict[str, object],
    discovery_key: str,
    nonce: str,
    hook_event: str,
) -> str | None:
    """Verify the daemon's challenge response exactly like the managed bridge."""

    proof = challenge.get("proof")
    unsigned = {key: value for key, value in challenge.items() if key != "proof"}
    expected_fields = {
        "protocol_version": _CODEX_DISCOVERY_PROTOCOL_VERSION,
        "nonce": nonce,
        "state_id": state.get("state_id"),
        "host": state.get("host"),
        "port": state.get("port"),
        "pid": state.get("pid"),
        "started_at": state.get("started_at"),
        "guard_home": state.get("guard_home"),
        "hook_event": hook_event,
    }
    if any(unsigned.get(key) != value for key, value in expected_fields.items()):
        return None
    issued_at_ms = unsigned.get("issued_at_ms")
    expires_at_ms = unsigned.get("expires_at_ms")
    now_ms = int(time.time() * 1000)
    if (
        type(issued_at_ms) is not int
        or type(expires_at_ms) is not int
        or issued_at_ms > now_ms + 1000
        or expires_at_ms < now_ms
        or expires_at_ms - issued_at_ms > _CODEX_CHALLENGE_TTL_MS
    ):
        return None
    try:
        key = bytes.fromhex(discovery_key)
    except ValueError:
        return None
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    expected_proof = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return proof if isinstance(proof, str) and secrets.compare_digest(proof, expected_proof) else None


def _codex_daemon_hook_request(
    *,
    state_path: str,
    identity: tuple[dict[str, object], str, str],
    query: str,
    data: str,
    event_name: str,
    deadline: float,
) -> dict[str, object] | None:
    """Run one authenticated hook round-trip against the resident daemon."""

    state, discovery_key, token = identity
    host = str(state["host"])
    port = state["port"]
    if not isinstance(port, int) or isinstance(port, bool):
        return None
    nonce = secrets.token_hex(32)
    connection = http.client.HTTPConnection(host, port, timeout=max(0.5, deadline - time.monotonic()))
    try:
        connection.request(
            "POST",
            "/v1/daemon/identity-challenge",
            body=json.dumps(
                {
                    "protocol_version": _CODEX_DISCOVERY_PROTOCOL_VERSION,
                    "nonce": nonce,
                    "state_id": state["state_id"],
                    "hook_event": event_name,
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "Connection": "keep-alive"},
        )
        challenge_response = connection.getresponse()
        if challenge_response.status != 200:
            return None
        challenge_body = challenge_response.read(_CODEX_MAX_DAEMON_RESPONSE_BYTES + 1)
        if len(challenge_body) > _CODEX_MAX_DAEMON_RESPONSE_BYTES:
            return None
        try:
            challenge = json.loads(challenge_body.decode("utf-8", errors="replace").strip())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(challenge, dict):
            return None
        proof = _codex_daemon_challenge_proof(
            challenge,
            state=state,
            discovery_key=discovery_key,
            nonce=nonce,
            hook_event=event_name,
        )
        if proof is None:
            return None
        refreshed = _codex_daemon_identity(state_path)
        if (
            refreshed is None
            or _codex_daemon_identity_tuple(refreshed[0]) != _codex_daemon_identity_tuple(state)
            or not secrets.compare_digest(refreshed[1], discovery_key)
        ):
            return None
        remaining = deadline - time.monotonic()
        if remaining < 0.01:
            return None
        connection.timeout = remaining
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        hinted_data = _codex_hint_hook_data(data, event_name=event_name, deadline=deadline)
        connection.request(
            "POST",
            f"/v1/hooks/codex?{query}",
            body=hinted_data.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Connection": "close",
                "X-Guard-Token": token,
                "X-Guard-Daemon-Nonce": nonce,
                "X-Guard-Daemon-Proof": proof,
            },
        )
        hook_response = connection.getresponse()
        body = hook_response.read(_CODEX_MAX_DAEMON_RESPONSE_BYTES + 1)
        if len(body) > _CODEX_MAX_DAEMON_RESPONSE_BYTES or hook_response.status != 200:
            return None
        try:
            payload = json.loads(body.decode("utf-8", errors="replace").strip())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None
    finally:
        connection.close()


def _codex_normalize_hook_response(response: dict[str, object], *, event_name: str) -> dict[str, object]:
    """Apply the same Codex schema normalization as the managed bridge."""

    universal_keys = {"continue", "stopReason", "suppressOutput", "systemMessage"}
    event_keys = {
        "PostToolUse": {"decision", "reason"},
    }.get(event_name, set())
    allowed_keys = universal_keys | event_keys | {"hookSpecificOutput"}
    filtered = {key: value for key, value in response.items() if key in allowed_keys}
    hook_output = filtered.get("hookSpecificOutput")
    if event_name == "PostToolUse":
        if not isinstance(hook_output, dict):
            filtered.pop("hookSpecificOutput", None)
        else:
            post_tool_keys = {"hookEventName", "additionalContext", "updatedMCPToolOutput"}
            filtered["hookSpecificOutput"] = {key: value for key, value in hook_output.items() if key in post_tool_keys}
        return filtered
    if event_name == "PreToolUse" and "hookSpecificOutput" in filtered:
        cleaned: dict[str, object] = {"hookEventName": event_name}
        if isinstance(hook_output, dict):
            decision = hook_output.get("permissionDecision")
            normalized = decision.strip().lower() if isinstance(decision, str) else ""
            reason = hook_output.get("permissionDecisionReason")
            if normalized in {"deny", "ask"}:
                cleaned["permissionDecision"] = normalized
                if isinstance(reason, str) and reason:
                    cleaned["permissionDecisionReason"] = reason
            elif normalized == "allow":
                if (
                    response.get("policy_action") == "warn"
                    and isinstance(reason, str)
                    and reason.strip()
                    and not filtered.get("systemMessage")
                ):
                    filtered["systemMessage"] = reason
        filtered["hookSpecificOutput"] = cleaned
    return filtered


def _codex_daemon_worker_failed(response: dict[str, object]) -> bool:
    reason_code = response.get("reason_code")
    return isinstance(reason_code, str) and reason_code.startswith("daemon_hook_process_")


def _try_codex_daemon_bridge() -> bool:
    """Answer a managed Codex hook from the running daemon before frozen imports.

    Codex launches this binary for every managed hook event. The full bridge
    path first installs the frozen runtime, which extracts and dlopens the
    whole bundled graph on every invocation; under load that alone exceeds
    short hook budgets and failed invocations leave orphaned extraction dirs
    that further slow later launches. When the resident daemon is reachable,
    the hook needs only its authenticated loopback round-trip, so this path
    performs it with stdlib modules only. Any failure or malformed contract
    falls through to the existing bridge, which keeps the fallback and
    recovery semantics unchanged.
    """

    config = _codex_bridge_request_config()
    if config is None:
        return False
    try:
        raw_stdin = sys.stdin.buffer.read(_CODEX_HOOK_MAX_INPUT_BYTES + 1)
    except (AttributeError, OSError, ValueError):
        return False
    try:
        data = raw_stdin.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if len(data.encode("utf-8")) > _CODEX_HOOK_MAX_INPUT_BYTES:
        return False
    # Replay stdin so a fall-through keeps the managed bridge's input intact.
    sys.stdin = io.StringIO(data)
    try:
        payload = json.loads(data)
    except (ValueError, json.JSONDecodeError):
        return False
    event_name = _codex_hook_event_name(payload)
    hook_timeouts = config["hook_timeouts"]
    assert isinstance(hook_timeouts, dict)
    timeout = hook_timeouts.get(event_name, min(hook_timeouts.values()))
    deadline = time.monotonic() + max(1.0, float(timeout) - _CODEX_HOOK_TIMEOUT_GRACE_SECONDS)
    identity = _codex_daemon_identity(str(config["state_path"]))
    if identity is None:
        return False
    try:
        response = _codex_daemon_hook_request(
            state_path=str(config["state_path"]),
            identity=identity,
            query=str(config["query"]),
            data=data,
            event_name=event_name,
            deadline=deadline,
        )
    except (OSError, ValueError, http.client.HTTPException, TimeoutError):
        return False
    if response is None or _codex_daemon_worker_failed(response):
        return False
    sys.stdout.write(
        json.dumps(
            _codex_normalize_hook_response(response, event_name=event_name),
            separators=(",", ":"),
        )
    )
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
    if _try_codex_daemon_bridge():
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
