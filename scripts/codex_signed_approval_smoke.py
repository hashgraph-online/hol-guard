#!/usr/bin/env python3
"""Run one isolated, real Codex package-protection smoke test.

The command intentionally keeps all model output in a disposable directory.  The
summary only reports whether Guard produced a signed review link.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

URL_RE = re.compile(
    r"https?://(?:127\.0\.0\.1|localhost|\[::1\]):\d+/requests/[A-Za-z0-9_.~-]+(?:#[^\s\"'<>]*)?"
)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _open_private_output(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags | no_follow, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "wb")


def _write_private_text(path: Path, value: str) -> None:
    with _open_private_output(path) as output:
        output.write(value.encode("utf-8"))


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        with suppress(OSError, ProcessLookupError):
            process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        with suppress(OSError, ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    if os.name == "nt":
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=2)
        with suppress(OSError, ProcessLookupError):
            if process.poll() is None:
                process.kill()
    else:
        with suppress(OSError, ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    with suppress(OSError, ProcessLookupError, subprocess.TimeoutExpired):
        process.wait(timeout=2)


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    stdout: Path,
    stderr: Path,
    timeout: int,
) -> int:
    if timeout < 0:
        raise ValueError("timeout must be non-negative")
    with _open_private_output(stdout) as out, _open_private_output(stderr) as err:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=out,
            stderr=err,
            start_new_session=os.name != "nt",
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
        )
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            return 124


def _daemon_state(path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _daemon_endpoint(state: dict[str, object] | None) -> tuple[str, int, int] | None:
    if state is None:
        return None
    host = state.get("host")
    port = state.get("port")
    pid = state.get("pid")
    if not isinstance(host, str) or not host.strip():
        return None
    normalized_host = host.strip().lower()
    if normalized_host.startswith("[") and normalized_host.endswith("]"):
        normalized_host = normalized_host[1:-1]
    if normalized_host not in LOOPBACK_HOSTS or type(port) is not int or not 0 < port <= 65535:
        return None
    if type(pid) is not int or pid <= 0:
        return None
    return host, port, pid


def _daemon_is_ready(state: dict[str, object] | None) -> bool:
    endpoint = _daemon_endpoint(state)
    if endpoint is None:
        return False
    host, port, pid = endpoint
    try:
        os.kill(pid, 0)
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except (OSError, ValueError):
        return False


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _existing_root_layout_is_safe(root: Path) -> bool:
    for relative in (
        "home",
        "guard-home",
        "workspace",
        "workspace/fixture-package",
        "workspace/.git",
        "guard-home/config.toml",
        "workspace/fixture-package/package.json",
        "daemon.stderr",
        "last-message.txt",
        "codex.jsonl",
        "codex.stderr",
    ):
        if (root / relative).is_symlink():
            return False
    return True


def _daemon_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _daemon_log_summary(path: Path) -> str:
    value = _text(path).strip().replace("\n", " ")
    value = re.sub(r"guard-token=[^\s\"<>]+", "guard-token=REDACTED", value)
    value = re.sub(r"https?://[^\s\"<>]+", "URL_REDACTED", value)
    return value[-400:]


def _start_owned_daemon(
    *,
    guard: Path,
    home: Path,
    guard_home: Path,
    workspace: Path,
    root: Path,
    timeout: int = 60,
) -> tuple[subprocess.Popen[bytes], dict[str, object]]:
    port = _daemon_port()
    stderr_path = root / "daemon.stderr"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("HOL_GUARD_DESKTOP_NOTIFICATIONS", None)
    with _open_private_output(stderr_path) as stderr:
        process = subprocess.Popen(
            [
                str(guard),
                "daemon",
                "--serve",
                "--guard-home",
                str(guard_home),
                "--home",
                str(home),
                "--port",
                str(port),
            ],
            cwd=workspace,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            start_new_session=True,
        )
    state_path = guard_home / "daemon-state.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = _daemon_state(state_path)
        endpoint = _daemon_endpoint(state)
        if endpoint is not None and endpoint[1] == port and _daemon_is_ready(state):
            return process, state or {}
        if process.poll() is not None:
            detail = _daemon_log_summary(stderr_path)
            raise RuntimeError(f"daemon exited ({process.returncode}); {detail or 'no daemon diagnostics'}")
        time.sleep(0.1)
    detail = _daemon_log_summary(stderr_path)
    _stop_owned_daemon(process)
    raise RuntimeError(f"daemon readiness timeout; {detail or 'no daemon diagnostics'}")


def _stop_owned_daemon(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        with suppress(OSError, ProcessLookupError):
            process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with suppress(OSError, ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(OSError, ProcessLookupError):
            process.kill()
        with suppress(OSError, ProcessLookupError):
            process.wait(timeout=5)


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _urls(text: str) -> list[str]:
    return URL_RE.findall(text)


def _url_summary(url: str) -> tuple[str, bool]:
    parsed = urlsplit(url)
    request_id = parsed.path.rsplit("/", 1)[-1]
    fingerprint = hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:12]
    return fingerprint, bool(parse_qs(parsed.fragment).get("guard-token"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=_non_negative_int, default=180)
    parser.add_argument("--existing-root", help="reuse an existing synthetic smoke root")
    parser.add_argument("--guard-binary", help="installed hol-guard executable to exercise")
    parser.add_argument(
        "--keep-daemon",
        action="store_true",
        help="keep a daemon started by this run for follow-up browser verification",
    )
    parser.add_argument(
        "--artifact-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="prepared installed artifact checkout",
    )
    args = parser.parse_args()

    artifact_root = Path(args.artifact_root).resolve()
    guard = (
        Path(args.guard_binary).expanduser().resolve()
        if args.guard_binary
        else artifact_root / ".approval-venv" / "bin" / "hol-guard"
    )
    if not guard.is_file():
        print("status=blocked reason=installed_artifact_missing")
        return 2
    codex = shutil.which("codex")
    if codex is None:
        print("status=blocked reason=codex_cli_missing")
        return 2

    existing_root = Path(args.existing_root).expanduser() if args.existing_root else None
    if existing_root is not None and existing_root.is_symlink():
        print("status=blocked reason=existing_root_symlinked")
        return 3
    root = (
        existing_root.resolve()
        if existing_root is not None
        else Path(tempfile.mkdtemp(prefix="hol-guard-codex-smoke-"))
    )
    if args.existing_root:
        if not root.is_dir() or not root.name.startswith("hol-guard-codex-smoke-"):
            print("status=blocked reason=existing_root_not_synthetic")
            return 3
        if root.stat().st_mode & 0o077:
            print("status=blocked reason=existing_root_not_private")
            return 3
        if not _existing_root_layout_is_safe(root):
            print("status=blocked reason=existing_root_symlinked")
            return 3
    else:
        root.chmod(0o700)
    home = root / "home"
    guard_home = root / "guard-home"
    workspace = root / "workspace"
    fixture = workspace / "fixture-package"
    for path in (home, guard_home, workspace, fixture):
        _private_dir(path)
    package_json = fixture / "package.json"
    config_path = guard_home / "config.toml"
    if args.existing_root and (package_json.is_symlink() or config_path.is_symlink()):
        print("status=blocked reason=existing_root_symlinked_file")
        return 3
    if not package_json.exists():
        _write_private_text(
            package_json,
            json.dumps(
                {
                    "name": "hol-guard-local-fixture",
                    "version": "1.0.0",
                    "private": True,
                }
            )
            + "\n",
        )
    else:
        package_json.chmod(0o600)
    if not (workspace / ".git").exists():
        if shutil.which("git") is None:
            print("status=blocked reason=git_missing")
            return 2
        try:
            subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
        except FileNotFoundError:
            print("status=blocked reason=git_missing")
            return 2
        except subprocess.CalledProcessError:
            print("status=blocked reason=git_init_failed")
            return 3
    if not config_path.exists():
        _write_private_text(config_path, "desktop_notifications = false\n")
    else:
        config_path.chmod(0o600)

    env = os.environ.copy()
    env["PATH"] = str(guard.parent) + os.pathsep + env.get("PATH", "")
    # Keep normal Codex authentication in its existing location.  --ignore-user-config
    # prevents that location's user configuration from changing this harness run.

    owned_daemon: subprocess.Popen[bytes] | None = None
    daemon_state: dict[str, object] | None
    if args.existing_root:
        daemon_state = _daemon_state(guard_home / "daemon-state.json")
        if not _daemon_is_ready(daemon_state):
            print("status=blocked reason=existing_daemon_not_ready")
            print(f"artifact_root={root}")
            return 3
    else:
        try:
            owned_daemon, daemon_state = _start_owned_daemon(
                guard=guard,
                home=home,
                guard_home=guard_home,
                workspace=workspace,
                root=root,
            )
        except RuntimeError as error:
            print(f"status=blocked reason=daemon_start_failed error={type(error).__name__}")
            print(f"artifact_root={root}")
            return 3
    daemon_endpoint = _daemon_endpoint(daemon_state)
    if daemon_endpoint is None:
        if owned_daemon is not None and not args.keep_daemon:
            _stop_owned_daemon(owned_daemon)
        print("status=blocked reason=daemon_state_invalid")
        print(f"artifact_root={root}")
        return 3
    print(f"daemon_pid={daemon_endpoint[2]}")
    print(f"daemon_port={daemon_endpoint[1]}")

    last_message = root / "last-message.txt"
    codex_json = root / "codex.jsonl"
    codex_err = root / "codex.stderr"
    protect_command = shlex.join(
        [
            str(guard),
            "protect",
            "--home",
            str(home),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--dry-run",
            "npm",
            "install",
            "file:./fixture-package",
        ]
    )
    command = [
        codex,
        "exec",
        "--ignore-user-config",
        "--ephemeral",
        "--sandbox",
        "workspace-write",
        "--add-dir",
        str(root),
        "--json",
        "-c",
        'approval_policy="never"',
        "-c",
        "sandbox_workspace_write.network_access=true",
        "--output-last-message",
        str(last_message),
        "--skip-git-repo-check",
        "-C",
        str(workspace),
        (
            "In this disposable workspace, execute exactly one shell command and do not approve it, retry it, "
            "or run an alternative. Execute this exact command:\n"
            f"{protect_command}\n"
            "The command must remain a dry run. Report the resulting HOL Guard review or block message and any "
            "approval link verbatim in your final response. Do not inspect credentials or unrelated files."
        ),
    ]
    try:
        codex_code = _run(
            command,
            cwd=workspace,
            env=env,
            stdout=codex_json,
            stderr=codex_err,
            timeout=args.timeout,
        )
    finally:
        if owned_daemon is not None and not args.keep_daemon:
            _stop_owned_daemon(owned_daemon)

    sources = {
        "assistant": _text(last_message),
        "codex_json": _text(codex_json),
        "codex_stderr": _text(codex_err),
    }
    found: dict[str, list[str]] = {name: _urls(value) for name, value in sources.items()}
    all_urls = [url for values in found.values() for url in values]
    signed = [url for url in all_urls if _url_summary(url)[1]]
    assistant_urls = found["assistant"]
    assistant_signed = [url for url in assistant_urls if _url_summary(url)[1]]
    assistant_raw = [url for url in assistant_urls if not _url_summary(url)[1]]
    fingerprints = sorted({_url_summary(url)[0] for url in all_urls})
    mutated = any((workspace / name).exists() for name in ("node_modules", "package-lock.json"))
    print(f"codex_exit={codex_code}")
    print("guard_mode=direct_protect_disposable_paths")
    print(f"review_url_seen={bool(all_urls)}")
    print(f"signed_url_seen={bool(signed)}")
    print(f"assistant_signed_url_seen={bool(assistant_signed)}")
    print(f"assistant_raw_url_seen={bool(assistant_raw)}")
    print(f"request_fingerprints={','.join(fingerprints) if fingerprints else 'none'}")
    print(f"workspace_package_mutated={mutated}")
    print(f"artifact_root={root}")
    if codex_code == 0 and assistant_signed and not assistant_raw and not mutated:
        print("status=review_link_captured")
        return 0
    print("status=no_signed_review_link")
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
