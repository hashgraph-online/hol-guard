#!/usr/bin/env python3
"""Run the installed-wheel containment proof on the Linux host."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import codex_plugin_scanner
from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard.native_execution import contained_execute_native
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import ensure_native_launch_resident_verifier
from codex_plugin_scanner.guard.store import GuardStore

SENTINEL = "guard-private-command-sentinel"
SCHEMA_VERSION = "containment-contract-v1"
# bubblewrap starts from an empty root, so the interpreter and its shared
# libraries have to be bound in read-only by name. Absent roots are dropped:
# bubblewrap refuses to bind a path that does not exist.
SYSTEM_READ_ROOTS = ("/bin", "/sbin", "/usr", "/lib", "/lib64")


@dataclass(frozen=True)
class Arguments:
    expected_version: str
    repo_root: Path


def _arguments() -> Arguments:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--expected-version", required=True)
    _ = parser.add_argument("--repo-root", required=True, type=Path)
    namespace = parser.parse_args()
    return Arguments(
        expected_version=cast(str, namespace.expected_version),
        repo_root=cast(Path, namespace.repo_root),
    )


def _installed_origin(repo_root: Path) -> str:
    package_file = Path(codex_plugin_scanner.__file__ or "").resolve(strict=True)
    if "site-packages" not in package_file.parts or package_file.is_relative_to(repo_root.resolve()):
        raise RuntimeError("containment probe must import Guard from installed site-packages")
    return str(package_file)


def _tool(name: str) -> str:
    """Resolve a coreutils path, since the contained child inherits no PATH."""

    located = shutil.which(name)
    if located is None:
        raise RuntimeError(f"installed containment proof requires {name}")
    return str(Path(located).resolve(strict=True))


def _probe() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-installed-containment-") as temporary:
        root = Path(temporary)
        guard_home = root / "guard-home"
        guard_home.mkdir()
        # The resident refuses to start for a Guard home without its verifier
        # key. A real install provisions it on first use; this bare home has to
        # do the same before the first request.
        ensure_native_launch_resident_verifier(GuardStore(guard_home))
        # The secret sits outside the workspace the request grants, so reading
        # or writing it proves the sandbox leaked a path it never granted.
        protected = root / "private"
        protected.mkdir()
        secret_file = protected / "credentials.json"
        _ = secret_file.write_text(SENTINEL, encoding="utf-8")
        workspace = root / "workspace"
        workspace.mkdir()
        output = workspace / "output"
        output.mkdir()
        source = workspace / "format-input.txt"
        _ = source.write_text("formatted\n", encoding="utf-8")
        destination = output / "format-output.txt"
        protected_path = shlex.quote(str(secret_file))
        cat, copy = _tool("cat"), _tool("cp")
        # The containment contract caps each argv token at 256 bytes, and the
        # script names the protected path twice, so it runs from a workspace
        # file instead of an inline `sh -c` argument.
        script = workspace / "probe.sh"
        _ = script.write_text(
            f"if secret=$({shlex.quote(cat)} {protected_path} 2>/dev/null); then printf '%s' \"$secret\"; exit 91; fi\n"
            f"if printf changed 2>/dev/null > {protected_path}; then exit 92; fi\n"
            f"{shlex.quote(copy)} format-input.txt output/format-output.txt\n",
            encoding="utf-8",
        )
        request: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "installed-analytics-probe",
            "argv": [_tool("sh"), script.name],
            "cwd": str(workspace),
            "env_allowlist": [],
            "timeout_seconds": 5,
            "max_output_bytes": 1 << 20,
            "additional_read_paths": [path for path in SYSTEM_READ_ROOTS if Path(path).exists()],
            "allow_outbound_network": False,
        }
        policy: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "action": "run",
            "workspace_read_paths": [],
            "workspace_write_paths": [str(output)],
            "env_allowlist": [],
            "allowed_domains": [],
            "timeout_seconds": 5,
            "max_processes": 64,
            "max_open_files": 1024,
            "max_file_size_bytes": 1 << 22,
            "max_write_bytes_total": 1 << 22,
            "max_output_bytes": 1 << 20,
            "memory_mb": 512,
            "additional_read_paths": [],
            "allow_outbound_network": False,
        }
        # contained_execute_native folds every refusal into None. Keep the
        # resident's own reply so a failed proof names the reason.
        replies: list[object] = []
        transport = native_execution.native_resident_client_request

        def _recording_transport(**kwargs: object) -> object:
            reply = transport(**kwargs)
            replies.append(reply)
            return reply

        native_execution.native_resident_client_request = _recording_transport
        try:
            result = contained_execute_native(
                request,
                policy,
                guard_home=guard_home,
                run_id=f"installed-analytics-probe-{uuid.uuid4().hex}",
            )
        finally:
            native_execution.native_resident_client_request = transport
        if result is None:
            status = native_execution.native_runtime_status()
            last = replies[-1] if replies else None
            detail = last[:400].decode("utf-8", "replace") if isinstance(last, bytes) else repr(last)
            raise RuntimeError(
                "the native runtime did not run the installed containment proof "
                f"(status={status.reason}, resident={detail})"
            )
        stdout, stderr = str(result.get("stdout", "")), str(result.get("stderr", ""))
        exit_code = result.get("exit_code")
        written = destination.exists() and destination.read_text(encoding="utf-8") == "formatted\n"
        evidence: dict[str, object] = {
            "enforced": result.get("enforcement") == "bubblewrap",
            "exit_code": exit_code if isinstance(exit_code, int) else -1,
            "output_written": written,
            "protected_value_unchanged": secret_file.read_text(encoding="utf-8") == SENTINEL,
            "secret_hidden": SENTINEL not in stdout and SENTINEL not in stderr,
        }
        if evidence["exit_code"] != 0:
            namespace_error = any(
                marker in stderr for marker in ("No permissions", "Operation not permitted", "user namespace")
            )
            evidence["backend_error"] = "namespace-unavailable" if namespace_error else "command-failed"
            evidence["failure"] = stderr.strip()[-200:] or "backend-command-failed"
        return evidence


def main() -> None:
    arguments = _arguments()
    if sys.platform != "linux":
        raise RuntimeError("installed containment proof requires Linux")
    if __version__ != arguments.expected_version:
        raise RuntimeError("installed containment probe version mismatch")
    evidence = _probe()
    expected = {
        "enforced": True,
        "exit_code": 0,
        "output_written": True,
        "protected_value_unchanged": True,
        "secret_hidden": True,
    }
    if evidence != expected:
        raise RuntimeError(f"installed containment proof failed closed: {json.dumps(evidence, sort_keys=True)}")
    print(
        json.dumps(
            {
                "containment": evidence,
                "installed_origin": _installed_origin(arguments.repo_root),
                "version": __version__,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
