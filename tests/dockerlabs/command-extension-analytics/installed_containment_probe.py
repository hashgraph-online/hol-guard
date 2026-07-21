#!/usr/bin/env python3
"""Run the installed-wheel containment proof on the Linux host."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import codex_plugin_scanner
from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentInput,
    ContainmentPolicy,
    ContainmentRequest,
)
from codex_plugin_scanner.guard.runtime.containment_executor import execute_contained, file_sha256

SENTINEL = "guard-private-command-sentinel"


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


def _probe() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-installed-containment-") as temporary:
        workspace = Path(temporary)
        protected = workspace / ".guard"
        protected.mkdir()
        secret_file = protected / "credentials.json"
        _ = secret_file.write_text(SENTINEL, encoding="utf-8")
        output = workspace / "output"
        output.mkdir()
        source = workspace / "format-input.txt"
        _ = source.write_text("formatted\n", encoding="utf-8")
        destination = output / "format-output.txt"
        executable = "/bin/sh"
        protected_path = shlex.quote(str(secret_file))
        command = (
            f"if secret=$(cat {protected_path} 2>/dev/null); then printf '%s' \"$secret\"; exit 91; fi; "
            f"if printf changed 2>/dev/null > {protected_path}; then exit 92; fi; "
            "cp format-input.txt output/format-output.txt"
        )
        request = ContainmentRequest(
            argv=(executable, "-c", command),
            cwd=str(workspace),
            environment=(("PATH", "/usr/bin:/bin"),),
            policy=ContainmentPolicy(str(workspace), (str(output),)),
            inputs=(ContainmentInput(str(source), "format-input.txt", file_sha256(str(source))),),
            launch_digest=hashlib.sha256(b"installed-command-analytics-lab").hexdigest(),
            executable_digest=file_sha256(executable),
            operation_id="installed.analytics.probe",
            declared_outputs=("output/format-output.txt",),
        )
        result = execute_contained(request, timeout_seconds=5)
        output_written = (
            len(result.outputs) == 1
            and result.outputs[0].snapshot_path == "output/format-output.txt"
            and result.outputs[0].content == b"formatted\n"
            and not destination.exists()
        )
        return {
            "enforced": result.enforced,
            "exit_code": result.exit_code,
            "output_written": output_written,
            "protected_value_unchanged": secret_file.read_text(encoding="utf-8") == SENTINEL,
            "secret_hidden": SENTINEL not in result.stdout and SENTINEL not in result.stderr,
        }


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
        raise RuntimeError("installed containment proof failed closed")
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
