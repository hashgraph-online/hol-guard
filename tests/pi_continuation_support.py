"""Generated Pi-family tool-call approval continuation coverage."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_PI_SDK_ROOT_ENV = "HOL_GUARD_PI_SDK_ROOT"

_PI_SDK_PACKAGE_NAME = "@earendil-works/pi-coding-agent"

_PI_SDK_PACKAGE_VERSION = "0.87.1"


def _node_executable() -> str | None:
    return shutil.which("node")


def _run_child(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise AssertionError(
            f"child process failed with exit code {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def _pi_runner_module() -> Path | None:
    explicit_root = os.environ.get(_PI_SDK_ROOT_ENV)
    if explicit_root:
        root = Path(explicit_root)
        if not root.is_absolute():
            pytest.fail(f"{_PI_SDK_ROOT_ENV} must be an absolute job-local SDK root")
        try:
            resolved_root = root.resolve(strict=True)
            metadata = json.loads((resolved_root / "package.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} does not point to a readable package: {error}")
        if not isinstance(metadata, dict):
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package metadata is not an object")
        if metadata.get("name") != _PI_SDK_PACKAGE_NAME:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package identity is not {_PI_SDK_PACKAGE_NAME!r}")
        if metadata.get("version") != _PI_SDK_PACKAGE_VERSION:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package version is not {_PI_SDK_PACKAGE_VERSION!r}")
        runner_module = resolved_root / "dist" / "index.js"
        try:
            resolved_runner = runner_module.resolve(strict=True)
        except OSError as error:
            pytest.fail(f"{_PI_SDK_ROOT_ENV} package has no dist/index.js: {error}")
        if not resolved_runner.is_relative_to(resolved_root):
            pytest.fail(f"{_PI_SDK_ROOT_ENV} runner resolves outside its package root")
        return resolved_runner

    pi_cli = shutil.which("pi")
    if pi_cli is None:
        return None
    cli_path = Path(pi_cli).resolve()
    if not cli_path.is_file():
        return None
    if cli_path.parent.name == "dist":
        package_root = cli_path.parent.parent
    elif cli_path.parent.name == "bundle" and cli_path.parent.parent.name == "dist":
        package_root = cli_path.parent.parent.parent
    else:
        return None
    try:
        package_root = package_root.resolve(strict=True)
        metadata = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(metadata, dict):
        return None
    if metadata.get("name") != _PI_SDK_PACKAGE_NAME or metadata.get("version") != _PI_SDK_PACKAGE_VERSION:
        return None
    raw_bin = metadata.get("bin")
    if isinstance(raw_bin, str):
        bin_targets = (raw_bin,)
    elif isinstance(raw_bin, dict):
        bin_targets = tuple(value for value in raw_bin.values() if isinstance(value, str))
    else:
        bin_targets = ()
    if not any(
        (package_root / target).resolve() == cli_path and (package_root / target).resolve().is_relative_to(package_root)
        for target in bin_targets
    ):
        return None
    runner_module = package_root / "dist" / "index.js"
    try:
        resolved_runner = runner_module.resolve(strict=True)
    except OSError:
        return None
    return resolved_runner if resolved_runner.is_relative_to(package_root) else None


def _write_pi_package(root: Path, bin_target: str) -> Path:
    root.mkdir(parents=True)
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": _PI_SDK_PACKAGE_NAME,
                "version": _PI_SDK_PACKAGE_VERSION,
                "bin": {"pi": bin_target},
            }
        ),
        encoding="utf-8",
    )
    cli_path = root / bin_target
    cli_path.parent.mkdir(parents=True, exist_ok=True)
    cli_path.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    runner_module = root / "dist" / "index.js"
    runner_module.parent.mkdir(parents=True, exist_ok=True)
    runner_module.write_text("export {};\n", encoding="utf-8")
    return cli_path


def _decode_json_object(stdout: str) -> dict[str, object]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    assert lines, stdout
    payload = json.loads(lines[-1])
    assert isinstance(payload, dict)
    return payload


def _handler_fragment(source: str) -> str:
    start = source.index('pi.on("tool_call", async (event, ctx) => {')
    end = source.index('\n  pi.on("message_end"', start)
    return source[start:end]
