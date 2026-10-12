#!/usr/bin/env python3
"""Record restricted execution outcomes from the pinned, unretired Python."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path

BASE = "d75f7f7c590536b3116bd03643033e19ca4117f9"
ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "codex_plugin_scanner.guard.runtime"
sys.path.insert(0, str(ROOT / "src"))


def record() -> dict:
    modules = {}
    hashes = {}
    for name in ("restricted_pytest_model", "restricted_pytest_validation", "restricted_pytest_sandbox"):
        path = f"src/codex_plugin_scanner/guard/runtime/{name}.py"
        source = subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT)
        hashes[path] = hashlib.sha256(source).hexdigest()
        module = types.ModuleType(f"{PACKAGE}.{name}")
        module.__package__ = PACKAGE
        sys.modules[module.__name__] = module
        exec(compile(source, path, "exec"), module.__dict__)
        modules[name] = module
    validation = modules["restricted_pytest_validation"]
    sandbox = modules["restricted_pytest_sandbox"]
    cases = []
    with tempfile.TemporaryDirectory(prefix="restricted-parity-") as directory:
        root = Path(directory).resolve()
        workspace = root / "project"
        (workspace / "bin").mkdir(parents=True)
        (workspace / "pyproject.toml").write_text("")
        (workspace / "sub").mkdir()
        executable = workspace / "bin/python"
        executable.write_text("#!/usr/bin/python3\n")
        executable.chmod(0o755)
        pytest_executable = workspace / "bin/pytest"
        pytest_executable.write_text("#!/bin/sh\n")
        pytest_executable.chmod(0o755)
        upper_python = workspace / "bin/Python"
        upper_python.write_text("#!/usr/bin/python3\n")
        upper_python.chmod(0o755)
        python_entrypoint = workspace / "bin/py.test"
        python_entrypoint.write_text(f"#!{upper_python}\n")
        python_entrypoint.chmod(0o755)
        (workspace / "alias").symlink_to(workspace / "sub", target_is_directory=True)

        def wire(value):
            if isinstance(value, (tuple, list)):
                return [wire(item) for item in value]
            if isinstance(value, dict):
                return {key: wire(item) for key, item in value.items()}
            if isinstance(value, Path):
                value = str(value)
            return value.replace(str(root), "$ROOT") if isinstance(value, str) else value

        def add(operation, inputs, function, *args, **kwargs):
            try:
                expected = {"value": wire(function(*args, **kwargs))}
            except modules["restricted_pytest_model"].RestrictedPytestError as error:
                expected = {"reason_code": error.reason_code, "message": wire(str(error))}
            cases.append({"operation": operation, "input": wire(inputs), "expected": expected})

        for command in (
            [],
            ["--"],
            ["pytest"],
            ["--", "pytest", "-q"],
            ["python", "-m", "pytest"],
            ["pytest", "nul\x00"],
            ["pytest", "é"],
            ["pytest"] * 4097,
        ):
            add("normalized_command", {"command": command}, validation._normalized_command, command)
        for args in (
            [],
            ["-m", "pytest"],
            ["-mpytest"],
            ["-m", "pytest.foo"],
            ["-m", "other"],
            ["-c", "pytest"],
            ["--", "-m", "pytest"],
            ["-W", "ignore", "-m", "pytest"],
            ["-Xdev", "-m", "pytest"],
            ["script.py"],
            ["--command=pytest"],
            ["-m"],
        ):
            add("python_args_target_pytest", {"command": args}, validation._python_args_target_pytest, args)
        for path in (workspace, workspace / "sub", workspace / "alias", root):
            add(
                "resolve_cwd",
                {"path": path, "workspace": workspace},
                validation._resolve_cwd,
                path,
                workspace=workspace,
            )
        for args in (
            ["-m", "pytest"],
            ["-mpytest"],
            ["-c", "pytest"],
            ["-W", "ignore", "-m", "pytest"],
            ["-X", "dev", "-m", "pytest"],
            ["script.py"],
            ["-m", "other"],
        ):
            command = (str(executable), *args)
            add(
                "resolve_pytest_executable",
                {"command": command, "cwd": workspace, "workspace": workspace},
                validation._resolve_pytest_executable,
                command,
                cwd=workspace,
                workspace=workspace,
            )
        add(
            "resolve_pytest_executable",
            {"command": [str(upper_python), "-m", "pytest"], "cwd": workspace, "workspace": workspace},
            validation._resolve_pytest_executable,
            (str(upper_python), "-m", "pytest"),
            cwd=workspace,
            workspace=workspace,
        )
        for target in (executable, pytest_executable, python_entrypoint):
            command = (str(target), "-m", "pytest") if target == executable else (str(target), "-q")
            add(
                "allowed_executables",
                {
                    "executable": target,
                    "launch_executable": target,
                    "command": command,
                    "cwd": workspace,
                    "workspace": workspace,
                },
                validation._allowed_executables,
                target,
                target,
                command,
                cwd=workspace,
                workspace=workspace,
            )
        for value in ("./bin/python", "bin/python", "../project/bin/python", str(executable)):
            add(
                "locate_executable",
                {"value": value, "cwd": workspace},
                validation._locate_executable,
                value,
                cwd=workspace,
            )
        for value in (
            "",
            ".",
            "sub",
            "alias",
            "alias/missing",
            "missing/../sub",
            "alias/missing/../",
            "sub:alias",
            "../",
            "sub::sub",
        ):
            add(
                "restricted_pythonpath",
                {"value": value, "workspace": workspace, "cwd": workspace},
                validation._restricted_pythonpath,
                value,
                workspace=workspace,
                cwd=workspace,
            )
        for path in (workspace, workspace / "sub", workspace / "alias", root):
            add("path_is_within", {"path": path, "root": workspace}, validation._path_is_within, path, workspace)
        for key in sorted(
            set(modules["restricted_pytest_model"]._SAFE_ENV_KEYS)
            | set(modules["restricted_pytest_model"]._DENIED_ENV_KEYS)
            | {"MY_API_KEY", "my_token", "LC_ALL", "PYTHONPATH", "OTHER", "HOME", "PATH"}
        ):
            source = {key: "sub" if key == "PYTHONPATH" else "example"}
            inputs = {
                "source": source,
                "workspace": workspace,
                "cwd": workspace,
                "private_home": root / "home",
                "private_tmp": root / "tmp",
                "allowed_executables": [executable],
            }
            add(
                "environment",
                inputs,
                sandbox._restricted_environment,
                source,
                workspace=workspace,
                cwd=workspace,
                private_home=root / "home",
                private_tmp=root / "tmp",
                allowed_executables=(executable,),
            )
    return {"schema": "restricted-pytest-parity.v1", "baseline": BASE, "source_sha256": hashes, "cases": cases}


if __name__ == "__main__":
    destination = ROOT / "rust/crates/guard-command/tests/fixtures/restricted_pytest_parity.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record(), indent=2, ensure_ascii=True) + "\n")
