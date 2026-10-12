#!/usr/bin/env python3
"""Capture old contained-execution outcomes before retiring their Python bodies."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = "1b76783140"
HELPERS = "d75f7f7c590536b3116bd03643033e19ca4117f9"
PACKAGE = "codex_plugin_scanner.guard.runtime"
sys.path.insert(0, str(ROOT / "src"))


def record() -> dict:
    modules, hashes = {}, {}
    for name in (
        "restricted_pytest_model",
        "restricted_pytest_validation",
        "restricted_credential_patterns",
        "restricted_pytest_sandbox",
        "restricted_pytest",
        "restricted_node_test",
        "restricted_vitest",
        "restricted_inline_eval",
        "restricted_linux_mapping_plan",
    ):
        path = f"src/codex_plugin_scanner/guard/runtime/{name}.py"
        # Dependency helpers were retired by an earlier port. Load their pinned
        # Python only in this transient recorder, never as a runtime fallback.
        revision = HELPERS if name.startswith("restricted_pytest") else BASE
        source = subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=ROOT)
        hashes[path] = {"revision": revision, "sha256": hashlib.sha256(source).hexdigest()}
        module = types.ModuleType(f"{PACKAGE}.{name}")
        module.__package__ = PACKAGE
        sys.modules[module.__name__] = module
        exec(compile(source, path, "exec"), module.__dict__)
        modules[name] = module
    cases = []
    with tempfile.TemporaryDirectory(prefix="contained-parity-") as directory:
        root = Path(directory).resolve()
        workspace = root / "project"
        (workspace / "bin").mkdir(parents=True)
        (workspace / "package.json").write_text("{}")
        (workspace / "tests").mkdir()
        node = workspace / "bin/node"
        node.write_bytes(b"\xcf\xfa\xed\xfe" + b"native-fixture")
        node.chmod(0o755)
        (workspace / "tests/test_sample.py").write_text("")
        manifest = workspace / "node_modules/vitest/package.json"
        manifest.parent.mkdir(parents=True)
        manifest.with_name("vitest.mjs").write_text("")
        manifest.write_text('{"name":"vitest","version":"4.0.0"}')

        def wire(value):
            if hasattr(value, "__dataclass_fields__"):
                value = asdict(value)
            if isinstance(value, (tuple, list)):
                return [wire(item) for item in value]
            if isinstance(value, dict):
                return {wire(key): wire(item) for key, item in value.items()}
            if isinstance(value, Path):
                value = str(value)
            return value.replace(str(root), "$ROOT") if isinstance(value, str) else value

        def add(operation, inputs, function, *args, **kwargs):
            try:
                expected = {"value": wire(function(*args, **kwargs))}
            except modules["restricted_pytest_model"].RestrictedPytestError as error:
                expected = {"reason_code": error.reason_code, "message": str(error)}
            except modules["restricted_linux_mapping_plan"].LinuxContainmentUnavailableError as error:
                expected = {"reason_code": "linux_mapping_unavailable", "message": str(error)}
            cases.append({"operation": operation, "input": wire(inputs), "expected": expected})

        commands = [
            [],
            ["node"],
            ["node", "--test"],
            ["python", "-c", "print(1)"],
            ["python3", "-I", "-S", "-c", "0"],
            ["python", "-II", "-c", "0"],
            ["python", "-IS", "-I", "-c", "0"],
            ["python", "tests/test_sample.py"],
            ["python", "../test_sample.py"],
            ["python", "test_sample.py/"],
            ["node", "--max-old-space-size=32", "-e", "0"],
            ["node", "--eval", "0"],
            ["node", "--max-old-space-size=15", "--test"],
            ["node", "--max-old-space-size=131073", "--test"],
            ["node", "--max-old-space-size=٣٢", "--test"],
            ["node", "--max-old-space-size=00016", "--test"],
            ["node", "--max-old-space-size=", "--test"],
            ["node", "--max-old-space-size=" + "9" * 200, "--test"],
        ]
        route_path = "src/codex_plugin_scanner/guard/runtime/contained_test_hook.py"
        route_source = subprocess.check_output(["git", "show", f"{BASE}:{route_path}"], cwd=ROOT).decode()
        hashes[route_path] = {"revision": BASE, "sha256": hashlib.sha256(route_source.encode()).hexdigest()}
        start = route_source.index("    inline_eval = is_inline_eval(command)")
        end = route_source.index("    inline_plan =", start)
        routing = (
            "def classify(command):\n"
            + route_source[start:end]
            + (
                '    return {"inline_eval": inline_eval, "node_test": node_test, "vitest": vitest, '
                '"git": git, "node_tool": node_tool}\n'
            )
        )
        environment = {
            "Path": Path,
            "is_inline_eval": modules["restricted_inline_eval"].is_inline_eval,
            "restricted_node_test": modules["restricted_node_test"],
            "restricted_vitest": modules["restricted_vitest"],
        }
        exec(compile(routing, route_path, "exec"), environment)
        for command in commands:
            add("contained_kind", {"command": command}, environment["classify"], command)
            for operation, module, function in (
                ("node_runtime_args", "restricted_node_test", "_node_runtime_args"),
                ("inline_eval", "restricted_inline_eval", "is_inline_eval"),
                ("python_runtime_args", "restricted_inline_eval", "_python_runtime_args"),
            ):
                add(operation, {"command": command}, getattr(modules[module], function), command)
        for script in (
            "test.py",
            "tests/test_x.py",
            "./test.py",
            "test.py/",
            "tests//test.py",
            "../test.py",
            "/test.py",
            "~test.py",
            "test_é.py",
            "foo_test.py",
            "run_tests.py",
            "test.py$",
            "",
        ):
            add("test_script", {"value": script}, modules["restricted_inline_eval"]._test_script, script)
        for command in (
            ["vitest", "run"],
            ["npx", "--no-install", "vitest", "run", "-q"],
            ["bun", "x", "vitest", "run"],
            ["bunx", "--cwd=tests", "vitest", "run"],
            ["bunx", "vitest", "run"],
            ["bun", "--cwd", "tests", "x", "--no-install", "vitest", "run"],
            ["bun", "--cwd=", "x", "vitest", "run"],
            ["vitest", "watch"],
            ["vitest", "run", ";"],
            ["node", str(manifest.with_name("vitest.mjs")), "run"],
            ["node", "--max-old-space-size=32", str(manifest.with_name("vitest.mjs")), "run"],
        ):
            add(
                "bun_vitest_invocation",
                {"command": command},
                modules["restricted_vitest"].bun_vitest_invocation,
                command,
            )
            add("vitest_arguments", {"command": command}, modules["restricted_vitest"].vitest_arguments, command)
        for version in ("3.4.1", "4.0.0", "04.1", "\uff14.0", "", None):
            manifest.write_text(json.dumps({"name": "vitest", "version": version}))
            for args in (("run",), ("run", "--configLoader=custom"), ("run", "--configLoader", "native")):
                add(
                    "readonly_config_arguments",
                    {"command": args, "path": manifest, "fixture_version": version},
                    modules["restricted_vitest"]._readonly_config_arguments,
                    args,
                    manifest,
                )
        for path in (str(workspace), 'a\\b"c\nd\re', ".env"):
            add("seatbelt_string", {"value": path}, modules["restricted_credential_patterns"]._seatbelt_string, path)
        add("credential_patterns", {}, modules["restricted_credential_patterns"]._read_only_credential_patterns)
        for hide in (False, True):
            add(
                "credential_denials",
                {"hide_metadata": hide},
                modules["restricted_credential_patterns"]._read_only_credential_denials,
                hide_metadata=hide,
            )
        add(
            "nearest_project_root",
            {"cwd": workspace / "tests", "workspace": workspace, "value": "node_modules/vitest/vitest.mjs"},
            modules["restricted_node_test"].nearest_project_root,
            workspace / "tests",
            workspace,
            "node_modules/vitest/vitest.mjs",
        )
        add(
            "approved_node",
            {"path": node, "workspace": workspace},
            modules["restricted_node_test"]._approved_node,
            node,
            workspace,
        )
        prior_path = os.environ.get("PATH")
        os.environ["PATH"] = str(node.parent)
        modules["restricted_node_test"]._select_backend = lambda **kwargs: ("macos-seatbelt", Path("/usr/bin/true"))
        manifest.write_text('{"name":"vitest","version":"4.0.0"}')
        for command in (
            ["node", "--test"],
            ["node", "--max-old-space-size=32", "--test", "tests"],
            ["node", "--test", ";"],
            ["node", "--require", "evil.js", "--test"],
        ):
            add(
                "prepare_node",
                {
                    "command": command,
                    "workspace": workspace,
                    "cwd": workspace,
                    "platform": "darwin",
                    "backend_executable": "/usr/bin/true",
                    "search_path": str(node.parent),
                },
                modules["restricted_node_test"].prepare_restricted_node_test,
                command,
                workspace=workspace,
                cwd=workspace,
                platform="darwin",
                backend_executable=Path("/usr/bin/true"),
            )
            if "value" in cases[-1]["expected"]:
                cases[-1]["expected"]["value"].pop("read_only_roots", None)
                cases[-1]["expected"]["value"].pop("output_roots", None)
        for command in (
            ["bunx", "--cwd", "tests", "vitest", "run"],
            ["bun", "--cwd=tests", "x", "vitest", "run"],
            ["vitest", "run"],
            ["node", str(manifest.with_name("vitest.mjs")), "run"],
        ):
            add(
                "prepare_vitest",
                {
                    "command": command,
                    "workspace": workspace,
                    "cwd": workspace,
                    "platform": "darwin",
                    "backend_executable": "/usr/bin/true",
                    "search_path": str(node.parent),
                },
                modules["restricted_vitest"].prepare_restricted_vitest,
                command,
                workspace=workspace,
                cwd=workspace,
            )
            if "value" in cases[-1]["expected"]:
                cases[-1]["expected"]["value"].pop("read_only_roots", None)
                cases[-1]["expected"]["value"].pop("output_roots", None)
        if prior_path is None:
            del os.environ["PATH"]
        else:
            os.environ["PATH"] = prior_path
        model = modules["restricted_pytest_model"]
        for profile in (
            "pytest-restricted-v1",
            "pytest-readonly-v2",
            "node-test-readonly-v1",
            "vitest-readonly-v1",
            "node-build-output-v1",
            "python-eval-readonly-v1",
        ):
            plan = model.RestrictedPytestPlan(
                profile_version=profile,
                backend="macos-seatbelt",
                backend_executable=Path("/usr/bin/true"),
                workspace=workspace,
                cwd=workspace,
                command=(str(node),),
                executable=node,
                allowed_executables=(node, Path("/usr/bin/true")),
                denied_capabilities=(),
                output_roots=(workspace / "dist",) if profile == "node-build-output-v1" else (),
            )
            fields = {
                key: getattr(plan, key)
                for key in (
                    "profile_version",
                    "workspace",
                    "cwd",
                    "allowed_executables",
                    "read_only_roots",
                    "output_roots",
                    "command",
                    "backend_executable",
                )
            }
            fields["private_root"] = root / "private"
            add(
                "macos_profile",
                fields,
                modules["restricted_pytest_sandbox"]._macos_profile,
                plan,
                private_root=root / "private",
            )
            # Relocate only fixture-parent metadata when replaying on hosts
            # whose temporary directory has a different ancestor depth.
            ancestor_metadata = " ".join(f'(literal "{parent}")' for parent in root.parents if parent != Path("/"))
            cases[-1]["expected"]["value"] = cases[-1]["expected"]["value"].replace(
                ancestor_metadata, "$FIXTURE_ANCESTORS"
            )
            system_files = [p for p in model._MACOS_READ_FILES if p.exists()]
            if profile in {"node-test-readonly-v1", "vitest-readonly-v1", "node-build-output-v1"}:
                system_files += [
                    Path(p)
                    for p in ("/opt/homebrew/etc/openssl@3/openssl.cnf", "/usr/local/etc/openssl@3/openssl.cnf")
                    if Path(p).is_file()
                ]
            cases[-1]["system_grants"] = wire(
                {"roots": [p for p in model._MACOS_READ_ROOTS if p.exists()], "files": system_files}
            )
        node.chmod(0o777)
        add(
            "approved_node",
            {"path": node, "workspace": workspace, "fixture_mode": 511},
            modules["restricted_node_test"]._approved_node,
            node,
            workspace,
        )
        source = subprocess.check_output(
            ["git", "show", f"{BASE}:tests/test_guard_restricted_linux_mapping_plan.py"], cwd=ROOT
        )
        image_module = types.ModuleType("mapping_fixture_source")
        exec(compile(source, "mapping_fixture_source", "exec"), image_module.__dict__)
        image = image_module._image
        mapping = modules["restricted_linux_mapping_plan"]
        runner = image(workspace / "runner")
        ordinary = image(workspace / "ordinary.so", library=True)
        optional = image(workspace / "optional.node", library=True, needed=("absent.so",))
        for needed in ((), ("ordinary.so",), ("absent.so",), ("../escape.so",)):
            image(runner, needed=needed)
            inputs = {
                "images": [runner],
                "read_files": [ordinary, optional],
                "runtime_roots": [],
                "workspace": workspace,
            }
            add(
                "mapping_evidence",
                inputs,
                mapping.collect_mapping_evidence,
                images={runner},
                read_files={ordinary, optional},
                runtime_roots=(),
                workspace=workspace,
            )
            cases[-1]["fixture_files"] = wire(
                {str(path): path.read_bytes().hex() for path in (runner, ordinary, optional)}
            )
            if "value" in cases[-1]["expected"]:
                for result in cases[-1]["expected"]["value"]:
                    result["identity"] = "$IDENTITY"
    sandbox = modules["restricted_pytest_sandbox"]
    previous_run, previous_platform = sandbox.subprocess.run, sys.platform
    try:
        for platform, raw, existing in (
            ("darwin", b"1\n2\n3\n", 2),
            ("darwin", b"1\n", 0),
            ("linux", b"8\n30\n3\n", 40),
        ):
            sys.platform = platform

            def measure(argv, measured=raw, **kwargs):
                kwargs["stdout"].write(measured)
                return types.SimpleNamespace(returncode=0)

            sandbox.subprocess.run = measure
            add("process_ceiling_snapshot", {"existing": existing}, sandbox._current_user_process_ceiling)
    finally:
        sandbox.subprocess.run, sys.platform = previous_run, previous_platform
    return {"schema": "contained-execution-parity.v1", "baseline": BASE, "source_sha256": hashes, "cases": cases}


if __name__ == "__main__":
    destination = ROOT / "rust/crates/guard-command/tests/fixtures/contained_execution_parity.json"
    destination.write_text(json.dumps(record(), indent=2, ensure_ascii=True) + "\n")
