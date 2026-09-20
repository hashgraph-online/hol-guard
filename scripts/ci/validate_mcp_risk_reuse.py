"""Run bounded MCP risk-reuse regression controls on the checked-out source."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
import traceback
from contextlib import suppress
from pathlib import Path

from mcp_risk_reuse_results import summarize_pytest

EXPECTED = json.loads(Path(__file__).with_name("mcp_risk_reuse_validation.json").read_text())
DRIVER_PATHS = (
    ".github/workflows/mcp-risk-reuse.yml",
    "scripts/ci/validate_mcp_risk_reuse.py",
    "scripts/ci/mcp_risk_reuse_validation.json",
    "scripts/ci/mcp_risk_reuse_results.py",
)
OUT = Path(os.environ.get("RSP100_EVIDENCE_DIR", "rsp100-approval-evidence"))
# Keep the executable symlink: resolving it bypasses virtualenv startup selection.
PYTHON = str((Path(".venv") / ("Scripts/python.exe" if os.name == "nt" else "bin/python")).absolute())
ENV = dict(os.environ, PYTHONPATH=str(Path("src").resolve()), PYTHONUNBUFFERED="1")
_RUN_DEADLINE = time.monotonic() + 25 * 60


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def blob(path: str) -> dict[str, object]:
    data = Path(path).read_bytes()
    header = f"blob {len(data)}\0".encode()
    return {
        "path": path,
        "bytes": len(data),
        "git_blob_sha": hashlib.sha1(header + data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def emit(name: str, value: object) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    # Finite original JSON records, independently recoverable from job logs.
    if len(data) > 65536:
        raise RuntimeError(f"record_limit:{name}:{len(data)}:{digest}")
    print(f"RSP100_RECORD name={name} bytes={len(data)} sha256={digest}", flush=True)
    for offset in range(0, len(data), 3072):
        print(
            f"RSP100_BASE64 name={name} offset={offset} data="
            + base64.b64encode(data[offset : offset + 3072]).decode(),
            flush=True,
        )


def source_binding() -> dict[str, object]:
    commit = git("rev-parse", "HEAD")
    platform_identity = {
        "cell": os.environ.get("RSP100_PLATFORM_CELL", ""),
        "system": platform.system(),
        "machine": platform.machine(),
        "python": ".".join(map(str, sys.version_info[:2])),
        "requested_python": os.environ.get("RSP100_PYTHON_VERSION", ""),
    }
    files = [blob(path) for path in (*EXPECTED["source_files"], *DRIVER_PATHS)]
    for item in files:
        item["committed_git_blob_sha"] = git("rev-parse", "HEAD:" + str(item["path"]))
    result = {
        "expected": EXPECTED,
        "commit": commit,
        "tree": git("rev-parse", "HEAD^{tree}"),
        "parents": git("show", "-s", "--format=%P", "HEAD").split(),
        "files": files,
        "tracked_files_unchanged": git("status", "--porcelain", "--untracked-files=no") == "",
        "source_blobs_match": all(item["git_blob_sha"] == item["committed_git_blob_sha"] for item in files),
        "python_driver": sys.version,
        "platform": platform.platform(),
        "platform_identity": platform_identity,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow_sha": os.environ.get("GITHUB_SHA"),
    }
    result["verified"] = (
        result["source_blobs_match"]
        and result["tracked_files_unchanged"]
        and commit == os.environ.get("GITHUB_SHA")
        and [platform_identity["system"], platform_identity["machine"]]
        in EXPECTED["platforms"].get(platform_identity["cell"], [])
        and platform_identity["python"] == platform_identity["requested_python"]
        and platform_identity["python"] in EXPECTED["platform_python_versions"].get(platform_identity["cell"], [])
    )
    return result


def run(name: str, command: list[str], timeout: int) -> dict[str, object]:
    start = time.monotonic()
    configured_timeout = timeout
    remaining = _RUN_DEADLINE - start - 120  # Reserve result/cleanup time.
    timeout = min(timeout, max(1, int(remaining)))
    timed_out = False
    group_retired = None
    group_signal = None
    actual_returncode = None
    windows_cleanup = None
    windows = os.name == "nt"
    try:
        if remaining <= 0:
            raise TimeoutError("driver_validation_budget_exhausted_before_launch")
        process = subprocess.Popen(
            command,
            env=ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=not windows,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if windows else 0,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            if windows:
                # A bounded best-effort tree request is not proof of descendant retirement.
                taskkill = Path(os.environ["SYSTEMROOT"]) / "System32" / "taskkill.exe"
                try:
                    cleanup = subprocess.run(
                        [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    windows_cleanup = {
                        "command": cleanup.args,
                        "returncode": cleanup.returncode,
                        "stdout_base64": base64.b64encode(cleanup.stdout).decode(),
                        "stderr_base64": base64.b64encode(cleanup.stderr).decode(),
                        "timed_out": False,
                    }
                except (OSError, subprocess.TimeoutExpired) as error:
                    expired = isinstance(error, subprocess.TimeoutExpired)
                    windows_cleanup = {
                        "error": repr(error),
                        "error_type": type(error).__name__,
                        "timed_out": expired,
                        "stdout_base64": base64.b64encode(error.stdout or b"" if expired else b"").decode(),
                        "stderr_base64": base64.b64encode(error.stderr or b"" if expired else b"").decode(),
                    }
                with suppress(OSError):
                    process.kill()
            else:
                group_signal = "SIGKILL"
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                process.stdout.close()
                process.stderr.close()
            code = 124
        actual_returncode = process.poll()
        if not windows:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                group_retired = True
            else:
                group_retired = False
                group_signal = "SIGKILL"
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    group_retired = True
                # Remaining group members are an explicit failure, even if the
                # direct command exited zero. Do not proceed to another test stage.
                code = code or 126
    except OSError as error:
        code, stdout, stderr = 125, b"", str(error).encode()
    (OUT / f"{name}.stdout.log").write_bytes(stdout)
    (OUT / f"{name}.stderr.log").write_bytes(stderr)
    result = {
        "name": name,
        "command": command,
        "exit_code": code,
        "actual_process_returncode": actual_returncode,
        "timed_out": timed_out,
        "configured_timeout_s": configured_timeout,
        "effective_timeout_s": timeout,
        "validation_budget_exhausted": remaining <= 0,
        "process_group_retired": group_retired,
        "group_signal": group_signal,
        "direct_process_retired": actual_returncode is not None,
        "windows_taskkill_attempt": windows_cleanup,
        "containment_scope": "windows_direct_child_only" if windows else "driver_process_group_only",
        "windows_descendant_retirement_proven": False if windows else None,
        "escaped_descendant_containment_proven": False,
        "elapsed_s": round(time.monotonic() - start, 6),
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    emit(f"{name}-result.json", result)
    # Retain each short original child output exactly in recoverable job records.
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        if len(data) <= 32768:
            emit(
                f"{name}-{stream}-original.json",
                {
                    "encoding": "base64",
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "data": base64.b64encode(data).decode(),
                },
            )
    return result


IMPORT = """
import hashlib, importlib, json, os, sys
from pathlib import Path
venv = Path(".venv").absolute()
executable = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
config_path = venv / "pyvenv.cfg"
config_bytes = config_path.read_bytes() if config_path.is_file() else None
environment = {
    "classification": "child_virtualenv_identity_before_product_import",
    "python": sys.version,
    "executable": str(Path(sys.executable).absolute()),
    "executable_resolved": str(Path(sys.executable).resolve()),
    "prefix": str(Path(sys.prefix).absolute()),
    "base_prefix": str(Path(sys.base_prefix).absolute()),
    "expected_executable": str(executable),
    "expected_prefix": str(venv),
    "expected_python": os.environ["RSP100_PYTHON_VERSION"],
    "pyvenv_config_path": str(config_path),
    "pyvenv_config_bytes": len(config_bytes) if config_bytes is not None else None,
    "pyvenv_config_sha256": hashlib.sha256(config_bytes).hexdigest() if config_bytes is not None else None,
}
environment["verified"] = (
    environment["executable"] == str(executable)
    and environment["prefix"] == str(venv)
    and environment["prefix"] != environment["base_prefix"]
    and config_bytes is not None
)
print(json.dumps(environment, sort_keys=True, allow_nan=False), flush=True)
if not environment["verified"]:
    raise SystemExit(1)
expected = [
    [
        "codex_plugin_scanner.guard.mcp_approval_risk",
        "src/codex_plugin_scanner/guard/mcp_approval_risk.py"
    ],
    [
        "codex_plugin_scanner.guard.mcp_request_risk",
        "src/codex_plugin_scanner/guard/mcp_request_risk.py"
    ],
    [
        "codex_plugin_scanner.guard.mcp_risk_dependencies",
        "src/codex_plugin_scanner/guard/mcp_risk_dependencies.py"
    ],
    [
        "codex_plugin_scanner.guard.mcp_risk_stdlib",
        "src/codex_plugin_scanner/guard/mcp_risk_stdlib.py"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "src/codex_plugin_scanner/guard/mcp_tool_calls.py"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "src/codex_plugin_scanner/guard/proxy/runtime_mcp.py"
    ]
]
loaded = []
for name, path in expected:
    module = importlib.import_module(name)
    actual = Path(module.__file__).resolve()
    wanted = Path(path).resolve()
    loaded.append({"module": name, "actual": str(actual), "expected": str(wanted), "matches": actual == wanted})
from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.proxy import runtime_mcp
report = {
    "python": sys.version,
    "environment": environment,
    "modules": loaded,
    "all_import_paths_match": all(item["matches"] for item in loaded),
    "available": calls._RISK_PAIR_HELPERS.available,
    "refusal_reason": calls._RISK_PAIR_HELPERS.refusal_reason,
    "binding_count": len(calls._RISK_PAIR_HELPERS._bindings),
    "approval_defaults_available": runtime_mcp._APPROVAL_RISK_DEFAULTS.available,
}
print(json.dumps(report, sort_keys=True, allow_nan=False))
raise SystemExit(0 if report["available"] and report["approval_defaults_available"]
                 and report["all_import_paths_match"]
                 and sys.version_info[:2] == tuple(map(int, os.environ["RSP100_PYTHON_VERSION"].split("."))) else 1)
"""
TRACE_IMPORT = """
import json, sys
events = []
def trace(frame, event, value):
    if event == "exception" and frame.f_code.co_filename.replace("\\\\", "/").endswith(
        ("/mcp_risk_dependencies.py", "/mcp_approval_risk.py")
    ):
        if len(events) < 48:
            observed = frame.f_locals.get("value")
            observed_kind = type(observed)
            member = frame.f_locals.get("name")
            events.append({
                "function": frame.f_code.co_name, "line": frame.f_lineno,
                "exception_type": value[0].__name__,
                "observed_value_type": observed_kind.__module__ + "." + observed_kind.__qualname__,
                "member_name": member[:160] if type(member) is str else None,
            })
    return trace
sys.settrace(trace)
try:
    from codex_plugin_scanner.guard import mcp_tool_calls as calls
    from codex_plugin_scanner.guard.proxy import runtime_mcp
    result = {"available": calls._RISK_PAIR_HELPERS.available,
              "refusal_reason": calls._RISK_PAIR_HELPERS.refusal_reason,
              "approval_defaults_available": runtime_mcp._APPROVAL_RISK_DEFAULTS.available}
except BaseException as error:
    result = {"import_exception_type": type(error).__name__}
finally:
    sys.settrace(None)
result.update({"classification": "diagnostic_only_traced_import", "events": events})
print(json.dumps(result, sort_keys=True, allow_nan=False))
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-only", action="store_true")
    options = parser.parse_args()
    initial = source_binding()
    emit("source-before.json", initial)
    if not initial["verified"]:
        return 2
    if options.bind_only:
        return 0
    results = []
    status = 1
    try:
        first = run("import-admission", [PYTHON, "-c", IMPORT], 180)
        results.append(first)
        if first["timed_out"] or first["process_group_retired"] is False:
            return 1
        if first["exit_code"] != 0:
            results.append(run("diagnostic-import-trace", [PYTHON, "-c", TRACE_IMPORT], 180))
            return 1
        results.append(
            run(
                "focused-pytest",
                [
                    PYTHON,
                    "-m",
                    "pytest",
                    "-q",
                    "--tb=short",
                    "--junitxml=" + str(OUT / "focused.xml"),
                    *EXPECTED["tests"],
                ],
                900,
            )
        )
        if results[-1]["timed_out"] or results[-1]["process_group_retired"] is False:
            return 1
        counts = summarize_pytest(
            OUT / "focused.xml",
            approval_nodes=EXPECTED["approval_positive_nodes"],
            additional_nodes=EXPECTED["additional_required_nodes"],
        )
        emit("pytest-counts.json", counts)
        if not all(
            counts.get(key, False)
            for key in (
                "positive_shape_controls_passed",
                "positive_approval_controls_passed",
                "additional_required_controls_passed",
            )
        ):
            results[-1]["evidence_verified"] = False
            results[-1]["positive_control_evidence_missing"] = True
        paths = [path for path in (*EXPECTED["source_files"], *DRIVER_PATHS) if path.endswith(".py")]
        results.append(run("ruff", [PYTHON, "-m", "ruff", "check", *paths], 180))
        if results[-1]["timed_out"] or results[-1]["process_group_retired"] is False:
            return 1
        results.append(run("format", [PYTHON, "-m", "ruff", "format", "--check", *paths], 180))
        if results[-1]["timed_out"] or results[-1]["process_group_retired"] is False:
            return 1
        results.append(
            run(
                "typecheck",
                [
                    PYTHON,
                    "-m",
                    "basedpyright",
                    "--level",
                    "error",
                    *[path for path in paths if path.startswith("src/")],
                ],
                600,
            )
        )
        status = int(any(result["exit_code"] != 0 or result.get("evidence_verified") is False for result in results))
    finally:
        after = source_binding()
        emit("source-after.json", after)
        emit(
            "result.json",
            {
                "classification": "mcp_risk_reuse_functional_regression",
                "source_verified_before": initial["verified"],
                "source_verified_after": after["verified"],
                "stages": results,
                "all_stages_succeeded": (
                    len(results) == 5
                    and all(
                        result["exit_code"] == 0 and result.get("evidence_verified") is not False for result in results
                    )
                    and bool(after["verified"])
                ),
                "qualification_complete": False,
                "old_campaigns_executed": False,
            },
        )
    return max(status, int(not after["verified"]))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        OUT.mkdir(parents=True, exist_ok=True)
        failure = traceback.format_exc()
        (OUT / "driver-failure.log").write_text(failure)
        emit("driver-failure.json", {"classification": "driver_failure", "traceback": failure})
        raise
