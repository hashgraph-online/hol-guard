"""Run the installed Builder and native Ollama lifecycle with exact wheel identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process  # noqa: E402
from scripts.ci.native_ollama_contract import validated_build_sha  # noqa: E402
from scripts.ci.verify_extension_builder_install import verify as verify_builder  # noqa: E402
from scripts.native_slo_artifact import wheel_package_digest  # noqa: E402
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def builder_evidence(builder: Mapping[str, object], expected_wheel_sha256: str) -> dict[str, object]:
    examples = builder.get("examples")
    maximum = builder.get("maximumInventory")
    if (
        not isinstance(examples, list)
        or not isinstance(maximum, Mapping)
        or any(not isinstance(item, dict) for item in examples)
    ):
        raise ValueError("installed Ollama Builder evidence malformed")
    checks = (
        builder.get("passed") is True,
        builder.get("sourceFallback") is False,
        builder.get("guardStateCreated") is False,
        builder.get("wheelSha256") == expected_wheel_sha256,
        len(examples) == 2 and {item.get("kind") for item in examples} == {"cli", "mcp"},
        all(
            isinstance(item, dict)
            and all(item.get(key) is True for key in ("generated", "validated", "identicalReplay", "idempotentApply"))
            for item in examples
        ),
        maximum.get("operations") == 256,
    )
    return {
        "passed": all(checks),
        "version": builder.get("builderVersion"),
        "cli_and_mcp_generated_validated": checks[4] and checks[5],
        "deterministic_replay": checks[5],
        "idempotent_apply": checks[5],
        "maximum_inventory_operations": maximum.get("operations"),
        "guard_state_created": builder.get("guardStateCreated"),
    }


def installed_native_evidence(python: Path, expected: Mapping[str, object]) -> tuple[bool, dict[str, object]]:
    validated_build_sha(expected.get("build_sha"))
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.pop("PYTHONHOME", None)
    with tempfile.TemporaryDirectory(prefix="hol-guard-ollama-install-") as temporary:
        root = Path(temporary).resolve()
        identity = root / "expected.json"
        identity.write_text(json.dumps(expected, sort_keys=True), encoding="utf-8")
        identity.chmod(0o600)
        completed = run_isolated_hook_process(
            (
                str(python),
                "-I",
                str(Path(__file__).with_name("installed_native_ollama_probe.py")),
                "--expected",
                str(identity),
            ),
            cwd=root,
            environment=environment,
            input_text="",
            timeout_seconds=180,
            output_limit=256 * 1024,
        )
        try:
            native = assert_privacy_safe(json.loads(completed.stdout))
        except (ValueError, TypeError):
            native = {"reason": "installed_worker_evidence_invalid"}
        native_ok = (
            completed.returncode == 0
            and not completed.timed_out
            and not completed.containment_failed
            and not completed.output_limit_exceeded
            and native.get("schema") == "hol-guard.installed-native-ollama.v1"
            and native.get("passed") is True
            and isinstance(native.get("identity"), Mapping)
            and all(cast(Mapping[str, object], native["identity"]).get(key) == value for key, value in expected.items())
        )
        return native_ok, {
            "native": native,
            "worker_timed_out": completed.timed_out,
            "worker_containment_failed": completed.containment_failed,
            "worker_limit_exceeded": completed.output_limit_exceeded,
        }


def verify(python: Path, wheel: Path, source: Path, source_sha: str) -> dict[str, object]:
    expected = {
        "wheel_sha256": _sha256(wheel),
        "installed_package_sha256": wheel_package_digest(wheel),
        "build_sha": validated_build_sha(source_sha),
        "contribution_sha256": _sha256(source / "contributions/extensions/command.ollama.json"),
        "program_sha256": _sha256(source / "contracts/extensions/native-command-program.v1.json"),
    }
    report: dict[str, object] = {
        "schema": "hol-guard.installed-native-ollama-qualification.v1",
        "passed": False,
        "identity": expected,
    }
    native_ok = False
    try:
        native_ok, evidence = installed_native_evidence(python, expected)
        report.update(evidence)
    except Exception as error:
        report["native_failure"] = failure_evidence(error)
    # Builder checks use the same installed interpreter, with no live target
    # execution. Preserve this independent result if the native platform fails.
    builder_ok = False
    try:
        builder = verify_builder(python, wheel, source)
        evidence = builder_evidence(builder, cast(str, expected["wheel_sha256"]))
        builder_ok = evidence["passed"] is True
        report["builder"] = evidence
    except Exception as error:
        report["builder_failure"] = failure_evidence(error)
    report["passed"] = native_ok and builder_ok
    return assert_privacy_safe(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.python.absolute(), args.wheel.resolve(), args.source_root.resolve(), args.source_sha)
    except Exception as error:
        result = {
            "schema": "hol-guard.installed-native-ollama-qualification.v1",
            "passed": False,
            "setup_failure": failure_evidence(error),
        }
    content = json.dumps(result, sort_keys=True, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    print(content, end="", flush=True)
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
