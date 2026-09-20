"""Moved diagnostic code remains reachable, replaceable and source-bound."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ci.native_runtime import probe_installed_offline_secrets as secrets
from scripts import native_slo_workloads as workloads


@pytest.mark.parametrize("mode", ["direct_help", "isolated_attestation"])
def test_isolated_secrets_entrypoint_ignores_foreign_cwd_and_retains_error_identity(tmp_path: Path, mode: str) -> None:
    # The actual installed collector runs this file with -I, outside its source
    # directory. A fake local namespace must not intercept the extracted helpers.
    foreign = tmp_path / "foreign"
    (foreign / "ci" / "native_runtime").mkdir(parents=True)
    (foreign / "ci" / "__init__.py").write_text('raise RuntimeError("foreign_ci_loaded")\n')
    script = Path(secrets.__file__).resolve()
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PYTHON")}
    destination = tmp_path / "receipt.json"
    if mode == "direct_help":
        command = [sys.executable, "-I", str(script), "--help"]
    else:
        command = [
            sys.executable,
            "-I",
            str(script),
            "--wheel",
            str(tmp_path / "unused.whl"),
            "--source-sha",
            "invalid",
            "--json",
            str(destination),
        ]
    result = subprocess.run(command, cwd=foreign, env=environment, capture_output=True, timeout=10)
    assert b"foreign_ci_loaded" not in result.stderr
    if mode == "direct_help":
        assert result.returncode == 0
        assert b"--mutation-worker" in result.stdout
    else:
        assert result.returncode == 1
        assert result.stderr == ("installed_offline_secrets_failed" + os.linesep).encode()
        receipt = json.loads(destination.read_text())
        assert receipt["status"] == "failed"
        assert receipt["reason"] == "source_identity"
        assert receipt["error_type"] == "ProbeError"
        assert receipt["failure_stage"] == "initial_attestation"
        assert receipt["probe_source_sha256"] == secrets._probe_source_digests()


def test_moved_launcher_validator_uses_live_facade_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    class RejectedError(RuntimeError):
        pass

    def reject(condition: bool, code: str) -> None:
        raise RejectedError(code)

    monkeypatch.setattr(secrets, "_require", reject)
    with pytest.raises(RejectedError, match="launcher_size"):
        secrets._launcher_wrapper(b"unused", module="unused", interpreter="/unused", windows=False)


def test_case_builder_uses_live_facade_manifest_before_writing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class RejectedError(RuntimeError):
        pass

    def reject() -> None:
        raise RejectedError("manifest_read")

    monkeypatch.setattr(workloads, "corpus_manifest", reject)
    with pytest.raises(RejectedError, match="manifest_read"):
        workloads.build_cases(tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("name", ["native_slo_workloads.py", "native_slo_workload_cases.py"])
def test_oracle_identity_changes_when_either_source_owner_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    original_root = Path(workloads.__file__).parent
    for source in ("native_slo_workloads.py", "native_slo_workload_cases.py"):
        (tmp_path / source).write_bytes((original_root / source).read_bytes())
    monkeypatch.setattr(workloads, "__file__", str(tmp_path / "native_slo_workloads.py"))
    original = workloads.oracle_source_digest()
    changed = tmp_path / name
    changed.write_bytes(changed.read_bytes() + b"\n# changed collector source\n")
    assert workloads.oracle_source_digest() != original
    changed.unlink()
    with pytest.raises(FileNotFoundError):
        workloads.oracle_source_digest()


@pytest.mark.parametrize("name", ["api", "identity", "cases"])
def test_secrets_receipt_binds_every_extracted_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    original_root = Path(secrets.__file__).parent
    expected = secrets._probe_source_digests()
    for source in expected:
        (tmp_path / source).write_bytes((original_root / source).read_bytes())
    monkeypatch.setattr(secrets, "__file__", str(tmp_path / "probe_installed_offline_secrets.py"))
    assert secrets._probe_source_digests() == expected
    changed_name = f"probe_installed_offline_secrets_{name}.py"
    changed = tmp_path / changed_name
    changed.write_bytes(changed.read_bytes() + b"\n# changed probe source\n")
    actual = secrets._probe_source_digests()
    assert {key for key in actual if actual[key] != expected[key]} == {changed_name}
