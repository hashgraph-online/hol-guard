"""Isolation, hostile-input and immutable-blob witnesses for RSP-070."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime import offline_archive_contract as contract
from codex_plugin_scanner.guard.runtime import offline_archive_inspection as inspector
from codex_plugin_scanner.guard.runtime import offline_archive_worker as worker

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/bench_guard_archive_worker.py"
SPEC = importlib.util.spec_from_file_location("bench_guard_archive_worker", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def _plain_archive(tmp_path: Path) -> tuple[Path, str]:
    path = benchmark.archive_blob(tmp_path, "safe", [("package/readme", b"ordinary data")], compressed=False)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _direct_worker(path: Path, digest: str) -> Any:
    return worker._inspect_archive(
        path,
        expected_sha256=digest,
        timeout_seconds=contract._DEFAULT_TIMEOUT_SECONDS,
        max_archive_bytes=contract._DEFAULT_MAX_ARCHIVE_BYTES,
        max_files=contract._DEFAULT_MAX_FILES,
        max_expanded_bytes=contract._DEFAULT_MAX_EXPANDED_BYTES,
        max_member_bytes=contract._DEFAULT_MAX_MEMBER_BYTES,
        max_package_json_bytes=contract._DEFAULT_MAX_PACKAGE_JSON_BYTES,
        max_decompression_ratio=contract._DEFAULT_MAX_DECOMPRESSION_RATIO,
        max_nested_archives=contract._DEFAULT_MAX_NESTED_ARCHIVES,
        max_path_depth=contract._DEFAULT_MAX_PATH_DEPTH,
    )


@pytest.mark.parametrize("alias", ["hardlink", "writable"])
def test_real_parent_rejects_mutable_or_shared_blob(tmp_path: Path, alias: str) -> None:
    path, digest = _plain_archive(tmp_path)
    if alias == "hardlink":
        os.link(path, tmp_path / "shared")
    else:
        path.chmod(0o600)
    result = inspector.inspect_archive_offline(path, expected_sha256=digest)
    assert (result.status, result.code) == ("blocked", "external_archive_blob_rejected")


def test_worker_rejects_equal_bytes_on_replaced_inode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, digest = _plain_archive(tmp_path)
    replacement = tmp_path / "replacement.tar"
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o400)
    original_inode = path.stat().st_ino
    original_hash = worker._hash_file

    def replace_after_path_hash(*args: Any, **kwargs: Any) -> Any:
        result = original_hash(*args, **kwargs)
        replacement.replace(path)
        assert path.stat().st_ino != original_inode
        return result

    monkeypatch.setattr(worker, "_hash_file", replace_after_path_hash)
    result = _direct_worker(path, digest)
    assert (result.status, result.code) == ("blocked", "external_archive_digest_mismatch")


def test_worker_rejects_same_inode_changed_during_inspection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, digest = _plain_archive(tmp_path)
    original_inode = path.stat().st_ino
    original_preflight = worker._preflight_expanded_tar_stream

    def mutate_after_preflight(*args: Any, **kwargs: Any) -> Any:
        result = original_preflight(*args, **kwargs)
        path.chmod(0o600)
        with path.open("r+b") as stream:
            stream.seek(512)  # Change opaque file data without damaging the tar header.
            stream.write(b"modified data")
        path.chmod(0o400)
        assert path.stat().st_ino == original_inode
        return result

    monkeypatch.setattr(worker, "_preflight_expanded_tar_stream", mutate_after_preflight)
    result = _direct_worker(path, digest)
    assert (result.status, result.code) == ("blocked", "external_archive_digest_mismatch")


def _probe(source: str, tmp_path: Path) -> subprocess.CompletedProcess[bytes]:
    command = inspector._isolated_child_command([])
    trailer = "raise SystemExit(m._child_main(sys.argv[1:]))"
    assert command[5].count(trailer) == 1
    command[5] = command[5].replace(trailer, f"m._install_child_capability_guard();exec({source!r})")
    sandboxed = inspector._platform_sandbox_command(command)
    if sandboxed is None:
        pytest.skip("platform sandbox unavailable")
    return subprocess.run(
        sandboxed,
        cwd=tmp_path,
        env=inspector._child_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=3,
    )


@pytest.mark.parametrize(
    "operation",
    [
        "open('forbidden-write', 'w').close()",
        "os.open('forbidden-write', os.O_WRONLY | os.O_CREAT, 0o600)",
        "socket.socket()",
        "subprocess.run([sys.executable, '-c', 'raise SystemExit(0)'], check=True)",
        "os.system('exit 0')",
    ],
)
def test_isolated_child_denies_write_network_and_process_capabilities(tmp_path: Path, operation: str) -> None:
    process = _probe(
        "import os,socket,subprocess,sys\n"
        "try:\n"
        f"    {operation}\n"
        "except PermissionError:\n"
        "    print('denied')\n"
        "else:\n"
        "    raise SystemExit(91)\n",
        tmp_path,
    )
    assert process.returncode == 0, process.stderr
    assert process.stdout == b"denied\n"
    assert not (tmp_path / "forbidden-write").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX resource sandbox")
def test_isolated_child_applies_real_resource_limits(tmp_path: Path) -> None:
    process = _probe(
        "import json,resource\n"
        "assert m._child_limits(2.0, 512 * 1024 * 1024)\n"
        "print(json.dumps({name:resource.getrlimit(getattr(resource,name)) "
        "for name in ['RLIMIT_CPU','RLIMIT_NOFILE','RLIMIT_AS']}))\n",
        tmp_path,
    )
    assert process.returncode == 0, process.stderr
    limits = json.loads(process.stdout)
    assert 0 < limits["RLIMIT_CPU"][0] <= 2
    assert 8 <= limits["RLIMIT_NOFILE"][0] <= 32
    assert limits["RLIMIT_AS"][0] > 0
    assert limits["RLIMIT_AS"][0] == limits["RLIMIT_AS"][1]
    if sys.platform != "darwin":
        assert limits["RLIMIT_AS"][0] <= 512 * 1024 * 1024


def test_real_child_ignores_ambient_python_and_credential_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest = _plain_archive(tmp_path)
    poison = tmp_path / "tarfile.py"
    poison.write_text("raise RuntimeError('ambient import executed')\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("ARCHIVE_QUALIFICATION_FAKE_TOKEN", "synthetic-sensitive-value")
    result = inspector.inspect_archive_offline(path, expected_sha256=digest)
    assert result.status == "clean"
    assert "PYTHONPATH" not in inspector._child_environment()
    assert "ARCHIVE_QUALIFICATION_FAKE_TOKEN" not in inspector._child_environment()


@pytest.mark.parametrize(
    ("returncode", "payload"),
    [
        (1, b'{"status":"clean"}'),
        (0, b"{}"),
        (0, b"not-json"),
        (0, b"\xff"),
        (0, b" " * (contract._CHILD_RESULT_MAX_BYTES + 1)),
    ],
)
def test_child_failure_or_invalid_result_cannot_be_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    payload: bytes,
) -> None:
    path, digest = _plain_archive(tmp_path)
    monkeypatch.setattr(
        inspector.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], returncode, stdout=payload),
    )
    result = inspector.inspect_archive_offline(path, expected_sha256=digest)
    assert (result.status, result.code) == ("incomplete", "external_archive_inspection_incomplete")


def test_clean_child_result_requires_expected_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, digest = _plain_archive(tmp_path)
    payload = json.dumps(
        {
            "status": "clean",
            "code": "external_archive_inspection_clean",
            "message": "clean",
            "severity": "low",
            "sha256": "0" * 64,
        }
    ).encode()
    monkeypatch.setattr(
        inspector.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=payload)
    )
    result = inspector.inspect_archive_offline(path, expected_sha256=digest)
    assert (result.status, result.code) == ("blocked", "external_archive_digest_mismatch")


def test_real_worker_deadline_is_incomplete(tmp_path: Path) -> None:
    path, digest = _plain_archive(tmp_path)
    result = inspector.inspect_archive_offline(path, expected_sha256=digest, timeout_seconds=1e-9)
    assert (result.status, result.code) == ("incomplete", "external_archive_inspection_timeout")


def test_parent_timeout_kills_and_reaps_an_unresponsive_isolated_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, digest = _plain_archive(tmp_path)
    isolated_command = inspector._isolated_child_command
    original_popen = inspector.subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []

    def stalled_child(arguments: list[str]) -> list[str]:
        command = isolated_command(arguments)
        command[5] = command[5].replace(
            "raise SystemExit(m._child_main(sys.argv[1:]))",
            "m._install_child_capability_guard();m._child_limits(1.0,512*1024*1024);exec('import time;time.sleep(60)')",
        )
        return command

    def remember_child(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(inspector, "_isolated_child_command", stalled_child)
    monkeypatch.setattr(inspector.subprocess, "Popen", remember_child)
    result = inspector.inspect_archive_offline(path, expected_sha256=digest, timeout_seconds=0.01)
    assert (result.status, result.code) == ("incomplete", "external_archive_inspection_timeout")
    assert len(children) == 1
    assert children[0].poll() is not None


def test_profile_preserves_real_child_result_and_three_digest_passes(tmp_path: Path) -> None:
    path, digest = _plain_archive(tmp_path)
    case = benchmark.ArchiveCase("profile-fixture", path, digest)
    sample = benchmark._profile(inspector, case)
    assert sample["child_exit_code"] == 0
    assert sample["phases"]["digest_reads"]["calls"] == 3
    assert sample["phases"]["expanded_stream_preflight"]["calls"] == 1
    assert sample["phases"]["resource_limits"]["calls"] == 1
    assert sample["phases"]["tar_member_decode"]["calls"] >= 1
    assert sample["inspection_remainder_ms"] >= 0
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert sorted(member.name for member in tmp_path.iterdir()) == ["safe.tar"]


def test_real_child_bad_arguments_exit_without_an_inspection_result(tmp_path: Path) -> None:
    command = inspector._platform_sandbox_command(inspector._isolated_child_command(["--child-inspect"]))
    if command is None:
        pytest.skip("platform sandbox unavailable")
    process = subprocess.run(
        command,
        cwd=tmp_path,
        env=inspector._child_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=3,
    )
    assert process.returncode == 2
    assert process.stdout == b""


def test_real_child_blocked_result_is_successful_inspection_exit(tmp_path: Path) -> None:
    path = benchmark.archive_blob(tmp_path, "unsafe", [("../outside", b"never extracted")])
    case = benchmark.ArchiveCase(
        "blocked-fixture", path, hashlib.sha256(path.read_bytes()).hexdigest(), "blocked", "tarball_zip_slip"
    )
    sample = benchmark._profile(inspector, case)
    assert sample["child_exit_code"] == 0
    assert not (tmp_path.parent / "outside").exists()


@pytest.mark.parametrize(("wrong_result", "diagnostic_timeout"), [(True, False), (False, True)])
def test_benchmark_retains_baseline_and_fails_on_wrong_result_or_diagnostic_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wrong_result: bool,
    diagnostic_timeout: bool,
) -> None:
    path, digest = _plain_archive(tmp_path)
    case = benchmark.ArchiveCase("failed-fixture", path, digest)
    output = tmp_path / "measurement.json"
    monkeypatch.setattr(benchmark, "build_cases", lambda _root: [case])
    result = (
        inspector.ArchiveInspectionResult("incomplete", "external_archive_inspection_timeout", "Timed out", "high")
        if wrong_result
        else inspector.ArchiveInspectionResult("clean", case.code, "Clean", "low", digest)
    )
    monkeypatch.setattr(inspector, "inspect_archive_offline", lambda *_args, **_kwargs: result)

    def timed_out(*_args: Any, **_kwargs: Any) -> Any:
        # Baseline samples must already be durable before profiling starts.
        checkpoint = json.loads(output.read_text(encoding="utf-8"))
        assert checkpoint["complete"] is False
        assert len(checkpoint["cases"][0]["samples"]) == 1
        if diagnostic_timeout:
            raise subprocess.TimeoutExpired(["synthetic-diagnostic"], 2.5)
        return {}

    monkeypatch.setattr(benchmark, "_profile", timed_out)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--samples", "1", "--profile-samples", "1", "--output", str(output)])
    assert benchmark.main() == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["complete"] is True
    assert report["expected_results_verified"] is not wrong_result
    assert report["diagnostic_failures"] == int(diagnostic_timeout)
    assert report["cases"][0]["diagnostic_failures"] == (
        [{"attempt": 1, "error": "TimeoutExpired"}] if diagnostic_timeout else []
    )
    assert report["cases"][0]["samples"][0]["status"] == result.status


@pytest.mark.parametrize("after_inspection", ["unchanged", "content_changed", "hardlink", "symlink", "writable"])
def test_actual_inspection_is_reverified_before_local_launch(tmp_path: Path, after_inspection: str) -> None:
    from codex_plugin_scanner.guard.local_supply_chain import _bound_external_archive_launch_command
    from codex_plugin_scanner.guard.runtime.restricted_archive_contract import RestrictedArchiveDownload

    path, digest = _plain_archive(tmp_path)
    inspected = inspector.inspect_archive_offline(path, expected_sha256=digest)
    assert inspected.status == "clean"
    source = "https://packages.example.invalid/qualification.tar"
    download = RestrictedArchiveDownload(
        path=path, sha256=digest, size=path.stat().st_size, source_url=source, final_url=source
    )
    if after_inspection == "content_changed":
        path.chmod(0o600)
        with path.open("r+b") as archive:
            archive.seek(512)
            archive.write(b"modified data")
        path.chmod(0o400)
    elif after_inspection == "hardlink":
        os.link(path, tmp_path / "untrusted-alias")
    elif after_inspection == "symlink":
        moved = tmp_path / "moved.tar"
        path.rename(moved)
        path.symlink_to(moved)
    elif after_inspection == "writable":
        path.chmod(0o600)
    command = _bound_external_archive_launch_command(
        ["npm", "install", f"fixture@{source}"],
        evaluation=SimpleNamespace(external_archive_downloads=(download,)),
    )
    if after_inspection == "unchanged":
        assert command == ["npm", "install", f"fixture@{path}"]
    else:
        assert command is None


@pytest.mark.parametrize(
    ("fixture", "decision", "code"),
    [
        ("clean", "ask", "external_tarball_source"),
        ("unsafe", "block", "tarball_zip_slip"),
        ("malformed", "block", "external_archive_inspection_incomplete"),
    ],
)
def test_package_scan_keeps_approval_and_incomplete_semantics_with_real_inspector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    decision: str,
    code: str,
) -> None:
    from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
    from codex_plugin_scanner.guard.runtime.restricted_archive_contract import RestrictedArchiveDownload

    if fixture == "malformed":
        path = tmp_path / "malformed.tgz"
        path.write_bytes(b"not an archive")
        path.chmod(0o400)
    else:
        name = "package/readme" if fixture == "clean" else "../outside"
        path = benchmark.archive_blob(tmp_path, fixture, [(name, b"ordinary data")])
    source = "https://packages.example.invalid/qualification.tgz"
    download = RestrictedArchiveDownload(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        size=path.stat().st_size,
        source_url=source,
        final_url=source,
    )
    monkeypatch.setattr(evaluator, "_download_external_tarball", lambda *_args, **_kwargs: download)
    scanned, retained = evaluator._scan_external_tarball(source, retain_download=True)
    assert scanned is not None
    assert (scanned["decision"], scanned["code"]) == (decision, code)
    if fixture == "clean":
        assert retained is download
        assert path.exists()
    else:
        assert retained is None
        assert not path.exists()
