"""Semantic and reporting gates for the offline-scanner qualification runner."""

from __future__ import annotations

import importlib
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from codex_plugin_scanner.guard.secrets import secret_detection as detection
from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def benchmark(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("bench_guard_secret_scans")


def test_all_provider_context_and_caller_hmac_expectations(benchmark: ModuleType) -> None:
    report = benchmark._qualify_detector()
    assert report["provider_rules"] == 17
    assert report["context_examples"] >= 14
    assert report["independent_expectations_passed"] is True
    assert len(report["public_hmac_sha256"]) == 64


def test_qualification_rejects_provider_coverage_loss(benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detection, "SECRET_RULES", detection.SECRET_RULES[1:])
    with pytest.raises(RuntimeError, match="full catalog"):
        benchmark._qualify_detector()


def test_qualification_rejects_tenant_independent_fingerprint(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(detection.SecretFinding, "fingerprint", lambda self, key: "0" * 64)
    with pytest.raises(RuntimeError, match="HMAC"):
        benchmark._qualify_detector()


def test_staged_finding_workload_really_differs_from_working_tree(benchmark: ModuleType, tmp_path: Path) -> None:
    fixtures = importlib.import_module("secret_scan_benchmark_fixtures")
    case = fixtures.Workload("staged", "staged", 17, 512, content="providers", unstaged_change=True)
    target = tmp_path / "repository"
    dimensions = fixtures.create_fixture(target, case)
    staged = scan_staged_secrets(target, max_findings=10_000)
    working = scan_repository_secrets(target)
    assert working.findings == ()
    assert len(staged.findings) == 17
    assert staged.files_scanned == dimensions["file_occurrences"] == 17
    assert staged.bytes_scanned == 17 * 512
    assert not staged.errors and not staged.truncated
    checks = benchmark._cli_contracts(ROOT, target, "staged", has_findings=True)
    assert {check["exit"] for check in checks["checks"]} == {0, 2, 3}


def test_history_workload_keeps_repeated_blob_occurrences(benchmark: ModuleType, tmp_path: Path) -> None:
    fixtures = importlib.import_module("secret_scan_benchmark_fixtures")
    case = fixtures.Workload("history", "history", 2, 2048, True, "catalog")
    target = tmp_path / "repository"
    dimensions = fixtures.create_fixture(target, case)
    result = scan_repository_secrets(target, include_history=True, max_findings=10_000)
    assert result.commits_scanned == 6
    assert result.files_scanned == dimensions["file_occurrences"] == 14
    assert result.bytes_scanned == 14 * 2048
    assert len(result.findings) == 14 * 17
    assert len({finding.commit for finding in result.findings if finding.commit}) == 6
    assert not result.truncated and not result.errors


def test_failed_file_data_eviction_cannot_claim_cold_cache(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache = importlib.import_module("secret_scan_benchmark_cache")
    if cache.sys.platform != "linux" or not hasattr(cache.os, "posix_fadvise"):
        pytest.skip("Linux cache preparation contract")
    (tmp_path / "data").write_bytes(b"A" * 4096)
    monkeypatch.setattr(cache, "_resident_pages", lambda fd, size: (1, 1))
    with pytest.raises(RuntimeError, match="refusing a cold-cache label"):
        cache.prepare_cache(tmp_path, "evicted")


def test_small_sample_percentile_preserves_outlier(benchmark: ModuleType) -> None:
    result = benchmark._summary([{"wall_ms": value} for value in (1, 1, 2, 3, 100)])
    assert result["wall_ms"] == {"median": 2, "p95": 100, "min": 1, "max": 100, "samples": 5}


def test_cli_exit_mismatch_fails_qualification(benchmark: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(benchmark.CLIExecutionError, match="CLI exit 2 differs from expected 0") as caught:
        benchmark._full_cli(ROOT, tmp_path / "absent", "working", expected_exit=0)
    assert caught.value.evidence["cli_exit"] == 2
    assert caught.value.evidence["stderr_bytes"] > 0
    assert caught.value.evidence["command_started_utc"] <= caught.value.evidence["command_finished_utc"]


def test_failed_cli_evidence_retains_only_bounded_diagnostics(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sensitive = "candidate-fragment-must-never-be-in-evidence"
    monkeypatch.setattr(
        benchmark.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 2, b"", f"No such file or directory: {sensitive}".encode()
        ),
    )
    with pytest.raises(benchmark.CLIExecutionError) as caught:
        benchmark._full_cli(ROOT, tmp_path, "working")
    evidence = caught.value.evidence
    assert evidence["diagnostic_categories"] == ["missing-path"]
    assert evidence["failure_category"] == "unexpected-exit"
    assert len(evidence["stderr_sha256"]) == 64
    assert sensitive not in json.dumps(evidence)


def test_cli_timeout_preserves_partial_output_digest_without_contents(
    benchmark: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired([], 120, output=b"private partial result", stderr=b"private error")

    monkeypatch.setattr(benchmark.subprocess, "run", timeout)
    with pytest.raises(benchmark.CLIExecutionError, match="120-second") as caught:
        benchmark._full_cli(ROOT, tmp_path, "working")
    assert caught.value.evidence["failure_category"] == "command-timeout"
    assert caught.value.evidence["stdout_bytes"] == len(b"private partial result")
    assert "private" not in json.dumps(caught.value.evidence)


def test_measurement_lock_releases_after_failed_workload(benchmark: ModuleType, tmp_path: Path) -> None:
    fcntl = pytest.importorskip("fcntl")
    lock_path = tmp_path / "measurement.lock"
    with pytest.raises(RuntimeError, match="workload failed"), benchmark._measurement_block(lock_path):
        with lock_path.open("a") as competing, pytest.raises(BlockingIOError):
            fcntl.flock(competing.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        raise RuntimeError("workload failed")
    with lock_path.open("a") as subsequent:
        fcntl.flock(subsequent.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(subsequent.fileno(), fcntl.LOCK_UN)


def test_checkpoint_cannot_report_partial_matrix_as_complete(benchmark: ModuleType, tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    args = SimpleNamespace(source_root=ROOT, output=output, repeats=5, measurement_lock=None, contracts_only=False)
    benchmark._write_report(args, {}, {}, {}, [{"case": "finished"}], ["prewarmed"], complete=False)
    partial = output.read_text()
    assert json.loads(partial)["run_complete"] is False
    with pytest.raises(TypeError):
        benchmark._write_report(args, {}, {}, {}, [{"bad": object()}], ["prewarmed"], complete=True)
    assert output.read_text() == partial
    benchmark._write_report(args, {}, {}, {}, [{"case": "finished"}], ["prewarmed"], complete=True)
    assert json.loads(output.read_text())["run_complete"] is True


@pytest.mark.parametrize("path", ["src/config.ts", ".env.production", "docs/setup.md"])
def test_ordinary_provider_matches_never_split_whole_file_context(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    token = "ghp_" + "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY"

    def unexpected(*args: object, **kwargs: object) -> str:
        raise AssertionError("ordinary provider matches must not materialize surrounding lines")

    # docs paths still consult fixture context; this test uses a documentation
    # suffix outside a sample directory to isolate the distinction.
    if path.startswith("docs/"):
        path = "guide.md"
    monkeypatch.setattr(detection, "_surrounding_context", unexpected)
    result = detection.scan_secret_text(f'TOKEN="{token}"\n' * 200, path=path, max_findings=1000)
    assert len(result.findings) == 200


@pytest.mark.parametrize(
    ("path", "prefix", "suffix", "detected"),
    [
        ("tests/config.ts", "// fixture\n", "", False),
        ("tests/config.ts", "// production\n", "", True),
        ("tests/.env", "// fixture\n", "", True),
        ("tests/config.ts", "// fixture\n\n\n\n", "", True),
        ("tests/config.ts", "", "\n\n// fixture", False),
        ("tests/config.ts", "// café\r\n// 雪\n// fixture\n", "", False),
        ("tests/config.ts", "// café\u2028// fixture\n", "", False),
    ],
)
def test_lazy_context_keeps_neighboring_line_suppression(path: str, prefix: str, suffix: str, detected: bool) -> None:
    token = "ghp_" + "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY"
    result = detection.scan_secret_text(prefix + f'TOKEN="{token}"' + suffix, path=path)
    assert bool(result.findings) is detected


def test_explicit_placeholder_context_precedes_sensitive_file_exception() -> None:
    token = "ghp_" + "example" + "7tH3mZ5qP9vC2xL4nR6sB8wF1jK0dE5uA7iY"
    assert detection.scan_secret_text(f'TOKEN="{token}"', path="tests/.env").findings == ()
