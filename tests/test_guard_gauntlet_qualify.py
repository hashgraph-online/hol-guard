"""Qualification driver tests: retry policy, caches and command construction. No live inference."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ci.gauntlet import qualify, qualify_setup

SHA = "a" * 40


def test_retry_policy_only_retries_recoverable_outcomes_within_budget() -> None:
    retryable_failed = [{"id": "x", "outcome": "inference-error"}]
    assert qualify.retryable(retryable_failed, 1, 2)
    assert not qualify.retryable(retryable_failed, 2, 2)
    assert not qualify.retryable([], 1, 2)
    for outcome in ("false-positive", "false-negative", "task-incomplete"):
        assert not qualify.retryable([{"id": "x", "outcome": outcome}], 1, 2)
    assert not qualify.retryable(
        [{"id": "x", "outcome": "not-exercised"}, {"id": "y", "outcome": "false-negative"}], 1, 3
    )


def test_macos_platform_maps_host_to_the_ci_wheel_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(qualify_setup.platform, "machine", lambda: "arm64")
    assert qualify_setup.macos_platform() == ("macosx_11_0_arm64", "aarch64-apple-darwin", "11.0")
    monkeypatch.setattr(qualify_setup.platform, "machine", lambda: "x86_64")
    assert qualify_setup.macos_platform() == ("macosx_13_0_x86_64", "x86_64-apple-darwin", "13.0")
    monkeypatch.setattr(qualify_setup.platform, "machine", lambda: "riscv64")
    with pytest.raises(RuntimeError):
        qualify_setup.macos_platform()
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="--wheel"):
        qualify_setup.macos_platform()


def test_gnu_sed_detection_prefers_path_then_gnubin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gnubin = tmp_path / "gnubin"
    gnubin.mkdir()
    (gnubin / "sed").write_text("#!/bin/sh\n")
    monkeypatch.setattr(qualify_setup, "GNU_SED_DIRS", (gnubin, tmp_path / "empty"))

    def gnu(_argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 0, stdout="sed (GNU sed) 4.9\n", stderr="")

    assert qualify_setup.gnu_sed_dir(probe=gnu) is None

    def bsd(_argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], 1, stdout="", stderr="sed: illegal option")

    assert qualify_setup.gnu_sed_dir(probe=bsd) == gnubin
    monkeypatch.setattr(qualify_setup, "GNU_SED_DIRS", (tmp_path / "empty",))
    with pytest.raises(RuntimeError):
        qualify_setup.gnu_sed_dir(probe=bsd)


def test_attempt_command_and_environment(tmp_path: Path) -> None:
    argv = qualify.attempt_argv(
        python=tmp_path / "candidate" / ".venv" / "bin" / "python",
        effort="medium",
        sdk_root=tmp_path / "sdk",
        jobs=4,
        host_slots=8,
        max_load=32.0,
        max_load_wait=600.0,
        sha=SHA,
        candidate_sha="b" * 40,
        evidence=tmp_path / "evidence" / "attempt-1",
        work_root=tmp_path / "work-1",
        timeout=300,
        max_rounds=32,
    )
    assert argv[1:3] == ["-m", "ci.gauntlet"]
    for flag in ("--native-luna-route", "--fail-fast", "--host-slots", "--max-load", "--expected-source-sha"):
        assert flag in argv
    assert argv[argv.index("--max-load") + 1] == "32.0"
    assert argv[argv.index("--max-load-wait") + 1] == "600.0"
    assert "low" not in argv
    assert argv[argv.index("--candidate-sha") + 1] == "b" * 40

    base = dict(os.environ)
    base.update(
        GUARD_GAUNTLET_PROVIDER_URL="https://x",
        GUARD_GAUNTLET_MODEL="m",
        GUARD_GAUNTLET_PROVIDER_IDENTITY="i",
        GUARD_GAUNTLET_API_KEY="secret",
        GUARD_GAUNTLET_REASONING_EFFORT="high",
        VIRTUAL_ENV="/elsewhere",
    )
    env = qualify.attempt_env(
        base, venv_bin=tmp_path / "candidate/.venv/bin", sdk_root=tmp_path / "sdk", gnu_sed=tmp_path / "gnubin"
    )
    assert not any(name in env for name in qualify.PROVIDER_ENV)
    assert "VIRTUAL_ENV" not in env
    assert env["PATH"].split(os.pathsep)[:3] == [
        str(tmp_path / "gnubin"),
        str(tmp_path / "candidate/.venv/bin"),
        str(tmp_path / "sdk" / "node_modules" / ".bin"),
    ]


def test_sdk_cache_installs_once_per_lock_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = json.dumps({"dependencies": {"@oh-my-pi/pi-coding-agent": "18.1.18"}}).encode()
    lock = b'{"lockfileVersion": 3}'
    monkeypatch.setattr(
        qualify_setup, "git_show", lambda _r, _s, path: package if path.endswith("package.json") else lock
    )
    calls: list[list[str]] = []

    def fake_logged(argv: list[str], *, cwd: Path, log: Path, **_kw: Any) -> None:
        calls.append(argv)
        assert argv[0] == "npm" and log.name == "setup.log"
        package_dir = cwd / "node_modules" / "@oh-my-pi" / "pi-coding-agent"
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text('{"version": "18.1.18"}')

    monkeypatch.setattr(qualify_setup, "run_logged", fake_logged)
    setup_log = tmp_path / "run" / "logs" / "setup.log"
    first = qualify_setup.ensure_sdk(tmp_path / "cache", tmp_path / "repo", SHA, setup_log)
    assert first["lock_sha256"] == hashlib.sha256(lock).hexdigest()
    assert first["omp_version"] == "18.1.18"
    assert len(calls) == 1
    # A second driver reuses the completed prefix without another npm install.
    second = qualify_setup.ensure_sdk(tmp_path / "cache", tmp_path / "repo", SHA, setup_log)
    assert second["root"] == first["root"] and len(calls) == 1


def test_wheel_cache_requires_a_matching_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(qualify_setup.platform, "machine", lambda: "arm64")
    # The rebuild path must not depend on this host actually carrying cargo/jq.
    monkeypatch.setattr(qualify_setup.shutil, "which", lambda tool: "/bin/" + tool)
    tag = "macosx_11_0_arm64"
    store = tmp_path / "cache" / "wheels" / f"{SHA}-{tag}"
    for level in (store.parent.parent, store.parent, store):
        level.mkdir(mode=0o700)
    wheel_bytes = b"fake wheel bytes"
    (store / f"hol_guard-1.0.0-{tag}.whl").write_bytes(wheel_bytes)
    calls: list[list[str]] = []

    def fake_logged(argv: list[str], *, cwd: Path, log: Path, **_kw: Any) -> None:
        calls.append(argv)
        if argv[:3] == ["nice", "-n", "10"]:
            dist = cwd / "native-dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / f"hol_guard-1.0.0-{tag}.whl").write_bytes(b"new wheel bytes")

    monkeypatch.setattr(qualify_setup, "run_logged", fake_logged)

    # A stale digest record rebuilds; the cache stores and digests the new wheel.
    (store / "wheel.sha256").write_text("0" * 64 + "\n")
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    digest = hashlib.sha256(b"new wheel bytes").hexdigest()
    assert result == {"path": str(store / f"hol_guard-1.0.0-{tag}.whl"), "sha256": digest, "cached": False}
    assert any(argv[:3] == ["nice", "-n", "10"] and argv[-1].endswith("build-native-wheel-macos.sh") for argv in calls)
    assert (store / "wheel.sha256").read_text().strip() == digest

    calls.clear()
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    assert result["cached"] is True and not calls


def _args(tmp_path: Path, **overrides: Any) -> SimpleNamespace:
    defaults = {
        "sha": SHA,
        "candidate_sha": None,
        "attempts": 2,
        "jobs": 4,
        "host_slots": 8,
        "max_load": 32.0,
        "max_load_wait": 600.0,
        "effort": "medium",
        "cache_root": tmp_path / "cache",
        "run_root": tmp_path / "run",
        "work_parent": tmp_path / "w",
        "wheel": None,
        "sdk_root": tmp_path / "sdk",
        "keep_work": False,
        "timeout": 300.0,
        "max_inference_rounds": 32,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, summaries: list[dict[str, Any]]) -> list:
    """Stub caches, the candidate worktree and the runner; return the verify calls."""
    sdk = tmp_path / "sdk"
    (sdk / "node_modules" / "@oh-my-pi" / "pi-coding-agent").mkdir(parents=True)
    (sdk / "node_modules" / "@oh-my-pi" / "pi-coding-agent" / "package.json").write_text('{"version": "18.1.18"}')
    monkeypatch.setattr(
        qualify_setup,
        "preflight",
        lambda _repo: {
            "verifier_sha": "c" * 40,
            "verifier_clean": True,
            "verifier_on_main": True,
            "independent_verifier": True,
            "gnu_sed": None,
        },
    )
    monkeypatch.setattr(qualify_setup, "ensure_commit", lambda *_a: None)
    monkeypatch.setattr(qualify_setup, "git_show", lambda *_a, **_k: b'{"lockfileVersion": 3}')
    wheel = tmp_path / "hol_guard-1.0.0-any.whl"
    wheel.write_bytes(b"wheel")
    monkeypatch.setattr(
        qualify_setup,
        "ensure_wheel",
        lambda *_a, **_k: {"path": str(wheel), "sha256": hashlib.sha256(b"wheel").hexdigest(), "cached": True},
    )

    def fake_candidate(_repo: Path, _sha: str, run_root: Path, _wheel: Path) -> Path:
        candidate = run_root / "candidate"
        (candidate / ".venv" / "bin").mkdir(parents=True)
        return candidate

    monkeypatch.setattr(qualify, "prepare_candidate", fake_candidate)
    monkeypatch.setattr(qualify, "_remove_candidate", lambda *_a: True)

    def fake_attempt(argv: list[str], *, cwd: Path, env: dict, log: Path) -> int:
        evidence = Path(argv[argv.index("--output") + 1])
        summary = summaries.pop(0)
        if summary is not None:
            evidence.mkdir(parents=True)
            (evidence / "summary.json").write_text(json.dumps(summary))
        return 0 if summary is None or summary.get("pass") else 1

    monkeypatch.setattr(qualify, "run_attempt", fake_attempt)
    verify_calls: list = []
    import ci.gauntlet.verify as verify

    monkeypatch.setattr(
        verify,
        "verify_report",
        lambda directory, **kw: verify_calls.append((directory, kw)) or {"verified": True, "merge_qualified": True},
    )
    return verify_calls


def _summary(cases: list[dict[str, Any]], passed: bool, qualified: bool = True) -> dict[str, Any]:
    return {
        "pass": passed,
        "merge_qualified": passed and qualified,
        "stopped_early": False,
        "cases": cases,
        "inference_usage": {"prompt_tokens": 5, "rounds": 1, "rounds_with_usage": 1},
    }


def test_qualifying_attempt_verifies_and_returns_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cases = [{"id": "a", "outcome": "pass", "reason": "ok"}]
    verify_calls = _fake_setup(monkeypatch, tmp_path, [_summary(cases, True)])
    result_code = qualify.main(_args(tmp_path))
    assert result_code == 0
    assert len(verify_calls) == 1
    _directory, kwargs = verify_calls[0]
    assert kwargs["source_root"] == tmp_path / "run" / "candidate"
    assert kwargs["expected_sha"] == SHA
    result = json.loads((tmp_path / "run" / "qualification.json").read_text())
    assert result["qualified"] is True and result["independent_verifier"] is True
    assert result["attempts"][0]["pass"] is True
    # Passing attempts remove their short work root; it stays out of `kept`.
    assert result["attempts"][0]["work_root"] == str((tmp_path / "w" / "1").resolve())
    assert not (tmp_path / "w" / "1").exists()
    assert result["attempts"][0]["work_root"] not in result["kept"]


def test_retryable_outcomes_earn_one_fresh_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    failing = {"id": "a", "outcome": "inference-error", "reason": "no live turn"}
    verify_calls = _fake_setup(
        monkeypatch, tmp_path, [_summary([failing], False), _summary([{"id": "a", "outcome": "pass"}], True)]
    )
    assert qualify.main(_args(tmp_path)) == 0
    assert len(verify_calls) == 1
    result = json.loads((tmp_path / "run" / "qualification.json").read_text())
    assert [Path(r["work_root"]).name for r in result["attempts"]] == ["1", "2"]
    # The retryable first attempt's work root is kept for diagnosis; the passing one is removed.
    assert result["attempts"][0]["work_root"] in result["kept"]
    assert (tmp_path / "w" / "1").exists() and not (tmp_path / "w" / "2").exists()


def test_product_outcomes_stop_without_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    failing = {"id": "a", "outcome": "false-negative", "reason": "protected effect occurred"}
    verify_calls = _fake_setup(monkeypatch, tmp_path, [_summary([failing], False)])
    assert qualify.main(_args(tmp_path, attempts=3)) == 1
    result = json.loads((tmp_path / "run" / "qualification.json").read_text())
    assert len(result["attempts"]) == 1 and result["qualified"] is False
    assert not verify_calls
    assert result["attempts"][0]["work_root"] in result["kept"]


def test_driver_stdout_is_exactly_one_json_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    cases = [{"id": "a", "outcome": "pass", "reason": "ok"}]
    _fake_setup(monkeypatch, tmp_path, [_summary(cases, True)])
    assert qualify.main(_args(tmp_path)) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out.rstrip("\n"))["qualified"] is True
    assert len(captured.out.splitlines()) == 1
    assert all(line.startswith("qualify:") for line in captured.err.splitlines())


def test_a_missing_summary_or_failed_verification_never_qualifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_setup(monkeypatch, tmp_path, [None])
    assert qualify.main(_args(tmp_path)) == 1
    result = json.loads((tmp_path / "run" / "qualification.json").read_text())
    assert result["attempts"][0]["error"] and result["qualified"] is False

    cases = [{"id": "a", "outcome": "pass", "reason": "ok"}]
    (tmp_path / "second").mkdir(mode=0o700)
    _fake_setup(monkeypatch, tmp_path / "second", [_summary(cases, True)])
    import ci.gauntlet.verify as verify

    monkeypatch.setattr(verify, "verify_report", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("stale")))
    assert qualify.main(_args(tmp_path / "second")) == 1
    result = json.loads((tmp_path / "second" / "run" / "qualification.json").read_text())
    assert result["qualified"] is False and "verify_error" in result["attempts"][0]


def test_driver_repo_is_the_checkout_root():
    from ci.gauntlet import qualify

    assert (qualify.REPO / "ci" / "gauntlet" / "qualify.py").is_file()


def test_setup_command_group_is_reaped_when_the_driver_is_interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "child.pid"
    real_wait = subprocess.Popen.wait
    waits = {"n": 0}

    def interrupted(self: subprocess.Popen[Any], timeout: float | None = None) -> int:
        waits["n"] += 1
        if waits["n"] > 1:
            return real_wait(self, timeout)
        # The interrupt lands only after the child started and reported its group.
        deadline = time.monotonic() + 10
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess.Popen, "wait", interrupted)
    with pytest.raises(KeyboardInterrupt):
        qualify_setup.run_logged(
            ["sh", "-c", f"sleep 30 & echo $$ $! > {pid_file}; wait"],
            cwd=tmp_path,
            log=tmp_path / "setup.log",
        )
    pgid, child = (int(value) for value in pid_file.read_text().split())
    for _ in range(50):
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("setup process group survived the interrupted driver")
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_cold_wheel_build_requires_cargo_and_jq(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(qualify_setup.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(qualify_setup.shutil, "which", lambda _tool: None)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path / "no-home"))
    with pytest.raises(RuntimeError, match="cargo"):
        qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    monkeypatch.setattr(qualify_setup.shutil, "which", lambda tool: "/bin/" + tool if tool == "cargo" else None)
    with pytest.raises(RuntimeError, match="jq"):
        qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run")
    # A supplied wheel skips the toolchain check entirely.
    wheel = tmp_path / "hol_guard-1.0.0-any.whl"
    wheel.write_bytes(b"wheel")
    result = qualify_setup.ensure_wheel(tmp_path / "cache", tmp_path / "repo", SHA, tmp_path / "run", wheel=wheel)
    assert result["path"] == str(wheel)


def test_parser_and_list_do_not_require_a_posix_uid(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """The CLI stays importable and listable where ``os.getuid`` does not exist."""
    from ci.gauntlet import __main__ as cli

    monkeypatch.delattr(os, "getuid")
    monkeypatch.setattr("sys.argv", ["gauntlet", "list"])
    assert cli.main() == 0
    assert isinstance(json.loads(capsys.readouterr().out), list)


def test_qualify_requires_a_posix_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(ValueError, match="POSIX"):
        qualify.main(_args(tmp_path))


def test_prepare_failure_still_cleans_the_candidate_worktree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_setup(monkeypatch, tmp_path, [_summary([], True)])

    def fake_prepare(_repo: Path, _sha: str, run_root: Path, _wheel: Path) -> Path:
        (run_root / "candidate").mkdir(parents=True)
        raise RuntimeError("wheel install failed")

    removed: list[Path] = []
    monkeypatch.setattr(qualify, "prepare_candidate", fake_prepare)
    monkeypatch.setattr(qualify, "_remove_candidate", lambda _r, candidate: removed.append(candidate) or True)
    assert qualify.main(_args(tmp_path)) == 1
    assert removed == [(tmp_path / "run" / "candidate").resolve()]
    result = json.loads((tmp_path / "run" / "qualification.json").read_text())
    assert result["cleanup"] == ["candidate-worktree-removed"]
    assert "wheel install failed" in result["error"]


def test_remove_candidate_tolerates_a_missing_worktree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pruned: list[list[str]] = []
    monkeypatch.setattr(qualify_setup, "git", lambda _r, *args: pruned.append(list(args)) or "")
    assert qualify._remove_candidate(tmp_path, tmp_path / "missing") is True
    assert pruned == [["worktree", "prune"]]


@pytest.mark.parametrize(
    "field, value",
    [
        ("max_load", float("nan")),
        ("max_load", float("inf")),
        ("max_load", float("-inf")),
        ("max_load_wait", float("nan")),
        ("max_load_wait", float("inf")),
    ],
)
def test_driver_rejects_non_finite_load_bounds(tmp_path: Path, field: str, value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        qualify.main(_args(tmp_path, **{field: value}))


@pytest.mark.parametrize(
    "flag, value",
    [
        ("--max-load", "nan"),
        ("--max-load", "inf"),
        ("--max-load-wait", "nan"),
        ("--max-load-wait", "inf"),
    ],
)
def test_run_cli_rejects_non_finite_load_bounds(tmp_path: Path, flag: str, value: str) -> None:
    argv = [
        sys.executable,
        "-m",
        "ci.gauntlet",
        "run",
        "--expected-source-sha",
        "a" * 40,
        "--output",
        str(tmp_path / "o"),
        "--provider-url",
        "https://x",
        "--model",
        "m",
        "--provider-identity",
        "i",
        flag,
        value,
    ]
    if flag == "--max-load-wait":
        argv += ["--max-load", "8"]
    env = {**os.environ, "GUARD_GAUNTLET_API_KEY": "k"}
    result = subprocess.run(argv, cwd=qualify.REPO, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 2
    assert "finite" in result.stderr
