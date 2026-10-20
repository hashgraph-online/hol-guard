"""One-command qualification driver: cached inputs, a pristine worktree, bounded fresh runs.

Run this module's ``qualify`` command from a clean trusted main checkout. Each
attempt is a complete fresh ``run`` of the candidate's own code in a detached
worktree; retries cover only infrastructure outcomes and the in-process verifier
here is trusted only when ``independent_verifier`` is reported true.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import lane_preflight, qualify_setup
from .extension_adapters import RELEASE_ASSETS_ENV
from .fixtures import create_numbered_dir
from .lane_coverage import lane_coverage
from .parallel import terminate_as_exit
from .source_identity import SHA
from .timing import PhaseTimings

REPO = Path(__file__).resolve().parents[2]
REAP_SECONDS = 150.0
RETRYABLE_OUTCOMES = frozenset({"not-exercised", "inference-error", "harness-error"})
PROVIDER_ENV = (
    "GUARD_GAUNTLET_PROVIDER_URL",
    "GUARD_GAUNTLET_MODEL",
    "GUARD_GAUNTLET_PROVIDER_IDENTITY",
    "GUARD_GAUNTLET_API_KEY",
    "GUARD_GAUNTLET_REASONING_EFFORT",
)


# The most fresh rounds one invocation may spend before it reports what it reached.
ATTEMPT_LIMIT = 10


def progress(message: str) -> None:
    """One terse status line; the JSON result is the only stdout payload."""
    print(f"qualify: {message}", file=sys.stderr, flush=True)


def retryable(failed: list[dict[str, Any]], attempt: int, attempts: int) -> bool:
    """Retry only recoverable categories; product outcomes and interruptions never earn another run.

    A case that interrupted ordinary work stays failed: an intermittent warning cannot be retried away.
    """
    return (
        bool(failed)
        and attempt < attempts
        and all(entry["outcome"] in RETRYABLE_OUTCOMES and not entry.get("interrupted") for entry in failed)
    )


def attempt_argv(
    *,
    python: Path,
    effort: str,
    sdk_root: Path,
    jobs: int,
    host_slots: int,
    max_load: float,
    max_load_wait: float,
    sha: str,
    candidate_sha: str | None,
    evidence: Path,
    work_root: Path,
    timeout: float,
    max_rounds: int,
    native_route: str | None = None,
) -> list[str]:
    """The candidate's own runner invocation for one complete fresh attempt."""
    argv = [
        str(python),
        "-m",
        "ci.gauntlet",
        "run",
        *(["--native-route", native_route] if native_route else ["--native-luna-route"]),
        "--reasoning-effort",
        effort,
        "--sdk-root",
        str(sdk_root),
        "--jobs",
        str(jobs),
        "--host-slots",
        str(host_slots),
        "--max-load",
        str(max_load),
        "--max-load-wait",
        str(max_load_wait),
        "--fail-fast",
        "--expected-source-sha",
        sha,
        "--output",
        str(evidence),
        "--work-root",
        str(work_root),
        "--timeout",
        str(timeout),
        "--max-inference-rounds",
        str(max_rounds),
    ]
    if candidate_sha is not None:
        argv += ["--candidate-sha", candidate_sha]
    return argv


def attempt_env(base: dict[str, str], *, venv_bin: Path, sdk_root: Path, gnu_sed: Path | None = None) -> dict[str, str]:
    """Strip provider credentials and put the candidate venv, SDK and GNU sed first."""
    env = {name: value for name, value in base.items() if name not in PROVIDER_ENV and name != "VIRTUAL_ENV"}
    parts = [str(venv_bin), str(sdk_root / "node_modules" / ".bin")]
    if gnu_sed is not None:
        parts.insert(0, str(gnu_sed))
    env["PATH"] = os.pathsep.join(parts) + os.pathsep + env.get("PATH", "")
    return env


def attempt_work_root(parent: Path) -> Path:
    """Allocate a short copy-safe attempt workspace; never reuse an existing entry."""
    return create_numbered_dir(qualify_setup.private_dir(parent, tighten=qualify_setup.driver_owned(parent)))


def _interrupted(case: dict[str, Any]) -> bool:
    """Ordinary work that raised any interruption event; protection denies are expected and do not count."""
    record = case.get("interruptions")
    return isinstance(record, dict) and record.get("benign") is True and bool(record.get("events"))


def summarize_attempt(
    attempt: int, evidence: Path, exit_code: int, elapsed: float, summary: dict[str, Any] | None
) -> dict[str, Any]:
    """One attempt record; a missing summary means the run never reported."""
    record: dict[str, Any] = {
        "attempt": attempt,
        "evidence": str(evidence),
        "exit": exit_code,
        "elapsed_seconds": round(elapsed, 3),
        "pass": False,
        "merge_qualified": False,
        "stopped_early": False,
    }
    if summary is None:
        record["error"] = "runner did not write summary.json"
        return record
    cases = summary.get("cases", [])
    interruptions = summary.get("interruptions") if isinstance(summary.get("interruptions"), dict) else None
    gaps = {g.get("id") for g in summary.get("known_gaps", []) if isinstance(g, dict)}
    record.update(
        {
            # A summary that omits the interruption metrics cannot prove a silent run.
            "pass": summary.get("pass") is True
            and interruptions is not None
            and interruptions.get("benign_interruptions") == 0
            and isinstance(interruptions.get("benign_cases"), int)
            and interruptions["benign_cases"] > 0,
            "interruptions": interruptions,
            "known_gaps": summary.get("known_gaps", []),
            "merge_qualified": summary.get("merge_qualified") is True,
            "stopped_early": summary.get("stopped_early") is True,
            "outcomes": dict(Counter(case.get("outcome") for case in cases)),
            "failed": [
                {
                    "id": case.get("id"),
                    "outcome": case.get("outcome"),
                    "reason": case.get("reason"),
                    "known_gap": case.get("id") in gaps,
                    "interrupted": _interrupted(case),
                }
                for case in cases
                if case.get("outcome") != "pass"
            ],
            "inference_usage": summary.get("inference_usage"),
            # How much of the catalog this attempt reached. A truncated attempt
            # that reports only its pass count reads as a clean record of the
            # whole profile, which is how 59% of the catalog went unrun through
            # a release sweep without anyone noticing.
            "case_coverage": summary.get("case_coverage"),
        }
    )
    return record


def run_attempt(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log: Path,
    on_started: Callable[[], None] | None = None,
) -> int:
    """Run one attempt in its own process group; interrupts reap the whole group.

    `on_started` fires once the child exists. An interrupt arriving after that
    leaves no attempt record, so without the callback the report would say the
    lane was never driven while inference had already run against the candidate.
    """
    with log.open("wb") as stream:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True
        )
        if on_started is not None:
            on_started()
        try:
            return process.wait()
        except BaseException:
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=REAP_SECONDS)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError, PermissionError):
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=30)
            raise


def prepare_candidate(repo: Path, sha: str, run_root: Path, wheel: Path) -> Path:
    """Create a pristine detached worktree and install the exact-source wheel into it."""
    candidate = run_root / "candidate"
    setup_log = run_root / "logs" / "setup.log"
    qualify_setup.run_logged(
        ["git", "worktree", "add", "--detach", str(candidate), sha],
        cwd=repo,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        log=setup_log,
    )
    env = {name: value for name, value in os.environ.items() if name != "VIRTUAL_ENV"}
    qualify_setup.run_logged(
        ["uv", "sync", "--frozen", "--no-dev", "--group", "ci-test", "--no-install-project", "--python", "3.12"],
        cwd=candidate,
        env=env,
        log=setup_log,
    )
    umask = os.umask(0o077)
    try:
        qualify_setup.run_logged(
            [
                "uv",
                "pip",
                "install",
                "--no-cache",
                "--python",
                str(candidate / ".venv/bin/python"),
                "--no-deps",
                str(wheel),
            ],
            cwd=candidate,
            env=env,
            log=setup_log,
        )
    finally:
        os.umask(umask)
    resolved = subprocess.check_output(
        [
            str(candidate / ".venv/bin/python"),
            "-c",
            "import codex_plugin_scanner, sys; print(codex_plugin_scanner.__file__)",
        ],
        cwd=candidate,
        env=env,
        text=True,
        timeout=60,
    ).strip()
    if not Path(resolved).resolve().is_relative_to((candidate / ".venv").resolve()):
        raise RuntimeError("the wheel did not install into the candidate venv")
    if qualify_setup.git(candidate, "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("candidate worktree is not clean after install")
    return candidate


def _remove_candidate(repo: Path, candidate: Path) -> bool:
    """Remove only the worktree this driver created, then prune stale records."""
    subprocess.run(
        ["git", "worktree", "remove", "--force", str(candidate)],
        cwd=repo,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        capture_output=True,
        text=True,
    )
    if candidate.exists():
        shutil.rmtree(candidate, ignore_errors=True)
    with suppress(Exception):
        qualify_setup.git(repo, "worktree", "prune")
    return not candidate.exists()


def _read_summary(evidence: Path) -> dict[str, Any] | None:
    path = evidence / "summary.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def main(args: Any) -> int:
    """Drive cached setup, bounded fresh attempts and trusted in-process verification."""
    if os.name == "nt":
        raise ValueError("qualify requires a POSIX host")
    started = time.monotonic()
    timings = PhaseTimings()
    sha = args.sha
    native_route = getattr(args, "native_route", None)
    if native_route:
        from .luna_route import BACKENDS, parse_backend

        if args.effort not in BACKENDS[parse_backend(native_route)]:
            raise ValueError("unsupported effort for --native-route")
    if SHA.fullmatch(sha) is None:
        raise ValueError("--sha must be a full 40-character commit")
    if args.candidate_sha is not None and SHA.fullmatch(args.candidate_sha) is None:
        raise ValueError("--candidate-sha must be a full 40-character commit")
    # A clean round needs every case to comply, so the odds of one compound against
    # the number of cases. Three rounds was a budget set when a truncated attempt was
    # cheap; it is not enough to clear model noise on a product that has nothing wrong
    # with it, and running out of rounds reads the same as a real failure.
    if not 1 <= args.attempts <= ATTEMPT_LIMIT:
        raise ValueError(f"--attempts must be from 1 to {ATTEMPT_LIMIT}")
    if not 1 <= args.jobs <= 8:
        raise ValueError("--jobs must be from 1 to 8")
    if not 1 <= args.host_slots <= 64:
        raise ValueError("--host-slots must be from 1 to 64")
    if not math.isfinite(args.max_load) or not args.max_load > 0:
        raise ValueError("--max-load must be a positive finite number")
    if not math.isfinite(args.max_load_wait) or args.max_load_wait < 0:
        raise ValueError("--max-load-wait must be a finite number >= 0")
    for field in ("cache_root", "run_root", "work_parent", "wheel", "wheel_release_assets", "sdk_root"):
        value = getattr(args, field)
        if value is not None:
            setattr(args, field, Path(value).resolve())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = (args.run_root or qualify_setup.default_tmp_root() / f"{sha[:12]}-{stamp}").resolve()
    work_parent = (args.work_parent or qualify_setup.default_tmp_root() / "w").resolve()
    if run_root.exists():
        raise ValueError("run root must not already exist: " + str(run_root))
    qualify_setup.private_dir(run_root.parent, tighten=qualify_setup.driver_owned(run_root.parent))
    run_root.mkdir(mode=0o700, parents=True)
    (run_root / "logs").mkdir()

    attempts: list[dict[str, Any]] = []
    # Attempt numbers whose process started. An attempt that is interrupted
    # mid-run leaves no record, and the lane was still driven.
    driven: list[int] = []
    candidate: Path | None = None
    verify_result: dict[str, Any] | None = None
    wheel_info: dict[str, Any] | None = None
    sdk_info: dict[str, Any] | None = None
    info: dict[str, Any] = {}
    qualified = False
    prepared = False
    error = None
    try:
        with terminate_as_exit():
            qualify_setup.private_dir(args.cache_root, tighten=qualify_setup.driver_owned(args.cache_root))
            with timings.measure("preflight"):
                info = qualify_setup.preflight(REPO)
            progress(f"preflight independent_verifier={info['independent_verifier']}")
            with timings.measure("source"):
                qualify_setup.ensure_commit(REPO, sha)
            if args.sdk_root is not None:
                sdk_info = {
                    "root": str(args.sdk_root),
                    "lock_sha256": hashlib.sha256(
                        qualify_setup.git_show(REPO, sha, "ci/pi-exact-continuation/package-lock.json")
                    ).hexdigest(),
                    "omp_version": json.loads(
                        (args.sdk_root / "node_modules/@oh-my-pi/pi-coding-agent/package.json").read_text()
                    ).get("version"),
                }
            else:
                with timings.measure("sdk"):
                    sdk_info = qualify_setup.ensure_sdk(args.cache_root, REPO, sha, run_root / "logs" / "setup.log")
            progress(f"sdk {sdk_info['omp_version']} {sdk_info['lock_sha256'][:12]}")
            # One exchange before the expensive inputs: a dead lane fails here, not as
            # a catalog of inference-error cases after the wheel build and a full retry.
            # --prepare-only runs no case, so it needs no lane and must not want one.
            if not args.prepare_only:
                with timings.measure("lane"):
                    lane = lane_preflight.check_lane(
                        Path(sdk_info["root"]),
                        effort=args.effort,
                        backend=lane_preflight.backend_for(native_route),
                    )
                progress(f"lane {lane['identity']} total_tokens={lane['total_tokens']}")
            with timings.measure("wheel"):
                wheel_info = qualify_setup.ensure_wheel(
                    args.cache_root,
                    REPO,
                    sha,
                    run_root,
                    wheel=args.wheel,
                    release_assets=args.wheel_release_assets,
                    release_profile=args.release_profile_wheel,
                )
            progress(f"wheel {wheel_info['sha256'][:12]} cached={wheel_info['cached']} profile={wheel_info['profile']}")
            candidate = run_root / "candidate"
            with timings.measure("install"):
                candidate = prepare_candidate(REPO, sha, run_root, Path(wheel_info["path"]))
            progress("candidate installed")
            # --prepare-only stops here and keeps the candidate for local `run` invocations.
            prepared = args.prepare_only
            for k in range(1, (0 if prepared else args.attempts) + 1):
                evidence = run_root / "evidence" / f"attempt-{k}"
                work = attempt_work_root(work_parent)
                argv = attempt_argv(
                    python=candidate / ".venv" / "bin" / "python",
                    effort=args.effort,
                    native_route=native_route,
                    sdk_root=Path(sdk_info["root"]),
                    jobs=args.jobs,
                    host_slots=args.host_slots,
                    max_load=args.max_load,
                    max_load_wait=args.max_load_wait,
                    sha=sha,
                    candidate_sha=args.candidate_sha,
                    evidence=evidence,
                    work_root=work,
                    timeout=args.timeout,
                    max_rounds=args.max_inference_rounds,
                )
                env = attempt_env(
                    dict(os.environ),
                    venv_bin=candidate / ".venv" / "bin",
                    sdk_root=Path(sdk_info["root"]),
                    gnu_sed=info["gnu_sed"],
                )
                if wheel_info.get("release_assets"):
                    env[RELEASE_ASSETS_ENV] = wheel_info["release_assets"]
                progress(f"attempt {k} starting")
                t0 = time.monotonic()
                with timings.measure("live_cases"):
                    rc = run_attempt(
                        argv,
                        cwd=candidate,
                        env=env,
                        log=run_root / "logs" / f"attempt-{k}.log",
                        on_started=lambda attempt=k: driven.append(attempt),
                    )
                record = summarize_attempt(k, evidence, rc, time.monotonic() - t0, _read_summary(evidence))
                record["work_root"] = str(work)
                attempts.append(record)
                covered = record.get("case_coverage") or {}
                reached = (
                    f" cases={covered['executed_cases']}/{covered['selected_cases']}"
                    if covered.get("selected_cases")
                    else ""
                )
                progress(f"attempt {k} exit={rc} pass={record['pass']}{reached}")
                if "error" in record:
                    break
                if record["pass"]:
                    try:
                        from .verify import verify_report

                        with timings.measure("verify"):
                            verify_result = verify_report(
                                evidence,
                                expected_sha=args.candidate_sha or sha,
                                source_root=candidate,
                            )
                    except ValueError as exc:
                        record["verify_error"] = str(exc)
                    qualified = (
                        verify_result is not None
                        and verify_result.get("verified") is True
                        and verify_result.get("merge_qualified") is True
                    )
                    break
                if not retryable(record["failed"], k, args.attempts):
                    break
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        progress(f"aborted: {error}")
    finally:
        cleanup: list[str] = []
        if candidate is not None and prepared and error is None:
            cleanup.append("candidate-worktree-kept")
        elif candidate is not None:
            try:
                with timings.measure("cleanup"):
                    removed = _remove_candidate(REPO, candidate)
            except Exception:
                removed = False
            cleanup.append("candidate-worktree-removed" if removed else "candidate-worktree-kept")
        for record in attempts:
            work = Path(record["work_root"])
            if record.get("pass") and not args.keep_work and work.exists():
                with timings.measure("cleanup"):
                    shutil.rmtree(work, ignore_errors=True)
                cleanup.append(f"work-{record['attempt']}-removed")
        kept = sorted(str(path) for path in run_root.iterdir())
        kept.extend(str(Path(record["work_root"])) for record in attempts if Path(record["work_root"]).exists())
        kept.sort()
        result = {
            "sha": sha,
            "candidate_sha": args.candidate_sha,
            "qualified": qualified,
            # One lane of eleven, and null when no attempt started. The rest carry
            # the work a person actually does, so the record names them rather
            # than letting `qualified` stand for them.
            "coverage": lane_coverage(driven=bool(driven)),
            "prepare_only": args.prepare_only,
            "candidate": str(candidate) if prepared and error is None and candidate is not None else None,
            "independent_verifier": info.get("independent_verifier"),
            "verifier_sha": info.get("verifier_sha"),
            "platform": platform.system().lower(),
            "wheel": wheel_info,
            "sdk": sdk_info,
            "effort": args.effort,
            "jobs": args.jobs,
            "host_slots": args.host_slots,
            "max_load": args.max_load,
            "max_load_wait": args.max_load_wait,
            "attempts": attempts,
            # How many rounds this invocation actually spent, against what it was allowed.
            # A reader who sees `qualified: false` needs to know whether the run proved
            # something about the product or merely ran out of budget, and the two look
            # alike in the outcome counts alone. The count is of rounds that started,
            # not of records: an interrupted round spent the lane and left no record,
            # and `attempts` already gives the completed count.
            "attempts_run": len(driven),
            "attempts_allowed": args.attempts,
            # Verified counts only; a failed or missing verify publishes null here and the
            # last attempt's runner counts under unverified_* so failing runs still show them.
            "interruptions": verify_result.get("interruptions") if verify_result else None,
            "known_gaps": verify_result.get("known_gaps") if verify_result else None,
            "unverified_interruptions": None if verify_result or not attempts else attempts[-1].get("interruptions"),
            "unverified_known_gaps": None if verify_result or not attempts else attempts[-1].get("known_gaps"),
            "verify": verify_result,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "phase_seconds": timings.report(),
            "cleanup": cleanup,
            "kept": kept,
            "run_root": str(run_root),
        }
        if error is not None:
            result["error"] = error
        (run_root / "qualification.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result))
    return 0 if qualified or (prepared and error is None) else 1
