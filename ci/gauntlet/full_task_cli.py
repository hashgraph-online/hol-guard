"""Command-line glue for the real-GitHub full-task profile (host and container sides)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

DEFAULT_OWNER = "gauntlet-dev"


def add_arguments(run: argparse.ArgumentParser) -> None:
    run.add_argument(
        "--full-task-docker",
        action="store_true",
        help="Run full tasks against real GitHub inside Docker behind the policy gateway (host side)",
    )
    run.add_argument("--guard-pypi", metavar="VERSION", help="With --full-task-docker: install this PyPI release")
    run.add_argument(
        "--guard-pr-head", metavar="SHA", help="With --full-task-docker: install the CI build of a PR head"
    )
    run.add_argument(
        "--guard-wheel",
        type=Path,
        metavar="PATH",
        help="With --full-task-docker and --guard-pr-head: an arm64 native wheel built from that head",
    )
    run.add_argument("--guard-build-sha", help="With --guard-pypi: build commit the release must report")
    run.add_argument("--github-owner", default=None, help="Account that owns every run-created repository")
    run.add_argument("--full-task-canary", help="Container side: synthetic canary planted in the honeypot")
    run.add_argument("--full-task-seed-repo", help="Container side: private repository seeded for this run")
    run.add_argument(
        "--full-task-account-home",
        metavar="PATH",
        type=Path,
        help="Container side: build the single task's HOME in this empty account home directory",
    )


def validate(args: argparse.Namespace) -> None:
    docker = args.full_task_docker
    if docker and args.profile != "full-tasks":
        raise ValueError("--full-task-docker requires --profile full-tasks")
    if docker == (args.guard_pypi is None and args.guard_pr_head is None):
        raise ValueError("--full-task-docker needs exactly one of --guard-pypi or --guard-pr-head")
    if args.guard_wheel and not (docker and args.guard_pr_head):
        raise ValueError("--guard-wheel needs --full-task-docker and --guard-pr-head")
    if docker and not args.github_owner:
        raise ValueError("--full-task-docker needs --github-owner")
    if docker and args.guard_pypi and args.guard_pr_head:
        raise ValueError("choose one of --guard-pypi or --guard-pr-head")
    if not docker and (args.guard_pypi or args.guard_pr_head or args.guard_build_sha or args.guard_wheel):
        raise ValueError(
            "--guard-pypi, --guard-pr-head, --guard-wheel and --guard-build-sha require --full-task-docker"
        )
    if args.full_task_seed_repo and not args.full_task_canary:
        raise ValueError("--full-task-seed-repo needs --full-task-canary")
    if args.full_task_account_home and not (args.full_task_canary and len(args.cases or ()) == 1):
        raise ValueError("--full-task-account-home needs --full-task-canary and exactly one --case")
    if not docker and args.expected_source_sha is None:
        raise ValueError("--expected-source-sha is required")
    if args.profile != "full-tasks" and (args.github_owner or args.full_task_canary or args.full_task_seed_repo):
        raise ValueError("GitHub options require --profile full-tasks")


def validate_harness(args: argparse.Namespace) -> None:
    """Claude Code and Codex run local tasks on this host; GitHub, Docker and canary worlds stay on omp."""
    from .full_task_harness import FULL_TASK_HARNESSES
    from .full_tasks import REMOTE_TASKS

    if args.harness not in FULL_TASK_HARNESSES:
        raise ValueError("--profile full-tasks supports --harness omp, claude-code or codex")
    if (
        args.full_task_docker
        or args.github_owner
        or args.full_task_canary
        or args.full_task_seed_repo
        or args.full_task_account_home
    ):
        raise ValueError(
            "--full-task-docker, --github-owner and the --full-task-canary/seed/account options need --harness omp"
        )
    if remote := sorted(set(args.cases or ()) & REMOTE_TASKS):
        raise ValueError(f"{', '.join(remote)} reach real GitHub; run them with --harness omp --full-task-docker")


def run_harness_profile(args: argparse.Namespace) -> dict[str, Any]:
    """Run local full tasks through Claude Code or Codex and Guard's installed hooks."""
    validate_harness(args)
    from .full_task_harness import run_harness_full_tasks

    return run_harness_full_tasks(
        harness=args.harness,
        expected_source_sha=args.expected_source_sha,
        output=args.output,
        mode=args.full_task_mode,
        model_timeout=args.timeout,
        selected_ids=args.cases,
        executable=args.harness_cli,
        model=args.harness_model,
        work_root=args.work_root,
        jobs=args.jobs,
    )


def run_profile(args: argparse.Namespace, provider: dict[str, Any]) -> dict[str, Any]:
    owner = args.github_owner or DEFAULT_OWNER
    if args.full_task_docker:
        if args.jobs != 1:
            raise ValueError("--full-task-docker tasks share one GitHub owner and run one at a time; omit --jobs")
        from .full_task_docker import run_docker_full_tasks
        from .full_task_docker_inputs import ARM_PLATFORM, ensure_image, pr_head_source, pypi_source, wheel_source

        # The guard source is resolved inside a scratch directory that run_docker_full_tasks owns.
        def source(inputs: Path) -> Any:
            if args.guard_wheel:
                return wheel_source(args.guard_wheel, args.guard_pr_head, inputs, ensure_image(ARM_PLATFORM))
            image = ensure_image()
            if args.guard_pr_head:
                return pr_head_source(args.guard_pr_head, inputs, image)
            return pypi_source(args.guard_pypi, inputs, image, args.guard_build_sha)

        return run_docker_full_tasks(
            output=args.output,
            provider=provider,
            mode=args.full_task_mode,
            source=source,
            owner=owner,
            timeout=args.timeout,
            selected_ids=args.cases,
        )
    from .full_task_runner import RemoteWorld, run_full_tasks

    world = (
        RemoteWorld(owner, args.full_task_canary, args.full_task_seed_repo, args.full_task_account_home)
        if args.full_task_canary or args.full_task_seed_repo
        else None
    )
    return run_full_tasks(
        expected_source_sha=args.expected_source_sha,
        output=args.output,
        provider=provider,
        mode=args.full_task_mode,
        model_timeout=args.timeout,
        selected_ids=args.cases,
        omp=args.omp,
        work_root=args.work_root,
        world=world,
        jobs=args.jobs,
    )


__all__ = ["add_arguments", "run_harness_profile", "run_profile", "validate", "validate_harness"]
