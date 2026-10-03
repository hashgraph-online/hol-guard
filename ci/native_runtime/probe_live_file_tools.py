"""Verify real Oh My Pi file tools against an isolated installed Guard wheel."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ci.native_runtime import probe_installed_pi_output as probe
from ci.native_runtime.probe_workflow_matrix import decode_events


def assert_file_tools(events: list[dict], workspace: Path, target_root: Path | None = None) -> None:
    target_root = target_root or workspace
    starts = [event for event in events if event.get("type") == "tool_execution_start"]
    ends = [event for event in events if event.get("type") == "tool_execution_end"]
    expected = [
        ("read", "seed.txt"),
        ("write", "copy.txt"),
        ("read", "copy.txt"),
        ("edit", "copy.txt"),
        ("read", "copy.txt"),
    ]
    if len(starts) != len(expected) or len(ends) != len(expected):
        raise AssertionError("Pi omitted or duplicated a required file tool")
    for (name, filename), start, end in zip(expected, starts, ends, strict=True):
        args = start.get("args")
        if not isinstance(args, dict) or start.get("toolName") != name:
            raise AssertionError("Pi changed the required file tool sequence")
        if "path" in args and "file_path" in args and args["path"] != args["file_path"]:
            raise AssertionError("Pi supplied conflicting file targets")
        if name == "write" and args.get("content") != "fixture-before\n":
            raise AssertionError("Pi changed the required write contents")
        target = args.get("path", args.get("file_path"))
        if name == "edit":
            anchored = args.get("input")
            anchored_target = None
            if isinstance(anchored, str):
                headers = re.findall(r"^\[([^\n]+)\]$", anchored, flags=re.MULTILINE)
                if len(headers) == 1:
                    matched = re.fullmatch(r"(.+)#[0-9A-Fa-f]{4}", headers[0])
                    if matched is not None:
                        anchored_target = matched.group(1)
            if anchored_target is None or (target is not None and target != anchored_target):
                raise AssertionError("Pi supplied conflicting or invalid anchored edit targets")
            target = anchored_target
        if not isinstance(target, str):
            raise AssertionError("Pi omitted a file target")
        try:
            path = Path(target).expanduser()
        except RuntimeError as error:
            raise AssertionError("Pi supplied an unknown home-relative target") from error
        if not path.is_absolute():
            path = workspace / path
        if path.resolve() != (target_root / filename).resolve():
            raise AssertionError("Pi changed the required file target")
        if not start.get("toolCallId") or start["toolCallId"] != end.get("toolCallId"):
            raise AssertionError("Pi file tool completion identity mismatched")
        if end.get("isError") is not False:
            raise AssertionError(f"Pi {name} failed")
    if (target_root / "copy.txt").read_text() != "fixture-after\n":
        raise AssertionError("Pi did not complete the required write/edit side effects")
    if (target_root / "seed.txt").read_text() != "fixture-before\n":
        raise AssertionError("Pi changed the read-only seed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--model", default="devin/gpt-6-luna")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--outside-cwd", action="store_true", help="Use absolute targets in another project")
    args = parser.parse_args()
    executable = shutil.which("omp")
    if executable is None:
        raise RuntimeError("Oh My Pi is required")
    _, identity, capabilities = probe._probe_native_identity()
    if capabilities.build_sha != args.expected_source_sha:
        raise AssertionError("installed native build is stale")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    summary_path = args.output / "summary.json"
    if summary_path.exists() or summary_path.is_symlink():
        summary_path.unlink()
    with tempfile.TemporaryDirectory(prefix="guard-file-tools-", dir=Path.cwd()) as temporary:
        root = Path(temporary).resolve()
        home, workspace, guard_home = root / "home", root / "workspace", root / "guard-home"
        home.mkdir()
        workspace.mkdir()
        target_root = home / "other-project" if args.outside_cwd else workspace
        target_root.mkdir(exist_ok=True)
        (target_root / "seed.txt").write_text("fixture-before\n")
        seed = json.dumps(str(target_root / "seed.txt") if args.outside_cwd else "seed.txt")
        copy = json.dumps(str(target_root / "copy.txt") if args.outside_cwd else "copy.txt")
        daemon = probe._start_installed_daemon(
            guard_home=guard_home,
            home=home,
            workspace=workspace,
            identity=identity,
        )
        try:
            probe._prepare_installed_daemon_workspace(daemon, workspace)
            settings, extension = root / "settings.json", root / "guard-file-tools.ts"
            settings.write_text("{}\n")
            probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=settings)
            worker = daemon._server.hook_worker
            before = worker.store.count_approval_requests(status=None)
            prompt = (
                "Synthetic regression. Use these exact five tool calls in order, no other calls: "
                f"1. read {seed}. 2. write {copy} with exactly fixture-before followed by newline. "
                f"3. read {copy} to obtain edit anchors. "
                f"4. edit {copy} replacing fixture-before with fixture-after, retaining the newline. "
                f"5. read {copy}. Stop if any tool is blocked. Do not use bash or python."
            )
            result = subprocess.run(
                [
                    executable,
                    "--model",
                    args.model,
                    "--cwd",
                    str(workspace),
                    "--no-extensions",
                    "--extension",
                    str(extension),
                    "--no-skills",
                    "--no-rules",
                    "--no-lsp",
                    "--no-session",
                    "--no-title",
                    "--tools",
                    "read,write,edit",
                    "--max-time",
                    "90",
                    "--mode",
                    "json",
                    "--print",
                    prompt,
                ],
                text=True,
                capture_output=True,
                timeout=120,
            )
            (args.output / "pi-file-tools.log").write_text(result.stdout + "\n" + result.stderr)
            if result.returncode != 0:
                raise AssertionError("Pi file workflow failed; inspect private event evidence")
            assert_file_tools(decode_events(result.stdout), workspace, target_root)
            # Each tool call produces one native pre-tool and one post-tool event.
            native_route_metrics = probe._wait_for_native_route_metrics(daemon, 10)
            if worker.store.count_approval_requests(status=None) != before:
                raise AssertionError("ordinary file tools created an approval")
            summary = {
                "pass": True,
                "actual_pi_calls": 5,
                "new_quiet_approvals": 0,
                "installed_source_sha": capabilities.build_sha,
                "outside_cwd": args.outside_cwd,
                "native_route_metrics": native_route_metrics,
            }
            summary_path.write_text(json.dumps(summary, indent=2))
            print(json.dumps(summary))
        finally:
            probe._cleanup_installed_daemon(daemon)
            probe._cleanup_native(identity, guard_home)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
