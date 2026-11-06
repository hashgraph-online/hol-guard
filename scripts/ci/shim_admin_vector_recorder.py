"""Record parity vectors for the package-shim admin operations.

Run against the Python implementation that preceded the resident ``shim_admin``
op (``codex_plugin_scanner.guard.shims`` at base commit ``78be1d8ba2``). The Python
bodies were removed once the helpers moved to the resident op, so re-recording needs
that commit checked out in a separate worktree::

    cd scripts/ci
    PYTHONPATH=../../src python shim_admin_vector_recorder.py [--work-base DIR]

Each scenario is a sequence of steps over a fresh scratch directory: file
writes that plant or tamper state, and ``call`` steps that invoke one retired
helper. After every ``call`` the recorder keeps the JSON result (or the fact that
it raised) and a digest of the whole scratch tree, and at the end of the scenario
the full tree. The process facts the Python code read from its interpreter are
pinned per scenario (see ``shim_admin_vector_support``), so the Rust replay needs
no interpreter. Output is gzip JSON at
``rust/crates/guard-command/tests/fixtures/shim_admin_vectors.v1.json.gz``.

``--platform windows`` records the Windows scenarios and must run on a real
Windows host, because the old code's ``ntpath``/``PureWindowsPath`` semantics,
extension-based executable bits and ``.cmd`` line endings cannot be reproduced
by patching ``os.name`` elsewhere. Its output goes to
``shim_admin_vectors_windows.v1.json.gz`` next to the POSIX fixture.

The scratch directory must not be transient (``/tmp``, ``/var/folders``...) because
shell-profile writes are skipped for transient guard homes.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from shim_admin_vector_profile_scenarios import all_profile_scenarios
from shim_admin_vector_scenarios import all_install_status_scenarios
from shim_admin_vector_state_scenarios import all_state_scenarios
from shim_admin_vector_support import (
    collect_hashes,
    expand,
    install_facts,
    is_transient_root,
    remap_hashes,
    snapshot,
    substitute,
    tree_digest,
    tree_files,
    undo_facts,
)
from shim_admin_vector_windows_scenarios import all_windows_scenarios

FIXTURES = Path(__file__).resolve().parents[2] / "rust/crates/guard-command/tests/fixtures"
OUT = FIXTURES / "shim_admin_vectors.v1.json.gz"
OUT_WINDOWS = FIXTURES / "shim_admin_vectors_windows.v1.json.gz"


def apply_step(root: str, step: dict[str, object]) -> None:
    path = Path(root) / str(step["path"])
    op = step["op"]
    if op == "write":
        path.parent.mkdir(parents=True, exist_ok=True)
        data = base64.b64decode(str(step["b64"])) if "b64" in step else str(step["text"]).encode("utf-8")
        path.write_bytes(data)
        path.chmod(0o755 if step.get("exec") else 0o644)
    elif op == "append":
        with path.open("ab") as handle:
            handle.write(str(step["text"]).encode("utf-8"))
    elif op == "mkdir":
        path.mkdir(parents=True, exist_ok=True)
    elif op == "symlink":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(str(step["target"]))
    elif op == "remove":
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
    else:
        raise ValueError(f"unknown step op {op!r}")


def run_call(shims: object, context: object, subop: str, args: dict[str, object]) -> object:
    managers = tuple(args["managers"]) if args.get("managers") is not None else None  # type: ignore[arg-type]
    path_env = args.get("path_env")
    if subop == "status":
        return shims.package_shim_status(context, path_env=path_env)  # type: ignore[attr-defined]
    if subop == "dashboard_status":
        return shims.package_shim_dashboard_status(context)  # type: ignore[attr-defined]
    if subop == "cloud_coverage":
        return shims.package_shim_cloud_coverage(context, generated_at=args.get("generated_at"))  # type: ignore[attr-defined]
    if subop == "path_order":
        return shims.get_path_order_status(context, manager=args["manager"], path_env=path_env)  # type: ignore[attr-defined]
    if subop == "install":
        return shims.install_package_shims(context, managers=managers, path_env=path_env)  # type: ignore[attr-defined]
    if subop == "activate":
        return shims.activate_package_shims(context, managers=managers, repair=bool(args.get("repair", False)))  # type: ignore[attr-defined]
    if subop == "repair":
        return shims.repair_package_shims(context, managers=managers, path_env=path_env)  # type: ignore[attr-defined]
    if subop == "uninstall":
        return shims.uninstall_package_shims(context, managers=managers)  # type: ignore[attr-defined]
    if subop == "probe_intercepts":
        workspace = args.get("workspace_dir")
        return shims.probe_package_shim_intercepts(  # type: ignore[attr-defined]
            context,
            managers=managers,
            workspace_dir=Path(str(workspace)) if workspace is not None else None,
            allow_inactive_path=bool(args.get("allow_inactive_path", False)),
            project_shell_profile=bool(args.get("project_shell_profile", False)),
            timeout_seconds=int(args["timeout_seconds"]),  # type: ignore[arg-type]
        )
    if subop == "supported_managers":
        return list(shims.package_shim_supported_managers())  # type: ignore[attr-defined]
    if subop == "ensure_package_shim_profile":
        return shims.ensure_package_shim_path_in_shell_profile(context)  # type: ignore[attr-defined]
    if subop == "remove_guard_profile_blocks":
        return shims.remove_guard_profile_blocks(context)  # type: ignore[attr-defined]
    raise ValueError(f"unknown subop {subop!r}")


def record_scenario(scenario: dict[str, object], work_base: str) -> dict[str, object]:
    from codex_plugin_scanner.guard import shims
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    root = os.path.realpath(tempfile.mkdtemp(prefix="v", dir=work_base))
    saved_environ = dict(os.environ)
    saved_cwd = os.getcwd()
    patches: list[tuple[object, str, object]] = []
    try:
        facts = expand(scenario["facts"], root)
        assert isinstance(facts, dict)
        context_spec = expand(scenario["context"], root)
        assert isinstance(context_spec, dict)
        steps = expand(scenario["steps"], root)
        assert isinstance(steps, list)
        context = HarnessContext(
            home_dir=Path(str(context_spec["home_dir"])),
            workspace_dir=Path(str(context_spec["workspace_dir"])) if context_spec["workspace_dir"] else None,
            guard_home=Path(str(context_spec["guard_home"])),
        )
        patches = install_facts(facts)
        os.environ.clear()
        os.environ.update({str(key): str(value) for key, value in facts["environ"].items()})  # type: ignore[attr-defined]
        hash_map: dict[str, str] = {}
        recorded_steps: list[dict[str, object]] = []
        for step in steps:
            if step["op"] != "call":
                apply_step(root, step)
                continue
            collect_hashes(snapshot(root), root, hash_map)
            os.chdir(str(facts["cwd"]))
            try:
                outcome: dict[str, object] = {
                    "ok": True,
                    "result": run_call(shims, context, str(step["subop"]), step["args"]),
                }
            except Exception as error:
                outcome = {"ok": False, "error": type(error).__name__}
            after = snapshot(root)
            collect_hashes(after, root, hash_map)
            outcome["_after"] = after
            recorded_steps.append(outcome)
        final = snapshot(root)
        collect_hashes(final, root, hash_map)
        expected_steps = []
        for outcome in recorded_steps:
            item = dict(outcome)
            item["tree"] = tree_digest(item.pop("_after"), root, hash_map)  # type: ignore[arg-type]
            if "result" in item:
                item["result"] = remap_hashes(substitute(json.loads(json.dumps(item["result"])), root), hash_map)
            expected_steps.append(item)
        recorded = {key: value for key, value in scenario.items() if key != "steps"}
        recorded["steps"] = scenario["steps"]
        recorded["expected"] = {"calls": expected_steps, "files": tree_files(final, root, hash_map)}
        return recorded
    finally:
        os.chdir(saved_cwd)
        undo_facts(patches)
        os.environ.clear()
        os.environ.update(saved_environ)
        shutil.rmtree(root, ignore_errors=True)


def git_revision() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-base", default=str(Path.home() / ".cache" / "rtm-shim-vectors-work"))
    parser.add_argument(
        "--platform",
        choices=("posix", "windows"),
        default="windows" if os.name == "nt" else "posix",
        help="windows records the nt scenarios and must run on a real Windows host",
    )
    parser.add_argument("--out", default="")
    parser.add_argument("--only", default="")
    parser.add_argument("--revision", default="", help="git revision of the Python implementation being recorded")
    args = parser.parse_args()
    work_base = Path(args.work_base)
    work_base.mkdir(parents=True, exist_ok=True)
    resolved = os.path.realpath(work_base)
    if args.platform == "posix" and is_transient_root(resolved + "/"):
        print(f"work base {resolved} is transient; pass --work-base outside temp dirs", file=sys.stderr)
        return 2
    if (args.platform == "windows") != (os.name == "nt"):
        print(f"--platform {args.platform} needs a matching host (os.name={os.name})", file=sys.stderr)
        return 2
    if args.platform == "windows":
        scenarios = all_windows_scenarios()
    else:
        # Scenarios that pretend to be Windows are recorded on a real Windows host.
        scenarios = [
            item
            for item in (*all_install_status_scenarios(), *all_state_scenarios(), *all_profile_scenarios())
            if not item["facts"].get("windows")  # type: ignore[union-attr]
        ]
    names = [str(item["name"]) for item in scenarios]
    if len(set(names)) != len(names):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        print(f"duplicate scenario names: {duplicates}", file=sys.stderr)
        return 2
    if args.only:
        scenarios = [item for item in scenarios if args.only in str(item["name"])]
    recorded = [record_scenario(item, resolved) for item in scenarios]
    document = {
        "schema": "guard-shim-admin-vectors.v1",
        "recorded_from": "codex_plugin_scanner.guard.shims (pre-cutover Python)",
        "recorded_at_revision": args.revision or git_revision(),
        "scenarios": recorded,
    }
    out = Path(args.out or (OUT_WINDOWS if args.platform == "windows" else OUT))
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    with gzip.GzipFile(filename="", mode="wb", fileobj=out.open("wb"), mtime=0, compresslevel=9) as handle:
        handle.write(payload)
    print(f"recorded {len(recorded)} scenarios, {len(payload)} bytes json, {out.stat().st_size} bytes gz")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
