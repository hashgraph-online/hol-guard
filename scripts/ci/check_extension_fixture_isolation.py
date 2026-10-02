"""Exercise source-only extension changes in an isolated checkout.

No target command is executed. The real native compiler evaluates authored
fixtures, and the existing CLI handoff and package paths must remain usable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXTENSION_ID = "command.hol-ci-fixture"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(
    arguments: list[str], root: Path, env: dict[str, str], *, payload: object | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        cwd=root,
        env=env,
        input=None if payload is None else json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if check and completed.returncode:
        raise RuntimeError(f"{arguments[0:4]} failed:\n{completed.stderr[-4000:]}\n{completed.stdout[-2000:]}")
    return completed


def exercise(root: Path, target: Path, results: list[dict[str, object]]) -> None:
    env = dict(os.environ)
    env.update(
        PYTHONPATH=os.pathsep.join((str(root / "src"), str(root))),
        CARGO_TARGET_DIR=str(target),
        CARGO_BUILD_JOBS="2",
        CARGO_PROFILE_DEV_DEBUG="0",
        CARGO_PROFILE_DEV_INCREMENTAL="false",
    )
    compiler = target / "debug" / ("guard-command-source.exe" if os.name == "nt" else "guard-command-source")
    build_command = [
        "cargo",
        "+1.88.0",
        "build",
        "--locked",
        "--manifest-path",
        "rust/Cargo.toml",
        "--message-format=json-render-diagnostics",
        "-p",
        "guard-command",
        "--bin",
        "guard-command-source",
    ]

    def record(name: str, **details: object) -> None:
        results.append({"case": name, "passed": True, **details})
        print(json.dumps(results[-1], sort_keys=True), flush=True)

    def build() -> subprocess.CompletedProcess[str]:
        return run(build_command, root, env)

    def export() -> dict:
        return json.loads(run([str(compiler), "export-built"], root, env).stdout)

    def verify() -> None:
        run([sys.executable, "scripts/ci/verify_native_command_program.py", "--compiler", str(compiler)], root, env)

    def prepare(source: Path, fixture: Path) -> None:
        result = run(
            [
                sys.executable,
                "scripts/prepare_extension_contribution.py",
                "--compiler",
                str(compiler),
                "--source",
                str(source),
                "--fixture",
                str(fixture),
            ],
            root,
            env,
        )
        payload = json.loads(result.stdout)
        require(payload.get("ok") is True and payload.get("targetCommandsExecuted") == 0, "unsafe preparation")
        result = run(
            [
                sys.executable,
                "-m",
                "codex_plugin_scanner",
                "extensions",
                "handoff",
                "--repo",
                str(root),
                "--source",
                str(source),
                "--fixture",
                str(fixture),
                "--compiler",
                str(compiler),
                "--json",
            ],
            root,
            env,
        )
        handoff = json.loads(result.stdout)
        require(handoff.get("readyForPullRequest") is True, "existing contributor handoff did not succeed")
        require(handoff.get("targetCommandsExecuted") == 0, "handoff executed a target")

    immutable = list((root / "tests/fixtures").glob("command-source-*.v1.json"))
    immutable += list((root / "contracts/managed-controls/v1").glob("*vector*.json"))
    immutable += [root / "tests/test_guard_extension_trust.py", root / "tests/test_policy_bundle_delivery_runtime.py"]
    preserved = {path: digest(path) for path in immutable}
    before_sources = {path: digest(path) for path in (root / "contributions/command-sources").glob("*.json")}
    started = time.monotonic()
    build()
    binary = digest(compiler)
    verify()
    require(digest(compiler) == binary, "projection preparation rebuilt the compiler")
    baseline = export()
    baseline_ids = {entry["extension_id"] for entry in baseline["catalog"]}
    record(
        "source_checkout_with_stale_projections",
        extensions=len(baseline_ids),
        seconds=round(time.monotonic() - started, 2),
    )

    fixture_paths = [
        sorted((root / "tests/fixtures").glob("command-source-*.v1.json"))[0],
        root / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json",
    ]
    for path in fixture_paths:
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n")
            result = build()
            artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
            rebuilt = [
                item
                for item in artifacts
                if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") in {"guard-command-source", "guard_command"}
                and not item.get("fresh")
            ]
            require(not rebuilt and digest(compiler) == binary, "fixture-only edit rebuilt native production code")
            require(export() == baseline, "fixture-only edit changed the embedded catalog")
        finally:
            path.write_bytes(original)
        record("fixture_edit_without_recompile", path=path.relative_to(root).as_posix())

    source_path = root / "contributions/command-sources" / f"{EXTENSION_ID}.json"
    fixture_path = root / "tests/fixtures/command-source-hol-ci-fixture.v1.json"
    trust_path = root / "contracts/extensions/trust-class-map.v1.json"
    old_trust = trust_path.read_bytes()
    source_text = (root / "contributions/command-sources/command.noodle.json").read_text()
    source = json.loads(source_text.replace("command.noodle", EXTENSION_ID).replace("noodle", "hol-ci-fixture"))
    source["extension"]["homepage"] = "https://example.com/hol-ci-fixture"
    trust = json.loads(old_trust)
    trust["classes"]["external"].append(EXTENSION_ID)
    trust["classes"]["external"].sort()
    source_path.write_text(json.dumps(source, indent=2) + "\n")
    trust_path.write_text(json.dumps(trust, indent=2) + "\n")
    fixture = {
        "schema": "guard.command-extension-fixtures.v1",
        "build": {
            "schema": "guard.command-extension-build.v1",
            "sources": [source],
            "mcp_sources": [],
            "trust": trust,
            "base": "packaged",
        },
        "cases": [
            {
                "id": "review-execution",
                "command": "hol-ci-fixture request run demo",
                "enabled_extensions": [EXTENSION_ID],
                "disabled_permissions": [],
                "expected_action": "review",
                "rule_id": EXTENSION_ID + ".run",
                "expected_effective_segments": [0],
            },
            {
                "id": "help",
                "command": "hol-ci-fixture request run demo --help",
                "enabled_extensions": [EXTENSION_ID],
                "disabled_permissions": [],
                "expected_action": "review",
                "rule_id": EXTENSION_ID + ".run",
                "expected_effective_segments": [],
            },
        ],
    }
    fixture_path.write_text(json.dumps(fixture, indent=2) + "\n")
    initial_fixture = json.loads(run([str(compiler), "test"], root, env, payload=fixture).stdout)
    require(initial_fixture.get("ok") is True, "new portable fixture failed against the prior packaged base")
    build()
    verify()
    prepare(source_path, fixture_path)
    current = export()
    require({entry["extension_id"] for entry in current["catalog"]} == baseline_ids | {EXTENSION_ID}, "inventory loss")
    descriptor = root / "contributions/extensions" / f"{EXTENSION_ID}.json"
    public = json.loads(descriptor.read_bytes())
    require(public["activation"] == "opt-in" and public["trustClass"] == "external", "external trust changed")
    record("source_only_add_and_existing_handoff")

    bad_fixture = json.loads(json.dumps(fixture))
    bad_fixture["cases"][0]["expected_action"] = "allow"
    negative = run([str(compiler), "test"], root, env, payload=bad_fixture, check=False)
    require(json.loads(negative.stdout).get("ok") is False, "incorrect security expectation passed")
    record("incorrect_behavior_fixture_rejected")

    source["extension"]["description"] = "Isolated CI contribution acceptance."
    source_path.write_text(json.dumps(source, indent=2) + "\n")
    fixture_path.write_text(json.dumps(fixture, indent=2) + "\n")
    build()
    verify()
    prepare(source_path, fixture_path)
    require(json.loads(descriptor.read_bytes())["description"] == source["extension"]["description"], "edit lost")
    record("source_only_edit_and_existing_handoff")

    dist = root / "build/fixture-acceptance-dist"
    run(["uv", "build", "--wheel", "--out-dir", str(dist)], root, env)
    wheels = list(dist.glob("*.whl"))
    require(len(wheels) == 1, "ambiguous wheel output")
    expected_commands = {path.name for path in (root / "contributions/command-sources").glob("command.*.json")}
    expected_mcp = {path.name for path in (root / "contributions/mcp-servers").glob("*.json")}
    with zipfile.ZipFile(wheels[0]) as wheel:
        for suffix, expected in (("extensions", expected_commands), ("mcp_servers", expected_mcp)):
            prefix = f"codex_plugin_scanner/guard/contracts/data/{suffix}/contributions/"
            observed = {
                name[len(prefix) :] for name in wheel.namelist() if name.startswith(prefix) and name.endswith(".json")
            }
            require(observed == expected, f"packaged {suffix} contribution inventory is incomplete")
        prefix = "codex_plugin_scanner/guard/contracts/data/extensions/"
        require(
            wheel.read(prefix + "native-command-program.v1.json")
            == (root / "contracts/extensions/native-command-program.v1.json").read_bytes(),
            "packaged program mismatch",
        )
    record("wheel_contains_every_existing_and_new_contribution", commands=len(expected_commands), mcp=len(expected_mcp))

    program_path = root / "contracts/extensions/native-command-program.v1.json"
    previous_program = program_path.read_bytes()
    source_path.write_text('{"schema":"invalid"}\n')
    failed = run(build_command, root, env, check=False)
    require(failed.returncode != 0, "malformed source produced a successful build")
    require(program_path.read_bytes() == previous_program, "failed source overwrote valid product projections")
    record("malformed_source_rejected_without_replacing_outputs")
    source_path.unlink()
    fixture_path.unlink()
    trust_path.write_bytes(old_trust)
    build()
    verify()
    require(export() == baseline and not descriptor.exists(), "source removal did not restore the original inventory")
    record("source_only_remove")
    run([sys.executable, "scripts/export_extension_directory.py"], root, env)
    run([sys.executable, "scripts/render_command_extension_directory.py"], root, env)
    run([sys.executable, "scripts/export_extension_directory.py", "--check"], root, env)
    run([sys.executable, "scripts/render_command_extension_directory.py", "--check"], root, env)
    require(
        all(digest(path) == value for path, value in preserved.items()), "an unrelated fixture or test was rewritten"
    )
    require(
        all(digest(path) == value for path, value in before_sources.items()), "an existing contributor source changed"
    )
    record("existing_directory_and_independent_expectations_preserved")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    results: list[dict[str, object]] = []
    failure = None
    target = args.target_dir.resolve()
    with tempfile.TemporaryDirectory(prefix="guard-fixture-acceptance-") as temporary:
        checkout = Path(temporary) / "checkout"
        subprocess.run(["git", "worktree", "add", "--detach", str(checkout), "HEAD"], cwd=ROOT, check=True)
        try:
            exercise(checkout, target, results)
        except Exception as error:
            failure = str(error)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(checkout)], cwd=ROOT, check=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"passed": failure is None, "cases": results, "failure": failure}, indent=2) + "\n"
    )
    if failure is not None:
        raise RuntimeError(failure)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
