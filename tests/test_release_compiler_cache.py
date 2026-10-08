"""Release compilation caches must stay content-addressed, trusted, and reproducible."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]


def _release_compile_steps():
    prepare = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")["jobs"]["compile"]["steps"]
    publish = load_workflow(ROOT / ".github/workflows/publish.yml")["jobs"]["build"]["steps"]
    projection = "Generate projections for release source distributions"
    return [
        (prepare, next(step for step in prepare if step.get("name") == "Compile canonical release inputs")),
        (publish, next(step for step in publish if step.get("name") == projection)),
    ]


@pytest.mark.parametrize(
    ("ref", "event", "mode"),
    [
        ("refs/heads/main", "push", "READ_WRITE"),
        ("refs/heads/main", "workflow_dispatch", "READ_ONLY"),
        ("refs/heads/main", "pull_request", "READ_ONLY"),
        ("refs/pull/3770/merge", "pull_request", "READ_ONLY"),
        ("refs/heads/contributor", "push", "READ_ONLY"),
        ("refs/heads/main-other", "push", "READ_ONLY"),
        ("refs/tags/v3.35.0", "push", "READ_ONLY"),
    ],
)
def test_release_compiler_cache_is_written_only_by_trusted_main_pushes(ref, event, mode):
    for _, step in _release_compile_steps():
        expression = step["env"]["SCCACHE_GHA_RW_MODE"].strip()[3:-2]
        for name, value in {"github.ref": ref, "github.event_name": event}.items():
            expression = expression.replace(name, repr(value))
        expression = "(" + expression.replace("&&", " and ").replace("||", " or ") + ")"
        tree = ast.parse(expression, mode="eval")
        permitted = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.Constant)
        assert all(isinstance(node, permitted) for node in ast.walk(tree)), "Unsupported cache-mode expression"
        assert eval(compile(tree, "<cache-mode>", "eval"), {"__builtins__": {}}) == mode


def test_release_compilation_is_content_addressed_and_feature_unified():
    for steps, step in _release_compile_steps():
        installer = next(item for item in steps if "sccache-action@" in item.get("uses", ""))
        assert re.fullmatch(r"mozilla-actions/sccache-action@[0-9a-f]{40}", installer["uses"])
        assert installer["with"]["version"] == "v0.18.0"
        assert steps.index(installer) < steps.index(step)
        assert step["env"]["SCCACHE_GHA_ENABLED"] == "on"
        assert step["env"]["SCCACHE_IGNORE_SERVER_IO_ERROR"] == "1"
    (prepare_steps, prepare), _ = _release_compile_steps()
    # Workspace-only wrapping keeps third-party crates in rust-cache and sccache entries small.
    assert prepare["env"]["RUSTC_WORKSPACE_WRAPPER"] == "sccache"
    assert "RUSTC_WRAPPER" not in prepare["env"]
    wheel_steps = load_workflow(ROOT / ".github/workflows/publish.yml")["jobs"]["build-native-guard-wheels"]["steps"]
    for steps in (prepare_steps, wheel_steps):
        cache = next(item for item in steps if "rust-cache@" in item.get("uses", ""))
        assert cache["with"]["prefix-key"] == "release-native-v1"
        assert cache["with"]["cache-workspace-crates"] is False
    script = prepare["run"]
    builds = [line for line in script.splitlines() if line.strip().startswith("cargo build")]
    assert len(builds) == 1
    for flag in ("-p hol-guard-runtime", "-p guard-command", "--bin hol-guard-runtime", "--bin guard-command-source"):
        assert flag in builds[0]
    order = [
        script.index("cargo build"),
        script.index('build_native_command_program.py --compiler "$SOURCE_COMPILER"'),
        script.index('"$RUNTIME" self-test --json'),
        script.index("prepared_native.py pack"),
    ]
    assert order == sorted(order)


def test_determinism_gate_compares_cached_and_cold_binaries_without_writing_caches():
    workflow = load_workflow(ROOT / ".github/workflows/release-native-determinism.yml")
    assert set(workflow[True]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["compare"]
    prepare = load_workflow(ROOT / ".github/workflows/release-native-prepare.yml")["jobs"]["compile"]
    assert job["strategy"]["matrix"]["include"] == prepare["strategy"]["matrix"]["include"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Restore trusted release dependencies"]["with"]["save-if"] == "false"
    cached = steps["Compile with the release compiler cache"]
    assert cached["env"]["SCCACHE_GHA_RW_MODE"] == "READ_ONLY"
    assert cached["env"]["SCCACHE_GHA_VERSION"] == "release-native-v1"
    cold = steps["Compile cold into an empty compiler cache"]
    assert cold["env"] == {
        "RUSTC_WORKSPACE_WRAPPER": cached["env"]["RUSTC_WORKSPACE_WRAPPER"],
        "SCCACHE_GHA_ENABLED": "off",
        "SCCACHE_DIR": "${{ runner.temp }}/sccache-cold",
    }
    order = [cold["run"].index(token) for token in ("--stop-server", "cargo clean", "cargo build", "hits != 0")]
    assert order == sorted(order)

    def build_line(script):
        return next(line for line in script.splitlines() if line.lstrip().startswith("cargo build"))

    assert build_line(cached["run"]) == build_line(cold["run"])
    compare = steps["Require byte-identical release binaries"]["run"]
    assert "hol-guard-runtime guard-command-source" in compare
    assert 'exit "$status"' in compare
    assert '"cache_hits"' in cached["run"]
    assert "hits == 0" in cached["run"]
    assert cached["run"].index("cache_hits") < cached["run"].index('mkdir -p "$RUNNER_TEMP/cached"')
    release = prepare_steps(prepare)
    build_sha_line = 'echo "HOL_GUARD_BUILD_SHA=$SOURCE_SHA" >> "$GITHUB_ENV"\n'
    bind = release["Bind exact source and version"]["run"].replace(build_sha_line, "")
    assert steps["Bind exact source and version"]["run"] == bind
    assert workflow[True]["workflow_dispatch"]["inputs"]["version"]["required"] is False
    assert job["env"]["VERSION"] == "${{ inputs.version }}"
    root_gate = "Verify release enrollment root"
    assert steps[root_gate]["run"] == release[root_gate]["run"]


def prepare_steps(job):
    return {step.get("name"): step for step in job["steps"]}
