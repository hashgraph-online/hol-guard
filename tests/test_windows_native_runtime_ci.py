"""Keep the packaged Windows daemon gate bound to its cached CI-built runtime."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import yaml

from tests.support.ci_workflow import composite_action_steps, load_ci_workflow

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ACTION = "ci-job-windows-native-runtime"


def _restore_step() -> dict:
    steps = composite_action_steps(RUNTIME_ACTION)
    return next(step for step in steps if step.get("uses", "").startswith("actions/cache/restore@"))


def _cache_key_globs() -> list[str]:
    """Extract the hashFiles globs embedded in the runtime cache key."""
    match = re.search(r"hashFiles\(([^)]*)\)", _restore_step()["with"]["key"])
    assert match is not None
    return re.findall(r"'([^']+)'", match.group(1))


def _covered(path: str, globs: list[str]) -> bool:
    """Match a repo-relative path against a hashFiles glob."""
    for glob in globs:
        if glob.endswith("/**"):
            prefix = glob[: -len("/**")]
            if path == prefix or path.startswith(prefix + "/"):
                return True
        elif path == glob:
            return True
    return False


def _embedded_inputs() -> list[str]:
    """Collect include_str!/include_bytes! literals resolving outside rust/."""
    embedded = []
    for source in sorted(ROOT.glob("rust/**/*.rs")):
        relative = source.relative_to(ROOT)
        if "target" in relative.parts or "tests" in relative.parts:
            continue
        if source.stem.endswith("_tests") or source.stem == "tests":
            continue
        text = source.read_text(encoding="utf-8")
        # Inline trailing test modules are absent from the release runtime too.
        text = re.sub(r"#\[cfg\(test\)\]\s*mod tests\s*\{.*\}\s*\Z", "", text, flags=re.DOTALL)
        for match in re.finditer(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"', text):
            resolved = (source.parent / match.group(1)).resolve()
            try:
                resolved = resolved.relative_to(ROOT).as_posix()
            except ValueError:
                resolved = resolved.as_posix()
            if not resolved.startswith("rust/"):
                embedded.append(resolved)
    return embedded


def _build_script_inputs() -> list[str]:
    """Collect the manifest and explicit source/trust records embedded by build.rs."""
    manifest = "contracts/extensions/core-defaults.v1.json"
    entries = json.loads((ROOT / manifest).read_text(encoding="utf-8"))["entries"]
    script = (ROOT / "rust/crates/guard-command-catalog-data/build.rs").read_text(encoding="utf-8")
    assert manifest in script
    assert "sources(root, &entries, true)" in script
    assert "sources(root, &entries, false)" in script
    assert "trust_map(root, &entries)" in script
    return [manifest, *(entry[field] for entry in entries for field in ("source", "trust"))]


def test_runtime_cache_key_covers_every_build_input_outside_rust() -> None:
    """Assert the runtime cache key hashes every non-rust build input."""
    globs = _cache_key_globs()
    embedded = _embedded_inputs()
    selected = _build_script_inputs()
    assert any(path.startswith("contributions/command-sources/") for path in selected)
    assert any(path.startswith("contracts/extensions/trust/") for path in selected)
    assert any(path.startswith("spec/") for path in embedded)
    for path in embedded + selected:
        assert _covered(path, globs), f"{path} is a build input missing from the runtime cache key"


def test_runtime_cache_key_and_build_gating_bind_profile_and_trusted_writes() -> None:
    """Bind the cache key to the release profile env and keep writes on main pushes."""
    steps = composite_action_steps(RUNTIME_ACTION)
    key = _restore_step()["with"]["key"]
    assert "env.CARGO_PROFILE_RELEASE_LTO" in key
    assert "env.CARGO_PROFILE_RELEASE_CODEGEN_UNITS" in key
    save = next(step for step in steps if step.get("uses", "").startswith("actions/cache/save@"))
    assert save["if"] == (
        "steps.runtime-cache.outputs.cache-hit != 'true' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    assert save["with"]["key"] == "${{ steps.runtime-cache.outputs.cache-primary-key }}"
    cache_miss = "steps.runtime-cache.outputs.cache-hit != 'true'"
    build = next(step for step in steps if "cargo build" in step.get("run", ""))
    assert build["if"] == cache_miss
    setup_rust = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert setup_rust["if"] == cache_miss


def test_packaged_daemon_matrix_tracks_the_frozen_bootstrap_parametrization() -> None:
    """Keep the matrix aligned with the test's native_diagnostics cases."""
    workflow = load_ci_workflow()
    job = workflow["jobs"]["windows-packaged-daemon"]
    needs = job["needs"] if isinstance(job["needs"], list) else [job["needs"]]
    assert "windows-native-runtime" in needs
    assert "native-command-evaluators" in needs
    source = (ROOT / "tests/test_frozen_windows_daemon_bootstrap.py").read_text(encoding="utf-8")
    marker = re.search(r'@pytest\.mark\.parametrize\("native_diagnostics",\s*(\[[^]]*\])\)', source)
    assert marker is not None
    assert job["strategy"]["matrix"]["native-diagnostics"] == ast.literal_eval(marker.group(1))
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert '$env:HOL_GUARD_NATIVE = "force"' in commands
    assert "test_packaged_windows_core_bootstrap_retry_and_repair[" in commands


def test_required_aggregate_includes_the_windows_native_lane() -> None:
    """Require both new Windows jobs in the needs graph and the lane-gated set."""
    workflow = load_ci_workflow()
    required = workflow["jobs"]["required"]
    assert "windows-native-runtime" in required["needs"]
    assert "windows-packaged-daemon" in required["needs"]
    run = "\n".join(step.get("run", "") for step in required["steps"])
    lane_gated = re.search(r"required\s*=\s*(\[[^]]*\])", run)
    assert lane_gated is not None
    gated = ast.literal_eval(lane_gated.group(1))
    assert "windows-native-runtime" in gated
    assert "windows-packaged-daemon" in gated
    assert "windows-shim-admin" in required["needs"]
    assert "windows-shim-admin" in gated


def test_windows_shim_admin_lane_replays_vectors_and_runs_the_native_op() -> None:
    """Partition the complete Windows contract inventory without weakening it."""
    job = load_ci_workflow()["jobs"]["windows-shim-admin"]
    assert job["runs-on"] == "windows-latest"
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["shim-gate"] == ["vectors", "native-op", "mcp"]
    assert job["env"]["CARGO_PROFILE_TEST_DEBUG"] == "line-tables-only"
    assert not any(
        key in job["env"]
        for key in (
            "CARGO_PROFILE_TEST_OPT_LEVEL",
            "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS",
            "CARGO_PROFILE_TEST_OVERFLOW_CHECKS",
        )
    )
    assert job["timeout-minutes"] >= 10
    # load_ci_workflow() deliberately expands in-tree composites, so inspect
    # the raw YAML when checking the call-site binding.
    raw = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    raw_steps = raw["jobs"]["windows-shim-admin"]["steps"]
    invoke = next(step for step in raw_steps if step.get("uses") == "./.github/actions/ci-job-windows-shim-admin")
    assert invoke["with"]["shim-gate"] == "${{ matrix.shim-gate }}"

    steps = composite_action_steps("ci-job-windows-shim-admin")
    check = next(step for step in steps if step.get("name") == "Validate the selected Windows shim contract gate")
    assert check["env"]["SHIM_GATE"] == "${{ inputs.shim-gate }}"
    assert "'vectors', 'native-op', 'mcp'" in check["run"]
    assert "throw" in check["run"]
    assert not check.get("continue-on-error", False)

    rust = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert rust["with"]["cache-key"] == "windows-shim-${{ inputs.shim-gate }}"
    assert "cache-fallback-key" not in rust["with"]
    vector = next(step for step in steps if step.get("name") == "Replay the recorded Windows shim vectors")
    native_op = next(
        step for step in steps if step.get("name") == "Install and report shims through the native op on Windows"
    )
    assert vector["if"] == "inputs.shim-gate == 'vectors'"
    assert native_op["if"] == "inputs.shim-gate == 'native-op'"
    assert not vector.get("continue-on-error", False)
    assert not native_op.get("continue-on-error", False)
    assert (
        "cargo test --manifest-path rust/Cargo.toml --locked -p guard-command --test shim_admin_vectors"
        in vector["run"]
    )
    assert (
        "cargo test --manifest-path rust/Cargo.toml --locked -p hol-guard-runtime --lib shim_op"
        in native_op["run"]
    )
    child_tree = next(
        step for step in steps if step.get("name") == "Contain MCP server process trees in a JobObject on Windows"
    )
    assert child_tree["if"] == "inputs.shim-gate == 'mcp'"
    assert not child_tree.get("continue-on-error", False)
    assert (
        "cargo test --manifest-path rust/Cargo.toml --locked -p guard-runtime-windows-process --test child_tree"
        in child_tree["run"]
    )
    probe = next(step for step in steps if step.get("name") == "Probe an MCP server catalog natively on Windows")
    assert probe["if"] == "inputs.shim-gate == 'mcp'"
    assert not probe.get("continue-on-error", False)
    assert (
        "cargo test --manifest-path rust/Cargo.toml --locked -p guard-command --test mcp_stdio_probe_windows"
        in probe["run"]
    )
    launch = next(step for step in steps if step.get("name") == "Verify MCP launch executables natively on Windows")
    assert launch["if"] == "inputs.shim-gate == 'mcp'"
    assert not launch.get("continue-on-error", False)
    assert (
        "cargo test --manifest-path rust/Cargo.toml --locked -p guard-command --test launch_identity_windows"
        in launch["run"]
    )

    required = load_ci_workflow()["jobs"]["required"]
    assert "windows-shim-admin" in required["needs"]
    assert '"windows-shim-admin"' in "\n".join(step.get("run", "") for step in required["steps"])


def test_windows_partition_union_keeps_every_original_cargo_contract() -> None:
    prefix = "cargo test --manifest-path rust/Cargo.toml --locked -p "
    expected = {
        "vectors": [
            "guard-command --test shim_admin_vectors",
            "guard-command --test pretool_windows_drive_path_writes",
            "guard-command --test pretool_windows_sibling_repository_writes",
            "guard-command --test pretool_windows_git_toplevel",
        ],
        "native-op": [
            "hol-guard-runtime --lib shim_op",
            "hol-guard-runtime --lib direct_lane_input_tests",
            "hol-guard-runtime --lib storage_gate",
            "hol-guard-runtime --lib daemon_storage_hold",
            "hol-guard-runtime --lib windows_expanded_home",
            "guard-runtime-windows-process --test process_liveness",
            "hol-guard-runtime --lib managed_owner_lock",
            "hol-guard-runtime --lib owner_release",
        ],
        "mcp": [
            "guard-runtime-windows-process --test child_tree",
            "guard-command --test mcp_stdio_probe_windows",
            "guard-command --test launch_identity_windows",
        ],
    }
    steps = composite_action_steps("ci-job-windows-shim-admin")
    selected = {}
    for gate, commands in expected.items():
        steps_for_gate = [step for step in steps if step.get("if") == f"inputs.shim-gate == '{gate}'"]
        assert all(not step.get("continue-on-error", False) for step in steps_for_gate)
        assert all("$PSNativeCommandUseErrorActionPreference = $true" in step["run"] for step in steps_for_gate)
        selected[gate] = [
            line.strip().removeprefix(prefix)
            for step in steps_for_gate
            for line in step["run"].splitlines()
            if line.strip().startswith(prefix)
        ]
        assert selected[gate] == commands
    flattened = [command for commands in selected.values() for command in commands]
    assert len(flattened) == len(set(flattened)) == 15


def test_cross_platform_builds_no_native_runtime() -> None:
    """Keep the cross-platform lane free of Rust toolchain setup and cargo."""
    steps = load_ci_workflow()["jobs"]["cross-platform"]["steps"]
    assert not any(step.get("uses") == "./.github/actions/setup-rust" for step in steps)
    assert not any("cargo" in step.get("run", "") for step in steps)
