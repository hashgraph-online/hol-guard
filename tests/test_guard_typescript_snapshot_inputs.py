from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.typescript_snapshot_inputs import typescript_snapshot_inputs


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")


def _workspace(root: Path) -> tuple[Path, Path]:
    workspace = root / "workspace"
    package_root = workspace / "node_modules" / "typescript"
    _write(workspace / "src" / "example.ts", "export const value: number = 1;\n")
    _write(package_root / "bin" / "tsc", "require('../lib/tsc.js');\n")
    _write(package_root / "lib" / "tsc.js", "process.exit(0);\n")
    _write(package_root / "package.json", '{"name":"typescript","version":"5.9.0"}\n')
    return workspace.resolve(), package_root.resolve()


@pytest.mark.parametrize("dependency", ("node_modules/@types/bad", "node_modules/parent-dep"))
def test_visible_ancestor_dependencies_require_guard_review(tmp_path: Path, dependency: str) -> None:
    workspace, package_root = _workspace(tmp_path / "project")
    _write(tmp_path / "project" / dependency / "index.d.ts", "declare const broken: MissingType;\n")

    with pytest.raises(ValueError, match="external TypeScript dependencies"):
        _ = typescript_snapshot_inputs(workspace, package_root, ("src/example.ts",))


@pytest.mark.parametrize("dependency", ("node_modules/@types/credentials", "node_modules/credentials"))
def test_protected_workspace_dependencies_require_guard_review(tmp_path: Path, dependency: str) -> None:
    workspace, package_root = _workspace(tmp_path)
    _write(workspace / dependency / "index.d.ts", "declare const broken: MissingType;\n")

    with pytest.raises(ValueError, match="protected TypeScript dependency"):
        _ = typescript_snapshot_inputs(workspace, package_root, ("src/example.ts",))


@pytest.mark.parametrize("budget", ("entries", "time"))
def test_streaming_discovery_enforces_hard_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget: str,
) -> None:
    workspace, package_root = _workspace(tmp_path)
    _write(package_root / "lib" / "extra.js", "module.exports = {};\n")
    if budget == "entries":
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.typescript_snapshot_inputs._MAX_DISCOVERY_ENTRIES",
            1,
        )
    else:
        observed_times = iter((0.0, 10.0))
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.typescript_snapshot_inputs.time.monotonic",
            lambda: next(observed_times),
        )

    expected_message = "discovery entry budget" if budget == "entries" else "discovery time budget"
    with pytest.raises(ValueError, match=expected_message):
        _ = typescript_snapshot_inputs(workspace, package_root, ("src/example.ts",))


def test_snapshot_input_order_and_digests_are_deterministic(tmp_path: Path) -> None:
    workspace, package_root = _workspace(tmp_path)
    _write(workspace / "src" / "util.ts", "export const util = true;\n")
    _write(workspace / "node_modules" / "@types" / "example" / "index.d.ts", "declare const ambient: string;\n")

    first = typescript_snapshot_inputs(workspace, package_root, ("src/example.ts",))
    second = typescript_snapshot_inputs(workspace, package_root, ("src/example.ts",))

    assert first == second
    closure_paths = tuple(item.snapshot_path for item in first[3])
    assert closure_paths == tuple(sorted(closure_paths))
    assert "src/util.ts" in closure_paths
    assert "node_modules/@types/example/index.d.ts" in closure_paths
