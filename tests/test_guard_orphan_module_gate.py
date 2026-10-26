"""Keep unreferenced Guard modules out of the tree as the Rust migration folds them."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.ci import guard_orphan_module_gate as gate

ROOT = Path(__file__).resolve().parents[1]


def _package(root: Path) -> Path:
    package = root / gate.PACKAGE
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    return package


def test_self_test_passes() -> None:
    """Keep the detector's own fixtures honest before it judges the repository."""
    gate._self_test()


def test_repository_has_no_orphaned_guard_modules() -> None:
    """Fail here too, so the required suite catches residue even if the audit job is skipped."""
    assert gate.find_orphans(ROOT) == []


def test_fold_residue_is_reported(tmp_path: Path) -> None:
    """A fold that lands the contents but forgets the `git rm` leaves a detectable file."""
    package = _package(tmp_path)
    (package / "owner.py").write_text("from .folded import helper\n", encoding="utf-8")
    (package / "folded.py").write_text("def helper() -> int:\n    return 1\n", encoding="utf-8")
    (package / "left_behind.py").write_text("def helper() -> int:\n    return 2\n", encoding="utf-8")
    suite = tmp_path / "tests"
    suite.mkdir()
    (suite / "test_owner.py").write_text(
        "from codex_plugin_scanner.guard.owner import helper\n",
        encoding="utf-8",
    )

    assert gate.find_orphans(tmp_path) == [f"{gate.PACKAGE}/left_behind.py"]


def test_package_markers_are_never_residue(tmp_path: Path) -> None:
    """`__init__` and `__main__` are reached through their package, not their own stem."""
    package = _package(tmp_path)
    (package / "__main__.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    nested = package / "daemon"
    nested.mkdir()
    (nested / "__init__.py").write_text("", encoding="utf-8")

    assert gate.find_orphans(tmp_path) == []


def test_a_name_used_only_in_a_string_still_counts(tmp_path: Path) -> None:
    """Dynamic imports and CI manifests name modules as text, so tokenize string literals too."""
    package = _package(tmp_path)
    (package / "dynamic.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "loader.py").write_text(
        'from importlib import import_module\n\nimport_module(".dynamic", __package__)\n',
        encoding="utf-8",
    )
    manifest = tmp_path / "scripts" / "ci"
    manifest.mkdir(parents=True)
    (manifest / "inventory.json").write_text(json.dumps({"modules": ["loader"]}), encoding="utf-8")

    assert gate.find_orphans(tmp_path) == []


def test_bytecode_caches_cannot_keep_a_deleted_module_alive(tmp_path: Path) -> None:
    """A stale `__pycache__` entry is not a reference."""
    package = _package(tmp_path)
    (package / "left_behind.py").write_text("VALUE = 1\n", encoding="utf-8")
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "left_behind.py").write_text("left_behind\n", encoding="utf-8")

    assert gate.find_orphans(tmp_path) == [f"{gate.PACKAGE}/left_behind.py"]


def test_the_allowlist_suppresses_a_declared_module(tmp_path: Path, monkeypatch) -> None:
    """A deliberate orphan stays out of the report once it is declared with a reason."""
    package = _package(tmp_path)
    (package / "left_behind.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(gate, "ALLOWLIST", (f"{gate.PACKAGE}/left_behind.py",))

    assert gate.find_orphans(tmp_path) == []


def test_a_missing_package_reports_nothing(tmp_path: Path) -> None:
    """Never fail a checkout that does not contain the Guard package."""
    assert gate.find_orphans(tmp_path) == []


def test_main_exits_nonzero_on_residue(tmp_path: Path, capsys) -> None:
    """The audit job depends on the exit status, not the printed report."""
    package = _package(tmp_path)
    (package / "left_behind.py").write_text("VALUE = 1\n", encoding="utf-8")

    assert gate.main(["--root", str(tmp_path)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == gate.SCHEMA_VERSION
    assert report["orphan_module_paths"] == [f"{gate.PACKAGE}/left_behind.py"]


def test_the_audit_job_runs_the_gate() -> None:
    """Keep the workflow wired to the detector it is named for."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/guard-orphan-modules.yml").read_text(encoding="utf-8"))
    [job] = workflow["jobs"].values()
    assert workflow["permissions"] == {"contents": "read"}
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    runs = [step.get("run", "") for step in job["steps"]]
    assert "python3 scripts/ci/guard_orphan_module_gate.py --self-test" in runs
    assert "python3 scripts/ci/guard_orphan_module_gate.py --root ." in runs


def test_the_audit_job_watches_the_package_it_guards() -> None:
    """Residue appears when `src/` changes, so the path filter must include it."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/guard-orphan-modules.yml").read_text(encoding="utf-8"))
    # PyYAML resolves the unquoted `on:` key to True.
    triggers = workflow[True]
    for event in ("pull_request", "push"):
        assert "src/**" in triggers[event]["paths"]


def test_detector_fixtures_cannot_shelter_a_real_module(tmp_path: Path) -> None:
    """Names used only by this detector's own fixtures must not count as repository references."""
    package = _package(tmp_path)
    (package / "left_behind.py").write_text("VALUE = 1\n", encoding="utf-8")
    for name in gate.FIXTURE_SOURCES:
        fixture = tmp_path / name
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text('(package / "left_behind.py").write_text("VALUE = 1")\n', encoding="utf-8")

    assert gate.find_orphans(tmp_path) == [f"{gate.PACKAGE}/left_behind.py"]


def test_the_excluded_fixture_sources_still_exist() -> None:
    """Renaming either file would turn the exclusion into a silent no-op."""
    for name in gate.FIXTURE_SOURCES:
        assert (ROOT / name).is_file(), name
