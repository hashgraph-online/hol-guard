from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import runtime_majority_report as report_module
from scripts.ci.runtime_majority_python import build_graph, closure, count_python_loc
from scripts.ci.runtime_majority_report import DEFAULT_SCOPE, ScopeError, build_report, load_scope, main
from scripts.ci.runtime_majority_rust import analyze_source

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_rust_loc_ignores_comments_blanks_and_cfg_test_blocks() -> None:
    source = (
        "// comment\n"
        "\n"
        "/* block\n   comment */\n"
        "pub fn run() -> u32 {\n"
        '    let s = "// not a comment";\n'
        "    1\n"
        "}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn it() {\n"
        "        assert_eq!(1, 1);\n"
        "    }\n"
        "}\n"
    )
    runtime_loc, test_loc, _code, _flags = analyze_source(source)
    assert runtime_loc == 4
    assert test_loc == 7


def test_rust_inner_cfg_test_attribute_strips_whole_file() -> None:
    runtime_loc, test_loc, _code, _flags = analyze_source("#![cfg(test)]\nfn a() {}\nfn b() {}\n")
    assert runtime_loc == 0
    assert test_loc >= 2


def test_python_loc_skips_comments_and_blank_lines_but_counts_docstrings() -> None:
    source = '"""doc\nstring"""\n\n# comment\nx = 1  # trailing\n\n\ndef f():\n    return x\n'
    assert count_python_loc(source) == 5


def _write(path: Path, text: str = "x = 1\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _package(tmp_path: Path) -> Path:
    pkg = tmp_path / "src" / "pkg"
    _write(pkg / "__init__.py", "")
    _write(
        pkg / "root.py",
        "from pkg import eager_dep\nfrom pkg.skipped import thing\n\ndef go():\n    import pkg.lazy_dep\n",
    )
    _write(pkg / "eager_dep.py", "y = 1\n")
    _write(pkg / "lazy_dep.py", "z = 1\nimport pkg.only_via_lazy\n")
    _write(pkg / "only_via_lazy.py", "q = 1\n")
    _write(pkg / "skipped.py", "from pkg import behind_skipped\nthing = 1\n")
    _write(pkg / "behind_skipped.py", "w = 1\n")
    _write(pkg / "typing_only.py", "v = 1\n")
    _write(pkg / "unused.py", "u = 1\n")
    _write(
        pkg / "tc.py",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pkg import typing_only\n",
    )
    return tmp_path


def test_closure_classifies_eager_lazy_and_prunes_exclusions(tmp_path: Path) -> None:
    repo = _package(tmp_path)
    graph = build_graph(repo, "src/pkg")
    exclusion = {"id": "skip", "category": "x", "reason": "r", "path": ["src/pkg/skipped.py"]}
    parent, excluded, kind = closure(graph, ["pkg.root", "pkg.tc"], exclusions=[exclusion])
    assert kind["pkg.eager_dep"] == "eager"
    assert kind["pkg.lazy_dep"] == "lazy"
    assert kind["pkg.only_via_lazy"] == "lazy"
    assert "pkg.skipped" in excluded and "pkg.skipped" not in parent
    assert "pkg.behind_skipped" not in parent
    assert "pkg.typing_only" not in parent
    assert "pkg.unused" not in parent


def _scope(**overrides: object) -> dict:
    scope = {
        "schema": "hol-guard.runtime-majority-scope.v1",
        "metric": {"formula": "rust/(rust+python)", "target_share": 0.7},
        "python": {
            "package_root": "src/pkg",
            "roots": [{"module": "pkg.root", "surface": "test"}],
            "exclusions": [
                {"id": "skip", "category": "cli_only", "reason": "offline", "path": ["src/pkg/skipped.py"]},
            ],
            "reviewed_runtime": [{"path": ["src/pkg/lazy_dep.py"], "reason": "reviewed"}],
            "tests": {"path": ["tests/*.py"]},
            "generated": {"path": []},
            "adapters": {"path": []},
        },
        "rust": {"workspace": "rust", "binary_crate": "bin", "exclude_paths": []},
    }
    scope.update(overrides)
    return scope


def _rust_workspace(repo: Path) -> None:
    _write(repo / "rust" / "Cargo.toml", '[workspace]\nmembers = ["crates/bin"]\nresolver = "2"\n')
    _write(repo / "rust" / "crates" / "bin" / "Cargo.toml", '[package]\nname = "bin"\nversion = "0.1.0"\n')
    _write(
        repo / "rust" / "crates" / "bin" / "src" / "main.rs",
        '// c\nfn main() {\n    println!("hi");\n}\n#[cfg(test)]\nmod t { fn x() {} }\n',
    )
    _write(repo / "tests" / "test_a.py", "assert True\n")


def _synthetic_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = _package(tmp_path)
    _rust_workspace(repo)
    scope_path = repo / DEFAULT_SCOPE
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text(json.dumps(_scope()), encoding="utf-8")
    return repo, scope_path


def test_report_computes_share_pending_and_exclusions(tmp_path: Path) -> None:
    repo, scope_path = _synthetic_repo(tmp_path)
    result = build_report(repo, scope_path, top=3)
    metric = result["metric"]
    assert metric["rust_runtime_loc"] == 3
    in_scope = {item["module"] for item in result["python"]["files"]}
    assert in_scope == {"pkg", "pkg.root", "pkg.eager_dep", "pkg.lazy_dep", "pkg.only_via_lazy"}
    assert metric["python_runtime_loc"] == sum(item["loc"] for item in result["python"]["files"])
    assert metric["share"] == pytest.approx(3 / (3 + metric["python_runtime_loc"]), abs=1e-6)
    # lazy_dep is reviewed; only_via_lazy is lazy-only and unreviewed -> pending.
    assert [item["module"] for item in result["python"]["pending_unclassified_modules"]] == ["pkg.only_via_lazy"]
    direct = [item for item in result["exclusions"] if item["language"] == "python"]
    assert {(item["path"], item["kind"]) for item in direct} == {
        ("src/pkg/skipped.py", "direct"),
        ("src/pkg/behind_skipped.py", "transitive"),
    }
    assert all(item["reason"] for item in result["exclusions"])
    assert len(result["retirement_worklist"]) <= 3
    assert result["non_runtime_totals"]["tests"]["python_loc"] == 1
    assert result["non_runtime_totals"]["tests"]["rust_loc"] == 2


def test_report_is_deterministic(tmp_path: Path) -> None:
    repo, scope_path = _synthetic_repo(tmp_path)
    assert build_report(repo, scope_path) == build_report(repo, scope_path)


def test_scope_requires_reason_on_exclusions(tmp_path: Path) -> None:
    bad = _scope()
    bad["python"]["exclusions"] = [{"id": "x", "category": "c", "reason": "", "path": ["a.py"]}]
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path)


def test_missing_root_is_an_error(tmp_path: Path) -> None:
    repo, scope_path = _synthetic_repo(tmp_path)
    scope = _scope()
    scope["python"]["roots"] = [{"module": "pkg.nope", "surface": "test"}]
    scope_path.write_text(json.dumps(scope), encoding="utf-8")
    with pytest.raises(ScopeError):
        build_report(repo, scope_path)


def test_min_share_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo, scope_path = _synthetic_repo(tmp_path)
    base = ["--repo", str(repo), "--scope", str(scope_path)]
    assert main([*base, "--min-share", "0.0"]) == 0
    assert main([*base, "--min-share", "0.99"]) == 1
    assert "below --min-share" in capsys.readouterr().err
    assert main([*base, "--json"]) == 0
    assert json.loads(capsys.readouterr().out.rsplit("runtime-majority:", 1)[0])["schema"] == report_module.SCHEMA


def test_shipped_scope_is_valid_and_has_no_stale_entries() -> None:
    scope = load_scope(REPO_ROOT / DEFAULT_SCOPE)
    assert scope["metric"]["target_share"] == 0.7
    ids = [entry["id"] for entry in scope["python"]["exclusions"]]
    assert len(ids) == len(set(ids))
    result = build_report(REPO_ROOT, REPO_ROOT / DEFAULT_SCOPE)
    assert [item["id"] for item in result["exclusion_summary"] if item["matches_nothing_in_closure"]] == []
    assert result["metric"]["rust_runtime_loc"] > 0
    assert 0 < result["metric"]["share"] < 1
    assert len(result["retirement_worklist"]) == 40
    assert result["exclusions"], "every exclusion must be reported"


def test_cli_entrypoint_runs_from_source_tree() -> None:
    completed = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "ci" / "runtime_majority_report.py"), "--top", "3"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert completed.returncode == 0, completed.stderr
    assert "runtime majority share" in completed.stdout
