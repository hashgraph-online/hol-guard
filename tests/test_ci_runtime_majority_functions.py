from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.runtime_majority_report import DEFAULT_SCOPE, ScopeError, build_report

REPO_ROOT = Path(__file__).resolve().parents[1]

RENDER = """\
from __future__ import annotations

import json
import textwrap

from pkg.fancy import panel
from pkg.helpers import redact

_TABLE: dict[str, object] = {}


def emit(payload, as_json):
    if as_json:
        return json.dumps(redact(payload))
    return _TABLE["x"](payload)


def _human(payload):
    return textwrap.dedent(str(panel(payload)))


_TABLE["x"] = _human
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _entry(**overrides: object) -> dict:
    entry = {
        "id": "render-human",
        "category": "cli_only",
        "path": "src/pkg/render.py",
        "symbols": ["_human", "_TABLE"],
        "entry_points": ["emit"],
        "reason": "terminal layout only",
        "evidence": "reachable only from emit's human branch",
    }
    entry.update(overrides)
    return entry


def _repo(tmp_path: Path, *, entries: list[dict], render: str = RENDER, root_extra: str = "") -> tuple[Path, Path]:
    pkg = tmp_path / "src" / "pkg"
    _write(pkg / "__init__.py", "")
    _write(pkg / "root.py", "from pkg.render import emit\n" + root_extra)
    _write(pkg / "render.py", render)
    _write(pkg / "helpers.py", "def redact(value):\n    return value\n")
    _write(pkg / "fancy.py", "def panel(value):\n    return value\n")
    _write(tmp_path / "rust" / "Cargo.toml", '[workspace]\nmembers = ["crates/bin"]\nresolver = "2"\n')
    _write(tmp_path / "rust" / "crates" / "bin" / "Cargo.toml", '[package]\nname = "bin"\nversion = "0.1.0"\n')
    _write(tmp_path / "rust" / "crates" / "bin" / "src" / "main.rs", "fn main() {}\n")
    _write(tmp_path / "tests" / "test_a.py", "assert True\n")
    scope = {
        "schema": "hol-guard.runtime-majority-scope.v1",
        "metric": {"formula": "rust/(rust+python)", "target_share": 0.7},
        "python": {
            "package_root": "src/pkg",
            "roots": [{"module": "pkg.root", "surface": "test"}],
            "exclusions": [],
            "function_exclusions": entries,
            "reviewed_runtime": [],
            "tests": {"path": ["tests/*.py"]},
            "generated": {"path": []},
            "adapters": {"path": []},
        },
        "rust": {"workspace": "rust", "binary_crate": "bin", "exclude_paths": []},
    }
    scope_path = tmp_path / DEFAULT_SCOPE
    _write(scope_path, json.dumps(scope))
    return tmp_path, scope_path


def _loc(report: dict, path: str) -> int:
    return next(item["loc"] for item in report["python"]["files"] if item["path"] == path)


def test_retained_reference_outside_entry_points_is_rejected(tmp_path: Path) -> None:
    repo, scope = _repo(tmp_path, entries=[_entry()])
    with pytest.raises(ScopeError, match="not a listed entry_point"):
        build_report(repo, scope)


def test_valid_exclusion_subtracts_loc_and_prunes_imports(tmp_path: Path) -> None:
    render = RENDER.replace('\n\n_TABLE["x"] = _human\n', "\n")
    repo, scope = _repo(tmp_path / "base", entries=[], render=render)
    whole = build_report(repo, scope)
    repo, scope = _repo(tmp_path / "cut", entries=[_entry(symbols=["_human", "_TABLE"])], render=render)
    cut = build_report(repo, scope)
    paths = {item["path"] for item in cut["python"]["files"]}
    # `panel` and `textwrap` were only used by the excluded symbol: the import edge to
    # pkg.fancy goes away with it, but `redact` stays reachable.
    assert "src/pkg/fancy.py" not in paths
    assert "src/pkg/helpers.py" in paths
    assert _loc(whole, "src/pkg/render.py") - _loc(cut, "src/pkg/render.py") == 5
    [record] = [item for item in cut["exclusions"] if item["kind"] == "function"]
    assert record["loc"] == 5
    assert record["pruned_import_loc"] == 2
    assert record["symbols"] == ["_TABLE", "_human"]
    [summary] = [item for item in cut["exclusion_summary"] if item["id"] == "render-human"]
    assert summary["loc"] == 5


def test_other_module_importing_an_excluded_symbol_is_rejected(tmp_path: Path) -> None:
    render = RENDER.replace('\n\n_TABLE["x"] = _human\n', "\n")
    repo, scope = _repo(tmp_path, entries=[_entry()], render=render, root_extra="from pkg.render import _human\n")
    with pytest.raises(ScopeError, match="imports excluded _human"):
        build_report(repo, scope)


@pytest.mark.parametrize(
    ("root_extra", "message"),
    [
        ("import pkg.render as r\nr._human(1)\n", "uses excluded _human"),
        ("import pkg.render\npkg.render._human(1)\n", "uses excluded _human"),
        ("from pkg import render\nrender._human(1)\n", "uses excluded _human"),
        ("from pkg.render import *\n", "imports excluded \\* from"),
    ],
)
def test_every_import_form_is_checked_for_excluded_symbols(tmp_path: Path, root_extra: str, message: str) -> None:
    render = RENDER.replace('\n\n_TABLE["x"] = _human\n', "\n")
    repo, scope = _repo(tmp_path, entries=[_entry()], render=render, root_extra=root_extra)
    with pytest.raises(ScopeError, match=message):
        build_report(repo, scope)


def test_rebinding_a_local_name_does_not_hide_an_excluded_symbol(tmp_path: Path) -> None:
    render = RENDER.replace('\n\n_TABLE["x"] = _human\n', "\n")
    extra = "from pkg import render\nrender._human(1)\n\n\ndef other():\n    from pkg import helpers as render\n"
    repo, scope = _repo(tmp_path, entries=[_entry()], render=render, root_extra=extra)
    with pytest.raises(ScopeError, match="uses excluded _human"):
        build_report(repo, scope)


def test_removed_and_retained_statements_sharing_a_line_are_rejected(tmp_path: Path) -> None:
    render = RENDER.replace('\n\n_TABLE["x"] = _human\n', "\n") + "_KEEP = 1; _GONE = 2\n"
    repo, scope = _repo(tmp_path, entries=[_entry(symbols=["_human", "_GONE"])], render=render)
    with pytest.raises(ScopeError, match="share source lines"):
        build_report(repo, scope)


def test_function_entry_ids_must_be_unique(tmp_path: Path) -> None:
    repo, scope = _repo(tmp_path, entries=[_entry(), _entry(symbols=["_TABLE"])])
    with pytest.raises(ScopeError, match="is not unique"):
        build_report(repo, scope)


def test_runtime_roots_cannot_be_partially_excluded(tmp_path: Path) -> None:
    repo, scope = _repo(tmp_path, entries=[_entry(path="src/pkg/root.py", symbols=["emit"], entry_points=[])])
    with pytest.raises(ScopeError, match="runtime root"):
        build_report(repo, scope)


def test_missing_symbol_and_unknown_entry_point_are_rejected(tmp_path: Path) -> None:
    render = RENDER.replace('\n\n_TABLE["x"] = _human\n', "\n")
    repo, scope = _repo(tmp_path / "a", entries=[_entry(symbols=["_nope"])], render=render)
    with pytest.raises(ScopeError, match="not found at module level"):
        build_report(repo, scope)
    repo, scope = _repo(tmp_path / "b", entries=[_entry(entry_points=["ghost"])], render=render)
    with pytest.raises(ScopeError, match="entry_points are not retained"):
        build_report(repo, scope)


def test_entries_need_evidence_and_reason(tmp_path: Path) -> None:
    repo, scope = _repo(tmp_path, entries=[_entry(evidence="")])
    with pytest.raises(ScopeError, match="needs evidence"):
        build_report(repo, scope)


def test_shipped_render_exclusion_keeps_hook_json_and_redaction_in_scope() -> None:
    scope = json.loads((REPO_ROOT / DEFAULT_SCOPE).read_text(encoding="utf-8"))
    [entry] = [item for item in scope["python"]["function_exclusions"] if item["id"] == "render-human-output"]
    retained_required = {
        "emit_guard_payload",
        "_redact_payload",
        "_render_redacted_json_payload",
        "_safe_json_output_text",
        "_sanitize_payload_for_output",
        "_JSON_RENDERERS",
    }
    assert retained_required.isdisjoint(entry["symbols"])
    assert entry["entry_points"] == ["emit_guard_payload"]
