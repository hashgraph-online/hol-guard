from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.runtime_majority_report import DEFAULT_SCOPE, ScopeError, build_report, load_scope

REPO_ROOT = Path(__file__).resolve().parents[1]
CRATES = "rust/crates"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _scope(**rust_overrides: object) -> dict:
    return {
        "schema": "hol-guard.runtime-majority-scope.v1",
        "metric": {"formula": "rust/(rust+python)", "target_share": 0.7},
        "python": {
            "package_root": "src/pkg",
            "roots": [{"module": "pkg.root", "surface": "test"}],
            "exclusions": [],
            "reviewed_runtime": [{"path": ["src/pkg/*.py"], "reason": "reviewed"}],
            "tests": {"path": []},
            "generated": {"path": []},
            "adapters": {"path": []},
        },
        "rust": {"workspace": "rust", "binary_crate": "bin", "exclude_paths": [], **rust_overrides},
    }


def _repo(tmp_path: Path, scope: dict, *, root: str = "x = 1\n") -> tuple[Path, Path]:
    _write(tmp_path / "src" / "pkg" / "__init__.py", "")
    _write(tmp_path / "src" / "pkg" / "root.py", root)
    _write(tmp_path / "rust" / "Cargo.toml", '[workspace]\nmembers = ["crates/bin", "crates/lib"]\nresolver = "2"\n')
    _write(
        tmp_path / CRATES / "bin" / "Cargo.toml",
        '[package]\nname = "bin"\nversion = "0.1.0"\n[dependencies]\nlib = { path = "../lib" }\n',
    )
    _write(tmp_path / CRATES / "lib" / "Cargo.toml", '[package]\nname = "lib"\nversion = "0.1.0"\n')
    _write(
        tmp_path / CRATES / "bin" / "src" / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\n"
        "fn main() {\n    wired::run();\n    lib::shared::answer();\n}\n",
    )
    _write(tmp_path / CRATES / "bin" / "src" / "wired.rs", "pub fn run() {\n    super::chained::deep();\n}\n")
    _write(tmp_path / CRATES / "bin" / "src" / "chained.rs", "pub fn deep() {\n    let a = 1;\n    let b = a;\n}\n")
    _write(
        tmp_path / CRATES / "bin" / "src" / "orphan.rs",
        "pub fn never_called() {\n    let a = 1;\n    let b = a;\n    let c = b;\n}\n",
    )
    _write(tmp_path / CRATES / "bin" / "src" / "unused_name.rs", "pub struct Idle {\n    pub a: u8,\n}\n")
    _write(tmp_path / CRATES / "lib" / "src" / "lib.rs", "pub mod shared;\npub mod dormant;\n")
    _write(tmp_path / CRATES / "lib" / "src" / "shared.rs", "pub fn answer() -> u8 {\n    42\n}\n")
    _write(tmp_path / CRATES / "lib" / "src" / "dormant.rs", "pub fn sleeping() -> u8 {\n    7\n}\n")
    scope_path = tmp_path / DEFAULT_SCOPE
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text(json.dumps(scope), encoding="utf-8")
    return tmp_path, scope_path


def test_unwired_rust_is_reported_and_not_counted(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope())
    result = build_report(repo, scope_path)
    wired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["files"]}
    unwired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}
    assert wired == {"main.rs", "wired.rs", "chained.rs", "lib.rs", "shared.rs"}
    assert unwired == {"orphan.rs", "unused_name.rs", "dormant.rs"}
    assert result["metric"]["rust_runtime_loc"] == sum(item["loc"] for item in result["rust"]["files"])
    assert result["rust"]["linked_loc"] == result["metric"]["rust_runtime_loc"] + result["rust"]["unwired_loc"]
    records = [item for item in result["exclusions"] if item["category"] == "unwired"]
    assert {item["path"].rsplit("/", 1)[1] for item in records} == unwired
    # Every wired file records the first referrer that reached it; the entry root has none.
    via = {item["path"].rsplit("/", 1)[1]: item["wired_via"] for item in result["rust"]["files"]}
    assert via["main.rs"] == ""
    assert via["chained.rs"].endswith("wired.rs")
    assert via["shared.rs"].endswith("main.rs")


def test_rust_exclusion_needs_evidence_and_reports_it(tmp_path: Path) -> None:
    entry = {"path": f"{CRATES}/bin/src/wired.rs", "category": "offline_build_tool", "reason": "offline"}
    repo, scope_path = _repo(tmp_path, _scope(exclude_paths=[entry]))
    with pytest.raises(ScopeError, match="evidence"):
        load_scope(scope_path)
    entry["evidence"] = "only build.rs calls it"
    scope_path.write_text(json.dumps(_scope(exclude_paths=[entry])), encoding="utf-8")
    result = build_report(repo, scope_path)
    excluded = [item for item in result["exclusions"] if item["category"] == "offline_build_tool"]
    assert [(item["path"], item["evidence"]) for item in excluded] == [(entry["path"], "only build.rs calls it")]
    # chained.rs was reachable only through the excluded file, so it is now unwired too.
    assert "chained.rs" in {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}


REGISTRY_ROOT = "import importlib\n\n\ndef load(name):\n    return importlib.import_module(name, __package__)\n"


def _dynamic(resolution: str, **extra: object) -> dict:
    entry = {"path": "src/pkg/root.py", "count": 1, "resolution": resolution, "evidence": "reviewed registry"}
    return {**entry, **extra}


def _with_dynamic(entries: list[dict]) -> dict:
    scope = _scope()
    scope["python"]["dynamic_imports"] = entries
    return scope


def _in_scope(result: dict) -> set[str]:
    return {item["module"] for item in result["python"]["files"]}


def test_undeclared_non_literal_import_is_an_error(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope(), root=REGISTRY_ROOT)
    _write(repo / "src" / "pkg" / "plugin.py", "p = 1\n")
    with pytest.raises(ScopeError, match=r"root\.py: 1 non-literal import site"):
        build_report(repo, scope_path)


def test_follow_adds_declared_targets_and_unfollowed_does_not(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope(), root=REGISTRY_ROOT)
    _write(repo / "src" / "pkg" / "plugin.py", "p = 1\n")
    for resolution, expected in (("follow", True), ("unfollowed", False)):
        scope = _with_dynamic([_dynamic(resolution, targets=[".plugin"])])
        scope_path.write_text(json.dumps(scope), encoding="utf-8")
        result = build_report(repo, scope_path)
        assert ("pkg.plugin" in _in_scope(result)) is expected
        assert result["python"]["dynamic_imports"][0]["resolution"] == resolution
        assert result["python"]["dynamic_imports"][0]["in_scope"] is True
        assert result["python"]["dynamic_import_sites_unresolved"] == 1


def test_external_resolution_adds_nothing_and_needs_no_targets(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope(), root=REGISTRY_ROOT)
    _write(repo / "src" / "pkg" / "plugin.py", "p = 1\n")
    scope_path.write_text(json.dumps(_with_dynamic([_dynamic("external")])), encoding="utf-8")
    assert _in_scope(build_report(repo, scope_path)) == {"pkg", "pkg.root"}


def test_declared_count_must_match_the_sites_found(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope(), root=REGISTRY_ROOT)
    scope_path.write_text(json.dumps(_with_dynamic([_dynamic("external", count=2)])), encoding="utf-8")
    with pytest.raises(ScopeError, match="declared 2"):
        build_report(repo, scope_path)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (_dynamic("guess"), "resolution"),
        (_dynamic("external", count=0), "count"),
        (_dynamic("external", evidence=" "), "evidence"),
        (_dynamic("follow"), "target"),
        (_dynamic("follow", targets=[".plugin"], mode="sometimes"), "mode"),
    ],
)
def test_dynamic_import_entries_are_validated(tmp_path: Path, entry: dict, message: str) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(_with_dynamic([entry])), encoding="utf-8")
    with pytest.raises(ScopeError, match=message):
        load_scope(path)


def test_dynamic_import_sites_outside_the_closure_need_no_declaration(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope())
    _write(repo / "src" / "pkg" / "unreached.py", REGISTRY_ROOT)
    assert _in_scope(build_report(repo, scope_path)) == {"pkg", "pkg.root"}


def test_shipped_scope_declares_every_dynamic_import_with_the_registry_decision() -> None:
    scope = load_scope(REPO_ROOT / DEFAULT_SCOPE)
    entries = {entry["path"]: entry for entry in scope["python"]["dynamic_imports"]}
    registry = entries["src/codex_plugin_scanner/guard/adapters/__init__.py"]
    assert registry["resolution"] == "follow"
    assert ".cursor" in registry["targets"]
    assert "Decision" in registry["evidence"]
    assert all(entry["evidence"].strip() for entry in entries.values())


def test_shipped_rust_exclusions_carry_evidence_and_unwired_is_reported() -> None:
    result = build_report(REPO_ROOT, REPO_ROOT / DEFAULT_SCOPE, top=1)
    rust_exclusions = [item for item in result["exclusions"] if item["language"] == "rust" and "evidence" in item]
    assert rust_exclusions and all(item["evidence"].strip() for item in rust_exclusions)
    assert result["rust"]["unwired_loc"] > 0
    counted = {item["path"] for item in result["rust"]["files"]}
    assert not counted & {item["path"] for item in result["rust"]["unwired_files"]}
    assert f"{CRATES}/guard-command/src/hook_responses.rs" in counted


def test_declaration_without_a_remaining_site_is_an_error(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope())
    scope_path.write_text(json.dumps(_with_dynamic([_dynamic("external")])), encoding="utf-8")
    with pytest.raises(ScopeError, match=r"root\.py: 0 non-literal import site\(s\), declared 1"):
        build_report(repo, scope_path)


def test_declared_path_must_name_a_module(tmp_path: Path) -> None:
    repo, scope_path = _repo(tmp_path, _scope(), root=REGISTRY_ROOT)
    entries = [_dynamic("external"), _dynamic("external", path="src/pkg/ghost.py")]
    scope_path.write_text(json.dumps(_with_dynamic(entries)), encoding="utf-8")
    with pytest.raises(ScopeError, match=r"ghost\.py: declared dynamic import entry names no module"):
        build_report(repo, scope_path)


@pytest.mark.parametrize("resolution", ["follow", "unfollowed"])
def test_declared_target_must_resolve_to_a_module(tmp_path: Path, resolution: str) -> None:
    repo, scope_path = _repo(tmp_path, _scope(), root=REGISTRY_ROOT)
    _write(repo / "src" / "pkg" / "plugin.py", "p = 1\n")
    scope_path.write_text(json.dumps(_with_dynamic([_dynamic(resolution, targets=[".plugn"])])), encoding="utf-8")
    with pytest.raises(ScopeError, match=r"target '\.plugn' resolves to no module"):
        build_report(repo, scope_path)


def test_pub_mod_alias_reaches_the_declaring_file_sibling(tmp_path: Path) -> None:
    """A ``pub(super) mod`` alias is nameable one level up; a private one is not."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod holder;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "holder.rs", "pub(super) mod shown;\nmod hidden;\n")
    _write(source / "holder" / "shown.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "holder" / "hidden.rs", "fn go() -> u8 {\n    2\n}\n")
    _write(
        source / "sibling.rs",
        "pub fn call() -> u8 {\n    super::holder::shown::go() + super::holder::hidden::go()\n}\n",
    )
    result = build_report(repo, scope_path)
    wired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["files"]}
    unwired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}
    assert "shown.rs" in wired
    assert "hidden.rs" in unwired
    via = {item["path"].rsplit("/", 1)[1]: item["wired_via"] for item in result["rust"]["files"]}
    assert via["shown.rs"].endswith("sibling.rs")


def test_a_restricted_pub_mod_alias_stops_at_the_level_it_names(tmp_path: Path) -> None:
    """``pub(super)`` twice over does not make the inner module crate-wide."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod outer;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "outer.rs", "pub(super) mod middle;\n")
    _write(source / "outer" / "middle.rs", "pub(super) mod deep;\n")
    _write(source / "outer" / "middle" / "deep.rs", "fn go() -> u8 {\n    1\n}\n")
    # Only code under outer.rs may name ``deep``; a file at the crate root
    # cannot, so mentioning it here must not mark it wired.
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::outer::middle::deep::go()\n}\n")
    result = build_report(repo, scope_path)
    unwired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}
    assert "deep.rs" in unwired


def test_an_unrestricted_pub_mod_alias_carries_past_its_declaring_file(tmp_path: Path) -> None:
    """A plain ``pub mod`` chain stays nameable from the crate root's subtree."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod outer;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "outer.rs", "pub mod middle;\n")
    _write(source / "outer" / "middle.rs", "pub mod deep;\n")
    _write(source / "outer" / "middle" / "deep.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::outer::middle::deep::go()\n}\n")
    result = build_report(repo, scope_path)
    wired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["files"]}
    assert "deep.rs" in wired


def test_pub_self_mod_hides_the_alias_like_a_private_one(tmp_path: Path) -> None:
    """``pub(self) mod`` says what a bare ``mod`` says, so the alias stays inside."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod holder;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "holder.rs", "pub(self) mod kept;\n")
    _write(source / "holder" / "kept.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::holder::kept::go()\n}\n")
    result = build_report(repo, scope_path)
    unwired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}
    assert "kept.rs" in unwired


def test_a_pub_mod_reaches_as_far_as_its_restricted_parent_does(tmp_path: Path) -> None:
    """``pub mod`` under ``pub(super) mod`` is nameable where that parent is."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod outer;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    # ``middle`` is declared ``pub(super)`` in outer.rs, so the crate root may
    # name it; ``deep`` is ``pub`` inside middle.rs, so it reaches just as far.
    _write(source / "outer.rs", "pub(super) mod middle;\n")
    _write(source / "outer" / "middle.rs", "pub mod deep;\n")
    _write(source / "outer" / "middle" / "deep.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::outer::middle::deep::go()\n}\n")
    result = build_report(repo, scope_path)
    wired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["files"]}
    assert "deep.rs" in wired


def test_pub_in_crate_reaches_the_crate_root_like_pub_crate(tmp_path: Path) -> None:
    """``pub(in crate) mod`` is another spelling of ``pub(crate) mod``."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod outer;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "outer.rs", "pub(super) mod middle;\n")
    _write(source / "outer" / "middle.rs", "pub(in crate) mod deep;\n")
    _write(source / "outer" / "middle" / "deep.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::outer::middle::deep::go()\n}\n")
    result = build_report(repo, scope_path)
    wired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["files"]}
    assert "deep.rs" in wired


def test_pub_in_self_hides_the_alias_like_a_private_one(tmp_path: Path) -> None:
    """``pub(in self) mod`` is another spelling of ``pub(self) mod``."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod holder;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "holder.rs", "pub(in self) mod kept;\n")
    _write(source / "holder" / "kept.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::holder::kept::go()\n}\n")
    result = build_report(repo, scope_path)
    unwired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}
    assert "kept.rs" in unwired


def test_pub_in_a_path_naming_the_declaring_module_stays_inside_it(tmp_path: Path) -> None:
    """``pub(in crate::holder)`` written in holder.rs reaches no further than ``pub(self)``."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod holder;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "holder.rs", "pub(in crate::holder) mod kept;\n")
    _write(source / "holder" / "kept.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::holder::kept::go()\n}\n")
    result = build_report(repo, scope_path)
    unwired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["unwired_files"]}
    assert "kept.rs" in unwired


def test_pub_in_super_reaches_the_file_above_like_pub_super(tmp_path: Path) -> None:
    """``pub(in super) mod`` is another spelling of ``pub(super) mod``."""
    repo, scope_path = _repo(tmp_path, _scope())
    source = repo / CRATES / "bin" / "src"
    _write(
        source / "main.rs",
        "mod wired;\nmod chained;\nmod orphan;\nmod unused_name;\nmod outer;\nmod sibling;\n"
        "fn main() {\n    wired::run();\n    sibling::call();\n    lib::shared::answer();\n}\n",
    )
    _write(source / "outer.rs", "pub(in super) mod middle;\n")
    _write(source / "outer" / "middle.rs", "pub mod deep;\n")
    _write(source / "outer" / "middle" / "deep.rs", "fn go() -> u8 {\n    1\n}\n")
    _write(source / "sibling.rs", "pub fn call() -> u8 {\n    super::outer::middle::deep::go()\n}\n")
    result = build_report(repo, scope_path)
    wired = {item["path"].rsplit("/", 1)[1] for item in result["rust"]["files"]}
    assert "deep.rs" in wired
