from __future__ import annotations

import importlib.util
import json
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "python_capability_cleanup_gate.py"
SPEC = importlib.util.spec_from_file_location("python_capability_cleanup_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


@pytest.fixture
def cleanup_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A small ownership contract for testing source changes and packaging together."""

    source = tmp_path / "src"
    source.mkdir()
    candidates = ["src/retired_first.py", "src/retired_second.py"]
    for candidate in candidates:
        (tmp_path / candidate).write_text("", encoding="utf-8")
    contract = GATE._read_json(ROOT / GATE.CONTRACT)
    contract.update(
        scope_globs=["src/retired_*.py"],
        capabilities=[{"id": "retired", "class": "dead_duplicate", "patterns": ["src/retired_*.py"]}],
        package_excluded_candidates=candidates,
        retired_modules=[],
        retired_bodies=[],
        retired_test_paths=[],
        oracle_tests=[],
        lazy_oracle_modules=[],
    )
    contract_path = tmp_path / GATE.CONTRACT
    contract_path.parent.mkdir(parents=True)
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    fixture = tmp_path / contract["parity_fixture"]
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes((ROOT / contract["parity_fixture"]).read_bytes())
    (tmp_path / "pyproject.toml").write_text(
        "[tool.hatch.build]\nexclude = " + json.dumps(candidates) + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(GATE, "_verify_import_surface", lambda *_args: None)
    return tmp_path


def test_cleanup_shares_one_analysis_across_candidates_and_artifacts(
    cleanup_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = cleanup_repository / "clean.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("active.py", "")
    sdist = cleanup_repository / "clean.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        archive.add(cleanup_repository / "pyproject.toml", arcname="package/pyproject.toml")
    analyses = 0
    analysis_module = importlib.import_module("scripts.ci.python_capability_cleanup_analysis")
    analyze = analysis_module._module_analyses

    def count_analysis(root: Path):
        nonlocal analyses
        analyses += 1
        return analyze(root)

    monkeypatch.setattr(analysis_module, "_module_analyses", count_analysis)

    payload = GATE.run(cleanup_repository, wheel, artifacts=[sdist])

    assert analyses == 1
    assert len(payload["candidate_evidence"]) == 2
    assert payload["checked_artifacts"] == [str(wheel), str(sdist)]

    with tarfile.open(sdist, "w:gz") as archive:
        archive.add(cleanup_repository / "src/retired_second.py", arcname="package/src/retired_second.py")
    with pytest.raises(RuntimeError, match=r"package artifact contains excluded dead module: retired_second\.py"):
        GATE.run(cleanup_repository, artifacts=[wheel, sdist])


@pytest.mark.parametrize(
    "loader",
    [
        "import retired_second\n",
        "import importlib\nimportlib.import_module('retired_second')\n",
    ],
)
def test_cleanup_reanalyzes_changed_sources_for_every_invocation(cleanup_repository: Path, loader: str) -> None:
    assert GATE.run(cleanup_repository)["status"] == "passed"
    (cleanup_repository / "src/loader.py").write_text(loader, encoding="utf-8")

    with pytest.raises(
        RuntimeError, match=r"dead candidate still has source import reachability: src/retired_second\.py"
    ):
        GATE.run(cleanup_repository)


def test_cleanup_shared_analysis_still_rejects_unbounded_imports(cleanup_repository: Path) -> None:
    (cleanup_repository / "src/loader.py").write_text(
        "import importlib\nimportlib.import_module(user_supplied)\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="dynamic import destination is not literal or statically bounded: loader:2"):
        GATE.run(cleanup_repository)


def test_cleanup_contract_covers_every_scoped_hook_capability() -> None:
    payload = GATE.run(ROOT)

    assert payload["schema"] == "hol-guard.python-capability-cleanup.v1"
    assert payload["status"] == "passed"
    # Every scoped file must have one capability owner, including extracted hook helpers.
    assert payload["scope_files"] == sum(payload["capabilities"].values())
    assert "legacy_python_resident_transport" not in payload["capabilities"]
    assert payload["candidate_evidence"] == []
    contract = GATE._read_json(ROOT / GATE.CONTRACT)
    assert payload["retired_evidence"] == [
        {
            "path": record["path"],
            "module": record["module"],
            "source_present": False,
            "source_importers": [],
        }
        for record in contract["retired_modules"]
    ]
    assert payload["dynamic_import_destinations_checked"] is True
    assert payload["dynamic_import_unbounded"] == []
    assert payload["dynamic_import_count"] == len(payload["dynamic_import_evidence"])


def test_dynamic_import_gate_rejects_unbounded_destination(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\ndef load(destination: str):\n    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:3"]


def test_dynamic_import_gate_does_not_leak_sibling_function_bindings(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "def unrelated():\n"
        "    destination = 'example.allowed'\n"
        "    return destination\n"
        "def load(destination: str):\n"
        "    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:6"]


def test_dynamic_import_gate_preserves_function_local_static_bindings(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "def load():\n"
        "    destination = 'example.allowed'\n"
        "    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == []
    assert evidence[0].destination_values == ("example.allowed",)


def test_dynamic_import_gate_resolves_statement_order_and_control_flow_conservatively(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "importlib.import_module(destination)\n"
        "destination = 'example.late'\n"
        "def load_branch(flag):\n"
        "    if flag:\n"
        "        branch_destination = user_supplied\n"
        "    else:\n"
        "        branch_destination = 'example.allowed'\n"
        "    return importlib.import_module(branch_destination)\n",
        encoding="utf-8",
    )

    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert evidence[0].destination_kind == "unbounded"
    assert evidence[1].destination_kind == "unbounded"
    assert unbounded == ["example:2", "example:9"]


def test_dynamic_import_gate_does_not_use_future_loop_source_assignments(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "for destination in destinations:\n"
        "    importlib.import_module(destination)\n"
        "destinations = ('example.allowed',)\n",
        encoding="utf-8",
    )

    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert evidence[0].destination_kind == "unbounded"
    assert unbounded == ["example:3"]


def test_dynamic_import_gate_requires_proof_from_cross_module_callers(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "def load(destination):\n"
        "    return importlib.import_module(destination)\n"
        "load('example.allowed')\n",
        encoding="utf-8",
    )
    (source / "caller.py").write_text(
        "from example import load\nload(user_supplied)\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:3"]


def test_dynamic_import_gate_does_not_merge_same_name_functions_across_modules(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "first.py").write_text(
        "import importlib\ndef load(destination):\n    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )
    (source / "second.py").write_text(
        "def load(destination):\n    return destination\nload('example.allowed')\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["first:3"]


def test_dynamic_import_gate_does_not_merge_nested_same_name_functions(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "def load(destination):\n"
        "    return importlib.import_module(destination)\n"
        "def wrapper():\n"
        "    def load(destination):\n"
        "        return destination\n"
        "    return load('example.allowed')\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:3"]


def test_dynamic_import_gate_does_not_inherit_conditional_parent_bindings(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "if user_supplied:\n"
        "    destination = 'example.allowed'\n"
        "def load():\n"
        "    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:5"]


def test_dynamic_import_gate_collects_function_local_import_aliases(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "def load_with_module_alias():\n"
        "    import importlib as local_importlib\n"
        "    return local_importlib.import_module('example.allowed')\n"
        "def load_with_function_alias():\n"
        "    from importlib import import_module as local_load\n"
        "    return local_load('example.other')\n",
        encoding="utf-8",
    )

    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == []
    assert [item.destination_values for item in evidence] == [("example.allowed",), ("example.other",)]


def test_dynamic_import_graph_records_alias_and_static_expression(tmp_path: Path) -> None:
    package = tmp_path / "src" / "codex_plugin_scanner" / "guard"
    package.mkdir(parents=True)
    (package / "native_runtime_resident.py").write_text("", encoding="utf-8")
    (package / "loader.py").write_text(
        "from importlib import import_module as load\n"
        "prefix = 'codex_plugin_scanner.guard.'\n"
        "destination = prefix + 'native_runtime_resident'\n"
        "load(destination)\n",
        encoding="utf-8",
    )

    importers = GATE._production_importers(tmp_path, "codex_plugin_scanner.guard.native_runtime_resident")

    assert any(item.startswith("codex_plugin_scanner.guard.loader:") for item in importers)


def test_cleanup_contract_requires_exclusion_or_physical_retirement_record() -> None:
    contract = GATE._read_json(ROOT / GATE.CONTRACT)
    contract["package_excluded_candidates"] = []
    contract["retired_modules"] = []

    with pytest.raises(RuntimeError, match="non-empty exclusion or retirement record"):
        GATE._run_inputs(ROOT, contract)


def test_retired_python_oracle_compat_loader_is_absent() -> None:
    retired = ROOT / "src" / "codex_plugin_scanner" / "guard" / "cli" / "commands_hook_compat_loader.py"
    assert not retired.exists()


def _retired_oracle_repository(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    """A minimal repository with the retired hook oracle contract entries."""

    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "rust/crates/guard-hook-core/src").mkdir(parents=True)
    (tmp_path / "rust/crates/guard-hook-core/src/lib.rs").write_text("", encoding="utf-8")
    contract: dict[str, object] = {
        "retired_modules": [
            {
                "path": "src/codex_plugin_scanner/guard/runtime/hook_review_engine.py",
                "module": "codex_plugin_scanner.guard.runtime.hook_review_engine",
                "source_sha256": "0" * 64,
                "forbidden_symbols": ["HookReviewEngine"],
                "native_replacements": ["rust/crates/guard-hook-core/src/lib.rs"],
            }
        ],
        "dependency_delta": {"removed_runtime_flags": ["HOL_GUARD_PYTHON_ORACLE"]},
    }
    return tmp_path, contract


def test_retired_module_rejects_renamed_test_copy(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    (root / "tests/oracle_copy.py").write_text("class HookReviewEngine:\n    pass\n", encoding="utf-8")
    analysis = GATE._analyze_import_graph(root)

    with pytest.raises(RuntimeError, match="retired implementation symbol HookReviewEngine"):
        GATE.validate_retired_modules(root, contract, analysis=analysis)

    (root / "tests/oracle_copy.py").write_text("value = 1\n", encoding="utf-8")
    (root / "tests/hook_review_engine.py").write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="retired module name reappeared"):
        GATE.validate_retired_modules(root, contract, analysis=analysis)


def test_retired_module_rejects_dynamic_import_destination(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    (root / "tests/loader.py").write_text(
        "import importlib\nimportlib.import_module('codex_plugin_scanner.guard.runtime.hook_review_engine')\n",
        encoding="utf-8",
    )
    analysis = GATE._analyze_import_graph(root)

    with pytest.raises(RuntimeError, match="dynamically imports retired module"):
        GATE.validate_retired_modules(root, contract, analysis=analysis)


def test_retired_module_rejects_reintroduced_oracle_flag_read(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    (root / "tests/reader.py").write_text(
        "import os\nvalue = os.environ.get('HOL_GUARD_PYTHON_ORACLE')\n",
        encoding="utf-8",
    )
    analysis = GATE._analyze_import_graph(root)

    with pytest.raises(RuntimeError, match="reads retired runtime flag HOL_GUARD_PYTHON_ORACLE"):
        GATE.validate_retired_modules(root, contract, analysis=analysis)


def test_retired_module_cannot_enter_a_package_artifact(tmp_path: Path) -> None:
    wheel = tmp_path / "fixture.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("codex_plugin_scanner/guard/native_runtime_resident.py", b"retained source")
    with pytest.raises(RuntimeError, match="package artifact contains retired module"):
        GATE.run(ROOT, wheel)

    sdist = tmp_path / "fixture.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        source = tmp_path / "native_runtime_resident.py"
        source.write_bytes(b"retained source")
        archive.add(source, arcname="hol_guard-3.0.1/src/codex_plugin_scanner/guard/native_runtime_resident.py")
    with pytest.raises(RuntimeError, match="package artifact contains retired module"):
        GATE.run(ROOT, sdist)


def test_cleanup_candidate_requires_dead_duplicate_class(cleanup_repository: Path) -> None:
    candidate = "src/retired_first.py"

    with pytest.raises(RuntimeError, match="not classified as dead_duplicate"):
        GATE._candidate_evidence(
            cleanup_repository,
            candidate,
            {candidate: "hook_control_and_transport"},
            {"hook_control_and_transport": "required_control_plane"},
            [candidate],
        )


def test_parity_fixture_stays_language_neutral() -> None:
    fixture = GATE._validate_fixture(ROOT, "tests/fixtures/native-hook-parity/cases.v1.json")

    assert fixture["case_count"] == 6


@pytest.mark.parametrize(
    "prefix, call",
    [
        ("import builtins\n", "builtins.__import__"),
        ("import builtins as loader\n", "loader.__import__"),
        ("from builtins import __import__ as load\n", "load"),
        ("", "__import__"),
    ],
)
def test_dynamic_import_graph_records_builtin_forms(tmp_path: Path, prefix: str, call: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "target.py").write_text("", encoding="utf-8")
    (source / "consumer.py").write_text(prefix + call + "('target')\n", encoding="utf-8")
    graph, evidence = GATE._module_imports(tmp_path)
    assert "target" in graph["consumer"]
    assert any(item.endswith(":target") for item in evidence)


def test_dynamic_builtin_import_requires_bounded_provenance(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "consumer.py").write_text(
        "import builtins as loader\nloader.__import__(user_supplied)\n", encoding="utf-8"
    )
    _, unbounded = GATE._dynamic_import_destinations(tmp_path)
    assert unbounded == ["consumer:2"]


@pytest.mark.parametrize(
    "imports",
    [
        "import importlib.util\n",
        "import importlib\nimport importlib.util\n",
        "import importlib.resources\nimport importlib.util\n",
        "import importlib\nimport importlib.util as utilities\n",
    ],
)
def test_dynamic_import_graph_preserves_unaliased_dotted_imports(tmp_path: Path, imports: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "consumer.py").write_text(imports + "importlib.import_module(destination)\n", encoding="utf-8")
    _, unbounded = GATE._dynamic_import_destinations(tmp_path)
    assert unbounded == [f"consumer:{imports.count(chr(10)) + 1}"]


@pytest.mark.parametrize(
    "imports, call",
    [
        ("import importlib.util as utilities\n", "utilities.import_module"),
        ("import importlib\nimport importlib.util as importlib\n", "importlib.import_module"),
    ],
)
def test_dynamic_import_graph_does_not_promote_aliased_submodules(tmp_path: Path, imports: str, call: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "consumer.py").write_text(imports + call + "(destination)\n", encoding="utf-8")
    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)
    assert evidence == []
    assert unbounded == []


@pytest.mark.parametrize(
    "prefix, call",
    [
        ("import importlib\nimport importlib.util\n", "importlib.import_module"),
        ("import importlib.util\n", "importlib.import_module"),
        ("import importlib.util\nimport importlib\n", "importlib.import_module"),
        ("import importlib, importlib.util\n", "importlib.import_module"),
        ("import builtins\nimport builtins.synthetic\n", "builtins.__import__"),
    ],
)
def test_dynamic_import_gate_preserves_unaliased_dotted_roots(tmp_path: Path, prefix: str, call: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    consumer = source / "consumer.py"
    consumer.write_text(prefix + call + "(user_supplied)\n", encoding="utf-8")
    _, unbounded = GATE._dynamic_import_destinations(tmp_path)
    assert unbounded == [f"consumer:{prefix.count(chr(10)) + 1}"]

    # The same classification must populate reachability for a bounded name.
    (source / "target.py").write_text("", encoding="utf-8")
    consumer.write_text(prefix + call + "('target')\n", encoding="utf-8")
    graph, evidence = GATE._module_imports(tmp_path)
    assert "target" in graph["consumer"]
    assert any(item.endswith(":target") for item in evidence)


@pytest.mark.parametrize(
    "source_text",
    [
        "import importlib.util as util\nutil.import_module(user_supplied)\n",
        "import importlib\nimport importlib.util as importlib\nimportlib.import_module(user_supplied)\n",
        "import importlib.util\nimportlib = replacement\nimportlib.import_module(user_supplied)\n",
        "import importlib.util\ndef load(importlib):\n    return importlib.import_module(user_supplied)\n",
    ],
)
def test_dynamic_import_gate_respects_dotted_aliases_and_shadowing(tmp_path: Path, source_text: str) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "consumer.py").write_text(source_text, encoding="utf-8")
    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)
    assert evidence == []
    assert unbounded == []


def test_dotted_submodule_alias_does_not_erase_separate_root_binding(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "consumer.py").write_text(
        "import importlib\nimport importlib.util as util\nimportlib.import_module(user_supplied)\n",
        encoding="utf-8",
    )
    _, unbounded = GATE._dynamic_import_destinations(tmp_path)
    assert unbounded == ["consumer:3"]


RETIRED_ORACLE = "codex_plugin_scanner.guard.runtime.hook_review_engine"


def _shipped_package(root: Path) -> Path:
    """The one package the fixture repository installs."""

    package = root / "src/codex_plugin_scanner"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    return package


def _validate(root: Path, contract: dict[str, object]) -> None:
    GATE.validate_retired_modules(root, contract, analysis=GATE._analyze_import_graph(root))


def test_shipped_source_rejects_a_retired_module_named_in_a_string(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{RETIRED_ORACLE}"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="names retired module"):
        _validate(root, contract)


def test_a_test_may_still_name_a_retired_module_in_a_string(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "tests/absence.py").write_text(
        f'def test_absent():\n    assert "{RETIRED_ORACLE}" not in installed()\n', encoding="utf-8"
    )

    _validate(root, contract)


def test_launcher_rejects_a_retired_module_target(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "src/codex_plugin_scanner/relaunch.py").write_text(
        f'ARGV = [executable, "-m", "{RETIRED_ORACLE}", "run"]\n', encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="launcher runs retired module"):
        _validate(root, contract)


def test_launcher_rejects_a_module_a_deletion_took(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "src/codex_plugin_scanner/relaunch.py").write_text(
        'ARGV = [executable, "-m", "codex_plugin_scanner.cli", "guard", "run"]\n', encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="launcher runs a module that does not exist"):
        _validate(root, contract)


def test_launcher_accepts_a_module_the_wheel_ships(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    (package / "cli.py").write_text("", encoding="utf-8")
    (package / "relaunch.py").write_text(
        'ARGV = [executable, "-m", "codex_plugin_scanner.cli", "guard", "run"]\n', encoding="utf-8"
    )

    _validate(root, contract)


def test_launcher_screens_a_bootstrap_that_passes_the_module_after_dash_c(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    (package / "bootstrap.py").write_text(
        'ARGV = [executable, "-c", LAUNCHER, str(import_root), "codex_plugin_scanner.cli"]\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="launcher runs a module that does not exist"):
        _validate(root, contract)


def test_launcher_screens_the_code_a_bootstrap_passes_through_a_name(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    # Guard's own relaunch builds its code in one statement, interpolates the
    # package root into it, and passes the name to the command in the next.
    (package / "bootstrap.py").write_text(
        "def parts(root):\n"
        "    code = (\n"
        '        "import sys;"\n'
        '        f"sys.path.insert(0, {str(root)!r});"\n'
        '        "from codex_plugin_scanner.cli import main;"\n'
        '        "raise SystemExit(main(sys.argv[1:]))"\n'
        "    )\n"
        '    return (executable, "-c", code, "guard")\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="launcher runs a module that does not exist"):
        _validate(root, contract)


def test_launcher_accepts_bootstrap_code_whose_module_the_wheel_ships(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    (package / "cli.py").write_text("", encoding="utf-8")
    (package / "bootstrap.py").write_text(
        'CODE = "from codex_plugin_scanner.cli import main"\nARGV = [executable, "-c", CODE, "guard"]\n',
        encoding="utf-8",
    )

    _validate(root, contract)


def test_launcher_rejects_a_retired_submodule_imported_from_its_package(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    for part in ("guard", "guard/runtime"):
        (package / part).mkdir(parents=True, exist_ok=True)
        (package / part / "__init__.py").write_text("", encoding="utf-8")
    # `from a.b import c` names `a.b` in the import statement and `a.b.c`
    # nowhere, so only walking the statement's module leaves the retired
    # submodule unseen.
    (package / "bootstrap.py").write_text(
        'CODE = "from codex_plugin_scanner.guard.runtime import hook_review_engine"\n'
        'ARGV = [executable, "-c", CODE, "guard"]\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="launcher runs retired module"):
        _validate(root, contract)


def test_launcher_accepts_an_attribute_imported_from_a_module_the_wheel_ships(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    (package / "cli.py").write_text("def main(argv):\n    return 0\n", encoding="utf-8")
    # `main` is an attribute of `cli`, not a module beside it, so the existence
    # check must not ask the install for `codex_plugin_scanner.cli.main`.
    (package / "bootstrap.py").write_text(
        'CODE = "from codex_plugin_scanner.cli import main"\nARGV = [executable, "-c", CODE, "guard"]\n',
        encoding="utf-8",
    )

    _validate(root, contract)


@pytest.mark.parametrize(
    "call",
    [
        "importlib.import_module('{target}')",
        "__import__('{target}')",
    ],
)
def test_launcher_rejects_a_retired_module_loaded_dynamically_after_dash_c(tmp_path: Path, call: str) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    code = "import importlib;" + call.format(target=RETIRED_ORACLE)
    (package / "bootstrap.py").write_text(
        f'CODE = "{code}"\nARGV = [executable, "-c", CODE, "guard"]\n', encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="launcher runs retired module"):
        _validate(root, contract)


def test_launcher_rejects_a_missing_module_loaded_dynamically_after_dash_c(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    (package / "bootstrap.py").write_text(
        "CODE = \"import importlib;importlib.import_module('codex_plugin_scanner.cli')\"\n"
        'ARGV = [executable, "-c", CODE, "guard"]\n',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="launcher runs a module that does not exist"):
        _validate(root, contract)


def test_a_wheel_member_under_a_scripts_package_is_read_as_shipped(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _, contract = _retired_oracle_repository(repository)
    wheel = tmp_path / "fixture.whl"
    with ZipFile(wheel, "w") as archive:
        # A wheel installs every member it carries, including a package of the
        # project's own named `scripts`. Reading the first path components the
        # way an sdist is read would excuse this file from the shipped rules.
        archive.writestr(
            "codex_plugin_scanner/scripts/boot.py",
            f'TARGET = "{RETIRED_ORACLE}"\n'.encode(),
        )

    with pytest.raises(RuntimeError, match="names retired module"):
        GATE.validate_retired_artifacts(contract, [wheel])


def test_shipped_source_rejects_a_retired_module_spelled_across_a_concatenation(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    prefix, _, basename = RETIRED_ORACLE.rpartition(".")
    # Neither fragment names the module; the value the two of them produce does,
    # and that is the name the interpreter would import.
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{prefix}." + "{basename}"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="names retired module"):
        _validate(root, contract)


def test_shipped_source_rejects_a_retired_module_spelled_with_an_escape(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    basename = RETIRED_ORACLE.rpartition(".")[2]
    escaped = RETIRED_ORACLE.replace(basename, f"\\x{ord(basename[0]):02x}{basename[1:]}")
    # The file carries no import and no plain basename, so only the decoded
    # value of the string says which module this would load.
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{escaped}"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="names retired module"):
        _validate(root, contract)


def test_shipped_source_may_name_a_live_module_that_starts_with_a_retired_name(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    # A longer final component is a different module, not the retired one.
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{RETIRED_ORACLE}_native"\n', encoding="utf-8")

    _validate(root, contract)


def test_shipped_source_rejects_a_submodule_of_a_retired_module(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{RETIRED_ORACLE}.plan"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="names retired module"):
        _validate(root, contract)


def test_shipped_source_rejects_a_basename_split_across_a_concatenation(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    prefix, _, basename = RETIRED_ORACLE.rpartition(".")
    head, tail = basename[:5], basename[5:]
    # The split falls inside the basename, so the raw text carries no symbol, no
    # basename and no `import` for a text screen to catch.
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{prefix}.{head}" "{tail}"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="names retired module"):
        _validate(root, contract)


def test_shipped_source_rejects_a_retired_module_spelled_with_an_octal_escape(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    _, _, basename = RETIRED_ORACLE.rpartition(".")
    octal = RETIRED_ORACLE.replace(basename, f"\\{ord(basename[0]):03o}{basename[1:]}")
    (root / "src/codex_plugin_scanner/shim.py").write_text(f'TARGET = "{octal}"\n', encoding="utf-8")

    with pytest.raises(RuntimeError, match="names retired module"):
        _validate(root, contract)


def test_contribution_rejects_a_retired_detector_module(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "contributions").mkdir()
    (root / "contributions/detector.json").write_text(
        json.dumps({"detector": {"kind": "python-module", "module": RETIRED_ORACLE}}),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="contribution names retired module"):
        _validate(root, contract)


def test_contribution_rejects_a_detector_module_that_does_not_exist(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    _shipped_package(root)
    (root / "contributions").mkdir()
    (root / "contributions/detector.json").write_text(
        json.dumps(
            {
                "contributions": [
                    {
                        "detector": {
                            "kind": "python-module",
                            "module": "codex_plugin_scanner.guard.runtime.absent",
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="contribution names a module that does not exist"):
        _validate(root, contract)


def test_contribution_accepts_a_detector_module_that_is_there(tmp_path: Path) -> None:
    root, contract = _retired_oracle_repository(tmp_path)
    package = _shipped_package(root)
    (package / "guard").mkdir()
    (package / "guard/__init__.py").write_text("", encoding="utf-8")
    (package / "guard/runtime").mkdir()
    (package / "guard/runtime/__init__.py").write_text("", encoding="utf-8")
    (package / "guard/runtime/present.py").write_text("", encoding="utf-8")
    (root / "contributions").mkdir()
    (root / "contributions/detector.json").write_text(
        json.dumps({"detector": {"kind": "python-module", "module": "codex_plugin_scanner.guard.runtime.present"}}),
        encoding="utf-8",
    )

    _validate(root, contract)
