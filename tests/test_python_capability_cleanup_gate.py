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
    # hook_launcher_recovery.py matches the existing hook control-plane scope glob.
    assert payload["scope_files"] == 100
    assert "legacy_python_resident_transport" not in payload["capabilities"]
    assert payload["candidate_evidence"] == []
    assert payload["retired_evidence"] == [
        {
            "path": f"src/codex_plugin_scanner/guard/{name}.py",
            "module": f"codex_plugin_scanner.guard.{name}",
            "source_present": False,
            "source_importers": [],
        }
        for name in ("native_runtime_resident", "native_runtime_resident_transport")
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


def test_retained_python_oracle_is_loaded_only_by_explicit_test_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")

    from codex_plugin_scanner.guard.cli.commands_hook_compat_loader import load_hook_compatibility_surface

    surface = load_hook_compatibility_surface()
    assert surface is not None
    assert callable(surface["_run_hook_generic_payload"])
    assert callable(surface["hydrate_hook_payload_reference"])


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
