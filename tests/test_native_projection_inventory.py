"""Projection preparation shares work while retaining checks and input binding."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from scripts.ci import verify_native_command_program as verifier
from tests.delivery_scripts import script
from tests.test_native_projection_descriptor_destinations import projection_builder as projection_builder

inventory_module = script("native_projection_inventory")
core = script("core_command_build_inputs")
directory_inventory = script("native_directory_inventory")
directory = script("prepare_extension_directory")


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    for relative in ("contributions/command-sources", "contributions/mcp-servers", "contracts/extensions/trust"):
        (tmp_path / relative).mkdir(parents=True)
    source = tmp_path / "contributions/command-sources/command.example.json"
    source.write_text('{"source":"original"}')
    trust = tmp_path / "contracts/extensions/trust/command.example.v1.json"
    trust.write_text('{"trustClass":"external"}')
    (tmp_path / "contracts/extensions/core-defaults.v1.json").write_text('{"entries":[]}')
    compiler = tmp_path / "compiler"
    compiler.write_bytes(b"compiler-original")
    monkeypatch.setattr(inventory_module, "implementation_digest", lambda root: "d" * 64)
    stages = []

    def stage(compiler, destination, *, source_root):
        stages.append(destination)
        objects = destination / "objects"
        objects.mkdir()

        def obj(value):
            data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(data).hexdigest()
            (objects / f"{digest}.json").write_bytes(data)
            return {"sha256": digest, "length": len(data), "expanded_length": len(data), "kind": "data"}

        descriptor = {"id": "command.example", "description": "Current compiled metadata"}
        matcher = obj({"matcher": "original"})
        manifest = obj(
            {
                "descriptors": obj([descriptor]),
                "catalog": obj([{"extension_id": "command.example"}]),
                "program": obj({"rules": [], "nodes": {"matcher-id": matcher}}),
            }
        )
        index = obj(
            {"schema": "guard.pack-index.v1", "prefix": "", "kind": "leaf", "entries": [["command.example", manifest]]}
        )
        (destination / "release.json").write_text(json.dumps({"index": index, "extensions": 1}))

    monkeypatch.setattr(inventory_module.packs, "stage", stage)
    return tmp_path, compiler, source, trust, stages


@pytest.mark.parametrize("failure", [None, "runtime-output", "directory-output", "ownership", "core-selection"])
@pytest.mark.parametrize("compiler_alias", [False, True])
def test_five_real_projection_gates_share_one_stage_and_keep_outputs(
    inputs, projection_builder, monkeypatch, capsys, failure, compiler_alias
):
    root, compiler, _, _, stages = inputs
    build, descriptor = projection_builder
    program = build.module
    monkeypatch.setitem(sys.modules, "build_native_command_program", program)
    monkeypatch.setattr(verifier, "ROOT", root)
    monkeypatch.setattr(directory, "ROOT", root)
    monkeypatch.setattr(
        program,
        "_pack_descriptors",
        lambda compiler, **kw: core.pack_descriptors(root, compiler, program.read_object, **kw),
    )
    public = root / "contributions/extensions/command.example.json"
    public.parent.mkdir(parents=True)
    public.write_bytes(program.canonical_bytes(descriptor))
    build.public_blobs["HEAD:contributions/extensions/command.example.json"] = public.read_bytes()
    markdown = root / "docs/guard/extensions/README.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("old directory\n")
    catalog = root / "docs/guard/extensions/catalog.v1.json"
    monkeypatch.setattr(
        directory, "public_entry", lambda root, rows: {"id": "command.example", "runtimeExtensionId": "command.example"}
    )
    import codex_plugin_scanner.guard.runtime.generated_command_catalog_loader as loader

    monkeypatch.setattr(loader, "_extension", lambda row: row)
    monkeypatch.setattr(directory.legacy, "render_directories", lambda root, **kw: {catalog: "current catalog\n"})
    monkeypatch.setattr(directory.markdown, "render_document", lambda current, **kw: "current directory\n")
    commands = []
    execute = program.subprocess.run

    def run(command, **kwargs):
        commands.append(command[-1])
        return execute(command, **kwargs)

    monkeypatch.setattr(program.subprocess, "run", run)
    requested_compiler = compiler
    if compiler_alias:
        requested_compiler = root / "compiler-alias"
        requested_compiler.symlink_to(compiler)
        source_main = program.main

        def require_pinned_compiler(arguments, **kwargs):
            assert arguments[:2] == ["--compiler", str(compiler.resolve(strict=True))]
            return source_main(arguments, **kwargs)

        monkeypatch.setattr(program, "main", require_pinned_compiler)
    if failure == "runtime-output":
        main = program.main

        def corrupt_runtime(arguments, **kwargs):
            result = main(arguments, **kwargs)
            if arguments == ["--compiler", str(compiler)]:
                (root / "contracts/extensions/build-descriptors/command.example.json").write_text("{}")
            return result

        monkeypatch.setattr(program, "main", corrupt_runtime)
    elif failure == "directory-output":
        prepare = directory.prepare

        def corrupt_directory(*args, **kwargs):
            result = prepare(*args, **kwargs)
            if not kwargs["check"]:
                markdown.write_text("corrupted directory\n")
            return result

        monkeypatch.setattr(directory, "prepare", corrupt_directory)
    elif failure == "ownership":
        (public.parent / "command.orphan.json").write_text("{}")
    elif failure == "core-selection":
        main = program.main

        def change_core_selection(arguments, **kwargs):
            result = main(arguments, **kwargs)
            if arguments[-1] == "--check":
                (root / "contracts/extensions/core-defaults.v1.json").write_text('{"entries":["changed"]}')
            return result

        monkeypatch.setattr(program, "main", change_core_selection)
    if failure:
        error = SystemExit if failure == "runtime-output" else ValueError
        with pytest.raises(error):
            verifier._prepare_directory(requested_compiler)
        assert len(stages) == 1 and not stages[0].exists()
        assert public.read_bytes() == program.canonical_bytes(descriptor)
        completed = [
            line.split()[2]
            for line in capsys.readouterr().out.splitlines()
            if line.startswith("Projection preparation ")
        ]
        expected = ["public-descriptors", "command-build", "command-check", "directory-build", "directory-check"]
        assert (
            completed
            == expected[: {"runtime-output": 2, "directory-output": 4, "ownership": 3, "core-selection": 2}[failure]]
        )
        return
    assert verifier._prepare_directory(requested_compiler) == compiler.resolve(strict=True)
    completed = [line for line in capsys.readouterr().out.splitlines() if line.startswith("Projection preparation ")]
    assert [line.split()[2] for line in completed] == [
        "public-descriptors",
        "command-build",
        "command-check",
        "directory-build",
        "directory-check",
    ]
    assert all(float(line.removesuffix("s").split()[-1]) >= 0 for line in completed)
    assert len(stages) == 1
    assert not stages[0].exists()
    assert commands.count("compile-stream") == 3
    assert commands.count("export-built") == commands.count("export-trust") == 3
    assert commands.count("evaluate-batch") == 1
    generated = root / "contracts/extensions/build-descriptors/command.example.json"
    assert generated.read_bytes() == public.read_bytes() == program.canonical_bytes(descriptor)
    assert markdown.read_text() == "current directory\n"
    assert catalog.read_text() == "current catalog\n"
    # A second wrapper gets a new private inventory and still runs every gate.
    before = {path: path.read_bytes() for path in (generated, public, markdown, catalog)}
    assert verifier._prepare_directory(requested_compiler) == compiler.resolve(strict=True)
    assert len(stages) == 2 and stages[0] != stages[1]
    assert all(path.read_bytes() == content for path, content in before.items())


@pytest.mark.parametrize(
    "mutation",
    ["source", "trust", "compiler", "core-defaults", "add-optional", "add-mcp", "delete", "symlink", "implementation"],
)
def test_changed_inputs_fail_closed_instead_of_reusing(inputs, monkeypatch, mutation):
    root, compiler, source, trust, stages = inputs
    inventory = inventory_module.ProjectionInventory(root, compiler)
    with pytest.raises(ValueError, match=r"changed|invalid source"), inventory:
        with inventory.open(compiler, root=root):
            pass
        if mutation in {"source", "trust", "compiler"}:
            {"source": source, "trust": trust, "compiler": compiler}[mutation].write_bytes(b"changed")
        elif mutation == "core-defaults":
            (root / "contracts/extensions/core-defaults.v1.json").write_text('{"entries":["changed"]}')
        elif mutation == "add-optional":
            (source.parent / "command.optional.json").write_text("{}")
        elif mutation == "add-mcp":
            (root / "contributions/mcp-servers/mcp.optional.json").write_text("{}")
        elif mutation == "delete":
            source.unlink()
        elif mutation == "symlink":
            source.unlink()
            source.symlink_to(trust)
        else:
            monkeypatch.setattr(inventory_module, "implementation_digest", lambda root: "changed")
        with inventory.open(compiler, root=root):
            pytest.fail("changed inputs must not reach a consumer")
    assert len(stages) == 1 and not stages[0].exists()
    with pytest.raises(ValueError, match="expired"):
        inventory.validate()


@pytest.mark.parametrize("target", ["release", "object", "matcher"])
def test_changed_pack_bytes_are_rejected(inputs, target):
    root, compiler, _, _, stages = inputs
    with (
        pytest.raises(ValueError, match=r"release changed|integrity invalid"),
        inventory_module.ProjectionInventory(root, compiler) as inventory,
    ):
        with inventory.open(compiler, root=root):
            pass
        if target == "release":
            (stages[0] / "release.json").write_text("{}")
        elif target == "matcher":
            matcher = next(
                path
                for path in (stages[0] / "objects").glob("*.json")
                if json.loads(path.read_bytes()) == {"matcher": "original"}
            )
            matcher.write_text('{"matcher":"changed"}')
        else:
            for path in (stages[0] / "objects").glob("*.json"):
                path.write_text("{}")
        core.pack_descriptors(root, compiler, inventory_module.packs.legacy.read_object, inventory=inventory)


def test_failed_public_blob_check_writes_no_projections(inputs, projection_builder, monkeypatch, capsys):
    root, compiler, _, _, stages = inputs
    build, _ = projection_builder
    monkeypatch.setitem(sys.modules, "build_native_command_program", build.module)
    monkeypatch.setattr(verifier, "ROOT", root)
    monkeypatch.setattr(
        build.module,
        "_pack_descriptors",
        lambda compiler, **kw: core.pack_descriptors(root, compiler, build.module.read_object, **kw),
    )
    with pytest.raises(SystemExit) as failure:
        verifier._prepare_directory(compiler)
    assert failure.value.code == 1
    assert "Projection preparation " not in capsys.readouterr().out
    assert not (root / "contracts/extensions/build-descriptors").exists()
    assert not (root / "src").exists()
    assert not (root / "docs").exists()
    assert len(stages) == 1 and not stages[0].exists()


def test_compiler_alias_retargeting_is_rejected_between_phases(inputs):
    root, compiler, _, _, stages = inputs
    alias = root / "compiler-alias"
    alias.symlink_to(compiler)
    replacement = root / "replacement-compiler"
    replacement.write_bytes(compiler.read_bytes())
    with (
        pytest.raises(ValueError, match="compiler binding changed"),
        inventory_module.ProjectionInventory(root, alias) as inventory,
    ):
        with inventory.open(alias, root=root):
            pass
        alias.unlink()
        alias.symlink_to(replacement)
        inventory.validate()
    assert len(stages) == 1 and not stages[0].exists()


def test_verifier_exports_the_validated_target_after_alias_retargeting(inputs, monkeypatch):
    root, compiler, _, _, _ = inputs
    alias = root / "compiler-alias.exe"
    alias.symlink_to(compiler)
    replacement = root / "replacement-compiler"
    replacement.write_bytes(compiler.read_bytes())
    environment = root / "workflow-environment"
    monkeypatch.setenv("GITHUB_ENV", str(environment))

    def prepare(original):
        assert original == alias
        alias.unlink()
        alias.symlink_to(replacement)
        return compiler.resolve(strict=True)

    monkeypatch.setattr(verifier, "_prepare_directory", prepare)
    assert verifier.main(["--compiler", str(alias), "--prepare-directory"]) == 0
    assert environment.read_text() == f"HOL_GUARD_BUILD_SOURCE_COMPILER={compiler.resolve(strict=True)}\n"


@pytest.fixture
def directory_inputs(inputs, monkeypatch):
    root = inputs[0]
    monkeypatch.setattr(directory, "ROOT", root)
    public = root / "contributions/extensions/command.example.json"
    public.parent.mkdir(parents=True)
    public.write_text("{}")
    markdown = root / "docs/guard/extensions/README.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("old directory\n")
    catalog = markdown.parent / "catalog.v1.json"
    monkeypatch.setattr(
        directory, "public_entry", lambda root, rows: {"id": "command.example", "runtimeExtensionId": "command.example"}
    )
    import codex_plugin_scanner.guard.runtime.generated_command_catalog_loader as loader

    monkeypatch.setattr(loader, "_extension", lambda row: row)
    monkeypatch.setattr(directory.legacy, "render_directories", lambda root, **kw: {catalog: "current catalog\n"})
    monkeypatch.setattr(directory.markdown, "render_document", lambda current, **kw: "current directory\n")
    return inputs, public, markdown, catalog


def test_directory_write_and_check_keeps_bytes_and_uses_one_fresh_inventory(directory_inputs):
    (root, compiler, _, _, stages), public, markdown, catalog = directory_inputs
    expected = directory.prepare(compiler, root=root)
    assert directory.prepare(compiler, root=root, check=True) == expected
    before = {path: path.read_bytes() for path in (public, markdown, catalog)}
    assert len(stages) == 2
    markdown.write_text("stale directory\n")
    catalog.write_text("stale catalog\n")
    assert directory.prepare_and_check(compiler, root=root) == expected
    assert len(stages) == 3
    assert all(path.read_bytes() == content for path, content in before.items())
    assert directory.prepare_and_check(compiler, root=root) == expected
    assert len(stages) == 4  # Never share a retained inventory across invocations.
    assert len(set(stages)) == 4 and all(not stage.exists() for stage in stages)


@pytest.mark.parametrize("mutation", ["source", "trust", "compiler", "alias", "catalog", "markdown", "ownership"])
def test_directory_write_and_check_rejects_mutation_between_gates(directory_inputs, monkeypatch, mutation):
    (root, compiler, source, trust, stages), public, markdown, catalog = directory_inputs
    original = directory.prepare
    requested = compiler
    if mutation == "alias":
        requested = root / "compiler-alias"
        requested.symlink_to(compiler)
    calls = []

    def prepare(*args, **kwargs):
        calls.append(kwargs["check"])
        result = original(*args, **kwargs)
        if not kwargs["check"]:
            if mutation in {"source", "trust", "compiler", "catalog", "markdown"}:
                {"source": source, "trust": trust, "compiler": compiler, "catalog": catalog, "markdown": markdown}[
                    mutation
                ].write_text("changed\n")
            elif mutation == "alias":
                replacement = root / "replacement-compiler"
                replacement.write_bytes(compiler.read_bytes())
                requested.unlink()
                requested.symlink_to(replacement)
            else:
                (public.parent / "command.orphan.json").write_text("{}")
        return result

    monkeypatch.setattr(directory, "prepare", prepare)
    with pytest.raises(ValueError, match=r"inputs changed|different inputs|directory is stale|sources differ"):
        directory.prepare_and_check(requested, root=root)
    assert calls == [False, True]  # The check is still executed and can fail.
    assert len(stages) == 1 and not stages[0].exists()


@pytest.mark.parametrize(
    "arguments,combined,check", [([], False, False), (["--check"], False, True), (["--write-and-check"], True, False)]
)
def test_directory_cli_preserves_existing_modes(monkeypatch, capsys, arguments, combined, check):
    calls = []
    monkeypatch.setattr(directory, "prepare", lambda compiler, **kw: calls.append((False, compiler, kw["check"])) or {})
    monkeypatch.setattr(directory, "prepare_and_check", lambda compiler: calls.append((True, compiler, False)) or {})
    directory.main(["--compiler", "configured-compiler", *arguments])
    assert calls == [(combined, directory.Path("configured-compiler"), check)]
    assert json.loads(capsys.readouterr().out) == {}
    with pytest.raises(SystemExit) as failure:
        directory.main(["--check", "--write-and-check"])
    assert failure.value.code == 2
