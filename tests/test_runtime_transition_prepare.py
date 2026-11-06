"""Whole enrolled binding preparation, before exact transition authorization."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext, PreparedHarnessInstall
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.runtime_transition import TransitionError, TransitionFile
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def preparation(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import runtime_transition_prepare as module

    home = tmp_path / "guard"
    store = GuardStore(home)
    context = HarnessContext(tmp_path, None, home)
    root = tmp_path / "managed-core"
    root.mkdir()
    pointer = root / "current.json"
    pointer.write_bytes(b"old pointer")
    pointer.chmod(0o600)
    artifacts, native = {}, {}
    for side in ("predecessor", "candidate"):
        executable = root / side
        executable.write_bytes(side.encode())
        executable.chmod(0o700)
        native_path = root / (side + "-native")
        native_path.write_bytes((side + "native").encode())
        native_path.chmod(0o700)
        metadata = native_path.stat()
        native[side] = {
            "path": str(native_path),
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "sha256": hashlib.sha256(native_path.read_bytes()).hexdigest(),
        }
        artifacts[side] = {
            "version": "3.15.2",
            "source_commit": "a" * 40,
            "target": "fixture",
            "format": "onedir",
            "sha256": "b" * 64,
            "path": str(executable),
            "generation": side,
        }
    bindings = {}
    calls = []
    for harness in ("codex", "claude"):
        path = tmp_path / (harness + ".json")
        path.write_bytes((harness + " old").encode())
        path.chmod(0o600)
        bindings[harness] = path
        store.set_managed_install(harness, True, None, {"binding": "old"}, "old-time")
    store.set_managed_install("cursor", False, None, {"binding": "inactive"}, "old-time")

    class Adapter:
        def __init__(self, harness):
            self.harness = harness

        def prepare_install(self, current):
            calls.append((self.harness, current))
            path = bindings[self.harness]
            return PreparedHarnessInstall(
                (TransitionFile(path, path.read_bytes(), b"new binding"),), {"harness": self.harness, "binding": "new"}
            )

    monkeypatch.setattr(module, "get_adapter", Adapter)
    request = module.RuntimeTransitionPreparation(
        operation_id=str(uuid.uuid4()),
        predecessor=artifacts["predecessor"],
        candidate=artifacts["candidate"],
        selection_files=(TransitionFile(pointer, b"old pointer", b"new pointer", kind="selection"),),
        native_runtimes=native,
        deadline_epoch=time.time() + 30,
    )
    return module, request, context, store, bindings, calls


def prepare(fixture, **kwargs):
    module, request, context, store, *_ = fixture
    with codex_install_transaction(context.guard_home, request.selection_files[0].path, actor="prepare-test"):
        return module.prepare_runtime_transition(
            request, context=context, store=store, deadline_monotonic=time.monotonic() + 20, **kwargs
        )


def test_preparation_captures_every_active_install_without_publication(preparation):
    _, request, context, store, bindings, calls = preparation
    before_rows = store.list_managed_installs()
    plan = prepare(preparation)
    assert [change.harness for change in plan.managed_installs] == ["claude", "codex"]
    assert [harness for harness, _ in calls] == ["claude", "codex"]
    assert all(current.guard_home == context.guard_home for _, current in calls)
    assert store.list_managed_installs() == before_rows
    assert all(path.read_bytes().endswith(b" old") for path in bindings.values())
    assert request.selection_files[0].path.read_bytes() == b"old pointer"
    assert not (context.guard_home / "managed" / "runtime-transition.json").exists()
    for artifact in (plan.predecessor, plan.candidate):
        assert any(str(change.path) == artifact["path"] and change.expected_digest for change in plan.files)


def test_preparation_composes_real_codex_and_claude_adapters_without_writes(preparation, monkeypatch):
    from codex_plugin_scanner.guard.adapters import get_adapter

    module, _, context, store, _, _ = preparation
    monkeypatch.setattr(module, "get_adapter", get_adapter)
    for harness in ("codex", "claude"):
        manifest = get_adapter(harness).install(context)
        store.set_managed_install(harness, True, None, manifest, "old-time")
    before_rows = store.list_managed_installs()
    plan = prepare(preparation)
    assert {change.harness for change in plan.managed_installs} == {"codex", "claude"}
    assert store.list_managed_installs() == before_rows
    for change in plan.files:
        if change.expected_digest is None:
            assert (change.path.read_bytes() if change.path.exists() else None) == change.before
    codex = next(change for change in plan.managed_installs if change.harness == "codex")
    assert codex.after["manifest"]["managed_hook_integrity"] == "authenticated"


def test_ordinary_install_restores_files_written_before_a_later_write_fails(tmp_path: Path, monkeypatch):
    from codex_plugin_scanner.guard.adapters.base import PreparedHarnessInstall
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionFile

    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"old-first")
    second.write_bytes(b"old-second")
    install = PreparedHarnessInstall(
        (
            TransitionFile(first, b"old-first", b"new-first"),
            TransitionFile(second, b"old-second", b"new-second"),
        ),
        {"ok": True},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.codex_install_transaction.require_codex_install_owner",
        lambda _home: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime_transition.assert_transition_mutation_allowed",
        lambda _home: None,
    )
    monkeypatch.setattr(RuntimeTransition, "_compare", staticmethod(lambda *_args, **_kwargs: None))
    original = RuntimeTransition._write_file

    def write(change, generation):
        if generation == "after" and str(change["path"]).endswith("second.txt"):
            raise TransitionError("publication_failed")
        original(change, generation)

    monkeypatch.setattr(RuntimeTransition, "_write_file", staticmethod(write))
    with pytest.raises(TransitionError, match="publication_failed"):
        install.publish(tmp_path)
    assert first.read_bytes() == b"old-first"
    assert second.read_bytes() == b"old-second"


def test_ordinary_install_leaves_a_concurrent_edit_in_place(tmp_path: Path, monkeypatch):
    from codex_plugin_scanner.guard.adapters.base import PreparedHarnessInstall
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionFile

    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"old-first")
    second.write_bytes(b"old-second")
    first.chmod(0o600)
    second.chmod(0o600)
    install = PreparedHarnessInstall(
        (
            TransitionFile(first, b"old-first", b"new-first"),
            TransitionFile(second, b"old-second", b"new-second"),
        ),
        {"ok": True},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.codex_install_transaction.require_codex_install_owner",
        lambda _home: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime_transition.assert_transition_mutation_allowed",
        lambda _home: None,
    )
    original = RuntimeTransition._write_file

    def write(change, generation):
        if generation == "after" and str(change["path"]).endswith("second.txt"):
            first.write_bytes(b"user-edit")
            raise TransitionError("publication_failed")
        original(change, generation)

    monkeypatch.setattr(RuntimeTransition, "_write_file", staticmethod(write))
    with pytest.raises(TransitionError, match="generation_changed") as caught:
        install.publish(tmp_path)
    assert isinstance(caught.value.__cause__, TransitionError)
    assert caught.value.__cause__.reason == "publication_failed"
    assert first.read_bytes() == b"user-edit"
    assert second.read_bytes() == b"old-second"


def test_preparation_refuses_unsupported_active_harness_before_publication(preparation, monkeypatch):
    module, _, _, store, bindings, _ = preparation
    store.set_managed_install("hermes", True, None, {}, "old-time")
    get_adapter = module.get_adapter

    def resolve(harness):
        if harness == "hermes":
            raise TransitionError("adapter_preparation_unavailable")
        return get_adapter(harness)

    monkeypatch.setattr(module, "get_adapter", resolve)
    with pytest.raises(TransitionError, match="adapter_preparation_unavailable"):
        prepare(preparation)
    assert all(path.read_bytes().endswith(b" old") for path in bindings.values())


def test_preparation_rejects_conflicting_selection_and_binding(preparation, monkeypatch):
    module, request, _, _, _, _ = preparation

    class Adapter:
        def prepare_install(self, context):
            change = replace(request.selection_files[0], kind="binding", after=b"foreign")
            return PreparedHarnessInstall((change,), {})

    monkeypatch.setattr(module, "get_adapter", lambda _: Adapter())
    with pytest.raises(TransitionError, match="adapter_preparation_generation_conflict"):
        prepare(preparation)


def test_preparation_preserves_recorded_workspace_and_explicit_hook_selection(preparation):
    _, _, context, store, _, calls = preparation
    workspace = context.home_dir / "workspace"
    workspace.mkdir()
    store.set_managed_install("codex", True, str(workspace), {"hook_workspace_explicit": True}, "old-time")
    plan = prepare(preparation)
    prepared_context = next(current for harness, current in calls if harness == "codex")
    assert prepared_context.workspace_dir == workspace and prepared_context.workspace_override_explicit is True
    row = next(change for change in plan.managed_installs if change.harness == "codex")
    assert row.before["workspace"] == str(workspace) and row.after["workspace"] == str(workspace)


def test_preparation_refuses_unreviewed_executable_bytes(preparation):
    module, request, *_ = preparation
    digests = {
        side: hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest()
        for side, artifact in (("predecessor", request.predecessor), ("candidate", request.candidate))
    }
    digests["candidate"] = "f" * 64
    modified = (module, replace(request, executable_digests=digests), *preparation[2:])
    with pytest.raises(TransitionError, match="artifact_generation_changed"):
        prepare(modified)


def test_preparation_refuses_foreign_file_after_adapter_read(preparation, monkeypatch):
    module, _, _, _, bindings, _ = preparation
    resolve = module.get_adapter

    def adapter(harness):
        original = resolve(harness)
        prepare_install = original.prepare_install

        def raced(context):
            result = prepare_install(context)
            bindings[harness].write_bytes(b"foreign edit")
            return result

        original.prepare_install = raced
        return original

    monkeypatch.setattr(module, "get_adapter", adapter)
    with pytest.raises(TransitionError, match="generation_changed"):
        prepare(preparation)


@pytest.mark.parametrize("fault", ["native_digest", "native_mtime", "symlink", "store_race", "expired"])
def test_preparation_refuses_changed_authority_boundaries(preparation, monkeypatch, fault):
    module, request, context, store, _, calls = preparation
    if fault.startswith("native_"):
        native = {side: dict(identity) for side, identity in request.native_runtimes.items()}
        native["candidate"]["sha256" if fault == "native_digest" else "mtime_ns"] = (
            "f" * 64 if fault == "native_digest" else native["candidate"]["mtime_ns"] + 1
        )
        preparation = (module, replace(request, native_runtimes=native), *preparation[2:])
    elif fault == "symlink":
        candidate = dict(request.candidate)
        link = context.home_dir / "candidate-link"
        link.symlink_to(candidate["path"])
        candidate["path"] = str(link)
        preparation = (module, replace(request, candidate=candidate), *preparation[2:])
    elif fault == "store_race":
        read_rows = store.list_managed_installs
        reads = 0

        def changed_rows():
            nonlocal reads
            reads += 1
            rows = read_rows()
            if reads > 1:
                rows.append(
                    {"harness": "foreign", "active": True, "workspace": None, "manifest": {}, "updated_at": "foreign"}
                )
            return rows

        monkeypatch.setattr(store, "list_managed_installs", changed_rows)
    else:
        expired = replace(request, deadline_epoch=time.time() - 1)
        preparation = (module, expired, *preparation[2:])
    with pytest.raises((TransitionError, CodexHookIntegrityError)) as error:
        prepare(preparation)
    assert (
        getattr(error.value, "reason", None)
        == {
            "native_digest": "native_runtime_generation_changed",
            "native_mtime": "native_runtime_generation_changed",
            "symlink": "codex_hook_artifact_not_regular",
            "store_race": "managed_install_generation_changed",
            "expired": "deadline_invalid",
        }[fault]
    )
    if fault == "expired":
        assert calls == []


@pytest.mark.parametrize("fault", ["digest", "mode", "invocation"])
def test_shared_dependency_merge_refuses_conflicting_identity(preparation, fault):
    from codex_plugin_scanner.guard.runtime_transition import merge_transition_dependency

    _, request, *_ = preparation
    identity = request.native_runtimes["candidate"]
    owner = Path(identity["path"]).stat().st_uid
    dependency = TransitionFile.artifact_dependency({**identity, "mode": 0o700, "role": "bridge", "owner_uid": owner})
    if fault == "digest":
        changed = replace(dependency, expected_digest="f" * 64)
    elif fault == "mode":
        changed = replace(dependency, before_mode=0o600, after_mode=0o600)
    else:
        invocation = {"path": identity["path"], "mode": 0o700, "owner_uid": owner, "link_target": None}
        dependency = replace(dependency, invocation_identity=invocation)
        changed = replace(dependency, invocation_identity={**invocation, "mode": 0o600})
    with pytest.raises(TransitionError, match="adapter_preparation_generation_conflict"):
        merge_transition_dependency(dependency, changed)
