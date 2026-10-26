"""The publisher's pack-record reads go to the resident, not a one-shot."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_execution, native_resident_client, store_extension_control_manifest
from codex_plugin_scanner.guard.catalog_delivery import lifecycle, projection
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog

_KEY = b"k" * 32


def _store(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(guard_home=tmp_path / "home", path=tmp_path / "home" / "guard.db")


def _resident(monkeypatch, answer, *, ready=True):
    calls = []
    status = SimpleNamespace(identity=SimpleNamespace(path=Path("runtime")))
    monkeypatch.setattr(native_execution, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_resident_client, "native_resident_client_ready", lambda _path, _home: ready)

    def request(*, operation, request, guard_home, **_kwargs):
        calls.append((operation, request, guard_home))
        return answer(request)

    monkeypatch.setattr(native_execution, "_resident_request", request)
    return calls


def _one_shot(monkeypatch):
    calls = []

    def invoke(kind, **fields):
        calls.append((kind, fields))
        return {"value": {"from": "one-shot"}}

    monkeypatch.setattr(lifecycle, "invoke", invoke)
    return calls


def _ok(request):
    return {
        "schema": "guard-command-pack-record-result.v1",
        "request_id": request["request_id"],
        "status": "ok",
        "payload": {"value": {"from": "resident"}},
    }


@pytest.mark.parametrize("operation", ["verify", "open"])
def test_a_bound_store_reads_records_in_the_resident(tmp_path, monkeypatch, operation):
    store = _store(tmp_path)
    resident = _resident(monkeypatch, _ok)
    spawned = _one_shot(monkeypatch)

    with lifecycle.resident(store):
        result = lifecycle.record(operation, "activation", key=_KEY, record="{}", digest="d", mac="m")

    assert result == {"value": {"from": "resident"}}
    assert spawned == []
    ((name, request, guard_home),) = resident
    assert name == "command_pack_record"
    assert guard_home == store.guard_home
    assert request["schema"] == "guard-command-pack-record-request.v1"
    assert request["store_path"] == str(store.path)
    assert request["record"] == {
        "kind": "record",
        "operation": operation,
        "purpose": "activation",
        "key": _KEY.hex(),
        "record": "{}",
        "digest": "d",
        "mac": "m",
    }


def test_a_tampered_answer_from_the_resident_is_still_tampered(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError

    def tampered(request):
        return {**_ok(request), "payload": {"fault": "tampered", "reason": "mac"}}

    _resident(monkeypatch, tampered)
    spawned = _one_shot(monkeypatch)

    with lifecycle.resident(_store(tmp_path)), pytest.raises(ExtensionControlAuthorityError, match="mac"):
        lifecycle.record("verify", "activation", key=_KEY, record="{}", digest="d", mac="m")
    assert spawned == []


@pytest.mark.parametrize(
    "answer",
    [
        lambda _request: None,
        lambda request: {**_ok(request), "request_id": "another"},
        lambda request: {**_ok(request), "payload": None},
    ],
    ids=["unavailable", "another-request", "no-payload"],
)
def test_a_resident_that_does_not_answer_leaves_the_record_to_the_one_shot(tmp_path, monkeypatch, answer):
    _resident(monkeypatch, answer)
    spawned = _one_shot(monkeypatch)

    with lifecycle.resident(_store(tmp_path)):
        result = lifecycle.record("verify", "activation", key=_KEY, record="{}", digest="d", mac="m")

    assert result == {"value": {"from": "one-shot"}}
    assert [kind for kind, _ in spawned] == ["record"]


def test_an_unreachable_resident_leaves_the_record_to_the_one_shot(tmp_path, monkeypatch):
    def unreachable(_request):
        raise OSError("socket")

    _resident(monkeypatch, unreachable)
    spawned = _one_shot(monkeypatch)

    with lifecycle.resident(_store(tmp_path)):
        lifecycle.record("verify", "activation", key=_KEY, record="{}", digest="d", mac="m")
    assert len(spawned) == 1


def test_a_poll_never_starts_a_resident_to_read_a_record(tmp_path, monkeypatch):
    resident = _resident(monkeypatch, _ok, ready=False)
    spawned = _one_shot(monkeypatch)

    with lifecycle.resident(_store(tmp_path)):
        lifecycle.record("verify", "activation", key=_KEY, record="{}", digest="d", mac="m")

    assert resident == []
    assert len(spawned) == 1


def test_sealing_and_unbound_reads_never_reach_the_resident(tmp_path, monkeypatch):
    resident = _resident(monkeypatch, _ok)
    spawned = _one_shot(monkeypatch)

    lifecycle.record("verify", "activation", key=_KEY, record="{}", digest="d", mac="m")
    with lifecycle.resident(_store(tmp_path)):
        lifecycle.record("seal", "activation", key=_KEY, payload={})

    assert resident == []
    assert [fields["operation"] for _, fields in spawned] == ["verify", "seal"]


def test_the_registry_is_indexed_once_per_authenticated_record(tmp_path, monkeypatch):
    monkeypatch.setattr(projection, "_kept", None)
    built = []

    class Catalog:
        @staticmethod
        def from_prepared_packs(committed):
            built.append(committed.record_digest)
            return object()

    store = _store(tmp_path)
    first = SimpleNamespace(record_digest="a" * 64)
    registry = projection._registry(store, first, Catalog)

    assert projection._registry(store, SimpleNamespace(record_digest="a" * 64), Catalog) is registry
    assert projection._registry(store, SimpleNamespace(record_digest="b" * 64), Catalog) is not registry
    assert projection._registry(_store(tmp_path / "other"), first, Catalog) is not registry
    assert built == ["a" * 64, "b" * 64, "a" * 64]


def test_the_pack_registry_manifest_is_compiled_once_beside_the_built_in_one(monkeypatch):
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    monkeypatch.setattr(store_extension_control_manifest, "_manifest_cache", {})
    compiled = []
    monkeypatch.setattr(
        store_extension_control_manifest,
        "_build_catalog_target_manifest",
        lambda registry: compiled.append(registry) or {"id": str(id(registry))},
    )
    pack = object.__new__(GeneratedCommandCatalog)
    pack._extensions = ()
    pack.catalog_digest = "c" * 64

    for _ in range(2):
        first = store_extension_control_manifest.catalog_target_manifest(pack)
        store_extension_control_manifest.catalog_target_manifest(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    first["id"] = "mutated"

    assert compiled == [pack, BUILT_IN_COMMAND_EXTENSION_REGISTRY]
    assert store_extension_control_manifest.catalog_target_manifest(pack) == {"id": str(id(pack))}
