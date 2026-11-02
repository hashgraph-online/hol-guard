"""The harness protection contract loader refuses malformed contract data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import contract_registry


def _event(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "event": "PreToolUse",
        "transport": "native_hook",
        "mode": "blocking",
        "declared_actions": ["observe", "block"],
        "error_behavior": "fails closed",
        "mandatory_compatibility": "honors the response",
        "known_blind_spots": [],
        "source_reference": "adapter.py",
    }
    event.update(overrides)
    return event


def _contract(**overrides: object) -> dict[str, object]:
    contract: dict[str, object] = {
        "harness": "fixture",
        "install_aliases": ["fixture"],
        "config_paths": ["~/.fixture/config.json"],
        "event_surfaces": ["shell"],
        "native_approval": True,
        "browser_fallback": False,
        "resume_support": False,
        "known_blind_spots": "none",
        "smoke_command": "hol-guard install fixture --dry-run",
        "capability_events": [_event()],
    }
    contract.update(overrides)
    return contract


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: object) -> tuple[object, ...]:
    contract_path = tmp_path / "contracts.json"
    contract_path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(contract_registry, "_CONTRACT_PATH", contract_path)
    return contract_registry._load()


def _document(*contracts: object) -> dict[str, object]:
    return {"schema": "hol-guard.harness-protection-contracts.v1", "contracts": list(contracts)}


def test_omitted_capability_fields_take_the_documented_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (contract,) = _load(tmp_path, monkeypatch, _document(_contract()))
    capability = contract.capability_events[0]
    assert (capability.harness, capability.adapter) == ("fixture", "fixture")
    assert (capability.host_version_scope, capability.os_arch, capability.local_hosted) == (
        "unknown",
        "unknown",
        "local",
    )
    assert (contract.surface_capabilities, contract.supported_actions) == ((), ())
    assert (contract.docs_path, contract.icon_label) == (None, None)


def test_explicit_capability_fields_override_the_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    event = _event(adapter="fixture-cloud", host_version_scope=">=2", os_arch="linux-x64", local_hosted="hosted")
    (contract,) = _load(tmp_path, monkeypatch, _document(_contract(capability_events=[event])))
    capability = contract.capability_events[0]
    assert (capability.adapter, capability.host_version_scope, capability.os_arch, capability.local_hosted) == (
        "fixture-cloud",
        ">=2",
        "linux-x64",
        "hosted",
    )


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"schema": "hol-guard.harness-protection-contracts.v2", "contracts": []},
        {"schema": "hol-guard.harness-protection-contracts.v1"},
        _document("fixture"),
        _document(_contract(unexpected=True)),
        _document(_contract(capability_events=[])),
        _document(_contract(capability_events=[_event(unexpected=True)])),
        _document(_contract(capability_events=[_event(local_hosted="remote")])),
        _document(_contract(native_approval="yes")),
        _document(_contract(install_aliases=["fixture", 7])),
        _document(_contract(smoke_command=None)),
        _document(_contract(docs_path=7)),
        _document(_contract(supported_actions="block")),
        _document(_contract(capability_events=[_event(declared_actions="block")])),
    ],
)
def test_malformed_contract_data_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: object) -> None:
    with pytest.raises(ValueError):
        _load(tmp_path, monkeypatch, document)
