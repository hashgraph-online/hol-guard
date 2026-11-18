"""The harness registry builds its dataclasses from the native runtime's answer, field for field."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_runner_authority
from codex_plugin_scanner.guard import setup_contract_registry as contract_registry


def _event() -> dict[str, object]:
    return {
        "harness": "fixture",
        "adapter": "fixture-cloud",
        "host_version_scope": ">=2",
        "os_arch": "linux-x64",
        "local_hosted": "hosted",
        "event": "PreToolUse",
        "tools": ["apply_patch"],
        "surface": "cli",
        "transport": "native_hook",
        "mode": "blocking",
        "declared_actions": ["observe", "block"],
        "error_behavior": "fails closed",
        "mandatory_compatibility": "honors the response",
        "known_blind_spots": ["none"],
        "source_reference": "adapter.py",
    }


def _contract() -> dict[str, object]:
    return {
        "harness": "fixture",
        "install_aliases": ["fixture", "fx"],
        "config_paths": ["~/.fixture/config.json"],
        "event_surfaces": ["shell"],
        "native_approval": True,
        "browser_fallback": False,
        "resume_support": False,
        "known_blind_spots": "none",
        "smoke_command": "hol-guard install fixture --dry-run",
        "surface_capabilities": ["cli"],
        "supported_actions": ["block"],
        "docs_path": "docs/fixture.md",
        "icon_label": "F",
        "capability_events": [_event()],
    }


@pytest.fixture
def answers(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def answer(kind: str, args: dict[str, object], *_rest: object, **_keywords: object) -> dict[str, object]:
        calls.append((kind, dict(args)))
        if args["op"] == "contracts":
            return {"contracts": [_contract()]}
        if args["op"] == "harnesses":
            return {"harnesses": ["fixture"]}
        return {"contract": _contract() if args["harness"] in {"fixture", "fx"} else None}

    for cached in (
        contract_registry.harness_contracts,
        contract_registry.harness_names,
        contract_registry.contract_for,
    ):
        cached.cache_clear()
    monkeypatch.setattr(native_runner_authority, "native_runner_authority", answer)
    yield calls
    for cached in (
        contract_registry.harness_contracts,
        contract_registry.harness_names,
        contract_registry.contract_for,
    ):
        cached.cache_clear()


def test_the_contract_is_built_field_for_field_from_the_native_row(answers: list[object]) -> None:
    (contract,) = contract_registry.harness_contracts()
    assert contract.install_aliases == ("fixture", "fx")
    assert (contract.docs_path, contract.icon_label) == ("docs/fixture.md", "F")
    assert contract.supported_actions == ("block",)
    capability = contract.capability_events[0]
    assert (capability.adapter, capability.local_hosted, capability.tools) == (
        "fixture-cloud",
        "hosted",
        ("apply_patch",),
    )
    assert capability.surface == "cli"
    assert capability.declared_actions == ("observe", "block")
    assert (capability.deployment_health, capability.evidence_level) == ("unverified", "not_run")
    assert contract_registry.harness_names() == ("fixture",)
    assert answers[0][0] == "harness_contract_registry"


def test_a_name_or_alias_resolves_natively_and_an_unknown_name_has_no_contract(answers: list[object]) -> None:
    assert contract_registry.contract_for("fx") == contract_registry.harness_contracts()[0]
    assert contract_registry.contract_for("nonesuch") is None
    assert [call for call in answers if call[1].get("harness") == "fx"]


def test_the_registry_stays_importable_by_name_and_is_read_only_on_first_use(answers: list[object]) -> None:
    from codex_plugin_scanner.guard import setup_contracts as contracts

    assert answers == []
    assert contract_registry.harness_contracts() == contracts.HARNESS_CONTRACTS
    with pytest.raises(AttributeError):
        _ = contracts.NOT_A_REGISTRY
