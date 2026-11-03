"""Stored layers are checked for composability by the native runtime, never by a Python default.

A runtime rejection of the layers is a verdict on the stored layers. A runtime
that cannot answer is an outage, reported as the unavailability the authority
lease reports, so a transient outage never reads as a corrupt store.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from codex_plugin_scanner.guard import store_extension_control_authority_support as support
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlAuthorityUnavailableError,
)
from codex_plugin_scanner.guard.native_extension_control import NativeExtensionControlError
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolverFailure,
    ExtensionControlLayer,
    ResolverFailureCode,
)

_DIGEST = "a" * 64


def _layers(
    kind: ControlLayerKind = ControlLayerKind.LOCAL_ADMIN, *, lockdown: bool = False
) -> tuple[ExtensionControlLayer, ...]:
    return (ExtensionControlLayer(CONTROL_SCHEMA_VERSION, kind, _DIGEST, lockdown, ()),)


@pytest.fixture(autouse=True)
def _fresh_cache() -> Iterator[None]:
    support._require_composable.cache_clear()
    yield
    support._require_composable.cache_clear()


def _compose_with(
    monkeypatch: pytest.MonkeyPatch, answer: Callable[[], ComposedExtensionControls]
) -> list[tuple[ExtensionControlLayer, ...]]:
    asked: list[tuple[ExtensionControlLayer, ...]] = []

    def compose(layers: tuple[ExtensionControlLayer, ...]) -> ComposedExtensionControls:
        asked.append(layers)
        return answer()

    monkeypatch.setattr(support, "compose_control_layers", compose)
    return asked


def _raising(code: str) -> Callable[[], ComposedExtensionControls]:
    def answer() -> ComposedExtensionControls:
        raise NativeExtensionControlError(code)

    return answer


def test_layers_the_runtime_rejects_are_invalid_stored_layers(monkeypatch: pytest.MonkeyPatch) -> None:
    _compose_with(monkeypatch, _raising("native_extension_control_layer_invalid"))

    with pytest.raises(ExtensionControlAuthorityError, match="invalid extension control layers"):
        support._require_composable(_layers())


def test_layers_the_runtime_composes_with_failures_are_invalid_stored_layers(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = ControlResolverFailure(ResolverFailureCode.DUPLICATE_LAYER_KIND, ControlLayerKind.LOCAL_ADMIN)
    _compose_with(monkeypatch, lambda: ComposedExtensionControls(False, (), (failure,)))

    with pytest.raises(ExtensionControlAuthorityError, match="invalid extension control layers"):
        support._require_composable(_layers())


@pytest.mark.parametrize(
    "code",
    [
        "native_extension_control_unavailable",
        "native_extension_control_payload_invalid",
        "native_extension_control_too_large",
    ],
)
def test_a_runtime_that_cannot_answer_is_an_outage_and_not_a_verdict(
    monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    _compose_with(monkeypatch, _raising(code))

    with pytest.raises(NativeCommandControlAuthorityUnavailableError) as caught:
        support._require_composable(_layers())
    assert not isinstance(caught.value, ExtensionControlAuthorityError)


def test_an_accepted_layer_set_is_asked_once_and_a_refusal_is_asked_again(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _compose_with(monkeypatch, lambda: ComposedExtensionControls(False, ()))

    for _ in range(3):
        support._require_composable(_layers())
    support._require_composable(_layers(lockdown=True))
    assert len(asked) == 2

    refused = _compose_with(monkeypatch, _raising("native_extension_control_unavailable"))
    for _ in range(2):
        with pytest.raises(NativeCommandControlAuthorityUnavailableError):
            support._require_composable(_layers(ControlLayerKind.SIGNED_CLOUD))
    assert len(refused) == 2
