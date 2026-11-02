"""Guard Surface Server schema helpers.

The native runtime owns the ``guard-surface-server.v1`` contract and the
protocol negotiation (the ``surface_server_handshake`` kind).
"""

from __future__ import annotations

from collections.abc import Sequence

from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_UNAVAILABLE_MESSAGE = "Guard could not load the surface server contract. Check that the Guard daemon is running."


class SurfaceServerUnavailableError(RuntimeError):
    """The native runtime could not answer the surface server handshake."""


def surface_server_handshake(supported_protocol_versions: Sequence[object] = ()) -> dict[str, object]:
    """The contract, protocol block and negotiated version for one client.

    ``negotiated_version`` is ``None`` when no listed version is compatible.
    """

    try:
        answer = native_runner_authority(
            "surface_server_handshake",
            {"supported_protocol_versions": list(supported_protocol_versions)},
        )
    except NativeRunnerAuthorityError as error:
        raise SurfaceServerUnavailableError(_UNAVAILABLE_MESSAGE) from error
    if not isinstance(answer.get("contract"), dict) or not isinstance(answer.get("protocol"), dict):
        raise SurfaceServerUnavailableError(_UNAVAILABLE_MESSAGE)
    return answer


def build_surface_server_contract() -> dict[str, object]:
    return surface_server_contract(surface_server_handshake())


def surface_server_contract(handshake: dict[str, object]) -> dict[str, object]:
    contract = handshake.get("contract")
    if not isinstance(contract, dict):
        raise SurfaceServerUnavailableError(_UNAVAILABLE_MESSAGE)
    return contract
