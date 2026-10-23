"""Extension-control composition and resolution answered by the native runtime.

How control layers compose, which catalog identities a set of layers blocks and
whether an extension is active are decided by the resident
(``extension_control``), the same resolver command evaluation runs. Python
builds the request from layer and catalog values and renders the answer; there
is no Python evaluator. A reply that is not a bound, strictly decoded ``ok``
raises ``NativeExtensionControlError`` and callers fail closed.
"""

from __future__ import annotations

import functools
import json
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from .native_daemon_route import _decide
from .native_resident_decision import ResidentOperation, shape_fields
from .runtime.extension_control_contract import (
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolverFailure,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from .runtime.extension_control_limits import MAX_CONTROL_LAYERS
from .runtime.extension_trust import trust_class_for

if TYPE_CHECKING:
    from .runtime.command_extensions import CommandSafetyExtensionRegistry

EXTENSION_CONTROL_FEATURE: Final = "extension-control-v1"
_TIMEOUT_SECONDS: Final = 5.0
# The resident client clamps a deadline to a per-operation ceiling
# (``EXTENSION_CONTROL_TIMEOUT_CEILING_MS`` in ``managed_resident_client_timeout.rs``),
# and the daemon client waits out every resident call a request makes
# (``daemon/extension_control_timeouts.py``); raising this raises both.
_PREVIEW_TIMEOUT_SECONDS: Final = 15.0
# The resident bounds one request to 4 MiB of canonical JSON, 4096 items and 64
# scenarios; larger questions are split across requests below those bounds. The
# byte budget leaves room for the request envelope.
_MAX_REQUEST_BYTES: Final = 4 * 1024 * 1024 + 64 * 1024
_MAX_BATCH_BYTES: Final = 4 * 1024 * 1024 - 64 * 1024
_MAX_ITEMS_PER_REQUEST: Final = 2048
_MAX_SCENARIOS_PER_REQUEST: Final = 64
_MAX_CONCURRENT_ASKS: Final = 4
_SLOTS: Final = threading.BoundedSemaphore(_MAX_CONCURRENT_ASKS)
_OPT_STR: Final = (str, type(None))
_OPT_BOOL: Final = (bool, type(None))


# Refusals of a preview too big or too costly for one answer: the request size
# (refused here, before the resident is asked, or by the resident), the work
# bound and the reply bound. They name the request, not a broken runtime, so
# callers report a limit.
PREVIEW_LIMIT_CODES: Final = frozenset(
    {
        "native_extension_control_too_large",
        "native_extension_control_too_many_items",
        "native_extension_control_reply_too_large",
    }
)


# Why the resident refuses a local mutation (`EXTENSION_CONTROL_MUTATION_*` in
# `guard-contracts`). A refusal describes the draft, so it is a normal reply;
# a code outside this set is a reply this client cannot interpret.
MUTATION_REFUSAL_CODES: Final = frozenset(
    {
        "layer_limit_exceeded",
        "layer_control_limit_exceeded",
        "control_limit_exceeded",
        "unknown_extension",
        "unknown_permission",
        "duplicate_control_target",
        "catalog_conflict",
        "managed_layer_mutation",
        "immutable_extension",
        "immutable_permission",
        "invalid_mutation",
    }
)


class NativeExtensionControlError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION: Final = ResidentOperation(
    operation="extension_control",
    feature=EXTENSION_CONTROL_FEATURE,
    prefix="native_extension_control",
    request_schema="guard-extension-control-request.v1",
    request_id_prefix="extension-control",
    result_schema="guard-extension-control-result.v1",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeExtensionControlError,
)


# One preview resolves every catalog permission against the current, proposed
# and per-target reverted layers in a single ask, so it gets a longer budget
# than one resolution batch.
_PREVIEW_OPERATION: Final = replace(_OPERATION, timeout_seconds=_PREVIEW_TIMEOUT_SECONDS)


@dataclass(frozen=True, slots=True)
class ControlItem:
    """One resolution: the identities to resolve and, optionally, one to test for activity."""

    extension_ids: tuple[str, ...] = ()
    permission_ids: tuple[str, ...] = ()
    active_extension_id: str | None = None


@dataclass(frozen=True, slots=True)
class ControlScenario:
    """Items resolved against one set of layers on one surface."""

    layers: tuple[ExtensionControlLayer, ...]
    items: tuple[ControlItem, ...]
    surface: ControlSurface = ControlSurface.COMMAND_EVALUATION
    authority_failure: ResolverFailureCode | None = None


@dataclass(frozen=True, slots=True)
class ControlAnswer:
    """The effective state of one item."""

    blocked: bool
    reason_codes: tuple[str, ...]
    failures: tuple[ControlResolverFailure, ...]
    explicitly_enabled_permission_ids: tuple[str, ...]
    active: bool | None


@dataclass(frozen=True, slots=True)
class ScenarioAnswer:
    """A scenario's lockdown state and the answer to each of its items, in order."""

    global_lockdown: bool
    items: tuple[ControlAnswer, ...]


@dataclass(frozen=True, slots=True)
class MutationVerdict:
    """The resident's judgement of a mutation: why it is refused, or its canonical layers."""

    refusal: str | None
    layers: tuple[ExtensionControlLayer, ...]


def _invalid() -> RuntimeError:
    return NativeExtensionControlError(_OPERATION.invalid)


def _shape(value: object, fields: Mapping[str, Any]) -> dict[str, Any]:
    return shape_fields(value, fields, _invalid)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _invalid()
    return tuple(value)


def _failures(value: object) -> tuple[ControlResolverFailure, ...]:
    if not isinstance(value, list):
        raise _invalid()
    failures: list[ControlResolverFailure] = []
    for raw in value:
        entry = _shape(raw, {"code": str, "layer_kind": _OPT_STR})
        try:
            kind = None if entry["layer_kind"] is None else ControlLayerKind(entry["layer_kind"])
            failures.append(ControlResolverFailure(ResolverFailureCode(entry["code"]), kind))
        except ValueError:
            raise _invalid() from None
    return tuple(failures)


def _composed(value: object) -> ComposedExtensionControls:
    fields = _shape(value, {"global_lockdown": bool, "controls": list, "failures": list})
    controls: list[ExtensionControl] = []
    for raw in fields["controls"]:
        entry = _shape(raw, {"target_kind": str, "target_id": str, "state": str})
        try:
            target = ControlTarget(ControlTargetKind(entry["target_kind"]), entry["target_id"])
            controls.append(ExtensionControl(target, ControlState(entry["state"])))
        except ValueError:
            raise _invalid() from None
    return ComposedExtensionControls(fields["global_lockdown"], tuple(controls), _failures(fields["failures"]))


_ITEM_FIELDS: Final = {
    "blocked": bool,
    "factor_reason_codes": list,
    "failures": list,
    "explicitly_enabled_permission_ids": list,
    "active": _OPT_BOOL,
}


def _answer(value: object, item: ControlItem) -> ControlAnswer:
    fields = _shape(value, _ITEM_FIELDS)
    # The answer carries an activity verdict exactly when the item asked for one.
    if (fields["active"] is None) != (item.active_extension_id is None):
        raise _invalid()
    return ControlAnswer(
        fields["blocked"],
        _strings(fields["factor_reason_codes"]),
        _failures(fields["failures"]),
        _strings(fields["explicitly_enabled_permission_ids"]),
        fields["active"],
    )


def _scenario_answers(value: object, asked: Sequence[Sequence[ControlItem]]) -> list[ScenarioAnswer]:
    if not isinstance(value, list) or len(value) != len(asked):
        raise _invalid()
    scenarios: list[ScenarioAnswer] = []
    for raw, items in zip(value, asked, strict=True):
        fields = _shape(raw, {"global_lockdown": bool, "results": list})
        results = fields["results"]
        if len(results) != len(items):
            raise _invalid()
        scenarios.append(
            ScenarioAnswer(
                fields["global_lockdown"],
                tuple(_answer(result, item) for result, item in zip(results, items, strict=True)),
            )
        )
    return scenarios


def _layer_wire(layer: ExtensionControlLayer) -> dict[str, object]:
    return {
        "schema_version": layer.schema_version,
        "kind": layer.kind.value,
        "catalog_digest": layer.catalog_digest,
        "global_lockdown": layer.global_lockdown,
        "controls": [
            {
                "target_kind": control.target.kind.value,
                "target_id": control.target.target_id,
                "state": control.state.value,
            }
            for control in layer.controls
        ],
    }


def _registry_wire(registry: CommandSafetyExtensionRegistry, *, trust_classes: bool) -> dict[str, object]:
    return {
        "catalog_digest": registry.catalog_digest,
        "extensions": [
            {
                "extension_id": extension.extension_id,
                "aliases": list(extension.aliases),
                "dependencies": list(extension.dependencies),
                "required": extension.required,
                "trust_class": trust_class_for(extension.extension_id) if trust_classes else None,
            }
            for extension in registry.extensions
        ],
        "permissions": [
            {
                "permission_id": permission.permission_id,
                "extension_id": permission.extension_id,
                "dependencies": list(permission.dependencies),
                "implied_permissions": list(permission.implied_permissions),
            }
            for permission in registry.permissions
        ],
    }


def _preview_registry_wire(registry: CommandSafetyExtensionRegistry) -> dict[str, object]:
    return {
        "catalog_digest": registry.catalog_digest,
        "extensions": [
            {
                "extension_id": extension.extension_id,
                "name": extension.name,
                "aliases": list(extension.aliases),
                "dependencies": list(extension.dependencies),
                "rule_ids": [rule.rule_id for rule in extension.rules],
            }
            for extension in registry.extensions
        ],
        "permissions": [
            {
                "permission_id": permission.permission_id,
                "extension_id": permission.extension_id,
                "label": permission.label,
                "risk_tier": permission.risk_tier,
                "baseline_floor": permission.baseline_floor,
                "rule_ids": list(permission.rule_ids),
                "dependencies": list(permission.dependencies),
                "conflicts": list(permission.conflicts),
                "implied_permissions": list(permission.implied_permissions),
            }
            for permission in registry.permissions
        ],
    }


def _item_wire(item: ControlItem) -> dict[str, object]:
    return {
        "extension_ids": list(item.extension_ids),
        "permission_ids": list(item.permission_ids),
        "active_extension_id": item.active_extension_id,
    }


def _wire_bytes(value: object) -> int:
    """Canonical size of ``value``; ASCII escaping never counts fewer bytes than the resident reads."""

    return len(json.dumps(value, separators=(",", ":")))


@dataclass(frozen=True, slots=True)
class _Piece:
    """A scenario, or a run of its items when it is larger than one request."""

    index: int
    wire: dict[str, object]
    items: tuple[ControlItem, ...]
    size: int


def _pieces(scenarios: Sequence[ControlScenario]) -> Iterator[_Piece]:
    for index, scenario in enumerate(scenarios):
        layers = [_layer_wire(layer) for layer in islice(scenario.layers, MAX_CONTROL_LAYERS + 1)]
        base: dict[str, object] = {
            "layers": layers,
            "surface": scenario.surface.value,
            "authority_failure": None if scenario.authority_failure is None else scenario.authority_failure.value,
        }
        for start in range(0, max(len(scenario.items), 1), _MAX_ITEMS_PER_REQUEST):
            items = scenario.items[start : start + _MAX_ITEMS_PER_REQUEST]
            wire = {**base, "items": [_item_wire(item) for item in items]}
            yield _Piece(index, wire, items, _wire_bytes(wire))


def _too_large() -> RuntimeError:
    return NativeExtensionControlError(f"{_OPERATION.prefix}_too_large")


def _batches(pieces: Iterable[_Piece], registry_bytes: int) -> Iterator[list[_Piece]]:
    """Group pieces into requests that stay inside every resident bound.

    Each request carries the registry, so a piece that cannot fit beside it has
    no request to travel in and the whole question is refused.
    """

    batch: list[_Piece] = []
    batch_items = 0
    batch_bytes = registry_bytes
    for piece in pieces:
        if registry_bytes + piece.size > _MAX_BATCH_BYTES:
            raise _too_large()
        if batch and (
            len(batch) >= _MAX_SCENARIOS_PER_REQUEST
            or batch_items + len(piece.items) > _MAX_ITEMS_PER_REQUEST
            or batch_bytes + piece.size > _MAX_BATCH_BYTES
        ):
            yield batch
            batch, batch_items, batch_bytes = [], 0, registry_bytes
        batch.append(piece)
        batch_items += len(piece.items)
        batch_bytes += piece.size
    if batch:
        yield batch


def _ask(
    query: dict[str, object],
    guard_home: Path | None,
    fields: Mapping[str, Any],
    parse: Callable[[dict[str, Any]], Any],
    *,
    operation: ResidentOperation = _OPERATION,
) -> Any:
    """Ask the resident; ``parse`` runs inside payload validation so a bad payload counts against its health."""

    parsed: list[Any] = []

    def validate(payload: dict[str, Any]) -> None:
        parsed.append(parse(payload))

    _decide(
        query,
        guard_home,
        fields,
        validate,
        operation=operation,
        max_request_bytes=_MAX_REQUEST_BYTES,
        slots=_SLOTS,
    )
    return parsed[0]


def compose_control_layers(
    layers: Iterable[ExtensionControlLayer],
    *,
    guard_home: Path | None = None,
) -> ComposedExtensionControls:
    """Compose layers with disable dominance and deterministic output."""

    query: dict[str, object] = {"kind": "compose", "layers": [_layer_wire(layer) for layer in layers]}
    return _ask(query, guard_home, {"composed": dict}, lambda payload: _composed(payload["composed"]))


def resolve_scenarios(
    registry: CommandSafetyExtensionRegistry,
    scenarios: Sequence[ControlScenario],
    *,
    guard_home: Path | None = None,
    trust_classes: bool = False,
) -> tuple[ScenarioAnswer, ...]:
    """Resolve every scenario's items against ``registry``, one answer per scenario in order.

    ``trust_classes`` sends each extension's curated trust class; it is needed
    only by items that ask whether an extension is active.
    """

    if not scenarios:
        return ()
    registry_wire = _registry_wire(registry, trust_classes=trust_classes)
    # Size every piece before the first ask, so a question that cannot be
    # carried is refused without a partial round of requests.
    batches = list(_batches(list(_pieces(scenarios)), _wire_bytes(registry_wire)))
    items: list[list[ControlAnswer]] = [[] for _ in scenarios]
    lockdowns: list[bool | None] = [None] * len(scenarios)
    for batch in batches:
        query: dict[str, object] = {
            "kind": "resolve",
            "registry": registry_wire,
            "scenarios": [piece.wire for piece in batch],
        }
        asked = [piece.items for piece in batch]
        answered: list[ScenarioAnswer] = _ask(
            query,
            guard_home,
            {"scenarios": list},
            lambda payload, asked=asked: _scenario_answers(payload["scenarios"], asked),
        )
        for piece, answer in zip(batch, answered, strict=True):
            # Every piece of one scenario resolves the same layers.
            if lockdowns[piece.index] not in (None, answer.global_lockdown):
                raise _invalid()
            lockdowns[piece.index] = answer.global_lockdown
            items[piece.index].extend(answer.items)
    return tuple(
        ScenarioAnswer(bool(lockdown), tuple(answers)) for lockdown, answers in zip(lockdowns, items, strict=True)
    )


def preview_control_mutation(
    registry: CommandSafetyExtensionRegistry,
    current_layers: Sequence[ExtensionControlLayer],
    proposed_layers: Sequence[ExtensionControlLayer],
    render: Callable[[object, Callable[[], RuntimeError]], dict[str, object]],
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """The resident's semantic preview of replacing ``current_layers`` with ``proposed_layers``.

    ``render`` validates and shapes the ``preview`` payload, raising the given
    error for a malformed one, so a bad payload counts against resident health.
    """

    query: dict[str, object] = {
        "kind": "preview",
        "registry": _preview_registry_wire(registry),
        "current_layers": [_layer_wire(layer) for layer in current_layers],
        "proposed_layers": [_layer_wire(layer) for layer in proposed_layers],
    }
    if _wire_bytes(query) > _MAX_BATCH_BYTES:
        raise _too_large()
    return _ask(
        query,
        guard_home,
        {"preview": dict},
        lambda payload: render(payload["preview"], _invalid),
        operation=_PREVIEW_OPERATION,
    )


def preview_event_targets(
    registry: CommandSafetyExtensionRegistry,
    current_layers: Sequence[ExtensionControlLayer],
    proposed_layers: Sequence[ExtensionControlLayer],
    render: Callable[[object, Callable[[], RuntimeError]], list[dict[str, object]]],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """The audit projection the resident makes of the semantic preview of the same replacement.

    One entry per changed target, named by a digest of its kind and id. ``render``
    validates and shapes the ``targets`` payload, raising the given error for a
    malformed one, so a bad payload counts against resident health.
    """

    query: dict[str, object] = {
        "kind": "preview_event_targets",
        "registry": _preview_registry_wire(registry),
        "current_layers": [_layer_wire(layer) for layer in current_layers],
        "proposed_layers": [_layer_wire(layer) for layer in proposed_layers],
    }
    if _wire_bytes(query) > _MAX_BATCH_BYTES:
        raise _too_large()
    return _ask(
        query,
        guard_home,
        {"targets": list},
        lambda payload: render(payload["targets"], _invalid),
        operation=_PREVIEW_OPERATION,
    )


def _mutation_registry_wire(
    registry: CommandSafetyExtensionRegistry,
    overlay: Iterable[Any],
) -> dict[str, object]:
    return {
        "extensions": [
            {"extension_id": extension.extension_id, "aliases": list(extension.aliases), "required": extension.required}
            for extension in registry.extensions
        ],
        "permissions": [
            {"permission_id": permission.permission_id, "configurable": permission.configurable}
            for permission in registry.permissions
        ],
        "overlay": [
            {
                "extension_id": extension.extension_id,
                "required": extension.required,
                "permissions": [
                    {"permission_id": permission.permission_id, "configurable": permission.configurable}
                    for permission in extension.permissions
                ],
            }
            for extension in overlay
        ],
    }


_LAYER_FIELDS: Final = {
    "schema_version": str,
    "kind": str,
    "catalog_digest": str,
    "global_lockdown": bool,
    "controls": list,
}


def _layer(value: object) -> ExtensionControlLayer:
    fields = _shape(value, _LAYER_FIELDS)
    controls: list[ExtensionControl] = []
    for raw in fields["controls"]:
        entry = _shape(raw, {"target_kind": str, "target_id": str, "state": str})
        try:
            target = ControlTarget(ControlTargetKind(entry["target_kind"]), entry["target_id"])
            controls.append(ExtensionControl(target, ControlState(entry["state"])))
        except ValueError:
            raise _invalid() from None
    try:
        return ExtensionControlLayer(
            fields["schema_version"],
            ControlLayerKind(fields["kind"]),
            fields["catalog_digest"],
            fields["global_lockdown"],
            tuple(controls),
        )
    except ValueError:
        raise _invalid() from None


def _same_layer(asked: ExtensionControlLayer, answered: ExtensionControlLayer) -> bool:
    """Whether ``answered`` is ``asked`` with only extension ids renamed."""

    return (
        (asked.schema_version, asked.kind, asked.catalog_digest, asked.global_lockdown)
        == (answered.schema_version, answered.kind, answered.catalog_digest, answered.global_lockdown)
        and len(asked.controls) == len(answered.controls)
        and all(
            (before.target.kind, before.state) == (after.target.kind, after.state)
            and (before.target.kind is ControlTargetKind.EXTENSION or before.target.target_id == after.target.target_id)
            for before, after in zip(asked.controls, answered.controls, strict=True)
        )
    )


def _refusal(payload: dict[str, Any]) -> str | None:
    refusal = payload["refusal"]
    if refusal is not None and refusal not in MUTATION_REFUSAL_CODES:
        raise _invalid()
    return refusal


def _mutation_verdict(payload: dict[str, Any], asked: Sequence[ExtensionControlLayer]) -> MutationVerdict:
    refusal = _refusal(payload)
    layers = tuple(_layer(raw) for raw in payload["layers"])
    # A refusal carries no layers; an acceptance carries the asked layers.
    if len(layers) != (len(asked) if refusal is None else 0):
        raise _invalid()
    if not all(_same_layer(before, after) for before, after in zip(asked, layers, strict=False)):
        raise _invalid()
    return MutationVerdict(refusal, layers)


_REFUSAL_FIELDS: Final = {"refusal": _OPT_STR}
_MUTATION_FIELDS: Final = {"refusal": _OPT_STR, "layers": list}


def _ask_refusal(query: dict[str, object], guard_home: Path | None) -> str | None:
    """Ask a query whose answer is only the reason it refuses, if it does."""

    if _wire_bytes(query) > _MAX_BATCH_BYTES:
        raise _too_large()
    return _ask(query, guard_home, _REFUSAL_FIELDS, _refusal)


def _ask_mutation(
    query: dict[str, object],
    guard_home: Path | None,
    asked: Sequence[ExtensionControlLayer],
) -> MutationVerdict:
    if _wire_bytes(query) > _MAX_BATCH_BYTES:
        raise _too_large()
    return _ask(query, guard_home, _MUTATION_FIELDS, lambda payload: _mutation_verdict(payload, asked))


def mutation_bounds(
    layers: Sequence[ExtensionControlLayer],
    *,
    guard_home: Path | None = None,
) -> str | None:
    """The reason ``layers`` break the bounds of one mutation, or ``None`` when they stay within them."""

    query: dict[str, object] = {"kind": "mutation_bounds", "layers": [_layer_wire(layer) for layer in layers]}
    return _ask_refusal(query, guard_home)


def validate_mutation(
    registry: CommandSafetyExtensionRegistry,
    overlay: Iterable[Any],
    *,
    catalog_digest: str,
    requested_catalog_digest: str,
    current_layers: Sequence[ExtensionControlLayer],
    layers: Sequence[ExtensionControlLayer],
    guard_home: Path | None = None,
) -> MutationVerdict:
    """Whether ``layers`` may replace ``current_layers`` against the catalog served as ``catalog_digest``.

    ``overlay`` is the request-local extension metadata consulted after
    ``registry``. An accepted verdict carries ``layers`` with every extension
    target named by its canonical id.
    """

    query: dict[str, object] = {
        "kind": "mutation_validate",
        "registry": _mutation_registry_wire(registry, overlay),
        "catalog_digest": catalog_digest,
        "requested_catalog_digest": requested_catalog_digest,
        "current_layers": [_layer_wire(layer) for layer in current_layers],
        "layers": [_layer_wire(layer) for layer in layers],
    }
    return _ask_mutation(query, guard_home, layers)


def mutability_validate(
    registry: CommandSafetyExtensionRegistry,
    current_layers: Sequence[ExtensionControlLayer],
    layers: Sequence[ExtensionControlLayer],
    *,
    guard_home: Path | None = None,
) -> str | None:
    """The reason ``layers`` change the managed layer or an immutable control of ``current_layers``, if they do."""

    query: dict[str, object] = {
        "kind": "mutability_validate",
        "registry": _mutation_registry_wire(registry, ()),
        "current_layers": [_layer_wire(layer) for layer in current_layers],
        "layers": [_layer_wire(layer) for layer in layers],
    }
    return _ask_refusal(query, guard_home)


def resolve_extension_controls(
    layers: Iterable[ExtensionControlLayer],
    registry: CommandSafetyExtensionRegistry,
    *,
    extension_ids: tuple[str, ...],
    permission_ids: tuple[str, ...],
    surface: ControlSurface,
    authority_failure: ResolverFailureCode | None = None,
    guard_home: Path | None = None,
) -> ControlAnswer:
    """Resolve one set of catalog identities against ``layers``."""

    scenario = ControlScenario(
        tuple(layers),
        (ControlItem(extension_ids, permission_ids),),
        surface,
        authority_failure,
    )
    return resolve_scenarios(registry, (scenario,), guard_home=guard_home)[0].items[0]


def _hex_digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise _invalid()
    return value


def _digest(payload: dict[str, Any]) -> str:
    return _hex_digest(payload["digest"])


def mutation_digest(
    *,
    previous_revision: int,
    catalog_digest: str,
    layers: Iterable[ExtensionControlLayer],
    actor_id: str,
    idempotency_key: str,
    nonce: str,
    guard_home: Path | None = None,
) -> str:
    """The digest a commit proof binds, computed by the resident from the mutation it describes."""

    query: dict[str, object] = {
        "kind": "mutation_digest",
        "previous_revision": previous_revision,
        "catalog_digest": catalog_digest,
        "layers": [_layer_wire(layer) for layer in layers],
        "actor_id": actor_id,
        "idempotency_key": idempotency_key,
        "nonce": nonce,
    }
    return _ask(query, guard_home, {"digest": str}, _digest)


def enrollment_digest(
    *,
    catalog_digest: str,
    actor_id: str,
    nonce: str,
    guard_home: Path | None = None,
) -> str:
    """The digest a first-enrollment proof binds, computed by the resident."""

    query: dict[str, object] = {
        "kind": "enrollment_digest",
        "catalog_digest": catalog_digest,
        "actor_id": actor_id,
        "nonce": nonce,
    }
    return _ask(query, guard_home, {"digest": str}, _digest)


def snapshot_digest(
    *,
    catalog_digest: str,
    health: str,
    revision: int,
    managed_revision: int,
    layers: Iterable[ExtensionControlLayer],
    guard_home: Path | None = None,
) -> str:
    """The digest that identifies the runtime snapshot of one authority view.

    One hook builds the same snapshot several times, so the digest is kept for
    the process: it is a pure function of these inputs, and asking again would
    spend a resident round trip per build.
    """

    return _snapshot_digest(catalog_digest, health, revision, managed_revision, tuple(layers), guard_home)


@functools.lru_cache(maxsize=32)
def _snapshot_digest(
    catalog_digest: str,
    health: str,
    revision: int,
    managed_revision: int,
    layers: tuple[ExtensionControlLayer, ...],
    guard_home: Path | None,
) -> str:
    query: dict[str, object] = {
        "kind": "snapshot_digest",
        "catalog_digest": catalog_digest,
        "health": health,
        "revision": revision,
        "managed_revision": managed_revision,
        "layers": [_layer_wire(layer) for layer in layers],
    }

    return _ask(query, guard_home, {"digest": str}, _digest)


_REQUEST_DIGEST_FIELDS: Final = (
    "previous_revision",
    "catalog_digest",
    "layers",
    "actor_id",
    "idempotency_key",
    "nonce",
)


def request_json(payload: Mapping[str, object]) -> str:
    """Snapshot the request wire fields for transport and committed-response replay."""
    query: dict[str, object] = {"kind": "request_digest"}
    query.update({field: payload.get(field) for field in _REQUEST_DIGEST_FIELDS})
    try:
        encoded = json.dumps(query, separators=(",", ":"), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise NativeExtensionControlError(f"{_OPERATION.prefix}_invalid_digest_input") from error
    if len(encoded) > _MAX_BATCH_BYTES:
        raise _too_large()
    return encoded


def request_digest(payload: Mapping[str, object], *, guard_home: Path | None = None) -> str:
    """The digest that identifies one apply request, computed by the resident.

    The resident hashes exactly the fields that make two requests the same
    request, as the caller sent them (``None`` for one that is missing): the
    request is not yet known to be well formed. A request the resident could not
    encode (a non-finite number) or is too big for one ask names no digest, so
    it matches no preview.
    """

    query = json.loads(request_json(payload))
    return _ask(query, guard_home, {"digest": str}, _digest)


def candidate_nonce(
    *,
    nonce: str,
    activation_digest: str,
    lifecycle_before: str,
    lifecycle_after: str,
    security_digest: str | None,
    guard_home: Path | None = None,
) -> str:
    """The nonce a prepared candidate's mutation is proven under, computed by the resident.

    The caller's nonce is bound to the identities of the activation records
    staged for the candidate, so an approval cannot commit other records than
    the ones it was shown.
    """

    query: dict[str, object] = {
        "kind": "candidate_nonce",
        "nonce": nonce,
        "activation_digest": activation_digest,
        "lifecycle_before": lifecycle_before,
        "lifecycle_after": lifecycle_after,
        "security_digest": security_digest,
    }
    return _ask(query, guard_home, {"nonce": str}, lambda payload: _hex_digest(payload["nonce"]))
