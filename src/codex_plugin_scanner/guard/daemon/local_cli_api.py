"""Bounded daemon API for unlisted CLI observation and this-device grants."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from ..approval_gate import (
    ApprovalGateError,
    consume_local_cli_trust_grant,
    input_from_mapping,
    require_local_cli_trust,
)
from ..local_cli_trust import utc_now
from ..runtime.local_cli_identity import (
    LocalCliKind,
    UnlistedCliIdentity,
    is_local_cli_id,
    recognize_operator_cli,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_LOCAL_CLI_API_SCHEMA = "guard.daemon.local-clis.v1"
_VALID_STATES = frozenset({"allowed", "blocked", "unset"})


class LocalCliApiError(Exception):
    def __init__(self, status: int, code: str, message: str | None = None) -> None:
        self.status = status
        self.code = code
        super().__init__(message or code)

    def to_payload(self) -> dict[str, object]:
        return {"error": self.code, "message": str(self)}


class LocalCliApiService:
    def __init__(self, *, store: GuardStore) -> None:
        self._store = store

    def list_items(self) -> dict[str, object]:
        items = self._store.list_local_cli_items()
        revision = self._store.read_local_cli_revision()
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "revision": revision,
            "items": items,
            "cloud": {
                "sync_local_only": True,
                "summary": (
                    "Custom extensions stay on this device. "
                    "Guard Cloud can keep the same extension on your other machines."
                ),
            },
        }

    def recognize(self, payload: dict[str, object]) -> dict[str, object]:
        command = self._required_string(payload, "command")
        home_dir = Path.home()
        identity, code, message = recognize_operator_cli(command, cwd=home_dir, home_dir=home_dir)
        if identity is None:
            raise LocalCliApiError(400, code, message)
        self._store.record_local_cli_observation(identity, seen_at=utc_now())
        listed = next(
            (item for item in self._store.list_local_cli_items() if item.get("cli_id") == identity.cli_id),
            None,
        )
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "revision": self._store.read_local_cli_revision(),
            "item": listed or identity.to_dict(),
            "summary": (
                f"Later commands from this same {identity.name} file are covered. "
                "Different flags are fine. Pipes and wrappers are not."
            ),
        }

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        identity, state = self._mutation_from_payload(payload)
        current = self._store.read_local_cli_revision()
        expected = self._required_int(payload, "previous_revision")
        if expected != current:
            raise LocalCliApiError(409, "revision_conflict")
        summary = _preview_summary(identity.name, state)
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "previous_revision": current,
            "next_revision": current + 1,
            "cli_id": identity.cli_id,
            "identity_hash": identity.identity_hash,
            "state": state,
            "summary": summary,
        }

    def apply(self, payload: dict[str, object]) -> dict[str, object]:
        identity, state = self._mutation_from_payload(payload)
        expected = self._required_int(payload, "previous_revision")
        session_nonce = self._required_string(payload, "session_nonce")
        action = f"local-cli-{state}"
        subject = f"{identity.cli_id}:{identity.identity_hash}:{state}:{expected}"
        try:
            grant = require_local_cli_trust(
                self._store.guard_home,
                approval_gate_input=input_from_mapping(payload),
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
            consume_local_cli_trust_grant(
                self._store.guard_home,
                grant,
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
        except ApprovalGateError as exc:
            raise LocalCliApiError(exc.status, exc.code, str(exc)) from exc
        try:
            revision = self._store.upsert_local_cli_grant(
                identity=identity,
                state=state,
                expected_revision=expected,
                updated_at=utc_now(),
            )
        except ValueError as exc:
            if str(exc) == "local_cli_revision_conflict":
                raise LocalCliApiError(409, "revision_conflict") from exc
            raise LocalCliApiError(400, "invalid_local_cli_mutation", str(exc)) from exc
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "status": "applied",
            "revision": revision,
            "cli_id": identity.cli_id,
            "state": state,
        }

    def _mutation_from_payload(self, payload: dict[str, object]) -> tuple[UnlistedCliIdentity, str]:
        cli_id = self._required_string(payload, "cli_id")
        identity_hash = self._required_string(payload, "identity_hash")
        name = self._required_string(payload, "name")
        kind = self._required_string(payload, "kind")
        state = self._required_string(payload, "state")
        if not is_local_cli_id(cli_id):
            raise LocalCliApiError(400, "invalid_cli_id")
        if len(identity_hash) != 64 or any(character not in "0123456789abcdef" for character in identity_hash):
            raise LocalCliApiError(400, "invalid_identity_hash")
        typed_kind = _cli_kind(kind)
        if typed_kind is None:
            raise LocalCliApiError(400, "invalid_cli_kind")
        if state not in _VALID_STATES:
            raise LocalCliApiError(400, "invalid_cli_state")
        example_label = payload.get("example_label")
        interpreter_name = payload.get("interpreter_name")
        if example_label is not None and not isinstance(example_label, str):
            raise LocalCliApiError(400, "invalid_example_label")
        if interpreter_name is not None and not isinstance(interpreter_name, str):
            raise LocalCliApiError(400, "invalid_interpreter_name")
        identity = UnlistedCliIdentity(
            cli_id=cli_id,
            name=name[:120],
            kind=typed_kind,
            identity_hash=identity_hash,
            example_label=(example_label or name)[:160],
            interpreter_name=interpreter_name,
        )
        return identity, state

    def _required_string(self, payload: dict[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise LocalCliApiError(400, f"missing_{key}")
        return value.strip()

    def _required_int(self, payload: dict[str, object], key: str) -> int:
        value = payload.get(key)
        if type(value) is not int:
            raise LocalCliApiError(400, f"missing_{key}")
        return value


def _preview_summary(name: str, state: str) -> str:
    if state == "allowed":
        return f"Add {name} as a custom extension and allow its matching commands on this device."
    if state == "blocked":
        return f"Keep {name} as a custom extension and block its matching commands on this device."
    return f"Remove the {name} custom extension from this device."


def _cli_kind(value: str) -> LocalCliKind | None:
    if value == "executable":
        return "executable"
    if value == "script":
        return "script"
    return None
