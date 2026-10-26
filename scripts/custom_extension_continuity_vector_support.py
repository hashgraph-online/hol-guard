"""Shared fixtures for the custom-Extension continuity vector recorder.

Loads the reference snapshot named by ``GUARD_PY_SNAPSHOT`` (or the first
argument), and provides the fake store, request projection and vector
builders that ``record_custom_extension_continuity_vectors.py`` uses.
"""

from __future__ import annotations

import copy
import hashlib
import os
import random
import sys
from pathlib import Path
from types import SimpleNamespace

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard.runtime import custom_extension_continuity as reference  # noqa: E402
from codex_plugin_scanner.guard.runtime.local_cli_identity import (  # noqa: E402
    UnlistedCliIdentity,
    is_local_cli_id,
)

OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures"
STATE = reference.CUSTOM_EXTENSION_CONTINUITY_STATE_KEY
LAST_GOOD = reference.CUSTOM_EXTENSION_CONTINUITY_LAST_GOOD_STATE_KEY
REMOVALS = reference.CUSTOM_EXTENSION_CONTINUITY_REMOVALS_STATE_KEY
V1 = reference.CUSTOM_EXTENSION_CONTINUITY_SCHEMA
V2 = reference.CUSTOM_EXTENSION_CONTINUITY_SCHEMA_V2
LOCAL_KEYS = ("identity_hash", "kind", "name", "example_label", "interpreter_name", "observed_count", "surface")
CLI_IDS = ("local-cli.deploy", "local-cli.build-tool", "local-cli.lint", "local-cli.x9")
WORKSPACE = "ws_1"
DEVICE = "device-a"
OBSERVED = "2026-10-01T00:00:00Z"
EXPIRES = "2026-12-01T00:00:00Z"
FRESH = "2026-10-11T00:00:00Z"
LATE = "2027-01-01T00:00:00+00:00"


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def scoped(identity_hash: str, workspace: str = WORKSPACE) -> str:
    return h(f"{V1}:{workspace}:{identity_hash}")


def device_hash(workspace: str = WORKSPACE, device: str = DEVICE) -> str:
    return h(f"{V1}:device:{workspace}:{device}")


def binding(workspace: str = WORKSPACE, device: str = DEVICE) -> dict[str, str]:
    return {"workspaceHash": h(f"{V1}:workspace:{workspace}"), "deviceHash": device_hash(workspace, device)}


class FakeStore:
    def __init__(self, snap: dict[str, object]) -> None:
        self.snap = snap
        self.applied: dict[str, object] | None = None

    def get_sync_payload(self, key: str) -> object:
        return copy.deepcopy(self.snap["sync"].get(key))  # type: ignore[union-attr]

    def read_local_cli_revision(self) -> int:
        return self.snap["authority_revision"]  # type: ignore[return-value]

    def list_local_cli_items(self) -> list[dict[str, object]]:
        return copy.deepcopy(self.snap["locals"])  # type: ignore[arg-type]

    def _detail(self, cli_id: str) -> dict[str, object]:
        return self.snap["details"].get(cli_id, {}) if is_local_cli_id(cli_id) else {}  # type: ignore[union-attr]

    def read_local_cli_command_catalog(self, cli_id: str) -> list[SimpleNamespace]:
        return [SimpleNamespace(command_id=item) for item in self._detail(cli_id).get("catalog_ids", [])]

    def read_local_cli_grant(self, cli_id: str) -> dict[str, object] | None:
        grant = self._detail(cli_id).get("grant")
        return None if grant is None else {**grant, "revision": 1, "updated_at": FRESH}

    def read_local_cli_command_states(self, cli_id: str) -> dict[str, str]:
        return dict(self._detail(cli_id).get("command_states", {}))

    def apply_custom_extension_continuity_transaction(self, **kwargs: object) -> int:
        self.applied = kwargs
        return 7


def project_local(item: dict[str, object]) -> dict[str, object]:
    commands = item.get("commands")
    return {
        "cli_id": item["cli_id"],
        **{key: item.get(key) for key in LOCAL_KEYS},
        "command_ids": [c.get("command_id") for c in commands if isinstance(c, dict)]
        if isinstance(commands, list)
        else [],
    }


def detail_request(store: FakeStore, cli_id: str) -> dict[str, object]:
    grant = store.read_local_cli_grant(cli_id)
    return {
        "grant": None if grant is None else {"identity_hash": grant["identity_hash"], "state": grant["state"]},
        "command_states": store.read_local_cli_command_states(cli_id),
        "catalog_ids": [command.command_id for command in store.read_local_cli_command_catalog(cli_id)],
    }


def item_order(payload: object) -> list[str]:
    if isinstance(payload, dict) and isinstance(payload.get("items"), dict):
        return [key for key in payload["items"] if isinstance(key, str)]
    return []


def identity_out(identity: UnlistedCliIdentity) -> dict[str, object]:
    return identity.to_dict()


def plan_vector(name: str, snap: dict[str, object], bundle: dict[str, object], device_id: str | None, now: str):
    store = FakeStore(snap)
    locals_ = [item for item in store.list_local_cli_items() if isinstance(item.get("cli_id"), str)]
    previous = store.get_sync_payload(STATE)
    removals = store.get_sync_payload(REMOVALS)
    request = {
        "operation": "plan",
        "continuity": bundle["payload"][reference.CUSTOM_EXTENSION_CONTINUITY_FIELD],
        "workspace_id": bundle.get("workspaceId"),
        "device_id": device_id,
        "now": now,
        "previous": previous,
        "previous_item_order": item_order(previous),
        "removals": removals,
        "locals": [project_local(item) for item in locals_],
        "details": {str(item["cli_id"]): detail_request(store, str(item["cli_id"])) for item in locals_},
    }
    try:
        mutation, state = reference.prepare_verified_custom_extension_continuity(
            store,  # type: ignore[arg-type]
            bundle,
            device_id=device_id,
            now=now,
        )
    except reference.CustomExtensionContinuityError as error:
        return {"name": name, "request": request, "expected": {"error": str(error)}}
    assert mutation is not None
    assert mutation.expected_revision == store.read_local_cli_revision()
    assert mutation.updated_at == now
    assert mutation.sync_payloads[STATE] is state
    assert LAST_GOOD not in mutation.sync_payloads or mutation.sync_payloads[LAST_GOOD] is state
    assert set(mutation.sync_payloads) <= {STATE, LAST_GOOD, REMOVALS}
    assert dict(mutation.sync_preconditions) == {STATE: previous, REMOVALS: removals}
    v2 = mutation.requires_protected_extension_authority
    assert mutation.required_negotiated_capability == ("custom-extension-continuity.v2" if v2 else None)
    expected = {
        "error": None,
        "authority_updates": [
            {**identity_out(identity), "state": state_, "commands": dict(commands)}
            for identity, state_, commands in mutation.authority_updates
        ],
        "events": [[event, payload] for event, payload in mutation.events],
        "observation_preconditions": dict(mutation.observation_preconditions),
        "state": state,
        "state_item_order": list(state["items"]),
        "write_last_good": LAST_GOOD in mutation.sync_payloads,
        "removals": mutation.sync_payloads.get(REMOVALS),
        "v2": v2,
    }
    return {"name": name, "request": request, "expected": expected}


def local_mutation_vector(name: str, snap: dict[str, object], cli_id: str, identity_hash: str, state: str, now: str):
    store = FakeStore(snap)
    identity = UnlistedCliIdentity(
        cli_id=cli_id, name="deploy", kind="script", identity_hash=identity_hash, example_label="deploy"
    )
    local = next((item for item in store.list_local_cli_items() if item.get("cli_id") == cli_id), None)
    request = {
        "operation": "local_mutation",
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "state": state,
        "now": now,
        "active": store.get_sync_payload(STATE),
        "active_item_order": item_order(store.get_sync_payload(STATE)),
        "removals": store.get_sync_payload(REMOVALS),
        "local": None if local is None else project_local(local),
    }
    reference.record_local_custom_extension_mutation(
        store,  # type: ignore[arg-type]
        identity=identity,
        state=state,
        expected_revision=3,
        command_states={},
        now=now,
    )
    applied = store.applied
    assert applied is not None
    sync_payloads = applied["sync_payloads"]
    assert set(sync_payloads) <= {STATE, REMOVALS}
    assert applied["sync_preconditions"] == {STATE: request["active"], REMOVALS: request["removals"]}
    (event,) = applied["events"]
    expected = {
        "removals": sync_payloads[REMOVALS],
        "active": sync_payloads.get(STATE),
        "active_item_order": item_order(sync_payloads.get(STATE)),
        "event": [event[0], event[1]],
        "observation_precondition": applied["observation_preconditions"][cli_id],
    }
    return {"name": name, "request": request, "expected": expected}


def public_state_vector(name: str, stored: object, now: str):
    store = FakeStore({"sync": {STATE: stored}})
    states = reference.continuity_state_for_local_items(store, now=now)  # type: ignore[arg-type]
    return {
        "name": name,
        "request": {"operation": "public_state", "stored": copy.deepcopy(stored), "now": now},
        "expected": {"states": states},
    }


def local(cli_id: str, **overrides: object) -> dict[str, object]:
    base = cli_id.removeprefix("local-cli.")
    item: dict[str, object] = {
        "cli_id": cli_id,
        "identity_hash": h(cli_id),
        "kind": "script",
        "name": base,
        "example_label": f"python3 {base}.py",
        "interpreter_name": "python3",
        "observed_count": 3,
        "surface": "cli",
        "state": "allowed",
        "commands": [{"command_id": "root", "state": "inherit"}, {"command_id": "sub", "state": "allow"}],
        "mcp_catalog": {"tools": []},
    }
    item.update(overrides)
    return item


def detail(cli_id: str, *, grant: object = "same", states: dict[str, str] | None = None, catalog=("root", "sub")):
    if grant == "same":
        grant = {"identity_hash": h(cli_id), "state": "allowed"}
    return {"grant": grant, "command_states": states or {}, "catalog_ids": list(catalog)}


def obs1(items: list[object], **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schemaVersion": V1,
        "revision": 2,
        "observedAt": OBSERVED,
        "expiresAt": EXPIRES,
        "items": items,
    }
    value.update(overrides)
    return value


def item1(cli_id: str, *, identity_hash: str | None = None, state: str = "allowed", commands=None) -> dict[str, object]:
    return {
        "cliId": cli_id,
        "identityHash": identity_hash or h(cli_id),
        "settings": {"state": state, "commands": commands if commands is not None else {}},
    }


def obs2(items: list[object], **overrides: object) -> dict[str, object]:
    value = obs1(items, **overrides)
    if "schemaVersion" not in overrides:
        value["schemaVersion"] = V2
    return value


def item2(identity_hash: str, *, state: str = "allowed", devices=None) -> dict[str, object]:
    return {
        "identityHash": identity_hash,
        "deviceIdentityHashes": devices if devices is not None else [device_hash()],
        "state": state,
    }


def bundle(continuity: object, workspace: object = WORKSPACE) -> dict[str, object]:
    return {"payload": {reference.CUSTOM_EXTENSION_CONTINUITY_FIELD: continuity}, "workspaceId": workspace}


def snap(locals_=(), details=None, previous=None, removals=None, revision=4) -> dict[str, object]:
    sync: dict[str, object] = {}
    if previous is not None:
        sync[STATE] = previous
    if removals is not None:
        sync[REMOVALS] = removals
    return {"sync": sync, "authority_revision": revision, "locals": list(locals_), "details": details or {}}


def random_vectors(count: int) -> list[dict[str, object]]:
    rng = random.Random(20261011)
    vectors = []
    for index in range(count):
        v2 = rng.random() < 0.5
        cli_ids = rng.sample(CLI_IDS, rng.randint(0, len(CLI_IDS)))
        locals_ = []
        details = {}
        for cli_id in CLI_IDS:
            if rng.random() < 0.25:
                continue
            identity_hash = h(cli_id) if rng.random() < 0.8 else h(cli_id + "-changed")
            locals_.append(
                local(
                    cli_id,
                    identity_hash=identity_hash,
                    observed_count=rng.choice([0, 1, 4]),
                    kind=rng.choice(["script", "executable", "executable", "script", "executable", "odd"]),
                    surface=rng.choice(["cli", "mcp", "package-scripts", "other"]),
                )
            )
            grant = rng.choice([None, "same", {"identity_hash": identity_hash, "state": "blocked"}])
            details[cli_id] = detail(
                cli_id,
                grant=grant,
                states=rng.choice([{}, {"sub": "block"}, {"root": "allow"}]),
                catalog=rng.choice([("root", "sub"), ("root", "sub"), ("root", "sub"), ("root",), ()]),
            )
        removals = {}
        for cli_id in CLI_IDS:
            if rng.random() < 0.2:
                removals[cli_id] = {
                    "identity_hash": h(cli_id),
                    "cloud_revision": rng.choice([1, 2, 3]),
                    "state": rng.choice(["allowed", "blocked", "unset"]),
                }
        revision = rng.choice([1, 2, 3])
        if v2:
            items = [
                item2(
                    scoped(h(cli_id)),
                    state=rng.choice(["allowed", "blocked", "removed"]),
                    devices=[device_hash() if rng.random() < 0.85 else h("other-device")],
                )
                for cli_id in cli_ids
            ]
            observation = obs2(items, revision=revision)
        else:
            items = [
                item1(
                    cli_id,
                    state=rng.choice(["allowed", "blocked"]),
                    commands=rng.choice([{}, {"sub": "block"}, {"root": "allow", "sub": "inherit"}]),
                )
                for cli_id in cli_ids
            ]
            observation = obs1(items, revision=revision)
        previous = None
        roll = rng.random()
        if roll < 0.3:
            previous = {
                "schema_version": V2 if v2 else V1,
                "cloud_revision": rng.choice([1, 2]),
                "binding": binding(rng.choice([WORKSPACE, "ws_old"])),
                "items": {
                    cli_id: {"status": rng.choice(["applied", "removed"]), "identity_hash": h(cli_id)}
                    for cli_id in rng.sample(CLI_IDS, 2)
                },
            }
        now = rng.choice([FRESH, FRESH, LATE])
        vectors.append(
            plan_vector(
                f"random_{index}",
                snap(locals_, details, previous=previous, removals=removals or None, revision=rng.randint(0, 9)),
                bundle(observation),
                DEVICE,
                now,
            )
        )
    return vectors


def local_mutation_vectors() -> list[dict[str, object]]:
    deploy = CLI_IDS[0]
    active = {
        "schema_version": V1,
        "cloud_revision": 4,
        "items": {deploy: {"status": "applied", "reason": "same_identity"}, "local-cli.z": {"status": "stale"}},
    }
    vectors = []
    for state in ("unset", "allowed", "blocked"):
        for name, snapshot in {
            "empty": snap(),
            "active": snap([local(deploy)], previous=active, removals={"local-cli.z": {"state": "allowed"}}),
            "active_float_revision": snap(
                [local(deploy, observed_count=0)], previous={**active, "cloud_revision": 4.0}
            ),
            "active_without_item": snap([local(deploy)], previous={"cloud_revision": 2, "items": {}}),
            "active_list": snap([local(deploy, commands=None)], previous=[1], removals=["x"]),
            "active_items_list": snap([local(deploy)], previous={"cloud_revision": 1, "items": []}),
        }.items():
            vectors.append(local_mutation_vector(f"local_{state}_{name}", snapshot, deploy, h(deploy), state, FRESH))
    return vectors


def public_state_vectors() -> list[dict[str, object]]:
    items = {
        "local-cli.a": {"status": "applied", "reason": "same_identity", "cloud_revision": 2, "surface": "cli", "x": 1},
        "local-cli.b": {"status": "removed", "reason": "removed_locally"},
        "local-cli.c": {"status": "changed_identity"},
        "local-cli.d": "x",
        "local-cli.e": {},
    }
    stored = {"items": items, "expires_at": EXPIRES}
    return [
        public_state_vector("public_fresh", stored, FRESH),
        public_state_vector("public_stale", stored, LATE),
        public_state_vector("public_equal", stored, EXPIRES),
        public_state_vector("public_bad_now", stored, "garbage"),
        public_state_vector("public_naive_expiry", {**stored, "expires_at": "2026-12-01T00:00:00"}, FRESH),
        public_state_vector("public_missing_expiry", {"items": items}, FRESH),
        public_state_vector("public_items_list", {"items": [], "expires_at": EXPIRES}, FRESH),
        public_state_vector("public_not_dict", [1], FRESH),
        public_state_vector("public_none", None, FRESH),
    ]
