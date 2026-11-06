"""Transport, protected credential IO and leases for native security policy.

No hook calls this module. Roots originate only in fixed installed/remote
factories or a previously authenticated protected native observation.
"""

from __future__ import annotations

import time

from ..native_command_control_authority_io import (
    hold_command_control_authority_lock,
    read_private_state,
    require_exclusive_command_control_mutation_lease,
    write_private_state,
)
from ..native_command_control_authority_store import _key
from . import activation_store, lifecycle, lifecycle_store
from .located_store import LocatedStore
from .object_native import sessioned

PREFIX = "guard-command-pack-active-security"
FILE = "active-pack-security.v1.json"
MAX_BYTES = 262144


# Native answers these from the request alone: no files, clock or randomness
# (see the matching note in active_pack_security.rs). The resident answers them
# in process for the store it serves, so daemon polling, which repeats the same
# few requests every second, starts no runtime for them.
_RESIDENT_OPERATIONS = frozenset({"scope", "check", "read", "change", "marker", "binding", "resume"})


def invoke(operation, store, **fields):
    request = {"operation": operation, "key": _key(store).hex(), **fields}
    if operation in _RESIDENT_OPERATIONS:
        result = lifecycle.resident_answer(store, {"kind": "active-security", **request})
        if result is not None:
            return result
    return lifecycle.invoke("active-security", **request)


def read(store):
    backend = getattr(store, "_policy_integrity_secret_store", None)
    if backend is None or store._should_skip_policy_integrity_keychain_access(backend):
        if _activation(store) is None:
            return None
        raise ValueError("active_security_protected_store_unavailable")
    record = store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(PREFIX))
    if record is None and (store.guard_home / "native-runtime" / FILE).exists():
        raise ValueError("active_security_protected_record_missing")
    return record


def _activation(store):
    with store._connect() as connection:
        exists = connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_control_schema_migration'"
        ).fetchone()
        row = activation_store._row(connection) if exists else None
    if row is None:
        return None
    from .activation_baseline import is_baseline

    if is_baseline(row["record_json"]):
        return None
    return dict(activation=row["record_json"], activation_digest=row["record_digest"], activation_mac=row["record_mac"])


def _commit(store, captured, activation, result):
    """CAS/readback and publication closure in the existing EX interval; no fetch."""
    from ..native_command_control_authority_store import begin_native_command_control_mutation

    with store._extension_control_authority_lock():
        require_exclusive_command_control_mutation_lease(store.guard_home)
        if read(store) != captured or _activation(store) != activation:
            raise ValueError("active_security_observation_conflict")
        invoke("read", store, record=result["record"])
        if captured == result["record"]:
            return
        # Old warm readers examine this existing marker on every decision. Close
        # it before protected observation IO, including failure/crash paths.
        changed = invoke("change", store, record=captured, next=result["record"])["enforcement_changed"]
        if changed:
            begin_native_command_control_mutation(store)
        backend = store._policy_integrity_secret_store
        backend.set_secret(store._build_scoped_secret_ref(PREFIX), result["record"])
        if read(store) != result["record"]:
            raise ValueError("active_security_protected_write_mismatch")
        write_private_state(store.guard_home, FILE, result["record"].encode(), MAX_BYTES)


def _no_fetch(target, maximum):
    raise ValueError("active_security_required_proofs_unavailable")


@sessioned
def _prepare(store, captured, activation, publication, fetch, *, profile=None, installed_identity=None):
    arguments = dict(
        record=captured,
        publication=publication,
        profile=profile,
        installed_identity=installed_identity,
        lineage_floor=lifecycle_store.read(store),
        **activation,
    )
    pending = invoke("begin", store, **arguments)
    if "lineage_source" in pending:
        floor = lifecycle.invoke("read", key=_key(store).hex(), floor=pending["lineage_floor"])
        pending = invoke("begin", store, **arguments, ancestry=lifecycle.ancestry(floor, pending["lineage_source"]))
    if pending.get("ignored"):
        return None
    directory = activation_store.directory_for_store(store)
    from .cache_io import stage_archive

    transfer = fetch or _no_fetch
    reader = LocatedStore(directory / "objects", fetch=transfer)
    complete = dict(record=pending["record"], directory=str(directory), **activation)
    try:
        # Rust charges each requested object once against one cumulative budget
        # and bounds the rounds; only the echoed budget is carried between calls.
        result = invoke("complete", store, **complete)
        while "need" in result or "need_archives" in result:
            if "need_archives" in result:
                for archive in result["need_archives"]:
                    stage_archive(directory, archive, transfer)
            else:
                reader.blob(result["need"])
            result = invoke("complete", store, budget=result["budget"], **complete)
        return result
    except (ValueError, OSError):
        # A known authenticated newer epoch is retained even if a required
        # proof is missing, corrupt or unavailable. It cannot revive old LKG.
        _commit(store, captured, activation, pending)
        raise


def observe(store):
    """Update/preparation control path; callers cannot supply a Root or active IDs."""
    from .preparation_authority import load_installed_bundle
    from .transport import fetch_object, fetch_root

    activation = _activation(store)
    captured = read(store)
    if activation is None:
        if captured is not None:
            invoke("read", store, record=captured)
            raise ValueError("active_security_activation_missing")
        return
    installed = load_installed_bundle()
    if installed is not None:
        _observe_capability(store, captured, activation, installed, installed.fetch)
        captured = read(store)
    try:
        remote = fetch_root(now=int(time.time()))
    except (ValueError, OSError):
        if captured is not None and invoke("read", store, record=captured)["pending"]:
            raise ValueError("active_security_required_proofs_unavailable") from None
        return  # Unrelated discovery outage does not expire complete active policy.
    _observe_capability(store, captured, activation, remote, fetch_object)


def _observe_capability(store, captured, activation, authority, fetch):
    from .cache_io import Lease

    with Lease(activation_store.directory_for_store(store)):
        return _observe_leased(store, captured, activation, authority, fetch)


def _observe_leased(store, captured, activation, authority, fetch):
    from .authority import VerifiedDistribution
    from .preparation_authority import installed_bundle_type

    if type(authority) is not VerifiedDistribution and type(authority) is not installed_bundle_type():
        raise ValueError("active_security_authenticated_publication_required")
    result = _prepare(
        store,
        captured,
        activation,
        authority.data.decode(),
        fetch,
        profile="remote" if type(authority) is VerifiedDistribution else "installed",
        installed_identity=None if type(authority) is VerifiedDistribution else lifecycle.installed_identity(authority),
    )
    if result is not None:
        _commit(store, captured, activation, result)


def observe_preparation(store, authority):
    from .preparation import cached_fetcher
    from .preparation_authority import installed_bundle_type

    activation = _activation(store)
    if activation is None:
        return
    fetch = (
        authority.fetch
        if type(authority) is installed_bundle_type()
        else cached_fetcher(activation_store.directory_for_store(store) / "transfers")
    )
    _observe_capability(store, read(store), activation, authority, fetch)


def reconcile(store):
    """Use retained native observation after SQL replacement or restart, offline."""
    captured = read(store)
    if captured is None:
        return
    activation = _activation(store)
    if activation is None:
        raise ValueError("active_security_activation_missing")
    # The native operation authenticates this record before reusing its Root.
    result = invoke("resume", store, record=captured, **activation)
    if result["active_matches"]:
        # Pending records publish a conservative terminal quarantine; discovery
        # refresh, never a hook, retries their unavailable proofs.
        data = captured.encode()
        with hold_command_control_authority_lock(store.guard_home, shared=True):
            if read(store) != captured or _activation(store) != activation:
                raise ValueError("active_security_observation_conflict")
            if read_private_state(store.guard_home, FILE, MAX_BYTES) == data:
                return
        with store._extension_control_authority_lock():
            if read(store) != captured or _activation(store) != activation:
                raise ValueError("active_security_observation_conflict")
            # Preserve the resident publication fence when the protected
            # observation already has an identical private file on disk.
            if read_private_state(store.guard_home, FILE, MAX_BYTES) != data:
                write_private_state(store.guard_home, FILE, data, MAX_BYTES)
        return
    from .cache_io import Lease

    with Lease(activation_store.directory_for_store(store)):
        result = _prepare(store, captured, activation, result["publication"], None)
        _commit(store, captured, activation, result)


def binding(store, value):
    captured = read(store)
    if captured is None:
        return value
    return invoke("binding", store, record=captured, binding=value)


def marker(store, value):
    captured = read(store)
    if captured is None:
        return value
    return invoke("marker", store, record=captured, marker=value)


def scope_identity(store):
    return invoke("scope", store, record=read(store))["applicable_digest"]


def check_scope(store, expected):
    require_exclusive_command_control_mutation_lease(store.guard_home)
    invoke("check", store, record=read(store), expected=expected)
