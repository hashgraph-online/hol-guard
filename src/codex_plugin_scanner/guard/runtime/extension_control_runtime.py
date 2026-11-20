"""Immutable, in-memory extension-control state for hot-path decisions."""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from ..native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError
from .extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .extension_control_contract import ExtensionControlLayer, ResolverFailureCode

_NO_CONTROL_DIGEST = hashlib.sha256(b"hol.guard.extension-control:none:v1").hexdigest()
# Names a snapshot the resident gave no digest for. It is framed differently
# from every runtime snapshot digest, so no binding can ever match it.
_UNANSWERED_DIGEST = hashlib.sha256(b"hol.guard.extension-control:unanswered:v1").hexdigest()
_MAX_PROTECTED_FLOORS = 32


class ExtensionControlSnapshotUnavailableError(NativeCommandControlAuthorityUnavailableError):
    """The resident gave no digest, so no snapshot was built.

    Like a lease timeout, this says the authority was not read, never that it
    is unhealthy, so a caller keeps the snapshot it already holds.
    """

    code = "native_extension_control_snapshot_unavailable"

    def __init__(self) -> None:
        super().__init__(shared=True)
        self.args = ("The native runtime did not answer for the extension control snapshot digest.",)


@dataclass(frozen=True, slots=True)
class ExtensionControlDecisionEvidence:
    revision: int
    managed_revision: int
    effective_digest: str

    def __repr__(self) -> str:
        return "ExtensionControlDecisionEvidence(<private>)"


@dataclass(frozen=True, slots=True)
class ExtensionControlRuntimeSnapshot:
    health: AuthorityHealth
    revision: int
    catalog_digest: str
    effective_digest: str
    layers: tuple[ExtensionControlLayer, ...]
    managed_revision: int = 0
    # Carried from the view this snapshot was built from: the authority behind
    # it was never read. It stays out of the effective digest so an unread
    # placeholder and a read authority with the same contents still agree.
    unread: bool = False

    @classmethod
    def from_authority_view(cls, view: ExtensionControlAuthorityView) -> ExtensionControlRuntimeSnapshot:
        """The snapshot of ``view``, identified by the digest the resident computes.

        The resident checks the same digest when it installs a command-control
        binding, so computing it there leaves one definition of it.
        """

        from ..native_extension_control import NativeExtensionControlError, snapshot_digest

        try:
            digest = snapshot_digest(
                catalog_digest=view.catalog_digest,
                health=view.health.value,
                revision=view.revision,
                managed_revision=view.managed_revision,
                layers=view.layers,
            )
        except NativeExtensionControlError as error:
            raise ExtensionControlSnapshotUnavailableError() from error
        return cls(
            health=view.health,
            revision=view.revision,
            catalog_digest=view.catalog_digest,
            effective_digest=digest,
            layers=view.layers,
            managed_revision=view.managed_revision,
            unread=view.unread,
        )

    @classmethod
    def unanswered(cls, catalog_digest: str) -> ExtensionControlRuntimeSnapshot:
        """The snapshot a daemon starts on when the resident cannot digest its view.

        It carries no layers and is marked unread, like a view the daemon could
        not read, so every hook fails closed and nothing acknowledges degraded
        mode off it. Its digest matches no binding, and the next refresh that
        the resident answers replaces it.
        """

        return cls(
            health=AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
            revision=0,
            catalog_digest=catalog_digest,
            effective_digest=_UNANSWERED_DIGEST,
            layers=(),
            unread=True,
        )

    @property
    def awaiting_enrollment(self) -> bool:
        """This device never enrolled: packaged first-party protection applies and
        no permission can change until the authority is enrolled.

        It is the first-install baseline the resident accepts, with no layers at
        revision zero. An unenrolled reading that carries controls is a lost
        authority, not a new one.
        """

        return (
            self.health is AuthorityHealth.UNENROLLED
            and not self.unread
            and self.revision == 0
            and self.managed_revision == 0
            and not self.layers
        )

    @property
    def authority_failure(self) -> ResolverFailureCode | None:
        if self.health is AuthorityHealth.PROTECTED:
            return None
        if self.health in {AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED}:
            return ResolverFailureCode.AUTHORITY_TAMPERED
        return ResolverFailureCode.AUTHORITY_UNAVAILABLE

    @property
    def private_evidence(self) -> ExtensionControlDecisionEvidence:
        return ExtensionControlDecisionEvidence(self.revision, self.managed_revision, self.effective_digest)


class ExtensionControlRuntime:
    """Own one immutable snapshot and swap it atomically after mutations."""

    def __init__(self, initial: ExtensionControlAuthorityView) -> None:
        self._lock = threading.Lock()
        try:
            self._snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(initial)
        except ExtensionControlSnapshotUnavailableError:
            # Refusing to start would take the hook worker down with the
            # daemon, and a daemon that is not there protects nothing.
            self._snapshot = ExtensionControlRuntimeSnapshot.unanswered(initial.catalog_digest)
        started = self._snapshot
        self._highest_protected_revision = (
            (started.revision, started.managed_revision) if started.health is AuthorityHealth.PROTECTED else (0, 0)
        )
        # One floor digest per catalog. A view read for another catalog is a
        # different projection of the same authority, not a second authority
        # offered for the same revision, so one catalog's floor says nothing
        # about another's. Keeping only the last catalog's floor would let two
        # catalogs alternating at one revision step around the replacement
        # check, and this daemon alternates routinely: it rebinds whenever an
        # activation lands. The revision floor below still applies to all.
        self._protected_floors: OrderedDict[str, tuple[tuple[int, int], str]] = OrderedDict()
        if started.health is AuthorityHealth.PROTECTED:
            self._record_floor_locked(started)

    def current(self) -> ExtensionControlRuntimeSnapshot:
        with self._lock:
            return self._snapshot

    def refresh(self, view: ExtensionControlAuthorityView) -> ExtensionControlRuntimeSnapshot:
        candidate = ExtensionControlRuntimeSnapshot.from_authority_view(view)
        with self._lock:
            return self._install_candidate_locked(candidate)

    def replace_after_recovery(self, view: ExtensionControlAuthorityView) -> ExtensionControlRuntimeSnapshot:
        """Install authenticated recovered authority without retaining a poisoned revision floor."""

        candidate = ExtensionControlRuntimeSnapshot.from_authority_view(view)
        with self._lock:
            if (
                self._snapshot.health is AuthorityHealth.PROTECTED
                and self._snapshot.effective_digest == candidate.effective_digest
            ):
                return self._snapshot
            if self._snapshot.health not in {AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED}:
                raise ValueError("extension control runtime is not awaiting recovery")
            if candidate.health is not AuthorityHealth.PROTECTED:
                raise ValueError("extension control runtime recovery is not protected")
            self._highest_protected_revision = (candidate.revision, candidate.managed_revision)
            # Recovery exists to leave a poisoned floor behind, so every floor
            # the poisoned authority published goes with it.
            self._protected_floors.clear()
            self._record_floor_locked(candidate)
            self._snapshot = candidate
            return candidate

    def publish_after_commit(
        self,
        view: ExtensionControlAuthorityView,
        commit: Callable[[], None],
    ) -> ExtensionControlRuntimeSnapshot:
        """Commit durable authority before atomically exposing its staged snapshot."""

        candidate = ExtensionControlRuntimeSnapshot.from_authority_view(view)
        with self._lock:
            self._validate_candidate_locked(candidate)
            commit()
            return self._install_candidate_locked(candidate, validated=True)

    def _validate_candidate_locked(self, candidate: ExtensionControlRuntimeSnapshot) -> None:
        if candidate.health is not AuthorityHealth.PROTECTED:
            return
        candidate_revision = (candidate.revision, candidate.managed_revision)
        if (
            candidate.revision < self._highest_protected_revision[0]
            or candidate.managed_revision < self._highest_protected_revision[1]
        ):
            raise ValueError("extension control runtime revision cannot move backwards")
        floor = self._protected_floors.get(candidate.catalog_digest)
        if floor is not None and floor[0] == candidate_revision and floor[1] != candidate.effective_digest:
            raise ValueError("extension control runtime revision cannot be replaced")

    def _install_candidate_locked(
        self,
        candidate: ExtensionControlRuntimeSnapshot,
        *,
        validated: bool = False,
    ) -> ExtensionControlRuntimeSnapshot:
        if not validated:
            self._validate_candidate_locked(candidate)
        if candidate.health is AuthorityHealth.PROTECTED:
            self._highest_protected_revision = (candidate.revision, candidate.managed_revision)
            self._record_floor_locked(candidate)
        self._snapshot = candidate
        return candidate

    def _record_floor_locked(self, candidate: ExtensionControlRuntimeSnapshot) -> None:
        floors = self._protected_floors
        revision = (candidate.revision, candidate.managed_revision)
        floors[candidate.catalog_digest] = (revision, candidate.effective_digest)
        floors.move_to_end(candidate.catalog_digest)
        while len(floors) > _MAX_PROTECTED_FLOORS:
            # A daemon serves its core registry and the packs activated while
            # it runs, so this bound is not reached by ordinary use; it is here
            # so a churn of activations cannot grow the map without end. The
            # oldest catalog goes first, and the revision floor above still
            # refuses anything behind the highest revision installed.
            _ = floors.popitem(last=False)


def current_extension_control_binding_digest() -> str:
    # No hook path carries an extension-control snapshot, so every approval
    # binds the fixed no-control digest.
    return _NO_CONTROL_DIGEST


def _layer_payload(layer: ExtensionControlLayer) -> dict[str, object]:
    return {
        "catalog_digest": layer.catalog_digest,
        "controls": sorted(
            (
                {
                    "state": control.state.value,
                    "target_id": control.target.target_id,
                    "target_kind": control.target.kind.value,
                }
                for control in layer.controls
            ),
            key=lambda item: (str(item["target_kind"]), str(item["target_id"])),
        ),
        "global_lockdown": layer.global_lockdown,
        "kind": layer.kind.value,
        "schema_version": layer.schema_version,
    }
