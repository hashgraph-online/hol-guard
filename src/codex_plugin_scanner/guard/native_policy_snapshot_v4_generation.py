"""Reserve fresh V4 bytes under the shared private snapshot generation lock."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_command_control_binding import capture_native_command_control_binding
from .native_managed_configuration import MANAGED_CONFIGURATION_INPUT_KEY
from .native_policy_authority_contract import NativePolicyAuthorityCapabilities
from .native_policy_authority_read import NativeVerifiedPolicyInputs
from .native_policy_snapshot_codec import _strict_json_loads_v3, derive_native_policy_verifier_key
from .native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_EXPIRY_MS, NativePolicySnapshotError
from .native_policy_snapshot_generation import _v3_generation_for_policy
from .native_policy_snapshot_storage import (
    _recover_v3_snapshot_transaction,
    _v3_generation_lock,
    _write_v3_generation_state,
)
from .native_policy_snapshot_v4 import build_policy_snapshot_v4, snapshot_bytes_v4
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

if TYPE_CHECKING:
    from .config import GuardConfig


@dataclass(frozen=True, slots=True, repr=False)
class NativeV4Candidate:
    """Signed immutable bytes and their exact captured inputs; not application proof."""

    snapshot_bytes: bytes
    inputs: NativeVerifiedPolicyInputs

    @property
    def snapshot(self) -> dict[str, object]:
        # Never expose a mutable mapping retained by the publication barrier.
        return cast(dict[str, object], _strict_json_loads_v3(self.snapshot_bytes))


def reserve_snapshot_v4(
    *,
    config: GuardConfig | Mapping[str, object],
    guard_home: Path,
    runtime_identity: str,
    rule_digest: str,
    master_key: bytes,
    inputs: NativeVerifiedPolicyInputs,
    capabilities: NativePolicyAuthorityCapabilities,
    issued_at_ms: int,
    command_extensions: Mapping[str, object] | None = None,
    minimum_generation: int | None = None,
    deadline_monotonic: float | None = None,
) -> NativeV4Candidate:
    """Sign before committing the counter; every successful reservation is fresh.

    The caller supplies its compiled current config from the same captured
    source view. Recover the old V3 journal before sharing its generation state.
    V4 deliberately retains no reusable publisher cache: a lost response or
    restart consumes a new generation instead of re-signing an existing one.
    """
    if type(inputs) is not NativeVerifiedPolicyInputs or type(issued_at_ms) is not int or issued_at_ms < 0:
        raise NativePolicySnapshotError("native_policy_snapshot_inputs_invalid")
    # This local source is enforced by the separately authenticated V3
    # command program. Its delegated semantics are not a scoped V4 claim.
    if any(source.get("requires_native_command_binding") is True for source in inputs.sources):
        raise NativePolicySnapshotError("native_policy_authority_bundle_semantics_unsupported")
    expiry = issued_at_ms + POLICY_SNAPSHOT_MAX_EXPIRY_MS
    if inputs.expires_at_ms is not None:
        if type(inputs.expires_at_ms) is not int:
            raise NativePolicySnapshotError("native_policy_snapshot_expiry_invalid")
        expiry = min(expiry, inputs.expires_at_ms)
    if expiry <= issued_at_ms:
        raise NativePolicySnapshotError("native_policy_snapshot_expired")
    verifier_key: bytes | None = None
    try:
        verifier_key = derive_native_policy_verifier_key(master_key)
        frozen_config = config
        binding = capture_native_command_control_binding(command_extensions) if command_extensions is not None else None

        def build(generation: int) -> dict[str, object]:
            assert verifier_key is not None
            return build_policy_snapshot_v4(
                config=frozen_config,
                guard_home=guard_home,
                runtime_identity=runtime_identity,
                rule_digest=rule_digest,
                verifier_key=verifier_key,
                generation=generation,
                authority=inputs.authority,
                capabilities=capabilities,
                source_input_digest=inputs.input_digest,
                issued_at_ms=issued_at_ms,
                expires_at_ms=expiry,
                command_extensions=binding,
            )

        # Policy identity omits generation and lease timestamps. Validate and
        # derive it before entering the shared state transaction.
        proposed = cast(dict[str, object], _strict_json_loads_v3(snapshot_bytes_v4(build(1))))
        policy_digest = cast(str, proposed["policy_digest"])
        frozen_config = {**cast(dict[str, object], proposed["effective_policy"]), "mode": proposed["mode"]}
        if inputs.authority.managed_config is not None:
            frozen_config[MANAGED_CONFIGURATION_INPUT_KEY] = inputs.authority.managed_config.to_mapping()
        with _v3_generation_lock(guard_home, deadline_monotonic=deadline_monotonic) as descriptor:
            # Provision under the same lock: a concurrent first publisher must
            # not inspect a key file while another publisher is creating it.
            provision_native_policy_verifier_key(guard_home, master_key)
            _recover_v3_snapshot_transaction(guard_home, verifier_key)
            generation = _v3_generation_for_policy(
                guard_home,
                policy_digest,
                force_increment=True,
                minimum_generation=minimum_generation,
                deadline_monotonic=deadline_monotonic,
                lock_descriptor=descriptor,
                persist_state=False,
            )
            snapshot = proposed if generation == 1 else build(generation)
            if snapshot["policy_digest"] != policy_digest:
                raise NativePolicySnapshotError("native_policy_snapshot_inputs_changed")
            encoded = snapshot_bytes_v4(snapshot)
            _write_v3_generation_state(guard_home, generation=generation, policy_digest=policy_digest)
            return NativeV4Candidate(encoded, inputs)
    finally:
        verifier_key = None
        master_key = b""
