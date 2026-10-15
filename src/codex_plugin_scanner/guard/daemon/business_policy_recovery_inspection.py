"""Read-only native-authenticated recovery discovery and local rule preview."""

import time
from typing import cast

from .. import native_business_source_store as owner
from ..business_policy_document_view import without_provenance
from ..mcp.policy_recovery_state import request_recovery_recorded
from ..native_business_source_bridge import _consumer, _remaining, verify_business_source_record
from ..native_business_source_retention import read_retained_business_source_anchor
from ..native_command_control_authority_io import hold_command_control_authority_lock, read_private_state
from ..native_policy_snapshot_codec import derive_native_policy_verifier_key
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from ..policy_document import GuardPolicyDocument, policy_document_digest


def inspect_business_policy_recovery(store, request, document):
    digest = policy_document_digest(document)
    deadline = time.monotonic() + 5
    status = _consumer(deadline, anchor=True)
    if status.capabilities is None or owner.CURRENT_FENCE_CAPABILITY not in status.capabilities.features:
        raise owner._error("native_business_source_current_fence_unavailable")
    with hold_command_control_authority_lock(store.guard_home, shared=True, timeout_seconds=_remaining(deadline)):
        recovered = request_recovery_recorded(store, request.request_id)
        material = store._policy_integrity_secret_material(create=False)
        if material is None or material[0] is None:
            return {"state": "unavailable", "candidateDigest": digest, "requestRecovered": recovered}
        key = derive_native_policy_verifier_key(material[0])
        prepared = read_private_state(store.guard_home, owner.PREPARED_SOURCE_FILE_NAME, owner.MAX_RECORD_BYTES)
        if prepared is None:
            return {"state": "unavailable", "candidateDigest": digest, "requestRecovered": recovered}
        source = verify_business_source_record(prepared, key, deadline_monotonic=deadline)
        if source.source_digest != digest:
            return {"state": "unavailable", "candidateDigest": digest, "requestRecovered": recovered}
        try:
            installed = owner._verify_installed(
                read_private_state(store.guard_home, owner.SOURCE_FILE_NAME, owner.MAX_RECORD_BYTES),
                read_private_state(store.guard_home, owner.ANCHOR_FILE_NAME, owner.MAX_ANCHOR_BYTES),
                read_retained_business_source_anchor(store),
                owner._database_witness(store),
                key,
                deadline,
            )
        except NativePolicySnapshotError:
            state = "interrupted"
        else:
            state = "installed" if installed is not None and installed.source_digest == digest else "interrupted"
        # Preview comes only from the native-authenticated record, never the
        # request/browser's text. Author metadata is redacted by the shared view.
        record = cast(dict[str, object], owner._strict_json_loads_v3(source.record_bytes))
        preview = without_provenance(
            GuardPolicyDocument.from_mapping(cast(dict[str, object], record["source_document"]))
        )
        return {
            "state": state,
            "candidateDigest": source.source_digest,
            "policy": preview.to_mapping(),
            "provenanceRedacted": True,
            "requestRecovered": recovered,
        }
