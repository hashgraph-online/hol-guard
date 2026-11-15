"""Authenticated-by-origin file proofs for Guard-managed harness installs.

The native ``harness_adapter`` kind digests the files a manifest names and
checks them again later; this module only carries the manifest across.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from .adapters.base import HarnessContext

MANAGED_INSTALL_PROOF_SCHEMA = "guard.managed-install-proof.v1"


def _wire(manifest: Mapping[str, object]) -> object:
    return json.loads(json.dumps(dict(manifest), default=lambda _: None))


def bind_managed_install_proof(
    manifest: Mapping[str, object],
    context: HarnessContext,
) -> dict[str, object]:
    from .adapters.native_harness import ask

    proof = ask("proof_bind", context, manifest=_wire(manifest)).get("proof")
    if not isinstance(proof, str):
        raise ValueError("Managed install proof answer is malformed")
    return {**manifest, "protection_artifact_proof": json.loads(proof)}


def verify_managed_install_proof(
    manifest: object,
    context: HarnessContext,
) -> bool | None:
    if not isinstance(manifest, Mapping):
        return None
    from .adapters.native_harness import ask

    verified = ask("proof_verify", context, manifest=_wire(manifest)).get("verified")
    return verified if isinstance(verified, bool) else None


__all__ = (
    "MANAGED_INSTALL_PROOF_SCHEMA",
    "bind_managed_install_proof",
    "verify_managed_install_proof",
)
