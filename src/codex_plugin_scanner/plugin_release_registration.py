"""Send HOL Plugin Release evidence to HOL, authenticated by GitHub OIDC."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import Mapping

from .guarded_repository_registration import HOL_REGISTRATION_USER_AGENT, _github_oidc_token

DEFAULT_ENDPOINT = "https://hol.org/api/guard/plugins/releases/attestations"


def oidc_audience(evidence_sha256: str) -> str:
    """Binds the OIDC token to this exact evidence, so it cannot be replayed for other evidence."""

    return f"hol-plugin-release:{evidence_sha256}"


def register_plugin_release_evidence(
    *,
    evidence_json: str,
    attestation_url: str,
    attestation_id: str,
    endpoint: str,
    oidc_request_url: str,
    oidc_request_token: str,
) -> Mapping[str, object]:
    if not endpoint.startswith("https://"):
        raise ValueError("release endpoint must use HTTPS")
    # The digest covers the exact attested file, so HOL can recompute it from the posted evidence.
    evidence_digest = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    oidc_token = _github_oidc_token(
        request_url=oidc_request_url,
        request_token=oidc_request_token,
        audience=oidc_audience(evidence_digest),
    )
    body = json.dumps(
        {
            "evidence": json.loads(evidence_json),
            "evidenceSha256": evidence_digest,
            "attestationUrl": attestation_url,
            "attestationId": attestation_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        method="POST",
        data=body,
        headers={
            "Authorization": f"Bearer {oidc_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": HOL_REGISTRATION_USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, Mapping):
        raise ValueError("release endpoint returned an invalid response")
    return result
