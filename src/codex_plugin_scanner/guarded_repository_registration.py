"""Register sanitized Guarded Repository evidence with the public verifier."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import asdict

from .guarded_repository_evidence import (
    GuardedRepositoryEvidence,
    guarded_repository_evidence_sha256,
)


def _github_oidc_token(*, request_url: str, request_token: str, audience: str) -> str:
    if not request_url.startswith("https://"):
        raise ValueError("GitHub OIDC request URL must use HTTPS")
    separator = "&" if "?" in request_url else "?"
    url = f"{request_url}{separator}{urllib.parse.urlencode({'audience': audience})}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    token = payload.get("value") if isinstance(payload, Mapping) else None
    if not isinstance(token, str) or not token:
        raise ValueError("GitHub OIDC response did not contain a token")
    return token


def register_guarded_repository_evidence(
    *,
    evidence: GuardedRepositoryEvidence,
    attestation_url: str,
    attestation_id: str,
    endpoint: str,
    oidc_request_url: str,
    oidc_request_token: str,
) -> Mapping[str, object]:
    if not endpoint.startswith("https://"):
        raise ValueError("verification endpoint must use HTTPS")
    evidence_digest = guarded_repository_evidence_sha256(evidence)
    oidc_token = _github_oidc_token(
        request_url=oidc_request_url,
        request_token=oidc_request_token,
        audience=f"hol-guard-repository:{evidence_digest}",
    )
    body = json.dumps(
        {
            "evidence": asdict(evidence),
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
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, Mapping):
        raise ValueError("verification endpoint returned an invalid response")
    return result
