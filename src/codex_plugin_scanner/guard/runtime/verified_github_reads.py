"""Credential-free, Guard-owned positive proof for public GitHub reads.

The native runtime (`verified-github-read`) checks what may be read, reads
both replies and binds the proof; Python sends the two GET requests through
the managed transport.
"""

from __future__ import annotations

import base64
import math
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final, cast

from ...no_redirect import RejectRedirects
from ..mdm.network import managed_opener, resolved_network_policy
from ..mdm.network_urlopen import ManagedOpener
from ..mdm.runtime_request import runtime_answer
from ..native_verified_read_decision import NativeVerifiedReadDecisionError, github_public_read_decision
from .effect_contract import ProofRequirement, ProofRoute
from .effect_decision import EffectDecision, FinalDisposition, PositiveProof

VERIFIED_GITHUB_READ_VERSION: Final = "guard.verified-github-read.v1"
VERIFIED_GITHUB_RULE_VERSION: Final = "guard.verified-read.github-public.v1"
_FEATURE: Final = "native-verified-github-read-v1"
_COMMAND: Final = "verified-github-read"
_API_ORIGIN: Final = "https://api.github.com"
_MAX_RESPONSE_BYTES: Final = 1_048_576
_REQUIREMENTS: Final = frozenset(
    {
        ProofRequirement.OPERATION_AND_TARGETS,
        ProofRequirement.REMOTE_RESOURCE_IDENTITY,
        ProofRequirement.CONFIGURATION_IDENTITY,
        ProofRequirement.SHELL_DATA_FLOW,
        ProofRequirement.PARSER_CONFIDENCE,
        ProofRequirement.EXPECTED_EFFECTS,
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedGitHubReadResult:
    stdout: str
    proof: PositiveProof
    decision: EffectDecision
    operation_id: str = "github-public-pull-request-view"


def try_read_verified_public_github_pull_request(
    owner: str,
    repository: str,
    pull_number: int,
    *,
    fields: tuple[str, ...] = ("number", "state", "mergeable"),
    timeout_seconds: float = 15.0,
) -> VerifiedGitHubReadResult | None:
    """Read one public pull request without origin credentials or redirects."""

    raw_timeout = cast(object, timeout_seconds)
    if type(raw_timeout) not in {int, float}:
        return None
    bounded_timeout = float(cast(int | float, raw_timeout))
    if not math.isfinite(bounded_timeout) or not 0 < bounded_timeout <= 30:
        return None
    raw_fields = cast(object, fields)
    raw_number = cast(object, pull_number)
    if not isinstance(raw_fields, tuple) or type(raw_number) is not int:
        return None
    try:
        network_policy, managed = resolved_network_policy(None)
        ca_bundle = network_policy.ca_bundle_path
        read: dict[str, object] = {
            "owner": owner,
            "repository": repository,
            "pull_number": pull_number,
            "fields": list(cast(tuple[object, ...], raw_fields)),
            "network_policy": network_policy.to_dict(),
            "ca_bundle_path": None if ca_bundle is None else os.path.abspath(ca_bundle),
            "executor_path": os.path.abspath(__file__),
        }
        plan = _answer({"op": "plan", **read})
        urls = None if plan is None else plan.get("urls")
        identity = None if plan is None else plan.get("identity")
        if not isinstance(identity, str) or not isinstance(urls, list) or len(cast(list[object], urls)) != 2:
            return None
        repository_url, pull_url = cast(list[object], urls)
        if not isinstance(repository_url, str) or not isinstance(pull_url, str):
            return None
        # Without a managed policy the opener keeps its direct-connection fallback.
        opener = managed_opener(network_policy if managed else None, redirect_handler=RejectRedirects())
        repository_body = _public_get(repository_url, timeout_seconds=bounded_timeout, opener=opener)
        pull_body = _public_get(pull_url, timeout_seconds=bounded_timeout, opener=opener)
    except (OSError, RuntimeError, TypeError, ValueError, urllib.error.URLError):
        return None
    composed = _answer(
        {
            "op": "compose",
            **read,
            "identity": identity,
            "tls_runtime": ssl.OPENSSL_VERSION,
            "repository_body": base64.b64encode(repository_body).decode("ascii"),
            "pull_body": base64.b64encode(pull_body).decode("ascii"),
        }
    )
    stdout = None if composed is None else composed.get("stdout")
    binding_digest = None if composed is None else composed.get("binding_digest")
    if not isinstance(stdout, str) or not isinstance(binding_digest, str):
        return None
    proof = PositiveProof(ProofRoute.VERIFIED, binding_digest, _REQUIREMENTS)
    try:
        # Both effect factors and the operation are fixed by the executor that
        # produced the proof, so only the binding digest crosses.
        decision = github_public_read_decision(binding_digest=binding_digest)
    except NativeVerifiedReadDecisionError:
        return None
    if decision.disposition is not FinalDisposition.SILENT_VERIFIED:
        return None
    return VerifiedGitHubReadResult(stdout, proof, decision)


def _answer(request: dict[str, object]) -> dict[str, object] | None:
    return runtime_answer(_FEATURE, _COMMAND, request, output_limit=64 * 1024, timeout_seconds=10.0)


def _public_get(url: str, *, timeout_seconds: float, opener: ManagedOpener) -> bytes:
    """The reply body, read up to one byte past the limit."""

    if not url.startswith(f"{_API_ORIGIN}/") or "?" in url or "#" in url:
        raise ValueError("GitHub URL must use the exact public API origin")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "hol-guard-verified-read",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    response = opener.open(request, timeout=timeout_seconds)
    try:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("GitHub public read did not return the exact resource")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > _MAX_RESPONSE_BYTES:
            raise ValueError("GitHub response exceeds the verified-read bound")
        return response.read(_MAX_RESPONSE_BYTES + 1)
    finally:
        response.close()


__all__ = (
    "VERIFIED_GITHUB_READ_VERSION",
    "VERIFIED_GITHUB_RULE_VERSION",
    "VerifiedGitHubReadResult",
    "try_read_verified_public_github_pull_request",
)
