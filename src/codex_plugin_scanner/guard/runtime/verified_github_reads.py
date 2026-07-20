"""Credential-free, Guard-owned positive proof for public GitHub reads."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import ssl
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, cast

import certifi

from .effect_contract import (
    ContainmentRequirement,
    DecisionBasis,
    EffectAssessment,
    EffectBlastRadius,
    EffectConfidence,
    EffectEvidenceSource,
    EffectKind,
    EffectReversibility,
    EffectTargetScope,
    ProofRequirement,
    ProofRoute,
)
from .effect_decision import (
    DecisionFactor,
    DecisionFactorSource,
    EffectDecision,
    EffectDecisionRequest,
    FinalDisposition,
    PositiveProof,
    evaluate_effect_decision,
)
from .verified_read_execution import VERIFIED_READ_POLICY_VERSION

VERIFIED_GITHUB_READ_VERSION: Final = "guard.verified-github-read.v1"
VERIFIED_GITHUB_RULE_VERSION: Final = "guard.verified-read.github-public.v1"
_API_ORIGIN: Final = "https://api.github.com"
_MAX_RESPONSE_BYTES: Final = 1_048_576
_MAX_IDENTITY_FILE_BYTES: Final = 4 * 1024 * 1024
_OWNER_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})")
_FIELDS = frozenset({"mergeable", "number", "state"})
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


class _Headers(Protocol):
    def get(self, name: str, default: str | None = None) -> str | None: ...


class _UrlResponse(Protocol):
    status: int
    headers: _Headers

    def geturl(self) -> str: ...

    def read(self, amount: int) -> bytes: ...

    def close(self) -> None: ...


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
    """Read one public pull request without credentials, proxies, or redirects."""

    try:
        raw_timeout = cast(object, timeout_seconds)
        if type(raw_timeout) not in {int, float}:
            return None
        bounded_timeout = float(cast(int | float, raw_timeout))
        if not math.isfinite(bounded_timeout):
            return None
        if not 0 < bounded_timeout <= 30:
            return None
        normalized_fields = _validate_request(owner, repository, pull_number, fields)
        source_digest = _source_digest()
        tls_context, ca_bundle_digest = _tls_context()
        full_name = f"{owner}/{repository}"
        repository_url = f"{_API_ORIGIN}/repos/{owner}/{repository}"
        pull_url = f"{repository_url}/pulls/{pull_number}"
        repository_payload = _public_get_json(
            repository_url,
            timeout_seconds=bounded_timeout,
            tls_context=tls_context,
        )
        if repository_payload.get("private") is not False:
            return None
        observed_name = repository_payload.get("full_name")
        if not isinstance(observed_name, str) or observed_name.casefold() != full_name.casefold():
            return None
        pull_payload = _public_get_json(pull_url, timeout_seconds=bounded_timeout, tls_context=tls_context)
        if pull_payload.get("number") != pull_number or not _pull_belongs_to_repository(pull_payload, full_name):
            return None
        if not _valid_pull_fields(pull_payload):
            return None
        output = {field: pull_payload.get(field) for field in normalized_fields}
        if _source_digest() != source_digest:
            return None
    except (OSError, RuntimeError, TypeError, ValueError, urllib.error.URLError):
        return None
    stdout = json.dumps(output, sort_keys=True, separators=(",", ":")) + "\n"
    proof = _proof(
        owner=owner,
        repository=repository,
        pull_number=pull_number,
        fields=normalized_fields,
        source_digest=source_digest,
        ca_bundle_digest=ca_bundle_digest,
        repository_payload=repository_payload,
        pull_payload=pull_payload,
        stdout=stdout,
    )
    decision = _decision(proof)
    if decision.disposition is not FinalDisposition.SILENT_VERIFIED:
        return None
    return VerifiedGitHubReadResult(stdout, proof, decision)


def _validate_request(
    owner: str,
    repository: str,
    pull_number: int,
    fields: tuple[str, ...],
) -> tuple[str, ...]:
    if _OWNER_REPOSITORY.fullmatch(owner) is None or _OWNER_REPOSITORY.fullmatch(repository) is None:
        raise ValueError("owner and repository must be static GitHub identifiers")
    if type(pull_number) is not int or not 1 <= pull_number <= 2_147_483_647:
        raise ValueError("pull number must be a positive bounded integer")
    raw_fields = cast(object, fields)
    if not isinstance(raw_fields, tuple):
        raise ValueError("fields must be an exact string tuple")
    untyped_fields = cast(tuple[object, ...], raw_fields)
    if not untyped_fields or any(not isinstance(item, str) for item in untyped_fields):
        raise ValueError("fields must be an exact string tuple")
    normalized = tuple(sorted(set(fields)))
    if len(normalized) != len(fields) or not set(normalized) <= _FIELDS:
        raise ValueError("fields must be unique reviewed pull-request fields")
    return normalized


def _public_get_json(
    url: str,
    *,
    timeout_seconds: float,
    tls_context: ssl.SSLContext,
) -> dict[str, object]:
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
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context),
        _RejectRedirects(),
    )
    raw_response = opener.open(request, timeout=timeout_seconds)  # pyright: ignore[reportAny]
    response = cast(_UrlResponse, raw_response)
    try:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("GitHub public read did not return the exact resource")
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > _MAX_RESPONSE_BYTES:
            raise ValueError("GitHub response exceeds the verified-read bound")
        payload = response.read(_MAX_RESPONSE_BYTES + 1)
    finally:
        response.close()
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise ValueError("GitHub response exceeds the verified-read bound")
    decoded = cast(object, json.loads(payload))
    if not isinstance(decoded, dict):
        raise ValueError("GitHub response must be a JSON object")
    return cast(dict[str, object], decoded)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # pyright: ignore[reportImplicitOverride]
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _pull_belongs_to_repository(payload: dict[str, object], full_name: str) -> bool:
    base = payload.get("base")
    if not isinstance(base, dict):
        return False
    repository = cast(dict[str, object], base).get("repo")
    if not isinstance(repository, dict):
        return False
    observed = cast(dict[str, object], repository).get("full_name")
    return isinstance(observed, str) and observed.casefold() == full_name.casefold()


def _valid_pull_fields(payload: dict[str, object]) -> bool:
    number = payload.get("number")
    state = payload.get("state")
    mergeable = payload.get("mergeable")
    return type(number) is int and state in {"open", "closed"} and (type(mergeable) is bool or mergeable is None)


def _proof(
    *,
    owner: str,
    repository: str,
    pull_number: int,
    fields: tuple[str, ...],
    source_digest: str,
    ca_bundle_digest: str,
    repository_payload: dict[str, object],
    pull_payload: dict[str, object],
    stdout: str,
) -> PositiveProof:
    target = _digest(
        {
            "host": "github.com",
            "owner": owner.casefold(),
            "repository": repository.casefold(),
            "pull_number": pull_number,
        }
    )
    material = {
        "schema_version": VERIFIED_GITHUB_READ_VERSION,
        "policy_version": VERIFIED_READ_POLICY_VERSION,
        "rule_version": VERIFIED_GITHUB_RULE_VERSION,
        "operation": "github-public-pull-request-view",
        "target": target,
        "fields": fields,
        "method": "GET",
        "credential_mode": "none",
        "proxy_mode": "disabled",
        "redirect_mode": "rejected",
        "executor_source": source_digest,
        "ca_bundle": ca_bundle_digest,
        "tls_runtime": _digest(ssl.OPENSSL_VERSION),
        "repository_response": _digest(repository_payload),
        "pull_response": _digest(pull_payload),
        "output": _digest(stdout),
        "parser": "structured-github-public-read-v1",
        "io_flow": "public-get/repository-preflight/pull-request-get/stdout-bounded",
        "expected_effects": ["network-read", "remote-state-read"],
    }
    return PositiveProof(ProofRoute.VERIFIED, _digest(material), _REQUIREMENTS)


def _decision(proof: PositiveProof) -> EffectDecision:
    factors = tuple(
        DecisionFactor(
            source=DecisionFactorSource.EFFECT,
            reason_code=f"verified-{kind.value}",
            basis=DecisionBasis("allow", ProofRoute.VERIFIED),
            operation_ref="operation:github-public-pull-request-view",
            producer_ref="executor:verified-github-read-v1",
            evidence_digest=proof.binding_digest,
            assessment=EffectAssessment(
                kind,
                EffectTargetScope.REMOTE_RESOURCE,
                EffectReversibility.REVERSIBLE,
                EffectBlastRadius.SINGLE_RESOURCE,
                EffectEvidenceSource.RUNTIME,
                EffectConfidence.EXACT,
                ContainmentRequirement.NONE,
                _REQUIREMENTS,
            ),
            proof=proof,
        )
        for kind in (EffectKind.NETWORK_READ, EffectKind.REMOTE_STATE_READ)
    )
    return evaluate_effect_decision(EffectDecisionRequest(factors=factors))


def _source_digest() -> str:
    _payload, digest = _bounded_identity_file(Path(__file__))
    return digest


def _tls_context() -> tuple[ssl.SSLContext, str]:
    ca_payload, ca_digest = _bounded_identity_file(Path(certifi.where()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ca_payload.decode("ascii"))
    return context, ca_digest


def _bounded_identity_file(path: Path) -> tuple[bytes, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_IDENTITY_FILE_BYTES:
            raise ValueError("verified-read identity file is not bounded and regular")
        chunks: list[bytes] = []
        consumed = 0
        while chunk := os.read(descriptor, min(1024 * 1024, _MAX_IDENTITY_FILE_BYTES - consumed + 1)):
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > _MAX_IDENTITY_FILE_BYTES:
                raise ValueError("verified-read identity file exceeds its bound")
        payload = b"".join(chunks)
        final = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise ValueError("verified-read identity file changed during read")
        return payload, hashlib.sha256(payload).hexdigest()
    finally:
        os.close(descriptor)


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(payload).to_bytes(8, "big") + payload).hexdigest()


__all__ = (
    "VERIFIED_GITHUB_READ_VERSION",
    "VERIFIED_GITHUB_RULE_VERSION",
    "VerifiedGitHubReadResult",
    "try_read_verified_public_github_pull_request",
)
