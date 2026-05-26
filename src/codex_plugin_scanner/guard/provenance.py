"""Supply chain provenance, attestation, SLSA, registry identity, and source policy.

Implements SCRG146-158: npm provenance fetcher, PyPI attestation, Sigstore bundle
verification, SLSA provenance fields, repository binding policy, registry identity
pinning, dist integrity checks, HTTP source policy, and git source immutability.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request
from typing import Any

_HARD_RISK_CODES = frozenset(
    {
        "known_malware",
        "kev_exploited",
        "malware_confirmed",
        "security_hold",
        "osv_critical_active",
        "license_violation_hard",
    }
)

_OFFICIAL_REGISTRIES: dict[str, set[str]] = {
    "npm": {"https://registry.npmjs.org", "https://registry.yarnpkg.com"},
    "pypi": {"https://pypi.org", "https://files.pythonhosted.org"},
    "cargo": {"https://crates.io", "https://static.crates.io"},
    "rubygems": {"https://rubygems.org"},
    "maven": {"https://repo1.maven.org", "https://repo.maven.apache.org"},
    "go": {"https://proxy.golang.org", "https://goproxy.io"},
}

REGISTRY_IDENTITY_POLICY_ADR = """
ADR-SCRG152: Registry Identity and Pinning Policy

Status: Accepted

Context:
Package managers can be configured to pull from arbitrary registries. A compromised
or malicious registry can serve tampered packages even with matching names and versions.

Decision:
1. Each ecosystem has a set of official/trusted registries (see _OFFICIAL_REGISTRIES).
2. Any registry not in the trusted set produces an 'allowed: False' result with a
   non-empty reason and a recommendation to pin or explicitly allow-list the registry.
3. Workspace policy may extend the trusted set via allowed_registries config.
4. A registry fingerprint (SHA-256 of the registry base URL) is stored alongside
   package install receipts to enable drift detection.
5. Registry pinning is enforced at the point of source URL resolution, before download.

Consequences:
- Packages resolved from unofficial registries will produce warnings or blocks
  depending on workspace risk tolerance settings.
- Private registries must be explicitly listed in workspace config to avoid false
  positives in enterprise environments.
"""


def _fetch_npm_attestations(package: str, version: str) -> dict[str, Any]:
    """Fetch npm attestation data from the official npm registry API."""
    encoded = urllib.request.quote(f"{package}/-/{package}-{version}.tgz", safe="@/")
    url = f"https://registry.npmjs.org/-/npm/v1/attestations/{encoded}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _fetch_pypi_attestations(package: str, version: str) -> dict[str, Any]:
    """Fetch PyPI attestation data from the PyPI API."""
    url = f"https://pypi.org/integrity/{package}/{version}/attestations.json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def fetch_npm_provenance(package: str, version: str) -> dict[str, Any]:
    """Fetch and summarise npm provenance attestation for *package* at *version*.

    Returns a dict with at least:
    - ``status``: 'attested' | 'verified' | 'unverified' | 'missing' | 'error'
    - ``attestations``: list of raw attestation dicts (empty when missing/error)
    - ``error``: error string when status='error'
    """
    try:
        data = _fetch_npm_attestations(package, version)
    except Exception as exc:
        return {"status": "error", "attestations": [], "error": str(exc)}

    attestations = data.get("attestations", [])
    if not attestations:
        return {"status": "missing", "attestations": []}

    return {"status": "attested", "attestations": attestations, "package": package, "version": version}


def extract_npm_trusted_publisher(attestation: dict[str, Any]) -> dict[str, Any]:
    """Extract OIDC trusted publisher information from a single npm attestation dict.

    Returns a dict with:
    - ``provider``: 'github_actions' | 'unknown'
    - ``source_repository``: URL or None
    - ``ref``: branch/tag ref or None
    - ``run_uri``: CI run URI or None
    """
    predicate = attestation.get("predicate", {})
    run_uri = predicate.get("runInvocationUri") or predicate.get("runUri")
    source_repo = predicate.get("sourceRepositoryUri")
    ref = predicate.get("sourceRepositoryRef")

    if not source_repo and not run_uri:
        return {"provider": "unknown", "source_repository": None, "ref": None, "run_uri": None}

    provider = "unknown"
    if _is_github_host_url(run_uri) or _is_github_host_url(source_repo):
        provider = "github_actions"

    return {
        "provider": provider,
        "source_repository": source_repo,
        "ref": ref,
        "run_uri": run_uri,
    }


def fetch_pypi_attestation(package: str, version: str) -> dict[str, Any]:
    """Fetch and summarise PyPI attestation for *package* at *version*.

    Returns a dict with:
    - ``status``: 'attested' | 'missing' | 'error'
    - ``attestations``: list of attestation dicts
    """
    try:
        data = _fetch_pypi_attestations(package, version)
    except Exception as exc:
        return {"status": "error", "attestations": [], "error": str(exc)}

    attestations = data.get("attestations", [])
    if not attestations:
        return {"status": "missing", "attestations": []}

    return {"status": "attested", "attestations": attestations, "package": package, "version": version}


def verify_sigstore_bundle(bundle: dict[str, Any], *, expected_package_digest: str | None) -> dict[str, Any]:
    """Verify a Sigstore bundle structure without trusted root.

    Performs structural validation only (no network/crypto library calls):
    - Checks bundle mediaType
    - Checks verification material presence
    - Checks message digest matches expected_package_digest when provided

    Returns dict with:
    - ``valid``: bool
    - ``reason``: explanation string
    """
    if not bundle:
        return {"valid": False, "reason": "empty bundle"}

    media_type = bundle.get("mediaType", "")
    if "sigstore" not in media_type and "bundle" not in media_type:
        return {"valid": False, "reason": "unrecognised bundle mediaType"}

    verification_material = bundle.get("verificationMaterial")
    if not verification_material:
        return {"valid": False, "reason": "missing verificationMaterial"}

    if expected_package_digest is not None:
        msg_sig = bundle.get("messageSignature", {})
        actual_digest = msg_sig.get("messageDigest", {}).get("digest")
        if actual_digest and actual_digest != expected_package_digest:
            return {"valid": False, "reason": f"digest mismatch: {actual_digest} != {expected_package_digest}"}

    return {"valid": True, "reason": "structural validation passed"}


def build_slsa_provenance_record(ecosystem: str, attestation: dict[str, Any]) -> dict[str, Any]:
    """Build a SLSA provenance record from an attestation dict.

    Fields:
    - ``builder_id``: CI builder URI or None
    - ``source_repository``: source repo URI or None
    - ``source_ref``: branch/tag ref or None
    - ``source_commit``: commit SHA or None
    - ``build_type``: build type URI or None
    - ``slsa_level``: int 1-3 or None
    - ``ecosystem``: the package ecosystem
    """
    predicate = attestation.get("predicate", {})
    run_uri = predicate.get("runInvocationUri") or predicate.get("runUri")
    source_repo = predicate.get("sourceRepositoryUri")
    source_ref = predicate.get("sourceRepositoryRef")
    source_commit = predicate.get("sourceRepositoryCommit") or predicate.get("sourceCommit")
    build_type = predicate.get("buildType")
    builder_id = predicate.get("builderId") or predicate.get("builderUri") or run_uri

    slsa_level: int | None = None
    if source_repo and run_uri:
        slsa_level = 2 if source_commit and len(source_commit) >= 40 else 1

    return {
        "builder_id": builder_id,
        "source_repository": source_repo,
        "source_ref": source_ref,
        "source_commit": source_commit,
        "build_type": build_type,
        "slsa_level": slsa_level,
        "ecosystem": ecosystem,
    }


def check_repository_binding(
    *,
    actual_source: str | None,
    required_org: str | None,
    required_repo: str | None = None,
) -> dict[str, Any]:
    """Check whether a package's source repository matches workspace binding policy.

    Returns:
    - ``bound``: True if policy is satisfied
    - ``violation``: human-readable reason when bound=False, else None
    """
    if required_org is None and required_repo is None:
        return {"bound": True, "violation": None}

    if not actual_source:
        return {"bound": False, "violation": "no source repository in provenance"}

    if required_repo is not None and required_repo.lower() not in actual_source.lower():
        return {
            "bound": False,
            "violation": f"source {actual_source!r} does not match required repo {required_repo!r}",
        }

    if required_org is not None:
        org_pattern = f"/{required_org}/"
        alt_pattern = f":{required_org}/"
        if org_pattern.lower() not in actual_source.lower() and alt_pattern.lower() not in actual_source.lower():
            return {
                "bound": False,
                "violation": f"source {actual_source!r} does not match required org {required_org!r}",
            }

    return {"bound": True, "violation": None}


def check_registry_identity(ecosystem: str, registry_url: str) -> dict[str, Any]:
    """Check whether *registry_url* is an officially trusted registry for *ecosystem*.

    Returns:
    - ``allowed``: bool
    - ``reason``: explanation when not allowed
    - ``fingerprint``: SHA-256 hex of registry_url
    """
    canonical = registry_url.rstrip("/").lower()
    trusted = _OFFICIAL_REGISTRIES.get(ecosystem, set())
    trusted_lower = {u.rstrip("/").lower() for u in trusted}
    fingerprint = hashlib.sha256(registry_url.encode()).hexdigest()

    if canonical in trusted_lower:
        return {"allowed": True, "reason": None, "fingerprint": fingerprint}

    return {
        "allowed": False,
        "reason": (
            f"registry {registry_url!r} is not in the trusted set for ecosystem {ecosystem!r}. "
            "Add it to workspace.allowed_registries to allow installs from this registry."
        ),
        "fingerprint": fingerprint,
    }


def check_dist_integrity(
    *,
    lockfile_integrity: str | None,
    registry_integrity: str | None,
) -> dict[str, Any]:
    """Compare lockfile integrity hash against registry-provided integrity.

    Returns:
    - ``match``: True if hashes agree
    - ``status``: 'verified' | 'mismatch' | 'unverifiable'
    """
    if registry_integrity is None:
        return {"match": False, "status": "unverifiable", "lockfile_integrity": lockfile_integrity}

    if lockfile_integrity is None:
        return {"match": False, "status": "unverifiable", "registry_integrity": registry_integrity}

    match = lockfile_integrity == registry_integrity
    return {
        "match": match,
        "status": "verified" if match else "mismatch",
        "lockfile_integrity": lockfile_integrity,
        "registry_integrity": registry_integrity,
    }


def check_source_url_security(source_url: str | None) -> dict[str, Any]:
    """Return whether *source_url* uses a secure scheme.

    Returns:
    - ``secure``: bool
    - ``reason``: 'insecure_http' when scheme is http, None otherwise
    """
    if source_url is None:
        return {"secure": True, "reason": None, "url": None}

    url_lower = source_url.strip().lower()
    if url_lower.startswith("http://"):
        return {"secure": False, "reason": "insecure_http", "url": source_url}

    return {"secure": True, "reason": None, "url": source_url}


_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SEMVER_RE = re.compile(r"^v?\d+\.\d+")


def check_git_source_immutability(source_url: str) -> dict[str, Any]:
    """Determine whether a git source URL pins to an immutable commit SHA.

    Returns:
    - ``immutable``: True only when the fragment is a full 40-char hex commit SHA
    - ``reason``: 'mutable_branch' | 'mutable_tag' | 'no_pin' | None
    - ``fragment``: the fragment portion of the URL
    """
    if "#" not in source_url:
        return {"immutable": False, "reason": "no_pin", "fragment": None}

    fragment = source_url.split("#", 1)[1]
    if not fragment:
        return {"immutable": False, "reason": "no_pin", "fragment": fragment}

    if _SHA_RE.match(fragment):
        return {"immutable": True, "reason": None, "fragment": fragment}

    if _SEMVER_RE.match(fragment):
        return {"immutable": False, "reason": "mutable_tag", "fragment": fragment}

    return {"immutable": False, "reason": "mutable_branch", "fragment": fragment}


_PROVENANCE_COPY: dict[str, str] = {
    "verified": "Provenance verified: package build is attested to a trusted CI publisher.",
    "attested": "Provenance attested: package includes a build attestation.",
    "missing": "No provenance available for this package. Cannot verify build origin.",
    "mismatch": "Provenance mismatch: attestation data does not agree with package metadata.",
    "unknown": "Provenance status unknown: unable to retrieve attestation data.",
    "error": "Provenance check failed: could not contact the attestation registry.",
    "unverified": "Provenance unverified: attestation structure present but not fully validated.",
}


def build_provenance_copy(*, status: str, ecosystem: str, package: str) -> str:
    """Return a human-readable string describing the provenance status."""
    base = _PROVENANCE_COPY.get(status, f"Provenance status: {status}.")
    return f"{base} ({ecosystem}/{package})"


def provenance_overrides_hard_risk(
    *,
    decision: str,
    block_reason_code: str,
    provenance_status: str,
) -> bool:
    """Return whether valid provenance can override the given decision/risk code.

    Hard-risk decisions (known_malware, KEV, etc.) are never overridable by provenance.
    Returns False for any hard-risk code regardless of provenance status.
    """
    if block_reason_code in _HARD_RISK_CODES:
        return False
    if decision == "block":
        return False
    return provenance_status in {"verified", "attested"}


def _is_github_host_url(raw_url: str | None) -> bool:
    if not raw_url:
        return False
    parsed = urllib.parse.urlparse(raw_url)
    host = parsed.hostname
    if host is None and raw_url.startswith("git@"):
        host = raw_url.split("@", 1)[1].split(":", 1)[0]
    if host is None:
        return False
    normalized = host.lower().rstrip(".")
    return normalized == "github.com" or normalized.endswith(".github.com")
