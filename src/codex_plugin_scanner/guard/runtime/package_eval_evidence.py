"""Package evaluation evidence and source identity."""

from __future__ import annotations


def _persist_evidence(
    *, store: _eval.GuardStore, artifact: _eval.GuardArtifact, evaluation: _eval.PackageRequestEvaluation, now: str
) -> None:
    if evaluation.decision == "allow":
        return
    if evaluation.decision == "monitor" and not evaluation.record_monitor_evidence:
        return
    packages = tuple(
        package for package in evaluation.packages if _eval._should_record_package(package, evaluation.decision)
    )
    if not packages:
        return
    store.add_evidence_batch(
        _eval.EvidenceRecord(
            evidence_id=_eval._evidence_id(evaluation.package_intent_hash, package),
            action_id=artifact.artifact_id,
            request_id=evaluation.package_intent_hash,
            harness=artifact.harness,
            workspace=artifact.source_scope,
            signal_id=str(package.get("decision") or evaluation.decision),
            category="supply-chain",
            severity=_eval._reason_severity(package),
            confidence=1.0 if evaluation.decision in {"block", "ask"} else 0.6,
            summary=evaluation.risk_summary,
            details={
                "agent_app": _eval._optional_string(artifact.metadata.get("agent_app")) or artifact.harness,
                "command_shape": _eval._optional_string(artifact.metadata.get("redacted_command")),
                "decision": evaluation.decision,
                "enforcement": evaluation.enforcement,
                "exception_id": evaluation.exception_id,
                "harness": artifact.harness,
                "matched_rule_id": evaluation.matched_rule_id,
                "package": package,
                "package_manager": _eval._optional_string(artifact.metadata.get("package_manager")),
                "repo_fingerprint": evaluation.workspace_fingerprint,
                "reasons": package.get("reasons", []),
                "workspace_fingerprint": evaluation.workspace_fingerprint,
            },
            action_identity=evaluation.exception_id or evaluation.matched_rule_id,
            created_at=now,
        )
        for package in packages
    )


def _workspace_fingerprint(
    workspace_id: str,
    *,
    workspace_dir: _eval.Path | None,
    artifact: _eval.GuardArtifact,
    bundle_meta: dict[str, str] | None,
) -> str:
    manifest_hashes = _eval._hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    lockfile_hashes = _eval._hash_paths(workspace_dir, artifact.metadata.get("lockfile_paths"))
    return _eval._stable_hash(
        {
            "workspace_id": workspace_id,
            "workspace_name": workspace_dir.name if workspace_dir is not None else None,
            "manifest_hashes": manifest_hashes,
            "lockfile_hashes": lockfile_hashes,
            "lockfile_parser_version": _eval.LOCKFILE_PARSER_VERSION,
            "bundle_policy_hash": bundle_meta["policy_hash"] if bundle_meta is not None else None,
        }
    )


def _build_request_payload(
    *,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: _eval.Path | None,
    workspace_fingerprint: str,
    policy_version: str,
) -> dict[str, object]:
    lockfile_context = _eval._lockfile_context(workspace_dir, artifact)
    payload: dict[str, object] = {
        "commandShape": {
            "argCount": len(str(artifact.metadata.get("redacted_command") or "").split()),
            "flags": list(_eval._string_tuple(artifact.metadata.get("flags"))),
            "packageManager": str(artifact.metadata.get("package_manager") or "unknown"),
            "redacted": True,
            "verb": str(artifact.metadata.get("intent_kind") or "install"),
        },
        "harness": artifact.harness,
        "packages": [
            {
                "direct": True,
                "ecosystem": str(target["ecosystem"]),
                "name": str(target["name"]),
                "namespace": target["namespace"],
                **(
                    {"sourceUrl": str(target.get("source_redacted") or target["source_url"])}
                    if target.get("source_url")
                    else {}
                ),
                **({"sourceIdentity": str(target["source_identity"])} if target.get("source_identity") else {}),
                **({"version": str(target["version"])} if target.get("version") else {}),
                **({"range": str(target["range"])} if target.get("range") else {}),
            }
            for target in targets
        ],
        "policyVersion": policy_version,
        "workspaceFingerprint": workspace_fingerprint,
    }
    if lockfile_context is not None:
        # Guard Cloud zod schemas use .optional() (undefined), not .nullable().
        # Explicit nulls (common when a lockfile exists without a package.json) make
        # evaluate return HTTP 400 and fail-closed block paid/connected installs.
        payload["lockfileContext"] = {
            key: value
            for key in ("dependencyCount", "fileName", "lockfileHash", "manifestHash", "repository")
            if (value := lockfile_context.get(key)) is not None
        }
    return payload


def _hash_paths(workspace_dir: _eval.Path | None, raw_paths: object) -> list[str]:
    if workspace_dir is None or not isinstance(raw_paths, list):
        return []
    hashes: list[str] = []
    for item in raw_paths:
        payload = _eval.read_bytes_within_workspace(workspace_dir, str(item))
        if payload is None:
            continue
        hashes.append(_eval.stable_digest_hex(payload))
    return hashes


def _stable_hash(value: object) -> str:
    return _eval.stable_digest_hex(_eval.json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _evidence_id(package_intent_hash: str, package: dict[str, object]) -> str:
    decision = str(package.get("decision") or "monitor")
    dependency_path = _eval._optional_string(package.get("dependencyPath")) or "direct"
    identity_payload = {
        "decision": decision,
        "dependency_path": dependency_path,
        "package_identity": _eval._result_package_identity(package),
        "package_intent_hash": package_intent_hash,
    }
    encoded = _eval.json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"evidence-{_eval.stable_digest_hex(encoded, length=16)}"


def _result_package_identity(package: dict[str, object]) -> tuple[str, str, str, str, str, str]:
    ecosystem = _eval._optional_string(package.get("ecosystem"))
    name = _eval._optional_string(package.get("name")) or "package"
    namespace = _eval._optional_string(package.get("namespace"))
    version = _eval._optional_string(package.get("resolvedVersion")) or _eval._optional_string(
        package.get("requestedVersion")
    )
    if ecosystem is not None:
        try:
            identity = _eval.canonical_package_identity(
                ecosystem=ecosystem,
                namespace=namespace,
                name=name,
                version=version or "*",
            )
            return (
                "canonical",
                identity.ecosystem,
                identity.namespace or "",
                identity.name,
                identity.version,
                "",
            )
        except _eval.PackageIdentityError:
            pass
    opaque_sha256 = _eval.stable_digest_hex(
        _eval.json.dumps(package, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    )
    return ("opaque", ecosystem or "", namespace or "", name, version or "", opaque_sha256)


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
