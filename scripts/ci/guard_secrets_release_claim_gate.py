#!/usr/bin/env python3
"""Validate HOL Guard Secrets evidence before any protected publication path."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast


class ClaimGateError(ValueError):
    """Raised when release-gate input cannot be interpreted safely."""


class _CapabilityManifest(Protocol):
    """Runtime shape returned by the directly loaded V2 contract module."""

    required_capability_ids: frozenset[str]
    public_parity_claim_enabled: bool
    row_errors: tuple[str, ...]
    capabilities: Sequence[object]
    public_parity_requires: object


class _CapabilityValidator(Protocol):
    def __call__(
        self,
        capabilities: Sequence[object],
        *,
        required_capability_ids: frozenset[str],
        exact_release_commit: str,
        minimum_state: object,
    ) -> None: ...


_CONTRACTS_PATH = Path(__file__).resolve().parents[2] / "src/codex_plugin_scanner/guard/secrets/contracts_v2.py"
_CONTRACTS_MODULE_NAME = "_hol_guard_secrets_contracts_v2"


def _load_contracts_module() -> ModuleType:
    """Load the dependency-free contract module without importing package initializers."""

    existing = sys.modules.get(_CONTRACTS_MODULE_NAME)
    if isinstance(existing, ModuleType):
        return existing
    spec = importlib.util.spec_from_file_location(
        _CONTRACTS_MODULE_NAME,
        _CONTRACTS_PATH,
    )
    if spec is None or spec.loader is None:
        raise ClaimGateError(f"unable to load Secrets contracts from {_CONTRACTS_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(spec.name, None)
        raise ClaimGateError(f"unable to load Secrets contracts: {error}") from error
    return module


def _symbol(module: ModuleType, name: str) -> object:
    try:
        return getattr(module, name)
    except AttributeError as error:
        raise ClaimGateError(f"Secrets contracts do not export {name}") from error


def _contract_api() -> tuple[
    type[Exception],
    Callable[[str], bool],
    Callable[[Mapping[str, object]], _CapabilityManifest],
    Callable[[Mapping[str, object]], object],
    Callable[[Mapping[str, object]], object],
    Callable[[Mapping[str, object]], object],
    _CapabilityValidator,
]:
    module = _load_contracts_module()
    return (
        cast(type[Exception], _symbol(module, "SecretContractError")),
        cast(Callable[[str], bool], _symbol(module, "is_exact_commit_sha")),
        cast(
            Callable[[Mapping[str, object]], _CapabilityManifest],
            _symbol(module, "parse_capability_evidence_manifest"),
        ),
        cast(
            Callable[[Mapping[str, object]], object],
            _symbol(module, "parse_product_boundaries_manifest"),
        ),
        cast(
            Callable[[Mapping[str, object]], object],
            _symbol(module, "parse_source_capabilities_manifest"),
        ),
        cast(
            Callable[[Mapping[str, object]], object],
            _symbol(module, "parse_reason_codes_manifest"),
        ),
        cast(
            _CapabilityValidator,
            _symbol(module, "validate_capability_manifest"),
        ),
    )


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ClaimGateError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def load_manifest(path: Path) -> Mapping[str, object]:
    """Load a JSON manifest without weakening runtime schema validation."""

    return _mapping(json.loads(path.read_text(encoding="utf-8")), label=str(path))


def validate_manifest(
    capability_payload: Mapping[str, object],
    *,
    product_boundary_payload: Mapping[str, object],
    source_capability_payload: Mapping[str, object],
    reason_code_payload: Mapping[str, object],
    exact_release_commit: str | None,
    require_parity: bool,
    required_capabilities: frozenset[str],
) -> tuple[str, ...]:
    """Validate all authoritative manifests and optional exact parity evidence."""

    (
        secret_contract_error,
        is_exact_commit_sha,
        parse_capability_evidence_manifest,
        parse_product_boundaries_manifest,
        parse_source_capabilities_manifest,
        parse_reason_codes_manifest,
        validate_capability_manifest,
    ) = _contract_api()

    if exact_release_commit is None:
        raise ClaimGateError("release validation requires an exact release commit")
    if not is_exact_commit_sha(exact_release_commit):
        raise ClaimGateError("exact release commit must be a full lowercase SHA")

    try:
        _ = parse_product_boundaries_manifest(product_boundary_payload)
        _ = parse_source_capabilities_manifest(source_capability_payload)
        _ = parse_reason_codes_manifest(reason_code_payload)
        manifest = parse_capability_evidence_manifest(capability_payload)
    except secret_contract_error as error:
        raise ClaimGateError(str(error)) from error

    if required_capabilities != manifest.required_capability_ids:
        missing = sorted(manifest.required_capability_ids - required_capabilities)
        extra = sorted(required_capabilities - manifest.required_capability_ids)
        parts: list[str] = []
        if missing:
            parts.append(f"missing: {', '.join(missing)}")
        if extra:
            parts.append(f"unexpected: {', '.join(extra)}")
        detail = "; ".join(parts) or "mismatch"
        raise ClaimGateError(f"required capability list does not match claim policy ({detail})")

    if require_parity != manifest.public_parity_claim_enabled:
        if manifest.public_parity_claim_enabled:
            raise ClaimGateError("claim policy enables public parity; --require-parity cannot be omitted")
        raise ClaimGateError("claim policy disables public parity; --require-parity is not authorized")

    errors = list(manifest.row_errors)
    if require_parity and not errors:
        try:
            validate_capability_manifest(
                manifest.capabilities,
                required_capability_ids=manifest.required_capability_ids,
                exact_release_commit=exact_release_commit,
                minimum_state=manifest.public_parity_requires,
            )
        except secret_contract_error as error:
            errors.append(str(error))
    return tuple(errors)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--product-boundaries", type=Path, required=True)
    parser.add_argument("--source-capabilities", type=Path, required=True)
    parser.add_argument("--reason-codes", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--require-parity", action="store_true")
    parser.add_argument("--required-capability", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the gate with stable success, validation, and input exit codes."""

    args = _parse_args(argv)
    try:
        errors = validate_manifest(
            load_manifest(args.manifest),
            product_boundary_payload=load_manifest(args.product_boundaries),
            source_capability_payload=load_manifest(args.source_capabilities),
            reason_code_payload=load_manifest(args.reason_codes),
            exact_release_commit=args.release_commit,
            require_parity=args.require_parity,
            required_capabilities=frozenset(args.required_capability),
        )
    except (ClaimGateError, json.JSONDecodeError, OSError) as error:
        print(f"guard-secrets-claim-gate: {error}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"guard-secrets-claim-gate: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
