"""Receipt metadata helpers for package-firewall daemon operations (SCSR181-183)."""

from __future__ import annotations

from pathlib import Path

from .local_supply_chain import audit_receipt_metadata


def _read_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(manager) for manager in value if isinstance(manager, str)]


def _audit_installed_managers(result: dict[str, object]) -> list[str]:
    supply_chain = result.get("supply_chain")
    if not isinstance(supply_chain, dict):
        return []
    protection = supply_chain.get("package_manager_protection")
    if not isinstance(protection, dict):
        return []
    return _read_string_list(protection.get("installed_managers"))


def _resolve_manager_subset(
    managers: tuple[str, ...] | None,
    result: dict[str, object],
    operation: str,
) -> list[str]:
    if managers:
        return [str(manager) for manager in managers if isinstance(manager, str)]
    tested_managers = result.get("tested_managers")
    if isinstance(tested_managers, list):
        return _read_string_list(tested_managers)
    if operation == "audit":
        installed = _audit_installed_managers(result)
        if installed:
            return installed
        package_shims = result.get("package_shims")
        if isinstance(package_shims, dict):
            detected = _read_string_list(package_shims.get("detected_managers"))
            if detected:
                return detected
    installed_managers = result.get("installed_managers")
    if isinstance(installed_managers, list):
        return _read_string_list(installed_managers)
    return []


def _test_intercept_proofs(result: dict[str, object]) -> list[dict[str, object]]:
    manager_results = result.get("manager_results")
    if not isinstance(manager_results, list):
        return []
    proofs: list[dict[str, object]] = []
    for entry in manager_results:
        if not isinstance(entry, dict):
            continue
        manager = entry.get("manager")
        if not isinstance(manager, str):
            continue
        proof: dict[str, object] = {"manager": manager}
        command_hash = entry.get("command_hash")
        if isinstance(command_hash, str) and command_hash:
            proof["command_hash"] = command_hash
        evaluator_source = entry.get("evaluator_source")
        if isinstance(evaluator_source, str) and evaluator_source:
            proof["evaluator_source"] = evaluator_source
        if "evaluator_invoked" in entry:
            proof["evaluator_invoked"] = bool(entry.get("evaluator_invoked"))
        proofs.append(proof)
    return proofs


def package_firewall_receipt_metadata(
    *,
    operation: str,
    result: dict[str, object],
    managers: tuple[str, ...] | None = None,
    workspace_dir: Path | None = None,
) -> dict[str, object]:
    """Build receipt override fields for package-firewall headless operations."""

    manager_subset = _resolve_manager_subset(managers, result, operation)
    if operation == "audit":
        metadata = audit_receipt_metadata(result, workspace_dir=workspace_dir)
        scanner_evidence = metadata.get("scanner_evidence")
        if isinstance(scanner_evidence, dict):
            enriched = dict(scanner_evidence)
            enriched["manager_subset"] = manager_subset
            metadata = {**metadata, "scanner_evidence": enriched}
        return metadata

    scanner_evidence: dict[str, object] = {
        "operation": operation,
        "manager_subset": manager_subset,
    }
    if operation == "test":
        scanner_evidence["intercept_proofs"] = _test_intercept_proofs(result)
        intercept_proved = result.get("intercept_proved")
        if isinstance(intercept_proved, bool):
            scanner_evidence["intercept_proved"] = intercept_proved

    capabilities_summary = f"Package firewall {operation} completed for {len(manager_subset)} manager(s)."
    if operation == "test" and scanner_evidence.get("intercept_proofs"):
        proved_count = sum(
            1
            for proof in scanner_evidence["intercept_proofs"]
            if isinstance(proof, dict) and proof.get("evaluator_invoked") is True
        )
        capabilities_summary = (
            f"Intercept test recorded evaluator proof for {proved_count} of {len(manager_subset)} manager(s)."
        )

    return {
        "capabilities_summary": capabilities_summary,
        "artifact_name": f"Package firewall {operation}",
        "scanner_evidence": scanner_evidence,
    }


__all__ = ["package_firewall_receipt_metadata"]
