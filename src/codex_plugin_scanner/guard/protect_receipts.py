"""Install receipt construction and harness attribution through the live Protect facade."""

from __future__ import annotations


def _build_install_receipt(request: _protect.ProtectRequest, verdict: _protect.ProtectVerdict) -> _protect.GuardReceipt:
    primary_target = request.targets[0]
    artifact_hash = _protect._command_fingerprint(list(request.command))
    capabilities_summary = f"{request.executor} {request.install_kind.replace('_', ' ')}"
    provenance_summary = _protect.shlex.join(request.command)
    changed_capabilities = list(verdict.risk_signals)
    sample = ", ".join(changed_capabilities[:3])
    suffix = " ..." if len(changed_capabilities) > 3 else ""
    diff_summary = f"{len(changed_capabilities)} change(s): {sample}{suffix}" if changed_capabilities else None
    receipt_harness = request.harness
    if receipt_harness is None:
        if _protect._is_package_tool_request(request):
            # Unsupported package subcommands (for example `bun run`) bypass
            # the structured package projection. Keep their receipt aligned
            # with the package path's shared runtime-origin resolver.
            from .runtime.package_protect_projection import resolve_local_supply_chain_harness

            receipt_harness = resolve_local_supply_chain_harness()
        else:
            receipt_harness = request.executor
    return _protect.GuardReceipt(
        receipt_id=f"guard-receipt-{_protect.uuid4()}",
        timestamp=_protect.datetime.now(_protect.timezone.utc).isoformat(),
        harness=receipt_harness,
        artifact_id=primary_target.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=verdict.action,
        capabilities_summary=capabilities_summary,
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        artifact_name=primary_target.artifact_name,
        source_scope="install",
        diff_summary=diff_summary,
    )


def _is_package_tool_request(request: _protect.ProtectRequest) -> bool:
    if request.package_manager is not None:
        return True
    from .shims import package_shim_supported_managers

    return request.executor.strip().lower() in package_shim_supported_managers()


def _command_fingerprint(command: list[str]) -> str:
    payload = "\u0000".join(command).encode("utf-8")
    return _protect.hashlib.sha256(payload).hexdigest()


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import protect as _protect  # noqa: E402
