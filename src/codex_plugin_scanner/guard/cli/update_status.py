"""Read-only installed update status and trusted distribution reporting."""

from __future__ import annotations

from pathlib import Path

from ..mdm.contracts import ManagedPolicy
from .update_subprocess import InstalledDistribution, TrustedUpdateContext


def _current_version_from_subprocess(update_context: TrustedUpdateContext) -> str:
    """Return the validated post-install version from one trusted probe."""

    return _update.verify_installed_distribution(update_context)


def _trusted_update_public_payload(context: TrustedUpdateContext) -> dict[str, object]:
    return {
        "python": str(context.python.canonical_path),
        "python_sha256": context.python.sha256,
        "installer": str(context.installer.canonical_path) if context.installer is not None else "python-module-pip",
        "installer_sha256": context.installer.sha256 if context.installer is not None else context.python.sha256,
        "installer_interpreters": [
            {"path": str(identity.canonical_path), "sha256": identity.sha256}
            for identity in context.installer_interpreters
        ],
        "source": context.source.public_name,
        "source_fingerprint": context.source.fingerprint,
        "cwd": str(context.neutral_cwd),
        "environment_mode": "minimal",
    }


def build_guard_update_status_payload(*, guard_home: Path | None = None) -> dict[str, object]:
    resolved_guard_home = guard_home or _update.resolve_guard_home()
    update_channel = _update.load_guard_config(resolved_guard_home).update_channel
    include_alpha = update_channel == "alpha"
    install_surface = _update.build_guard_install_surface_payload()
    installer = str(install_surface.get("installer") or "")
    binary_diagnostics = install_surface.get("binary_diagnostics")
    if not isinstance(binary_diagnostics, dict):
        binary_diagnostics = {}
    managed_state = _update.load_managed_policy()
    managed_policy = managed_state.policy
    source_kind = (
        "managed_index" if managed_policy is not None and managed_policy.update.index_url is not None else "pypi"
    )
    auto_updatable = True
    blocked_reason: str | None = None
    trusted_failure_reason: str | None = None
    recovery_reinstall_available = False
    installed_distribution = (
        _update.InstalledDistribution(
            name="hol-guard",
            version=_update._current_version(),
            root=_update.Path(_update.sys.executable).resolve().parent,
        )
        if installer == "desktop"
        else None
    )

    if managed_state.status != "absent" and managed_policy is None:
        auto_updatable = False
        blocked_reason = "The managed update policy is unavailable or invalid."
    elif managed_policy is not None and managed_policy.update.owner == "mdm":
        auto_updatable = False
        blocked_reason = "HOL Guard updates are managed by the organization."
    elif (
        managed_policy is not None
        and not managed_policy.network.allow_public_registries
        and managed_policy.update.index_url is None
    ):
        auto_updatable = False
        blocked_reason = "An organization-configured package source is required."
    elif installer == "desktop":
        desktop_version = (
            installed_distribution.version if installed_distribution is not None else _update._current_version()
        )
        include_alpha, auto_updatable, blocked_reason = _update.desktop_update_status_state(
            current_version=desktop_version,
            requested_alpha=include_alpha,
        )
    else:
        try:
            installed_distribution = _update._status_installed_distribution(
                installer=installer,
                managed_policy=managed_policy,
                guard_home=resolved_guard_home,
            )
        except _update.UpdateSubprocessError as error:
            auto_updatable = False
            trusted_failure_reason = error.reason_code
            blocked_reason = "The trusted update environment could not be verified."

    # Verification failures block updates, but they must not erase display
    # metadata for the package that is already running.
    current_version = (
        installed_distribution.version if installed_distribution is not None else _update._current_version()
    )
    direct_url = installed_distribution.direct_url if installed_distribution is not None else None
    local_source_install = _update._local_source_install_payload(direct_url)
    local_archive_install = _update._recover_local_archive_install(
        _update._local_archive_install_payload(direct_url),
        direct_url=direct_url,
        guard_home=resolved_guard_home,
        installed_version=current_version,
    )
    version_check = (
        _update._version_check_payload(
            current_version,
            source_kind=source_kind,
            network_policy=(managed_policy.network if managed_policy is not None else _update.ManagedNetworkPolicy()),
            include_alpha=include_alpha,
        )
        if installed_distribution is not None
        else {
            "source": source_kind,
            "status": "unavailable",
            "current_version": current_version if current_version != "unknown" else None,
            "latest_version": None,
            "update_available": None,
        }
    )

    if installer != "desktop" and auto_updatable and _update._python_runtime_blocks_update(version_check):
        auto_updatable = False
        blocked_reason = _update._python_runtime_block_message(version_check)
    elif auto_updatable and isinstance(direct_url, dict):
        if bool(_update._read_direct_url_dir_info(direct_url).get("editable")):
            auto_updatable = False
            blocked_reason = (
                "This install was set up from local source code. Re-run your usual local install command instead."
            )
        elif local_archive_install is not None and str(local_archive_install.get("archive_type") or "") == "wheel":
            auto_updatable = False
            if bool(local_archive_install.get("path_exists")):
                blocked_reason = (
                    "This install was set up from a local wheel. "
                    "Re-run `hol-guard update --wheel <wheel-or-directory>` "
                    "or your usual local install command instead."
                )
            else:
                blocked_reason = (
                    "This install was set up from a local wheel whose source file is no longer available. "
                    "Pass a new wheel with `hol-guard update --wheel <wheel-or-directory>` "
                    "or re-run your usual local install command instead."
                )
            recovery_reinstall_available = True
        elif local_source_install is not None and bool(local_source_install.get("path_exists")):
            auto_updatable = False
            blocked_reason = (
                "This install was set up from a local folder. Re-run your usual local install command instead."
            )
            # Recovery can convert this install back to a normal PyPI package.
            recovery_reinstall_available = True

    update_available = auto_updatable and version_check.get("update_available") is True
    latest_version = version_check.get("latest_version")
    recovery_reinstall_command = (
        _update._shell_command(["hol-guard", "update", "--force-pypi-reinstall"])
        if recovery_reinstall_available
        else None
    )
    payload: dict[str, object] = {
        "current_version": current_version,
        "latest_version": latest_version if isinstance(latest_version, str) else None,
        "installer": installer,
        "binary_diagnostics": binary_diagnostics,
        "version_check": version_check,
        "auto_updatable": auto_updatable,
        "update_available": update_available,
        "blocked_reason": blocked_reason,
        "python_update_required": (
            False if installer == "desktop" else _update._python_runtime_blocks_update(version_check)
        ),
        "recovery_reinstall_available": recovery_reinstall_available,
        "recovery_reinstall_command": recovery_reinstall_command,
        "release_channel": "alpha" if include_alpha else update_channel,
    }
    if trusted_failure_reason is not None:
        payload["reason_code"] = trusted_failure_reason
    return _update.finalize_desktop_update_status(payload, pypi_payload=_update._last_pypi_payload)


def _status_installed_distribution(
    *,
    installer: str,
    managed_policy: ManagedPolicy | None,
    guard_home: Path,
) -> InstalledDistribution:
    network = managed_policy.network if managed_policy is not None else _update.ManagedNetworkPolicy()
    index_url = managed_policy.update.index_url if managed_policy is not None else None
    context = _update.build_trusted_update_context(
        guard_home=guard_home,
        workspace_dir=None,
        installer_kind=installer,
        source_url=index_url,
        source_kind="managed_index" if index_url is not None else "pypi",
        proxy_mode=network.proxy_mode,
        proxy_url=network.proxy_url,
        ca_bundle_path=network.ca_bundle_path,
    )
    return context.query_distribution()


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
