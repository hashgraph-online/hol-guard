"""Install, uninstall and plan preparation for one harness, run by the native runtime.

``install`` and ``uninstall`` run whole in the runtime, which publishes the launcher and the plan and journals every
write under the owner the caller names. The caller passes the owner fields it already holds (``owner_request`` in the
command layer), so this module never reaches into the install transaction.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .harness_context import HarnessContext, PreparedHarnessInstall
from .native_harness_client import _description, _surface, _text, canonical_harness, owned_ask, run_op
from .native_harness_ops import delegated_targets, launcher_name_of
from .native_harness_steps import planned_files


def _redirected(context: HarnessContext) -> bool:
    """Whether the runtime finds a link redirecting the Guard home."""
    from .native_harness_client import ask

    return ask("guard_home_redirected", context)["redirected"] is True


def preflight_management(harness: str, context: HarnessContext, *, operation: str) -> None:
    """Reject invalid targets without writes; a mutation rechecks them under ownership."""
    name = canonical_harness(harness)
    if operation == "install" and _description(name).get("install") == "delegated":
        delegated_targets(name, context)


def _shim_names(harness: str) -> dict[str, Any]:
    spec = _description(harness)

    return {"launcher_name": launcher_name_of(harness) or None, "display_name": spec.get("display_name")}


def prepare_install(harness: str, context: HarnessContext, *, surface: str | None = None) -> PreparedHarnessInstall:
    """The complete install plan for ``harness``, planned without publication."""
    from .runtime_transition import TransitionError
    from .shims import prepare_guard_shim

    name = canonical_harness(harness)
    if name == "codex":
        from .native_codex_ops import codex_prepare_install

        return codex_prepare_install(context)
    spec = _description(name)
    mode = spec.get("install")
    if mode == "delegated" or spec.get("prepare") == "unavailable":
        raise TransitionError("adapter_preparation_unavailable")
    if spec.get("prepare") == "detected":
        from .native_harness_steps import prepared_from_detection

        return prepared_from_detection(name, context, create_key=False)
    if spec.get("prepare") == "surfaces":
        from .native_harness_steps import prepared_surfaces

        return prepared_surfaces(name, context, **_surface(surface))
    shim = prepare_guard_shim(name, context, **_shim_names(name))
    if mode == "shim":
        manifest = {"harness": name, "active": True, "config_path": shim.manifest["shim_path"]}
        return PreparedHarnessInstall(shim.files, {**manifest, **shim.manifest})
    fields: dict[str, object] = {"shim": json.dumps(shim.manifest)}
    if spec.get("hook") is not None:
        from .native_harness_ops import hook_argv

        fields["hook_argv"] = hook_argv(name, context)
    answer = run_op(name, "prepare_install", context, **fields)
    files = planned_files(answer)
    return PreparedHarnessInstall((*shim.files, *files), json.loads(_text(answer, "manifest")))


def _mutation(
    harness: str,
    op: str,
    context: HarnessContext,
    *,
    owner: Mapping[str, object],
    timeout_seconds: float,
    **options: object,
) -> dict[str, object]:
    """Prepare, publish and journal the install or uninstall in one native call under ``owner``."""
    from .native_install_facts import adapter_manifest, install_facts
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(context.guard_home)
    if op == "adapter_install" and _description(harness).get("install") == "delegated" and not _redirected(context):
        # A delegated install records its provider rows; the runtime opens an existing store and never creates one.
        # A redirected Guard home is left for the runtime to refuse before anything is created beneath the link.
        from .cli.native_managed_install import ensure_store

        ensure_store(context)
    preflight_management(harness, context, operation="install" if op == "adapter_install" else "uninstall")
    answer = owned_ask(
        harness,
        _description(harness).get("hook_ownership"),
        op,
        context,
        timeout_seconds=timeout_seconds,
        **owner,
        **install_facts(context, (harness,), uninstall=op == "adapter_uninstall"),
        **options,
    )
    return adapter_manifest(answer)


def install(
    harness: str, context: HarnessContext, *, owner: Mapping[str, object], surface: str | None = None
) -> dict[str, object]:
    """Install ``harness`` whole in the runtime, under the owner the caller names."""
    from .native_transition_files import PUBLISH_TIMEOUT_SECONDS

    name = canonical_harness(harness)
    spec = _description(name)
    providers = len(spec.get("delegates", ())) if spec.get("install") == "delegated" else 0
    return _mutation(
        name,
        "adapter_install",
        context,
        owner=owner,
        timeout_seconds=(spec.get("install_timeout") or PUBLISH_TIMEOUT_SECONDS) * (1 + providers),
        **_surface(surface),
    )


def uninstall(
    harness: str, context: HarnessContext, *, owner: Mapping[str, object], surface: str | None = None
) -> dict[str, object]:
    """Uninstall ``harness`` whole in the runtime, under the owner the caller names."""
    from .native_transition_files import PUBLISH_TIMEOUT_SECONDS

    return _mutation(
        canonical_harness(harness),
        "adapter_uninstall",
        context,
        owner=owner,
        timeout_seconds=PUBLISH_TIMEOUT_SECONDS,
        **_surface(surface),
    )
