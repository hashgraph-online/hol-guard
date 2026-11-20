"""The Codex install flow's Python steps, kept for tests that drive publication one step at a time.

The runtime's ``install`` op plans, publishes and journals the whole install natively; these helpers
ask its individual ops so a test can stop between them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.codex_harness_client import (
    _PUBLISH_TIMEOUT_SECONDS,
    _b64,
    _codex,
    _home_is_current,
    _launch,
    _launch_fields,
    _reply_text,
    codex_paths,
)
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_harness_client import ask
from codex_plugin_scanner.guard.runtime_transition import TransitionFile


def publish_hooks(
    context: HarnessContext, request: Mapping[str, Any], files: Sequence[TransitionFile]
) -> dict[str, Any]:
    """One ``publish_hooks`` request, its journal records replayed."""
    from codex_plugin_scanner.guard.native_transition_files import _replay

    answer = dict(ask("publish_hooks", context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request))
    _replay(answer.get("events"), files, None)
    return answer


def publication_fault(fault: object) -> BaseException:
    """The exception a ``publish_hooks`` fault names."""
    from codex_plugin_scanner.guard.native_transition_files import _exception

    if isinstance(fault, Mapping) and isinstance(fault.get("runtime"), str):
        return RuntimeError(fault["runtime"])
    return _exception(fault)


def legacy_fields(context: HarnessContext) -> dict[str, Any]:
    """What an exact current bridge entry is matched against for legacy re-adoption,
    as the runtime builds it from this launch."""
    legacy = _codex("detect_legacy", context, launch=_launch_fields(context)).get("legacy")
    if not isinstance(legacy, dict):
        raise ValueError("Harness adapter answer is malformed")
    return legacy


def check_sources(
    context: HarnessContext,
    pairs: Sequence[tuple[Path, Path]],
    captured: Mapping[Path, bytes | None] | None = None,
) -> None:
    """Refuse a config or hooks source that is not a readable regular file or
    does not parse strictly; captured bytes are checked as they were captured."""
    fields: dict[str, object] = {"pairs": [[str(config), str(hooks)] for config, hooks in pairs]}
    if captured is not None:
        fields["contents"] = {str(path): _b64(data) for path, data in captured.items()}
    _codex("check_sources", context, **fields)


def ask_install_plan(
    context: HarnessContext, request: dict[str, Any], enroll_home: Path | None, op: str = "install_plan"
) -> dict[str, Any]:
    """One ``install_plan`` (or whole ``install``) answer.

    An enrolling plan may create the hook key, so it runs under the key's
    ordinary writer, as the generation always has. The runtime names the
    failure the answer ends in; this only raises it."""
    from codex_plugin_scanner.guard.codex_hook_file_integrity import check_hook_validation_deadline
    from codex_plugin_scanner.guard.codex_hook_integrity import _ordinary_hook_writer, hook_secret_file
    from codex_plugin_scanner.guard.native_transition_files import _budget, _package_roots, _replay

    request["package_roots"] = _package_roots()
    request["budget"] = _budget()
    check_hook_validation_deadline()
    if enroll_home is None:
        answer = ask(op, context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request)
    else:
        with _ordinary_hook_writer(enroll_home, hook_secret_file(enroll_home), actor="codex.authority-key"):
            answer = ask(op, context, harness="codex", timeout_seconds=_PUBLISH_TIMEOUT_SECONDS, **request)
    if isinstance(answer.get("reply"), Mapping):
        raise RuntimeError(f"{op} did not settle its replies")
    check_hook_validation_deadline()
    _replay(answer.get("events"), None, None)
    raise_publication_error(answer)
    return answer


def raise_publication_error(answer: Mapping[str, object]) -> None:
    """Raise the failure the runtime names in ``raise``, chained to its rollback's when that failed too."""
    raised = answer.get("raise")
    if not isinstance(raised, Mapping):
        return
    cause = raised.get("cause")
    if isinstance(raised.get("runtime"), str):
        raise RuntimeError(raised["runtime"]) from publication_fault(cause)
    failure = publication_fault(raised.get("fault"))
    rollback = raised.get("rollback")
    if rollback is None:
        raise failure
    rollback_error = publication_fault(rollback)
    error = RuntimeError(
        "Codex hook transaction failed and rollback could not be completed: "
        f"{type(rollback_error).__name__}: {rollback_error}"
    )
    add_note = getattr(error, "add_note", None)
    if callable(add_note):
        add_note(f"rollback error: {rollback_error!r}")
    raise error from failure


def install_manifest(
    context: HarnessContext, kind: str, shim_manifest: Mapping[str, object], **fields: object
) -> dict[str, object]:
    paths = codex_paths(context)
    fields.setdefault("hooks_path", str(paths.hooks))
    answer = _codex(
        "manifest",
        context,
        kind=kind,
        shim=json.dumps(shim_manifest),
        config_path=str(paths.config),
        hook_config_path=str(paths.config),
        workspace_explicit=context.workspace_override_explicit,
        **fields,
    )
    return json.loads(_reply_text(answer, "manifest"))


def current_launch(context: HarnessContext) -> dict[str, Any]:
    return _launch(context, home_is_current=_home_is_current(context))
