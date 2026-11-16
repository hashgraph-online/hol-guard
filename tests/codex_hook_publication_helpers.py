"""Codex hook publication helpers with no runtime caller, for tests.

The runtime's ``install`` op composes the hook generation, its config and
its publication natively; these helpers drive one step at a time so tests
can check each step against disk.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_config import _Wire, dump_toml
from codex_plugin_scanner.guard.codex_hook_integrity import canonical_manifest_bytes, hook_secret_path
from codex_plugin_scanner.guard.codex_hook_manifest import (
    CodexHookManifestSpec,
    PreparedCodexHookPublication,
    check_hook_validation_deadline,
    generation_request,
)
from codex_plugin_scanner.guard.codex_hook_self_binding import install_fields, settle_short_paths, short_path_fields
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction


def prepare_authenticated_hook_publication(
    spec: CodexHookManifestSpec,
    *,
    rendered_config: str,
    previous_manifest: Mapping[str, object] | None = None,
    create_key: bool = False,
) -> PreparedCodexHookPublication:
    """Capture a signed config/manifest generation without enrolling by default.

    The native runtime authenticates the baseline, signs the manifest and
    captures every file; see
    ``rust/crates/guard-runtime/src/transition_files/publication_generation.rs``.
    Enrollment runs under the install owner, which also guards the key."""
    import base64
    import json

    from codex_plugin_scanner.guard.codex_hook_integrity import _ordinary_hook_writer
    from codex_plugin_scanner.guard.native_transition_files import publication
    from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionError, TransitionFile

    request = generation_request(spec, previous_manifest=previous_manifest, create_key=create_key)
    request["rendered_config"] = rendered_config
    check_hook_validation_deadline()
    if create_key:
        with _ordinary_hook_writer(spec.guard_home, hook_secret_path(spec.guard_home), actor="codex.authority-key"):
            answer = publication("generation", spec.guard_home, **request)
    else:
        answer = publication("generation", spec.guard_home, **request)
    changes = answer.get("files") if isinstance(answer, dict) else None
    if not isinstance(changes, list) or len(changes) != 4:
        raise TransitionError("native_transition_invalid")
    # The prior bytes come in a second answer, which keeps each under the
    # resident's response cap; the runtime refuses any that changed since.
    named = [change for change in changes if "before_sha256" in change]
    prior = publication(
        "generation_before",
        spec.guard_home,
        files=[{"path": change["path"], "sha256": change["before_sha256"]} for change in named],
    )
    befores = prior.get("before") if isinstance(prior, dict) else None
    if not isinstance(befores, list) or len(befores) != len(named):
        raise TransitionError("native_transition_invalid")
    for change, before in zip(named, befores, strict=True):
        change["before"] = before
    check_hook_validation_deadline()

    def decoded(value: object) -> bytes | None:
        return None if value is None else base64.b64decode(str(value))

    config_change, manifest_change, authority, receipt_change = (
        TransitionFile(
            Path(change["path"]),
            decoded(change["before"]),
            decoded(change["after"]),
            before_mode=change["before_mode"],
            after_mode=change["after_mode"],
            no_follow=True,
            expected_digest=change.get("expected_digest"),
        )
        for change in changes
    )
    manifest = json.loads(manifest_change.after or b"null")
    if not isinstance(manifest, dict):
        raise TransitionError("native_transition_invalid")
    prepared = PreparedCodexHookPublication(
        manifest, rendered_config, config_change, manifest_change, authority, receipt_change
    )
    RuntimeTransition._compare({"files": [change.payload() for change in prepared.files]}, "before")
    return prepared


def install_config_hooks(
    payload: dict[str, object],
    context: HarnessContext,
    *,
    config_path: Path,
    owned_bindings: Sequence[Mapping[str, object]] = (),
) -> None:
    # Codex hooks are switched on, Guard's earlier handlers go, the managed
    # groups are written, each hook's state follows its handler and the
    # Guard handlers just written are trusted, all in the native runtime.
    # Codex skips a hook it has no trusted hash for, so an install that
    # cannot record trust refuses.
    owned = list(owned_bindings)
    wire = _Wire(payload, owned)
    request: dict[str, object] = {
        "payload": wire.text(payload),
        "tokens": wire.meanings,
        "owned": wire.text(owned),
        "managed": adapter._hook_registration(context).groups,
        "config": str(config_path),
        **adapter._legacy_fields(context),
        **install_fields(adapter._runtime_guard_home(context), None),
        **short_path_fields(),
    }
    answer = settle_short_paths(lambda: adapter._codex("config_hooks", context, **request), request, "config_hooks")
    installed = wire.decode(adapter._reply_text(answer, "payload"))
    payload.clear()
    payload.update(installed)


def write_authenticated_hook_config(
    context: HarnessContext,
    *,
    config_path: Path,
    payload: dict[str, object],
    previous_manifest: dict[str, object] | None,
) -> dict[str, object]:
    from codex_plugin_scanner.guard.runtime_transition import assert_transition_mutation_allowed

    with codex_install_transaction(context.guard_home, config_path, actor="publish"):
        assert_transition_mutation_allowed(context.guard_home)
        return write_authenticated_hook_config_owned(
            context, config_path=config_path, payload=payload, previous_manifest=previous_manifest
        )


def write_authenticated_hook_config_owned(
    context: HarnessContext,
    *,
    config_path: Path,
    payload: dict[str, object] | None,
    previous_manifest: dict[str, object] | None,
) -> dict[str, object]:
    """Commit manifest first, then config, rolling both back on any failure.

    During the short manifest-first window an old config fails closed against
    the new manifest.  Codex never observes a newly registered hook before
    its complete authenticated identity has been durably committed. The runtime's ``publish_hooks`` op prepares
    the record, writes the files, reads the hooks back, verifies them and
    commits, or runs the durable inverse.
    """
    from codex_plugin_scanner.guard.codex_hook_file_integrity import _python_package_roots
    from codex_plugin_scanner.guard.codex_hook_manifest import _spec_payload
    from codex_plugin_scanner.guard.codex_hook_recovery import _owned
    from codex_plugin_scanner.guard.native_transition_files import publication as publication_op
    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    spec = adapter._hook_manifest_spec(context)
    config = os.path.abspath(config_path.expanduser())
    if config_path.resolve(strict=False) != spec.config_path.resolve(strict=False):
        raise RuntimeError("Codex authenticated publication requires its canonical config target.")

    def publish() -> dict[str, Any]:
        # The runtime refuses a pending publication and snapshots the config.
        target = publication_op("target", context.guard_home, config=config)
        if not isinstance(target, dict):
            raise TransitionError("native_transition_invalid")
        before = target.get("before")
        assert payload is not None
        original = None if before is None else base64.b64decode(str(before))
        publication = prepare_authenticated_hook_publication(
            spec,
            rendered_config=dump_toml(payload, original=original),
            previous_manifest=previous_manifest,
            create_key=True,
        )
        files = publication.files
        request.update(
            home=os.path.abspath(context.guard_home),
            config=config,
            operation_id=_owned(context.guard_home),
            original=before,
            original_identity=target.get("identity"),
            key_present=target.get("key_present") is True,
            files=[change.payload() for change in files],
            config_index=files.index(publication.config_change),
            manifest_index=files.index(publication.manifest_change),
            receipt_index=files.index(publication.receipt_change),
            after_manifest=base64.b64encode(canonical_manifest_bytes(publication.manifest) + b"\n").decode(),
        )
        return adapter._publish_hooks(context, request, files)

    request: dict[str, Any] = {
        "spec": _spec_payload(spec),
        "package_roots": [str(root) for root in _python_package_roots()],
        "budget_spent": False,
        **short_path_fields(),
    }
    answer = settle_short_paths(publish, request, "publish_hooks")
    adapter._raise_publication_error(answer)
    state = json.loads(adapter._reply_text(answer, "state"))
    if not isinstance(state, dict):
        raise TransitionError("native_transition_invalid")
    return state
