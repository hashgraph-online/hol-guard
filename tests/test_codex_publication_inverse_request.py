"""Captured inverse review cannot grant or silently change restoration."""

import hashlib
import json
import time

import pytest

from codex_plugin_scanner.guard.adapters.codex import _hook_manifest_spec, codex_native_hook_state
from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput
from codex_plugin_scanner.guard.cli import codex_authority_repair as command
from codex_plugin_scanner.guard.codex_hook_recovery import hook_publication_pending
from codex_plugin_scanner.guard.codex_hook_repair_request import (
    load_codex_hook_repair_request,
    write_codex_hook_repair_request,
)
from codex_plugin_scanner.guard.codex_install_transaction import codex_install_transaction
from codex_plugin_scanner.guard.codex_publication_inverse_plan import PUBLICATION_INVERSE_ACTION
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.store import GuardStore

from .test_codex_authority_repair_cli import _args
from .test_codex_hook_recovery import installed  # noqa: F401
from .test_codex_publication_inverse_authorization import PASSWORD, inverse  # noqa: F401
from .test_codex_publication_inverse_plan import participant_digests


def capture(context, config, plan, tmp_path):
    directory = tmp_path / "private-review"
    directory.mkdir(mode=0o700)
    path = directory / "request.json"
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION):
        digest = write_codex_hook_repair_request(path, plan, deadline_monotonic=time.monotonic() + 30)
    return path, digest


def test_private_request_roundtrip_preserves_exact_review_and_changes_nothing(inverse, tmp_path):  # noqa: F811
    context, config, manifest, _, plan = inverse
    before = participant_digests(context, config, manifest)
    path, digest = capture(context, config, plan, tmp_path)
    with codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION):
        loaded = load_codex_hook_repair_request(
            path,
            guard_home=context.guard_home,
            config_path=config,
            expected_sha256=digest,
            deadline_monotonic=time.monotonic() + 30,
            inverse_spec=_hook_manifest_spec(context),
        )
    assert loaded.payload() == plan.payload()
    assert loaded.subject() == plan.subject()
    assert path.stat().st_mode & 0o777 == 0o600
    assert participant_digests(context, config, manifest) == before
    assert set(json.loads(path.read_bytes())) == {
        "schema",
        "guard_home",
        "config_path",
        "installation_id",
        "created_monotonic",
        "expires_monotonic",
        "plan",
        "subject",
        "authentication",
    }


@pytest.mark.parametrize("change", ["schema", "digest", "config", "same-byte-config"])
def test_request_refusal_precedes_approval_and_publication(inverse, tmp_path, monkeypatch, change):  # noqa: F811
    context, config, manifest, _, plan = inverse
    path, digest = capture(context, config, plan, tmp_path)
    if change == "schema":
        value = json.loads(path.read_bytes())
        value["schema"] = "hol-guard.codex-authority-repair-request.v1"
        path.write_text(json.dumps(value))
    elif change == "digest":
        digest = "0" * 64
    elif change == "config":
        config.write_bytes(config.read_bytes() + b"\n# changed after review\n")
    else:
        substitute = config.with_name("same-byte-substitution")
        substitute.write_bytes(config.read_bytes())
        substitute.chmod(0o600)
        substitute.replace(config)
    before = participant_digests(context, config, manifest)

    def forbidden(**kwargs):
        raise AssertionError("stale captured plan reached factor collection")

    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", forbidden)
    code, result = command.run_codex_authority_repair(
        _args("--authority-request", str(path), "--authority-request-sha256", digest),
        context,
        GuardStore(context.guard_home),
        None,
    )
    assert code == 2 and result["status"] == "recovery-required" and result["verified"] is False
    assert participant_digests(context, config, manifest) == before


def test_inverse_request_cannot_be_loaded_as_missing_authority_repair(inverse, tmp_path):  # noqa: F811
    context, config, _, _, plan = inverse
    path, digest = capture(context, config, plan, tmp_path)
    with pytest.raises(TransitionError, match="authority_repair_request_context_invalid"):
        load_codex_hook_repair_request(
            path,
            guard_home=context.guard_home,
            config_path=config,
            expected_sha256=digest,
            deadline_monotonic=time.monotonic() + 30,
        )


@pytest.mark.parametrize("change", ["target", "predecessor", "expired", "purpose"])
def test_mac_valid_request_cannot_change_live_inverse_or_replay_expired_review(inverse, tmp_path, change):  # noqa: F811
    from codex_plugin_scanner.guard.codex_hook_integrity import canonical_manifest_bytes, load_hook_secret
    from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload

    context, config, manifest, _, plan = inverse
    path, _ = capture(context, config, plan, tmp_path)
    value = json.loads(path.read_bytes())
    value.pop("authentication")
    if change == "target":
        value["plan"]["files"][0]["path"] = str(config.with_name("foreign-config.toml"))
    elif change == "predecessor":
        value["plan"]["files"][0]["after"] = value["plan"]["files"][1]["after"]
    elif change == "expired":
        value["created_monotonic"] = time.monotonic() - 301
        value["expires_monotonic"] = value["created_monotonic"] + 300
    value["subject"] = (
        f"codex-publication-inverse:{plan.operation_id}:"
        + hashlib.sha256(canonical_manifest_bytes(value["plan"])).hexdigest()
    )
    secret = load_hook_secret(context.guard_home)
    value["authentication"] = sign_local_authority_payload(
        value,
        key=secret.key,
        key_id=secret.key_id,
        signed_at=plan.operation_id,
        purpose="codex-authority-repair-request" if change == "purpose" else "codex-publication-inverse-request",
    )
    raw = canonical_manifest_bytes(value) + b"\n"
    path.write_bytes(raw)
    before = participant_digests(context, config, manifest)
    with (
        codex_install_transaction(context.guard_home, config, actor=PUBLICATION_INVERSE_ACTION),
        pytest.raises(TransitionError),
    ):
        load_codex_hook_repair_request(
            path,
            guard_home=context.guard_home,
            config_path=config,
            expected_sha256=hashlib.sha256(raw).hexdigest(),
            deadline_monotonic=time.monotonic() + 30,
            inverse_spec=_hook_manifest_spec(context),
        )
    assert participant_digests(context, config, manifest) == before


def test_bare_restore_flag_never_broadens_to_config_inverse(inverse):  # noqa: F811
    context, config, manifest, _, _ = inverse
    before = participant_digests(context, config, manifest)
    code, result = command.run_codex_authority_repair(_args(), context, GuardStore(context.guard_home), None)
    assert code == 2 and result["error"] == "authority_repair_publication_pending"
    assert participant_digests(context, config, manifest) == before


@pytest.mark.usefixtures("native_hook_force")
def test_cli_review_approval_publication_and_real_native_retirement(inverse, tmp_path, monkeypatch):  # noqa: F811
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    from .test_runtime_transition_configured_inverse import OwnedDaemonLifecycle

    context, config, manifest, _, _ = inverse
    identity = native_runtime_status().identity
    assert identity is not None
    directory = tmp_path / "cli-review"
    directory.mkdir(mode=0o700)
    request = directory / "request.json"
    store = GuardStore(context.guard_home)
    before = participant_digests(context, config, manifest)
    monkeypatch.setattr(command, "consume_desktop_lifecycle_env", lambda **kwargs: ApprovalGateInput(password=PASSWORD))
    code, preview = command.run_codex_authority_repair(
        _args("--dry-run", "--authority-request", str(request)),
        context,
        store,
        tmp_path,
    )
    assert code == 0 and preview["repair"] == "codex-publication-inverse"
    assert preview["verified"] is False
    assert participant_digests(context, config, manifest) == before
    daemon = OwnedDaemonLifecycle(context.home_dir, context.guard_home, identity.path)
    verify = command.verify_and_retire_codex_publication_inverse

    def verify_with_owned_daemon(pending, **kwargs):
        store.set_managed_install("codex", True, None, codex_native_hook_state(context), "isolated-cli-inverse")
        daemon.start(pending.authorization.deadline_monotonic)
        proof = verify(pending, **kwargs)
        daemon.stop(pending.authorization.deadline_monotonic)
        return proof

    monkeypatch.setattr(command, "verify_and_retire_codex_publication_inverse", verify_with_owned_daemon)
    try:
        code, result = command.run_codex_authority_repair(
            _args("--authority-request", str(request), "--authority-request-sha256", preview["request_sha256"]),
            context,
            store,
            tmp_path,
        )
        assert code == 0, result
        assert result["verified"] is True and result["recovery_required"] is False
        assert result["operation_id"] == preview["operation_id"]
        assert result["native_runtime_sha256"] == identity.sha256
        assert not hook_publication_pending(context.guard_home)
        assert daemon.retired == daemon.pids and len(daemon.pids) == 1
    finally:
        daemon.cleanup()
