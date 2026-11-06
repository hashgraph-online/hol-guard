"""Review artifacts preserve exact plans but convey no forward authority."""

import hashlib
import json
import random
import time

import pytest

from codex_plugin_scanner.guard import codex_hook_repair_request as requests
from codex_plugin_scanner.guard.codex_hook_integrity import canonical_manifest_bytes, load_hook_secret
from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_hook_recovery import installed  # noqa: F401 -- shared fixture
from .test_codex_hook_repair_authorization import prepared_repair  # noqa: F401 -- shared fixture
from .test_codex_hook_repair_native_binding import _prepare, native_binding  # noqa: F401 -- shared fixture
from .test_codex_publication_preparation import _tree


@pytest.fixture
def captured(native_binding, tmp_path):  # noqa: F811
    context, config, manifest, plan, identity, workspace = native_binding
    plan = _prepare(plan, identity, workspace)
    folder = tmp_path / "private-review"
    folder.mkdir(mode=0o700)
    return context, config, manifest, plan, folder / "request.json"


def _write(plan, path):
    return requests.write_codex_hook_repair_request(path, plan, deadline_monotonic=time.monotonic() + 10)


def _load(plan, path, digest):
    return requests.load_codex_hook_repair_request(
        path,
        guard_home=plan.guard_home,
        config_path=plan.config_path,
        expected_sha256=digest,
        deadline_monotonic=time.monotonic() + 10,
    )


def _resign(plan, path, payload, *, purpose="codex-authority-repair-request"):
    payload.pop("authentication", None)
    secret = load_hook_secret(plan.guard_home)
    payload["authentication"] = sign_local_authority_payload(
        payload,
        key=secret.key,
        key_id=secret.key_id,
        purpose=purpose,
        signed_at=plan.operation_id,
    )
    raw = canonical_manifest_bytes(payload) + b"\n"
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_binary_timestamp_round_trip_stays_inside_the_review_window(captured, monkeypatch):
    _context, _config, _manifest, plan, path = captured
    _write(plan, path)
    payload = json.loads(path.read_bytes())
    rng = random.Random(0)
    magnitudes = (1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)
    found = None
    for step in range(200_000):
        created = rng.random() * magnitudes[step % len(magnitudes)]
        expires = created + requests._REVIEW_SECONDS
        loaded_created, loaded_expires = json.loads(json.dumps([created, expires], separators=(",", ":")))
        window = loaded_expires - loaded_created
        if requests._REVIEW_SECONDS < window <= requests._REVIEW_SECONDS + requests._REVIEW_TIMESTAMP_SLACK_SECONDS:
            found = (loaded_created, loaded_expires)
            break
    assert found is not None
    payload["created_monotonic"], payload["expires_monotonic"] = found
    digest = _resign(plan, path, payload)
    stored = json.loads(path.read_bytes())
    stored_window = stored["expires_monotonic"] - stored["created_monotonic"]
    assert (
        requests._REVIEW_SECONDS < stored_window <= requests._REVIEW_SECONDS + requests._REVIEW_TIMESTAMP_SLACK_SECONDS
    )
    monkeypatch.setattr(requests.time, "monotonic", lambda: found[0] + 1.0)
    loaded = _load(plan, path, digest)
    assert loaded.payload() == plan.payload()
    assert loaded.subject() == plan.subject()


def test_exact_roundtrip_is_read_only_except_private_request(captured, tmp_path, monkeypatch):
    _context, _config, manifest, plan, path = captured
    now = time.monotonic()
    monkeypatch.setattr(requests.time, "monotonic", lambda: now)
    before = _tree(tmp_path)
    digest = _write(plan, path)
    assert path.stat().st_mode & 0o777 == 0o600
    loaded = _load(plan, path, digest)
    assert loaded.payload() == plan.payload()
    assert loaded.subject() == plan.subject()
    assert loaded.operation_id == plan.operation_id
    assert not manifest.exists()
    after = _tree(tmp_path)
    del after[str(path.relative_to(tmp_path))]
    parent = str(path.parent.relative_to(tmp_path))
    assert after[parent][:2] == before[parent][:2]
    del after[parent]
    del before[parent]
    # A live resident refreshes its own client-lease file's mtime during the
    # round trip; that liveness marker is not a request mutation.
    after = {
        rel: entry
        for rel, entry in after.items()
        if "resident-client-leases.v1" not in rel
    }
    before = {
        rel: entry
        for rel, entry in before.items()
        if "resident-client-leases.v1" not in rel
    }
    assert after == before
    raw = path.read_text()
    assert "grant_id" not in raw and "session_nonce" not in raw and "approval_gate_input" not in raw


def test_existing_request_is_never_overwritten(captured):
    _context, _config, _manifest, plan, path = captured
    path.write_bytes(b"foreign existing request")
    with pytest.raises(FileExistsError):
        _write(plan, path)
    assert path.read_bytes() == b"foreign existing request"


@pytest.mark.parametrize("mutation", ["bytes", "public", "symlink", "public-parent", "digest", "oversized"])
def test_private_request_or_digest_change_refuses_loading(captured, mutation, monkeypatch):
    _context, _config, manifest, plan, path = captured
    digest = _write(plan, path)
    if mutation == "bytes":
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "public":
        path.chmod(0o644)
    elif mutation == "symlink":
        other = path.with_name("copied-request")
        other.write_bytes(path.read_bytes())
        other.chmod(0o600)
        path.unlink()
        path.symlink_to(other)
    elif mutation == "public-parent":
        path.parent.chmod(0o755)
    elif mutation == "digest":
        digest = "0" * 64
    else:
        monkeypatch.setattr(requests, "_MAX_REQUEST", path.stat().st_size - 1)
    with pytest.raises(TransitionError):
        _load(plan, path, digest)
    assert not manifest.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "subject",
        "context",
        "extra-write",
        "extra-field",
        "expires",
        "authentication",
        "auth-extra-field",
    ],
)
def test_authenticated_request_still_requires_exact_constrained_plan(captured, mutation):
    _context, _config, manifest, plan, path = captured
    _write(plan, path)
    payload = json.loads(path.read_bytes())
    if mutation == "subject":
        payload["subject"] = "different reviewed plan"
    elif mutation == "context":
        payload["config_path"] = str(path.with_name("foreign-config"))
    elif mutation == "extra-write":
        payload["plan"]["files"].append(
            {
                "path": str(path.with_name("extra-write")),
                "before": None,
                "after": "eA==",
                "before_mode": 0o600,
                "after_mode": 0o600,
                "kind": "binding",
                "no_follow": True,
            }
        )
    elif mutation == "extra-field":
        payload["grant_id"] = "must never be accepted"
    elif mutation == "expires":
        payload["expires_monotonic"] = payload["created_monotonic"] + 301
    elif mutation == "auth-extra-field":
        payload["authentication"]["grant_id"] = "must never be accepted"
        raw = canonical_manifest_bytes(payload)
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        with pytest.raises(TransitionError, match="authentication_invalid"):
            _load(plan, path, digest)
        return
    else:
        digest = _resign(plan, path, payload, purpose="codex-hook-authority-receipt")
        with pytest.raises(TransitionError, match="authentication_invalid"):
            _load(plan, path, digest)
        return
    digest = _resign(plan, path, payload)
    with pytest.raises(TransitionError):
        _load(plan, path, digest)
    assert not manifest.exists()


@pytest.mark.parametrize("mutation", ["config", "native", "manifest"])
def test_changed_dependency_refuses_captured_plan_without_regeneration(captured, mutation):
    _context, config, manifest, plan, path = captured
    digest = _write(plan, path)
    if mutation == "config":
        config.write_bytes(config.read_bytes() + b"\n# newer configuration\n")
    elif mutation == "native":
        assert plan.native_runtime is not None
        plan.native_runtime.path.write_bytes(b"foreign artifact")
    else:
        manifest.write_bytes(b"foreign authority publication")
        manifest.chmod(0o600)
    with pytest.raises(TransitionError):
        _load(plan, path, digest)
    if mutation == "manifest":
        assert manifest.read_bytes() == b"foreign authority publication"
    else:
        assert not manifest.exists()


def test_expired_review_is_not_refreshed_by_loading(captured, monkeypatch):
    _context, _config, manifest, plan, path = captured
    digest = _write(plan, path)
    payload = json.loads(path.read_bytes())
    monkeypatch.setattr(requests.time, "monotonic", lambda: payload["expires_monotonic"] + 1)
    with pytest.raises(TransitionError, match="request_expired"):
        _load(plan, path, digest)
    assert not manifest.exists()


def test_nonfinite_unsigned_body_is_a_typed_authentication_failure(captured):
    _context, _config, manifest, plan, path = captured
    _write(plan, path)
    payload = json.loads(path.read_bytes())
    payload["created_monotonic"] = float("nan")
    raw = json.dumps(payload).encode()
    path.write_bytes(raw)
    with pytest.raises(TransitionError, match="request_authentication_invalid"):
        _load(plan, path, hashlib.sha256(raw).hexdigest())
    assert not manifest.exists()


def test_request_capacity_failure_does_not_create_or_modify_authority(captured, monkeypatch):
    _context, _config, manifest, plan, path = captured
    monkeypatch.setattr(requests, "_MAX_REQUEST", 1)
    with pytest.raises(TransitionError, match="request_too_large"):
        _write(plan, path)
    assert not path.exists()
    assert not manifest.exists()


def test_expired_parent_refuses_request_creation(captured):
    _context, _config, manifest, plan, path = captured
    with pytest.raises(TransitionError, match="deadline_exceeded"):
        requests.write_codex_hook_repair_request(path, plan, deadline_monotonic=time.monotonic() - 1)
    assert not path.exists()
    assert not manifest.exists()
