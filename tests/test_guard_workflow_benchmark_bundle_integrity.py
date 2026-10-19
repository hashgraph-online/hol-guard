"""Independent anchors, public-safe exports, filesystem and manifest attacks."""

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.bundle_integrity import SOURCE_KEYS, export_bundle, verify_bundle
from ci.gauntlet.benchmark.campaign import compile_campaign
from ci.gauntlet.benchmark.catalog import get_workflow, load_fixture
from ci.gauntlet.benchmark.contracts import ContractError, canonical_json, digest
from ci.gauntlet.benchmark.world import World


def raw_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def setup_bundle(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = {name: digest(name) for name in SOURCE_KEYS}
    campaign = compile_campaign(
        [get_workflow("business-sales-lead-qualification")], repetitions=1, frozen_inputs=source
    )
    world = World.create(
        tmp_path / "world.db",
        load_fixture("business-sales-lead-qualification"),
        signing_key=Ed25519PrivateKey.generate(),
    )
    world.call("mail.read", {"record_id": "lead-a"}, "read-1")
    receipts = world.receipts()
    anchors = {
        "world": {
            "public_key": base64.b64encode(world.key.public_key().public_bytes_raw()).decode(),
            "receipt_count": 1,
            "final_hash": digest(receipts[-1]),
        }
    }
    signer = Ed25519PrivateKey.generate()
    destination = tmp_path / "bundle"
    payloads = {
        "effects/world.json": {"kind": "world-receipts", "records": receipts, "stream_id": "world"},
        "state/initial.json": {"kind": "world-snapshot", "records": [world.snapshot()], "stream_id": None},
    }
    exported = export_bundle(
        destination,
        payloads,
        campaign=campaign,
        source_identities=source,
        effect_anchors=anchors,
        controller_key=signer,
    )
    options = {
        "trusted_public_key": signer.public_key().public_bytes_raw(),
        "expected_manifest_digest": exported["manifest_digest"],
        "expected_source_identities": source,
        "expected_effect_anchors": anchors,
    }
    return destination, options, signer, campaign, payloads


def resign_manifest(destination, signer, options, mutate):
    path = destination / "manifest.json"
    manifest = json.loads(path.read_text())
    mutate(manifest["record"])
    manifest["signature"] = signer.sign(canonical_json(manifest["record"]).encode()).hex()
    path.write_text(canonical_json(manifest) + "\n")
    return {**options, "expected_manifest_digest": raw_hash(path)}


def test_valid_export_is_data_only_and_exploratory(tmp_path):
    destination, options, _, campaign, _ = setup_bundle(tmp_path)
    verified = verify_bundle(destination, **options)
    assert verified["integrity"] == "valid"
    assert verified["status"] == "exploratory"
    assert not verified["qualification_eligible"]
    assert verified["scheduled_episodes"] == 8
    assert verified["recorded_episodes"] == 0
    assert len(verified["missing_episodes"]) == 8
    assert verified["files"] == 4
    assert campaign["qualification_eligible"] is False


def test_manifest_trust_anchor_cannot_be_chosen_by_bundle(tmp_path):
    destination, options, _, _, _ = setup_bundle(tmp_path)
    with pytest.raises(ContractError, match="signature"):
        verify_bundle(
            destination,
            **{**options, "trusted_public_key": Ed25519PrivateKey.generate().public_key().public_bytes_raw()},
        )
    with pytest.raises(ContractError, match="manifest digest"):
        verify_bundle(destination, **{**options, "expected_manifest_digest": digest("different expected manifest")})


@pytest.mark.parametrize("attack", ["missing", "tamper", "truncate", "unlisted"])
def test_missing_modified_truncated_and_unlisted_files_fail(tmp_path, attack):
    destination, options, _, _, _ = setup_bundle(tmp_path)
    target = destination / "effects/world.json"
    if attack == "missing":
        target.unlink()
    elif attack == "tamper":
        target.write_bytes(target.read_bytes().replace(b"lead-a", b"lead-x"))
    elif attack == "truncate":
        target.write_bytes(target.read_bytes()[:100])
    else:
        (destination / "extra.json").write_text("{}")
    with pytest.raises(ContractError):
        verify_bundle(destination, **options)


def test_mixed_source_and_mismatched_binary_identity_fail(tmp_path):
    destination, options, signer, _, _ = setup_bundle(tmp_path)
    for field in ("candidate", "native_build"):
        expected = {**options["expected_source_identities"], field: digest("wrong source/binary")}
        with pytest.raises(ContractError, match="revision or mismatched binary"):
            verify_bundle(destination, **{**options, "expected_source_identities": expected})
    changed = resign_manifest(
        destination,
        signer,
        options,
        lambda record: record["source_identities"].update(candidate=digest("another revision")),
    )
    with pytest.raises(ContractError, match="revision or mismatched binary"):
        verify_bundle(destination, **changed)


@pytest.mark.parametrize("field", ["oracle", "verifier", "policy"])
def test_resigned_scorer_or_policy_identity_cannot_replace_external_pin(tmp_path, field):
    destination, options, signer, _, _ = setup_bundle(tmp_path)
    changed = resign_manifest(
        destination, signer, options,
        lambda record: record["source_identities"].update({field: digest("attacker-controlled replacement")}),
    )
    # Even a new manifest hash and a valid producer signature cannot replace
    # source identities retained separately by the invoking trusted caller.
    with pytest.raises(ContractError, match="revision or mismatched binary"):
        verify_bundle(destination, **changed)


def test_signed_manifest_duplicate_paths_and_traversal_are_rejected(tmp_path):
    destination, options, signer, _, _ = setup_bundle(tmp_path)
    duplicate = resign_manifest(
        destination, signer, options, lambda record: record["files"].append(copy.deepcopy(record["files"][0]))
    )
    with pytest.raises(ContractError, match="duplicate"):
        verify_bundle(destination, **duplicate)
    destination, options, signer, _, _ = setup_bundle(tmp_path / "second")
    traversal = resign_manifest(
        destination, signer, options, lambda record: record["files"][0].update(path="../outside.json")
    )
    with pytest.raises(ContractError, match="traversing"):
        verify_bundle(destination, **traversal)


def test_symlink_file_root_and_ancestor_are_rejected(tmp_path):
    destination, options, _, _, _ = setup_bundle(tmp_path)
    target = destination / "state/initial.json"
    target.unlink()
    target.symlink_to(destination / "campaign.json")
    with pytest.raises(ContractError, match="symlink"):
        verify_bundle(destination, **options)
    alias = tmp_path / "alias"
    alias.symlink_to(destination, target_is_directory=True)
    with pytest.raises(ContractError, match="symlink"):
        verify_bundle(alias, **options)


@pytest.mark.parametrize("malicious", [b'{"record":{},"record":{}}', b'{"value":NaN}', b"PK\x03\x04compressed-archive"])
def test_strict_json_rejects_duplicate_nonfinite_and_archive_payloads(tmp_path, malicious):
    destination, options, _, _, _ = setup_bundle(tmp_path)
    target = destination / "manifest.json"
    target.write_bytes(malicious)
    with pytest.raises(ContractError):
        verify_bundle(destination, **{**options, "expected_manifest_digest": raw_hash(target)})


@pytest.mark.parametrize(
    "secret",
    [
        {"api_key": "even-short-secret"},
        {"provider_credentials": {"token": "private"}},
        {"body": "sk-" + "a" * 32},
        {"body": "-----BEGIN PRIVATE KEY-----"},
    ],
)
def test_public_export_rejects_credentials_before_creating_directory(tmp_path, secret):
    _, options, signer, campaign, payloads = setup_bundle(tmp_path)
    malformed = copy.deepcopy(payloads)
    malformed["state/initial.json"]["records"][0]["records"][0]["data"].update(secret)
    target = tmp_path / "unsafe"
    with pytest.raises(ContractError, match="credential"):
        export_bundle(
            target,
            malformed,
            campaign=campaign,
            source_identities=options["expected_source_identities"],
            effect_anchors=options["expected_effect_anchors"],
            controller_key=signer,
        )
    assert not target.exists()


def test_effect_truncation_fails_even_with_fresh_manifest_signature(tmp_path):
    _, options, signer, campaign, payloads = setup_bundle(tmp_path)
    malformed = copy.deepcopy(payloads)
    malformed["effects/world.json"]["records"] = []
    with pytest.raises(ContractError, match="count/anchor"):
        export_bundle(
            tmp_path / "truncated",
            malformed,
            campaign=campaign,
            source_identities=options["expected_source_identities"],
            effect_anchors=options["expected_effect_anchors"],
            controller_key=signer,
        )


def test_total_file_size_and_unsupported_executable_data_fail(tmp_path):
    destination, options, signer, campaign, payloads = setup_bundle(tmp_path)
    malformed = copy.deepcopy(payloads)
    malformed["candidate.py"] = {"kind": "oracle-plugin", "records": [], "stream_id": None}
    with pytest.raises(ContractError):
        export_bundle(
            tmp_path / "executable",
            malformed,
            campaign=campaign,
            source_identities=options["expected_source_identities"],
            effect_anchors=options["expected_effect_anchors"],
            controller_key=signer,
        )
    path = destination / "state/initial.json"
    with path.open("wb") as handle:
        handle.truncate(17 * 1024 * 1024)
    with pytest.raises(ContractError, match="oversized"):
        verify_bundle(destination, **options)


def test_episode_transplant_and_missing_effect_stream_fail_before_export(tmp_path):
    _, options, signer, campaign, payloads = setup_bundle(tmp_path)
    row = campaign["inventory"][0]
    episode = {key: row[key] for key in ("id", "workflow_id", "variant", "condition", "repetition", "snapshot_id")}
    episode.update(
        schema_version="1.0",
        campaign_id="other-campaign",
        attempt=0,
        evidence_status="valid",
        task_status="complete",
        security_status="held",
        exposure="not-applicable",
        intervention="none",
        attribution="not-exercised",
        events=[],
        reasons=[],
        initial_digest=digest("initial"),
        final_digest=digest("final"),
    )
    bad = {**payloads, "episodes.json": {"kind": "episode", "records": [episode], "stream_id": None}}
    with pytest.raises(ContractError, match="frozen campaign"):
        export_bundle(
            tmp_path / "transplant",
            bad,
            campaign=campaign,
            source_identities=options["expected_source_identities"],
            effect_anchors=options["expected_effect_anchors"],
            controller_key=signer,
        )
    with pytest.raises(ContractError, match="missing"):
        export_bundle(
            tmp_path / "missing-effects",
            {},
            campaign=campaign,
            source_identities=options["expected_source_identities"],
            effect_anchors=options["expected_effect_anchors"],
            controller_key=signer,
        )
    assert not (tmp_path / "transplant").exists()
    assert not (tmp_path / "missing-effects").exists()


def test_mistyped_manifest_and_payload_fields_are_rejected(tmp_path):
    destination, options, signer, campaign, payloads = setup_bundle(tmp_path)
    changed = resign_manifest(destination, signer, options, lambda record: record.update(scheduled_episodes=True))
    with pytest.raises(ContractError, match="inventory count"):
        verify_bundle(destination, **changed)
    malformed = copy.deepcopy(payloads)
    malformed["effects/world.json"]["stream_id"] = []
    with pytest.raises(ContractError, match="stream identity"):
        export_bundle(
            tmp_path / "bad-stream",
            malformed,
            campaign=campaign,
            source_identities=options["expected_source_identities"],
            effect_anchors=options["expected_effect_anchors"],
            controller_key=signer,
        )
