"""External signature/custody invariants; synthetic records never prove live isolation."""
import base64
import os
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json, digest, strict_json_loads
from ci.gauntlet.benchmark.product_custody import verify_product_audit


def fixture():
    key = Ed25519PrivateKey.generate()
    kernel = {"effective_uid": 10004, "effective_gid": 10004, "effective_capabilities": "0000000000000000",
              "no_new_privileges": 1, "boot_id": "boot", "start_time": "123",
              "mount_namespace": "product-mnt", "pid_namespace": "product-pid", "network_namespace": "product-net"}
    controller = {**kernel, "effective_uid": 0, "effective_gid": 0, "mount_namespace": "controller-mnt",
                  "pid_namespace": "controller-pid", "network_namespace": "controller-net"}
    mounts = [{"source": "/prefix", "destination": "/prefix", "mode": "ro"},
              *[{"source": "/owned/" + name, "destination": "/product/" + name, "mode": mode}
                for name, mode in (("public", "ro"), ("home", "rw"), ("guard", "rw"))],
              {"source": "/private/upstream", "destination": "/upstream", "mode": "ro"}]
    record = {"schema_version": "1.0", "kind": "isolated-native-mcp-observation", "collected_at": 1000,
        "product_plane": {"schema_version": "1.0", "kind": "isolated-product-plane", "container": "owned-test",
            "image_id": "sha256:" + "c" * 64, "source_sha_expected": "b" * 40, "uid": 10004,
            "prefix_digest": "a" * 64, "prefix_unchanged": True, "controller_identity": controller,
            "observations": [{"kind": "container-boundary", "identity": kernel, "mounts": mounts},
                {"kind": "proxy-process", "session_id": "session", "family": "docs", "host_exec_pid": 1234,
                 "product_pid": 5678, "identity": kernel}],
            "product_identity_claim": {"claimed_native": "untrusted"}, "product_claims_authenticated": False,
            "cleanup_complete": True, "cleanup_errors": [], "audit_error": None, "qualification_eligible": False},
        "product_events_self_reported": [{"claim": "every effect allowed"}], "product_claims_authenticated": False,
        "transport_observations": [
            {"sequence": 1, "run_id": "run", "kind": "peer-authenticated", "peer_uid": 10001, "allowed_uid": 10001},
            {"sequence": 2, "run_id": "run", "kind": "child-started", "session_id": "session", "family": "docs",
             "product_pid": 5678, "pid": 1234, "product_identity": kernel, "backend": "isolated-product-uid10004"}],
        "active_children": 0, "active_sessions": 0, "qualification_eligible": False}
    return key, record


def sign(key, record):
    return {"record": record, "signature": base64.b64encode(key.sign(canonical_json(record).encode())).decode()}


def verify(key, evidence, **kwargs):
    return verify_product_audit(evidence, trusted_public_key=key.public_key().public_bytes_raw(),
        expected_prefix_digest="a" * 64, expected_source_sha="b" * 40, expected_image_id="sha256:" + "c" * 64,
        expected_identity_wrapper_digest=digest({"product_self_report": {"claimed_native": "untrusted"},
                                                "authenticated": False}), **kwargs)


def test_valid_external_observations_never_authenticate_product_claims_or_qualification():
    key, record = fixture()
    result = verify(key, canonical_json(sign(key, record)), expected_frontdoor_run_id="run", require_exercised=True)
    assert result["custody_verified"] is True and result["product_proxy_count"] == 1
    assert result["product_claims_authenticated"] is False and result["qualification_eligible"] is False
    record["product_events_self_reported"] = [{"arbitrary_policy_claim": "deny everything"}]
    assert verify(key, sign(key, record)) == result  # Never derive efficacy from product prose.


def test_distinct_mcp_identity_requires_explicit_external_profile_and_real_uid():
    key,record=fixture()
    plane=record['product_plane']
    plane.update(schema_version='2.0',kind='isolated-product-plane.v2',uid=10005)
    for row in plane['observations']:
        row['identity']['effective_uid']=row['identity']['effective_gid']=10005
        row['identity'].update(uid_slots=[10005]*4,gid_slots=[10005]*4,supplementary_groups=[],
            capability_sets=dict.fromkeys(('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),'0000000000000000'))
    record['transport_observations'][1]['backend']='isolated-product-uid10005'
    with pytest.raises(ValueError,match='schema/UID'):
        verify(key,sign(key,record))
    assert verify(key,sign(key,record),expected_identity_profile='private-cell-mcp-v2')['custody_verified']
    plane['observations'][0]['identity']['effective_uid']=10004
    with pytest.raises(ValueError,match='UID/capability'):
        verify(key,sign(key,record),expected_identity_profile='private-cell-mcp-v2')


@pytest.mark.parametrize('profile',['root',10005,None,'unconfined'])
def test_product_profile_cannot_choose_an_arbitrary_identity(profile):
    from ci.gauntlet.benchmark.product_identity_profiles import product_uid
    with pytest.raises(ValueError,match='supported product identity'):
        product_uid(profile)


@pytest.mark.parametrize('groups',[[10005],[0],[10005,0],[10004],[10005,1000]])
def test_mcp_v2_permits_only_redundant_primary_group(groups):
    from ci.gauntlet.benchmark.product_custody import _kernel
    _,record=fixture()
    identity=record['product_plane']['observations'][0]['identity']
    identity.update(effective_uid=10005,effective_gid=10005,uid_slots=[10005]*4,gid_slots=[10005]*4,
        supplementary_groups=groups,
        capability_sets=dict.fromkeys(('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),'0000000000000000'))
    if groups==[10005]:
        _kernel(identity,record['product_plane']['controller_identity'],None,product_uid=10005)
    else:
        with pytest.raises(ValueError,match='saved identities/groups'):
            _kernel(identity,record['product_plane']['controller_identity'],None,product_uid=10005)


def test_wrong_external_key_and_unsigned_tampering_fail():
    key, record = fixture()
    evidence = sign(key, record)
    with pytest.raises(ValueError, match="signature"):
        verify(Ed25519PrivateKey.generate(), evidence)
    changed = deepcopy(evidence)
    changed["record"]["product_plane"]["prefix_digest"] = "d" * 64
    with pytest.raises(ValueError, match="signature"):
        verify(key, changed)


@pytest.mark.parametrize("field,value", [("prefix_digest", "d" * 64), ("source_sha_expected", "d" * 40),
    ("image_id", "sha256:" + "d" * 64), ("prefix_unchanged", False), ("cleanup_complete", False),
    ("cleanup_errors", ["surviving product process"]), ("product_claims_authenticated", True)])
def test_controller_signature_does_not_override_frozen_identity_or_cleanup(field, value):
    key, record = fixture()
    record["product_plane"][field] = value
    with pytest.raises(ValueError):
        verify(key, sign(key, record))


@pytest.mark.parametrize("field,value", [("effective_uid", 0), ("effective_gid", 10001),
    ("effective_capabilities", "0000000000000001"), ("no_new_privileges", 0),
    ("mount_namespace", "controller-mnt"), ("pid_namespace", "controller-pid"),
    ("network_namespace", "controller-net")])
def test_kernel_measurements_reject_root_caps_or_shared_namespaces(field, value):
    key, record = fixture()
    record["product_plane"]["observations"][0]["identity"][field] = value
    with pytest.raises(ValueError):
        verify(key, sign(key, record))


def test_shared_agent_namespace_and_mixed_episode_rejected():
    key, record = fixture()
    with pytest.raises(ValueError, match="agent namespace"):
        verify(key, sign(key, record), agent_identity={"mount_namespace": "product-mnt"})
    with pytest.raises(ValueError, match="different frontdoor"):
        verify(key, sign(key, record), expected_frontdoor_run_id="different")
    record["transport_observations"][1]["run_id"] = "mixed"
    with pytest.raises(ValueError, match="incomplete"):
        verify(key, sign(key, record))


def test_missing_actual_proxy_and_wrong_peer_cannot_establish_execution():
    key, record = fixture()
    record["product_plane"]["observations"].pop()
    record["transport_observations"].pop()
    result = verify(key, sign(key, record))
    assert result["product_proxy_exercised"] is False
    with pytest.raises(ValueError, match="not exercised"):
        verify(key, sign(key, record), require_exercised=True)
    record["transport_observations"][0]["peer_uid"] = 0
    with pytest.raises(ValueError, match="unexpected agent"):
        verify(key, sign(key, record))


def test_extra_private_mount_proxy_mismatch_and_unknown_claim_fields_rejected():
    key, record = fixture()
    for mutation in ("mount", "pid", "extra"):
        changed = deepcopy(record)
        if mutation == "mount":
            changed["product_plane"]["observations"][0]["mounts"].append(
                {"source": "/controller/keys", "destination": "/keys", "mode": "ro"})
        elif mutation == "pid":
            changed["transport_observations"][1]["product_pid"] += 1
        else:
            changed["chosen_trust_anchor"] = "product-key"
        with pytest.raises(ValueError):
            verify(key, sign(key, changed))


@pytest.mark.parametrize("raw", [b'{"record":{},"record":{}}', b'{"record":NaN}', b'{"record":Infinity}'])
def test_public_consumer_rejects_ambiguous_nonfinite_json(raw):
    key, _ = fixture()
    with pytest.raises(ValueError):
        verify(key, raw)


def test_retained_actual_control005_kernel_audit_and_tampering():
    # Explicit local observer anchor, independent of the consumed report. This
    # retained conformance artifact is optional on other developers' machines.
    default = (Path(__file__).resolve().parents[2] / "local-evidence-20261013"
               / "isolated-product-controls-20261013" / "005-control-result.json")
    path = Path(os.environ.get("HOL_WORKFLOW_PRODUCT_CONTROL005", str(default)))
    if not path.is_file():
        pytest.skip("local actual VM control005 artifact not provisioned")
    audit = strict_json_loads(path.read_bytes())["record"]["root_observed_audit"]
    anchor = base64.b64decode("jEvgT4KZNqgrmpVPa1A0mQJQ0SK2NtIa9JNLwBHVQxg=")
    kwargs = {"trusted_public_key": anchor,
        "expected_prefix_digest": "2bc55794239ece3483e5b3b5e53da958627e4b50ccdd4b59a6c87e71ccc4aad6",
        "expected_source_sha": "e2c4c18c12a64fd363c1992e28bc57fed74677d0",
        "expected_image_id": "sha256:827eaec482942aa5805beac1a75afd755b0daebade43024883b7d1637c27e52d",
        "require_exercised": True}
    result = verify_product_audit(audit, **kwargs)
    assert result["product_proxy_count"] == result["authenticated_agent_connections"] == 1
    assert result["product_audit_complete"] is True
    changed = deepcopy(audit)
    changed["record"]["product_plane"]["observations"][1]["identity"]["effective_uid"] = 0
    with pytest.raises(ValueError, match="signature"):
        verify_product_audit(changed, **kwargs)
