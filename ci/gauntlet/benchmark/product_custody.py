"""Data-only external verification of controller-observed product custody.

A controller signature authenticates its observations, not the truth of product
audit events. The caller supplies the independent controller key and frozen
prefix/build/image identity; bundle or product-selected anchors are never used.
No product code is imported, probed, or executed by this consumer.
"""
from __future__ import annotations

import base64
import re
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json, digest, strict_json_loads

_NAMESPACES = ("mount_namespace", "pid_namespace", "network_namespace")
_RECORD_FIELDS = {"schema_version", "kind", "collected_at", "product_plane", "product_events_self_reported",
                  "product_claims_authenticated", "transport_observations", "active_children", "active_sessions",
                  "qualification_eligible"}
_PLANE_FIELDS = {"schema_version", "kind", "container", "image_id", "source_sha_expected", "uid", "prefix_digest",
                 "prefix_unchanged", "controller_identity", "observations", "product_identity_claim",
                 "product_claims_authenticated", "cleanup_complete", "cleanup_errors", "audit_error",
                 "qualification_eligible"}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _exact(value, fields, label):
    _require(type(value) is dict and set(value) == fields, f"unexpected {label} fields")


def _positive_int(value):
    return type(value) is int and value > 0


def _kernel(identity, controller, agent,*,product_uid=10004):
    _require(type(identity) is dict, "missing controller-observed product kernel identity")
    _require(type(product_uid) is int and product_uid in {10004,10005}
             and type(identity.get("effective_uid")) is int and identity["effective_uid"] == product_uid
             and type(identity.get("effective_gid")) is int and identity["effective_gid"] == product_uid
             and identity.get("effective_capabilities") == "0000000000000000"
             and type(identity.get("no_new_privileges")) is int and identity["no_new_privileges"] == 1,
             "actual product UID/capability isolation mismatch")
    if product_uid==10005:
        _require(identity.get('uid_slots')==[10005]*4 and identity.get('gid_slots')==[10005]*4
            and identity.get('supplementary_groups') in ([],[10005]) and identity.get('capability_sets')==
                dict.fromkeys(('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),'0000000000000000'),
            'v2 MCP saved identities/groups/capability floor differs')
    _require(identity.get("boot_id") == controller.get("boot_id") and isinstance(identity.get("boot_id"), str)
             and isinstance(identity.get("start_time"), str) and identity["start_time"].isdigit(),
             "product process kernel identity is incomplete")
    for field in _NAMESPACES:
        _require(isinstance(identity.get(field), str) and bool(identity[field])
                 and isinstance(controller.get(field), str) and identity[field] != controller[field],
                 "product shares controller namespace")
        if agent is not None:
            _require(isinstance(agent.get(field), str) and identity[field] != agent[field],
                     "product shares agent namespace")


def _mounts(mounts):
    _require(type(mounts) is list and len(mounts) == 5, "exact product mount inventory required")
    destinations = {}
    for mount in mounts:
        _exact(mount, {"source", "destination", "mode"}, "mount")
        for field in ("source", "destination"):
            path = mount[field]
            _require(isinstance(path, str) and path.startswith("/") and ".." not in PurePosixPath(path).parts
                     and not any(char in path for char in ("\x00", "\n", ":")), "invalid product mount path")
        _require(mount["destination"] not in destinations, "duplicate product mount destination")
        destinations[mount["destination"]] = mount
    required = {"/product/public": "ro", "/product/home": "rw", "/product/guard": "rw", "/upstream": "ro"}
    for path, mode in required.items():
        _require(path in destinations and destinations[path]["mode"] == mode, "product mount mode mismatch")
    remaining = [mount for path, mount in destinations.items() if path not in required]
    _require(len(remaining) == 1 and remaining[0]["source"] == remaining[0]["destination"]
             and remaining[0]["mode"] == "ro", "installed product prefix must be the sole additional readonly mount")


def verify_product_audit(evidence: dict | str | bytes, *, trusted_public_key: bytes,
                         expected_prefix_digest: str, expected_source_sha: str, expected_image_id: str,
                         expected_identity_wrapper_digest: str | None = None,
                         expected_frontdoor_run_id: str | None = None,
                         agent_identity: dict | None = None, require_exercised: bool = False,
                         expected_identity_profile: str = 'native-product-v1',
                         expected_package_version: str | None = None) -> dict:
    """Verify custody only; return actual execution/peer counts, never policy credit."""
    if isinstance(evidence, (str, bytes)):
        evidence = strict_json_loads(evidence)
    else:
        evidence = strict_json_loads(canonical_json(evidence))
    _exact(evidence, {"record", "signature"}, "signed product audit")
    from .product_identity_profiles import product_uid
    expected_uid=product_uid(expected_identity_profile)
    _require(type(trusted_public_key) is bytes and len(trusted_public_key) == 32,
             "independently pinned controller public key required")
    _require(isinstance(expected_prefix_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_prefix_digest)
             and isinstance(expected_source_sha, str) and re.fullmatch(r"[0-9a-f]{40}", expected_source_sha)
             and isinstance(expected_image_id, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id),
             "exact external prefix/source/image identities required")
    try:
        signature = base64.b64decode(evidence["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            signature, canonical_json(evidence["record"]).encode())
    except (ValueError, TypeError, InvalidSignature) as error:
        raise ValueError("invalid externally anchored controller signature") from error
    record = evidence["record"]
    _exact(record, _RECORD_FIELDS, "controller audit")
    _require(record["schema_version"] == "1.0" and record["kind"] == "isolated-native-mcp-observation"
             and _positive_int(record["collected_at"]), "unsupported controller audit version/kind/time")
    _require(record["product_claims_authenticated"] is False and record["qualification_eligible"] is False,
             "product claims or qualification cannot be promoted by custody evidence")
    _require(type(record["active_children"]) is int and record["active_children"] == 0
             and type(record["active_sessions"]) is int and record["active_sessions"] == 0,
             "native frontdoor still active")
    _require(type(record["product_events_self_reported"]) is list
             and len(record["product_events_self_reported"]) <= 1000, "product audit exceeds declared bound")
    plane = record["product_plane"]
    _exact(plane, _PLANE_FIELDS, "product plane")
    if expected_package_version is not None:
        from .product_version import verify_claim_version
        verify_claim_version(plane['product_identity_claim'], expected_package_version)
    _require(plane["schema_version"] == ("1.0" if expected_uid==10004 else "2.0")
             and plane["kind"] == ("isolated-product-plane" if expected_uid==10004 else "isolated-product-plane.v2")
             and type(plane["uid"]) is int and plane["uid"] == expected_uid, "incorrect product plane schema/UID")
    _require(plane["prefix_digest"] == expected_prefix_digest and plane["image_id"] == expected_image_id
             and plane["source_sha_expected"] == expected_source_sha and plane["prefix_unchanged"] is True,
             "frozen product prefix/build/image mismatch")
    _require(plane["cleanup_complete"] is True and plane["cleanup_errors"] == []
             and plane["product_claims_authenticated"] is False and plane["qualification_eligible"] is False,
             "product cleanup or custody declaration incomplete")
    controller = plane["controller_identity"]
    _require(type(controller) is dict and type(controller.get("effective_uid")) is int
             and controller["effective_uid"] == 0, "controller kernel identity is not root")
    if expected_identity_wrapper_digest is not None:
        _require(digest({"product_self_report": plane["product_identity_claim"], "authenticated": False})
                 == expected_identity_wrapper_digest, "frozen product identity wrapper mismatch")
    observations = plane["observations"]
    _require(type(observations) is list and len(observations) <= 10000, "bounded actual kernel observations required")
    containers, proxies = [], {}
    for observation in observations:
        _require(type(observation) is dict, "malformed product observation")
        if observation.get("kind") == "container-boundary":
            _exact(observation, {"kind", "identity", "mounts"}, "container observation")
            _kernel(observation["identity"], controller, agent_identity,product_uid=expected_uid)
            _mounts(observation["mounts"])
            containers.append(observation)
        elif observation.get("kind") == "proxy-process":
            _exact(observation, {"kind", "session_id", "family", "host_exec_pid", "product_pid", "identity"},
                   "proxy observation")
            _require(isinstance(observation["session_id"], str) and observation["session_id"] not in proxies
                     and _positive_int(observation["host_exec_pid"]) and _positive_int(observation["product_pid"]),
                     "invalid or duplicate proxy observation")
            _kernel(observation["identity"], controller, agent_identity,product_uid=expected_uid)
            proxies[observation["session_id"]] = observation
        else:
            raise ValueError("unknown or changed product boundary observation")
    _require(len(containers) == 1, "exactly one actual product container observation required")
    events = record["transport_observations"]
    _require(type(events) is list and len(events) <= 100000, "bounded transport observations required")
    peers, children, run_ids = 0, set(), set()
    for sequence, event in enumerate(events, 1):
        _require(type(event) is dict and type(event.get("sequence")) is int and event["sequence"] == sequence
                 and isinstance(event.get("run_id"), str), "incomplete controller transport sequence")
        run_ids.add(event["run_id"])
        if event.get("kind") == "peer-authenticated":
            _require(type(event.get("peer_uid")) is int and event["peer_uid"] == 10001
                     and event.get("allowed_uid") == 10001, "frontdoor authenticated an unexpected agent UID")
            peers += 1
        if event.get("kind") == "child-started":
            session = event.get("session_id")
            _require(session in proxies and session not in children, "unmatched actual proxy child")
            observed = proxies[session]
            _require(event.get("backend") == f"isolated-product-uid{expected_uid}"
                     and event.get("product_pid") == observed["product_pid"]
                     and event.get("pid") == observed["host_exec_pid"]
                     and event.get("product_identity") == observed["identity"]
                     and event.get("family") == observed["family"], "proxy transport/kernel identity mismatch")
            children.add(session)
    _require(len(run_ids) == 1 and children == set(proxies) and peers >= len(children),
             "incomplete native frontdoor execution/peer evidence")
    if expected_frontdoor_run_id is not None:
        _require(run_ids == {expected_frontdoor_run_id}, "controller audit belongs to a different frontdoor run")
    _require(not require_exercised or bool(children), "actual product MCP proxy was not exercised")
    return {"custody_verified": True, "product_proxy_exercised": bool(children),
            "product_proxy_count": len(children), "authenticated_agent_connections": peers,
            "product_claims_authenticated": False, "qualification_eligible": False,
            "product_audit_complete": plane["audit_error"] is None}
