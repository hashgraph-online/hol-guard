"""Data-only verification of the separate developer builtin product profile.

Custody establishes real mediation, including refusals. It grants no protection
credit and authenticates no product policy claim or candidate functionality.
"""
from __future__ import annotations

import base64
from collections import Counter
from functools import wraps
from pathlib import PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .builtin_hook_supervisor import review_summary
from .contracts import canonical_json, digest, strict_json_loads
from .native_builtin_plane import decode_hook_response
from .native_contained_plane import TASK_IDMAP
from .product_custody import _PLANE_FIELDS, _kernel, verify_product_audit

_BUILTIN_EXTRA = {"profile","hooks","containment_execution_supported","workspace_path","workspace_readonly",
    "containment_execution_implemented","containment_conformance_established","backend_observation","executions",
    "declared_provider_mounts","idmapped_task_observations"}
_RUNTIME = {"schema_version","kind","settings","controller_session_id","public_prompt_digest","public_assets",
    "prompt_allowed","operations","agent_public_mounts","errors","native_mcp_audit","native_builtin_audit",
    "native_task_contexts","upstream_counts","product_claims_authenticated","qualification_eligible"}
_BUILTIN = {"schema_version","kind","controller_session_id","sdk_pid","sdk_identity","transport_observations",
    "product_plane","contained_transport_observations","product_claims_authenticated","qualification_eligible",
    "review_summary"}


def _require(value, message):
    if not value:
        raise ValueError(message)


def _signed(envelope, public_key):
    _require(type(envelope) is dict and set(envelope) == {"record","signature"},"invalid controller envelope")
    try:
        public_key.verify(base64.b64decode(envelope["signature"],validate=True),
                          canonical_json(envelope["record"]).encode())
    except Exception as error:
        raise ValueError("externally pinned controller signature invalid") from error
    return envelope["record"]


def _path(value):
    return (isinstance(value,str) and value.startswith("/") and ".." not in PurePosixPath(value).parts
            and not any(char in value for char in ("\x00","\n",":")))


def _mounts(plane, *, workspace_source, provider_mounts):
    containers = [row for row in plane["observations"] if row.get("kind")=="container-boundary"]
    _require(len(containers)==1,"exactly one actual builtin container observation required")
    mounts = containers[0]["mounts"]
    _require(type(mounts) is list and len(mounts)==6+len(provider_mounts),
             "exact separate executor mount profile required")
    destinations = {}
    for mount in mounts:
        _require(type(mount) is dict and set(mount) in ({"source","destination","mode"},
                 {"source","destination","mode","idmap"}),"unexpected executor mount fields")
        _require(_path(mount["source"]) and _path(mount["destination"])
                 and mount["destination"] not in destinations,"invalid duplicate executor mount path")
        destinations[mount["destination"]]=mount
    ordinary = {"/product/public":"ro","/runtime/home":"rw","/product/guard":"rw","/tmp":"rw"}
    for destination,mode in ordinary.items():
        _require(destination in destinations and destinations[destination]["mode"]==mode
                 and "idmap" not in destinations[destination],"private executor mount mode/profile mismatch")
    expected_mapped = {"/runtime/home/project":workspace_source,**{path:path for path in provider_mounts}}
    for destination,source in expected_mapped.items():
        _require(destinations.get(destination)=={"source":source,"destination":destination,
                 "mode":"rw","idmap":TASK_IDMAP},"task/provider mapping differs from external declared fixture")
    remaining = [row for destination,row in destinations.items()
                 if destination not in ordinary and destination not in expected_mapped]
    _require(len(remaining)==1 and remaining[0]["source"]==remaining[0]["destination"]
             and remaining[0]["mode"]=="ro" and "idmap" not in remaining[0],"sole additional readonly prefix required")
    mapped = plane["idmapped_task_observations"]
    _require(type(mapped) is list and len(mapped)==len(expected_mapped),"actual kernel idmap observations required")
    seen = set()
    for row in mapped:
        destination = row["destination"]
        _require(destination in expected_mapped and destination not in seen
                 and row["source"]==expected_mapped[destination] and row["mapping"]==TASK_IDMAP,
                 "unexpected or duplicate task mapping observation")
        seen.add(destination)
        physical,inside = row["physical"],row["product_view"]
        _require(set(physical)=={"uid","gid","mode","inode"} and type(physical["uid"]) is int
                 and physical["uid"]==physical["gid"]==10001 and type(physical["mode"]) is int
                 and not physical["mode"] & 0o022 and type(physical["inode"]) is int and physical["inode"]>0
                 and inside=={**physical,"uid":10004,"gid":10004},"idmap physical ownership/mode/inode proof mismatch")
        _require(type(row["kernel_observer_pid"]) is int and row["kernel_observer_pid"]>0
                 and row["product_report_authenticated"] is False,"mapping lacks independent kernel observer")
        _kernel(row["kernel_identity"],plane["controller_identity"],None)
    return containers[0]


def _hook(row, controller, agent,*,product_uid=10004):
    _require(type(row) is dict and type(row["product_pid"]) is int and row["product_pid"]>0
             and type(row["host_exec_pid"]) is int and row["host_exec_pid"]>0,"actual native hook process absent")
    _kernel(row["identity"],controller,agent,product_uid=product_uid)
    response,raw = row["response"],row["raw_response"]
    event = "UserPromptSubmit" if row["response_normalization"]=="normal-omp-prompt-protocol-2" else None
    normalized = decode_hook_response(canonical_json(raw).encode(),returncode=row["returncode"],event=event)
    _require(row["raw_response_digest"]==digest(raw) and row["response_digest"]==digest(response)
             and normalized==response,"native hook raw/normalized response binding invalid")
    return response


def _reviews(builtin, plane, *, sdk_pid, sdk_identity, require_sdk):
    events = builtin["transport_observations"]
    actual = [row for row in events if row.get("kind")=="actual-hook-response"]
    peers = [row for row in events if row.get("kind")=="peer-authenticated"]
    if require_sdk:
        _require(len(peers)>=len(actual) and all(row.get("peer_pid")==sdk_pid and row.get("peer_uid")==10001
                 and row.get("identity")==sdk_identity for row in peers),
                 "builtin review lacks exact authenticated SDK peer")
    pairs = Counter((row["payload_digest"],row["response_digest"]) for row in plane["hooks"])
    inputs = {}
    for row in actual:
        _require(row.get("hook_event_name") in {"PreToolUse","PostToolUse"}
                 and row.get("tool_name") in {"read","write","edit","bash"},"invalid builtin review classification")
        pair = row["payload_digest"],row["response_digest"]
        _require(pairs[pair]>0 and row["response_digest"]==digest(row["product_response"]),
                 "transport review has no matching actual native hook response")
        pairs[pair] -= 1
        call = row["tool_call_id"]
        if row["hook_event_name"]=="PreToolUse":
            _require(call not in inputs or inputs[call]==row["original_input_digest"],
                     "reused builtin call changed input")
            inputs[call]=row["original_input_digest"]
        else:
            _require(inputs.get(call)==row["original_input_digest"] and isinstance(row["actual_output_sha256"],str)
                     and len(row["actual_output_sha256"])==64,
                     "native output review original input/output binding absent")
            response = row["product_response"]
            if response.get("model_output_action")=="allow_original":
                _require(response.get("reviewed_output_sha256")==row["actual_output_sha256"],
                         "native original output digest differs from actual SDK output")
    return actual


def _operations(record, actual_reviews):
    operations = record["operations"]
    _require(set(operations)=={"maximum","admitted","events"}
             and type(operations["maximum"]) is int and operations["maximum"]==record["settings"]["max_tool_calls"]
             and type(operations["admitted"]) is int and 0<=operations["admitted"]<=operations["maximum"],
             "controller operation budget differs from frozen limit")
    rows = operations["events"]
    _require(type(rows) is list and len(rows)<=operations["maximum"]+1,"operation observations exceed frozen budget")
    admitted = Counter()
    for index,row in enumerate(rows,1):
        _require(set(row)=={"sequence","source","request_digest","admitted"} and row["sequence"]==index
                 and row["source"] in {"sdk-builtin","native-mcp"} and type(row["admitted"]) is bool,
                 "invalid controller operation observation")
        if row["admitted"]:
            admitted[row["source"],row["request_digest"]] += 1
    expected = Counter(("sdk-builtin",row["payload_digest"]) for row in actual_reviews
                       if row["hook_event_name"]=="PreToolUse")
    for row in record["native_mcp_audit"]["record"]["transport_observations"]:
        if row.get("kind")=="forwarded" and row.get("message",{}).get("method")=="tools/call":
            expected["native-mcp",digest({"family":row["family"],"session_id":row["session_id"],
                                         "message":row["message"]})] += 1
    _require(admitted==expected and sum(admitted.values())==operations["admitted"],
             "operation counters do not match actual native ingress reviews/requests")


def _validation_errors(function):
    @wraps(function)
    def bounded(*args,**kwargs):
        try:
            return function(*args,**kwargs)
        except (KeyError,TypeError,IndexError,AttributeError) as error:
            raise ValueError("malformed developer product custody data") from error
    return bounded


@_validation_errors
def verify_developer_product_runtime(evidence, *, trusted_public_key: bytes, expected_settings: dict,
                                    expected_session_id: str, expected_prompt_digest: str,
                                    workspace_source: str, provider_mounts: tuple[str,...],
                                    agent_identity: dict | None, sdk_pid: int | None = None,
                                    sdk_identity: dict | None = None, require_sdk: bool = True):
    """External caller freezes all identities/paths; no bundle-selected anchors."""
    _require(type(trusted_public_key) is bytes and len(trusted_public_key)==32,
             "external controller public key required")
    value = (strict_json_loads(evidence) if isinstance(evidence,(str,bytes))
             else strict_json_loads(canonical_json(evidence)))
    key = Ed25519PublicKey.from_public_bytes(trusted_public_key)
    record = _signed(value,key)
    version = '2.0' if 'package_version' in expected_settings else '1.0'
    _require(type(record) is dict and set(record)==_RUNTIME and record["schema_version"]==version
             and record["kind"]=="developer-product-runtime-observation","invalid runtime schema")
    _require(record["settings"]==expected_settings and record["controller_session_id"]==expected_session_id
             and record["public_prompt_digest"]==expected_prompt_digest,"runtime transplanted from different context")
    _require(record["errors"]==[] and all(type(v) is int and v==0 for v in record["upstream_counts"].values())
             and set(record["upstream_counts"])=={"active_children","active_workers","active_sessions"},
             "runtime/upstream cleanup incomplete")
    _require(record["product_claims_authenticated"] is False and record["qualification_eligible"] is False,
             "custody cannot promote product claims/qualification")
    from .product_version import version_options, verify_claim_version
    mcp = verify_product_audit(record["native_mcp_audit"],trusted_public_key=trusted_public_key,
        expected_prefix_digest=expected_settings["prefix_digest"],expected_source_sha=expected_settings["source_sha"],
        expected_image_id=expected_settings["mcp_image_id"],agent_identity=agent_identity,
        **version_options(expected_settings.get('package_version')))
    builtin = _signed(record["native_builtin_audit"],key)
    _require(set(builtin)==_BUILTIN and builtin["schema_version"]=="1.0"
             and builtin["kind"]=="isolated-native-builtin-observation"
             and builtin["controller_session_id"]==expected_session_id,"invalid builtin controller profile/session")
    plane = builtin["product_plane"]
    if 'package_version' in expected_settings:
        verify_claim_version(plane['product_identity_claim'], expected_settings['package_version'])
    _require(set(plane)==_PLANE_FIELDS|_BUILTIN_EXTRA
             and plane["kind"]=="isolated-contained-builtin-product-plane"
             and plane["profile"]=="native-contained-builtin-hooks-v1","invalid explicit builtin executor profile")
    _require(plane["prefix_digest"]==expected_settings["prefix_digest"] and plane["prefix_unchanged"] is True
             and plane["source_sha_expected"]==expected_settings["source_sha"]
             and plane["image_id"]==expected_settings["executor_image_id"]
             and plane["cleanup_complete"] is True and plane["cleanup_errors"]==[],
             "builtin prefix/cleanup identity mismatch")
    _require(plane["uid"]==10004 and plane["product_claims_authenticated"] is False
             and plane["qualification_eligible"] is False and plane["controller_identity"]["effective_uid"]==0,
             "builtin product/controller identity or claim boundary invalid")
    boundary = _mounts(plane,workspace_source=workspace_source,provider_mounts=provider_mounts)
    _kernel(boundary["identity"],plane["controller_identity"],agent_identity)
    _require(plane["backend_observation"]["sha256"]==expected_settings["bwrap_sha256"],
             "frozen bubblewrap bytes mismatch")
    if require_sdk:
        _require(type(sdk_pid) is int and sdk_pid>0 and builtin["sdk_pid"]==sdk_pid
                 and sdk_identity is not None and builtin["sdk_identity"]==sdk_identity
                 and agent_identity is not None,"missing independently observed SDK binding")
        _require(sdk_identity["effective_uid"]==10001 and sdk_identity["effective_capabilities"]=="0000000000000000"
                 and sdk_identity["no_new_privileges"]==1,"SDK privilege boundary mismatch")
    responses = [_hook(row,plane["controller_identity"],agent_identity) for row in plane["hooks"]]
    actual_reviews = _reviews(builtin,plane,sdk_pid=sdk_pid,sdk_identity=sdk_identity,require_sdk=require_sdk)
    _operations(record,actual_reviews)
    summary = review_summary(builtin["transport_observations"],builtin["contained_transport_observations"])
    _require(summary==builtin["review_summary"] and summary["missing_required_post_call_ids"]==[]
             and summary['unreviewable_hook_call_ids']==[],
             "admitted builtin backend lacks its actual native output review")
    _require(len(record["native_task_contexts"])==1,"exact MCP native public task context required")
    context = _signed(record["native_task_contexts"][0],key)
    _require(context["phase"]=="developer" and context["public_prompt_digest"]==expected_prompt_digest
             and digest(context["public_prompt"])==expected_prompt_digest and len(context["hooks"])==1,
             "MCP public task context differs")
    _hook(context["hooks"][0],plane["controller_identity"],agent_identity)
    mcp_plane = record["native_mcp_audit"]["record"]["product_plane"]
    mcp_boundary = next(row["identity"] for row in mcp_plane["observations"] if row["kind"]=="container-boundary")
    _require(all(context["hooks"][0]["identity"][field]==mcp_boundary[field] for field in
                 ("boot_id","mount_namespace","pid_namespace","network_namespace")),
             "public MCP task hook was outside its actual product plane")
    prompts = [event for event in builtin["transport_observations"] if event.get("kind")=="actual-user-prompt-response"]
    prompt_payload = {"hook_event_name":"UserPromptSubmit","prompt":context["public_prompt"],
                      "config_path":"/product/public/omp.json","session_id":expected_session_id}
    _require(len(prompts)==1 and prompts[0]["payload_digest"]==digest(prompt_payload)
             and any(row["payload_digest"]==prompts[0]["payload_digest"]
                     and row["response_digest"]==prompts[0]["response_digest"] for row in plane["hooks"]),
             "builtin public task context absent or differs from actual native hook")
    builtin_prompt = next(row["response"] for row in plane["hooks"] if row["payload_digest"]==digest(prompt_payload))
    prompt_allowed = builtin_prompt["decision"]==context["hooks"][0]["response"]["decision"]=="allow"
    _require(type(record["prompt_allowed"]) is bool and record["prompt_allowed"]==prompt_allowed,
             "declared task disposition differs from actual native prompt decisions")
    return {"custody_verified":True,"native_denial_count":sum(row["decision"] in {"deny","block"} for row in responses),
        "native_hook_count":len(responses),"mcp_proxy_count":mcp["product_proxy_count"],
        "sdk_bound":builtin["sdk_pid"] is not None,"product_claims_authenticated":False,"qualification_eligible":False}
