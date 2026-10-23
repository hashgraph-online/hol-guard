"""Data contracts and signatures; constructed kernel rows are not live proof."""
import base64
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import developer_product_custody as module
from ci.gauntlet.benchmark.contracts import canonical_json, digest


def kernel(uid=10004):
    return {"effective_uid":uid,"effective_gid":uid,"effective_capabilities":"0000000000000000",
        "no_new_privileges":1,"boot_id":"unit-boot","start_time":"123",
        "mount_namespace":"mnt:product","pid_namespace":"pid:product","network_namespace":"net:product"}


def controller():
    return {**kernel(0),"mount_namespace":"mnt:root","pid_namespace":"pid:root","network_namespace":"net:root"}


def mounts():
    ordinary = [("/installed","/installed","ro"),("/public","/product/public","ro"),
        ("/home","/runtime/home","rw"),("/guard","/product/guard","rw"),("/tmp-owned","/tmp","rw")]
    return [{"source":s,"destination":d,"mode":m} for s,d,m in ordinary]+[
        {"source":"/task","destination":"/runtime/home/project","mode":"rw","idmap":module.TASK_IDMAP},
        {"source":"/remote.git","destination":"/remote.git","mode":"rw","idmap":module.TASK_IDMAP}]


def plane():
    mapped = []
    for source,destination in (("/task","/runtime/home/project"),("/remote.git","/remote.git")):
        physical = {"uid":10001,"gid":10001,"mode":0o700,"inode":123}
        mapped.append({"source":source,"destination":destination,"mapping":module.TASK_IDMAP,
            "physical":physical,"product_view":{**physical,"uid":10004,"gid":10004},
            "kernel_observer_pid":99,"kernel_identity":kernel(),"product_report_authenticated":False})
    return {"controller_identity":controller(),"observations":[{"kind":"container-boundary","identity":kernel(),
        "mounts":mounts()}],"idmapped_task_observations":mapped}


def test_exact_executor_profile_accepts_declared_mapping_without_changing_mcp_five_profile():
    assert module._mounts(plane(),workspace_source="/task",provider_mounts=("/remote.git",))["identity"]==kernel()


@pytest.mark.parametrize("mutation", ["extra-private","group-write","wrong-owner","wrong-inode","missing-kernel"])
def test_extra_private_mount_or_metadata_only_mapping_fails(mutation):
    data = plane()
    if mutation=="extra-private":
        data["observations"][0]["mounts"].append({"source":"/controller/world.db","destination":"/leak","mode":"ro"})
    elif mutation=="group-write":
        data["idmapped_task_observations"][0]["physical"]["mode"]=0o770
    elif mutation=="wrong-owner":
        data["idmapped_task_observations"][0]["physical"]["uid"]=0
    elif mutation=="wrong-inode":
        data["idmapped_task_observations"][0]["product_view"]["inode"]=124
    else:
        data["idmapped_task_observations"][0]["kernel_observer_pid"]=None
    with pytest.raises(ValueError):
        module._mounts(data,workspace_source="/task",provider_mounts=("/remote.git",))


def test_external_key_required_and_tampered_signed_claim_cannot_verify():
    key,other = Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    record = {"qualification_eligible":False,"custody":"constructed-test"}
    envelope = {"record":record,"signature":base64.b64encode(key.sign(canonical_json(record).encode())).decode()}
    assert module._signed(envelope,key.public_key())==record
    with pytest.raises(ValueError,match="pinned"):
        module._signed(envelope,other.public_key())
    envelope["record"]["qualification_eligible"]=True
    with pytest.raises(ValueError,match="pinned"):
        module._signed(envelope,key.public_key())


def reviews():
    response = {"decision":"allow","model_output_action":"allow_original","reviewed_output_sha256":"a"*64}
    pre = {"kind":"actual-hook-response","hook_event_name":"PreToolUse","tool_name":"read",
        "tool_call_id":"call","payload_digest":"pre","response_digest":digest({"decision":"allow"}),
        "product_response":{"decision":"allow"},"original_input_digest":"input"}
    post = {**pre,"hook_event_name":"PostToolUse","payload_digest":"post","product_response":response,
        "response_digest":digest(response),"actual_output_sha256":"a"*64}
    peer = {"kind":"peer-authenticated","peer_pid":10,"peer_uid":10001,"identity":kernel(10001)}
    return {"transport_observations":[peer,pre,deepcopy(peer),post]}, {
        "hooks":[{"payload_digest":row["payload_digest"],"response_digest":row["response_digest"]}
                 for row in (pre,post)]}


def test_review_original_input_output_and_actual_sdk_peer_bindings_are_independent():
    data,actual_plane = reviews()
    assert len(module._reviews(data,actual_plane,sdk_pid=10,sdk_identity=kernel(10001),require_sdk=True))==2
    data["transport_observations"][-1]["original_input_digest"]="changed"
    with pytest.raises(ValueError,match="original input"):
        module._reviews(data,actual_plane,sdk_pid=10,sdk_identity=kernel(10001),require_sdk=True)
    data,actual_plane = reviews()
    data["transport_observations"][0]["peer_pid"]=11
    with pytest.raises(ValueError,match="SDK peer"):
        module._reviews(data,actual_plane,sdk_pid=10,sdk_identity=kernel(10001),require_sdk=True)


def test_pre_counter_cannot_omit_an_actual_admitted_builtin_call():
    data,_actual_plane = reviews()
    record = {"operations":{"maximum":1,"admitted":0,"events":[]},"settings":{"max_tool_calls":1},
              "native_mcp_audit":{"record":{"transport_observations":[]}}}
    with pytest.raises(ValueError,match="counters"):
        module._operations(record,[data["transport_observations"][1]])
    record["operations"]={"maximum":1,"admitted":1,"events":[{"sequence":1,"source":"sdk-builtin",
        "request_digest":"pre","admitted":True}]}
    module._operations(record,[data["transport_observations"][1]])
