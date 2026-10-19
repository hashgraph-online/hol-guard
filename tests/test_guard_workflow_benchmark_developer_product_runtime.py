"""Runtime wiring tests; planning doubles establish no actual product efficacy."""
import base64
import threading
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark import developer_product_runtime as module
from ci.gauntlet.benchmark.builtin_hook_supervisor import review_summary
from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor


class Upstream(ServiceSupervisor):
    def __init__(self, directory):
        self.directory,self.allowed_uid,self.socket_gid = directory,10004,10004
        self.sockets,self.families,self._stop = {},("docs","mail"),threading.Event()
        self.active_children,self.active_workers,self.active_sessions = 0,0,0
    @property
    def active_children(self): return 0
    @active_children.setter
    def active_children(self, value): pass
    @property
    def active_workers(self): return 0
    @active_workers.setter
    def active_workers(self, value): pass
    @property
    def active_sessions(self): return 0
    @active_sessions.setter
    def active_sessions(self, value): pass
    def start(self): self.sockets = {"docs":1,"mail":2}
    def close(self): self._stop.set()


class PlanningPlane:
    def __init__(self, **kwargs):
        self.options,self.prefix_digest = kwargs,"a"*64
        self.closed = False
    def start(self, *args): return self
    def close(self): self.closed = True


class PlanningFrontdoor:
    def __init__(self, *args, **kwargs):
        self.options,self.closed,self.exports = kwargs,False,0
        self.product_plane = kwargs["product_plane"]
    def start(self):
        self.product_plane.start()
        return self
    def close(self):
        self.closed=True
        self.product_plane.close()
    def collect_audit(self, **kwargs):
        self.exports += 1
        return {"record":{"kind":"planning-only"},"signature":"not-native-evidence"}


class PlanningHooks:
    def __init__(self, directory, **kwargs):
        self.directory,self.plane,self.options = directory,kwargs["plane"],kwargs
        self.bound = None
    def prepare_user_prompt(self, prompt): return {"decision":"deny","reason":"actual fixture cold refusal"}
    def start(self): return self
    def bind_sdk(self, pid, **kwargs): self.bound = (pid,kwargs)
    def close(self): self.plane.close()
    def evidence(self, **kwargs): return {"record":{"kind":"planning-only"},"signature":"not-native-evidence"}


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(module.os,"geteuid",lambda:0)
    monkeypatch.setattr(module,"NativeProductContainer",PlanningPlane)
    monkeypatch.setattr(module,"_BudgetPlane",PlanningPlane)
    monkeypatch.setattr(module,"_BudgetFrontdoor",PlanningFrontdoor)
    monkeypatch.setattr(module,"BuiltinHookSupervisor",PlanningHooks)
    monkeypatch.setattr(module,"prepare_task_context",lambda *args,**kwargs: ({"record":{"kind":"planning-only"}},True))
    return module.DeveloperProductRuntime(root=tmp_path/"private",upstream=Upstream(tmp_path/"upstream"),
        public_mcp_directory=tmp_path/"front",public_hook_directory=tmp_path/"hooks",
        python=Path("/frozen/.venv/bin/python"),source_sha="a"*40,prefix_digest="a"*64,bwrap_sha256="b"*64,
        workspace_source=tmp_path/"checkout",workspace_custody_root=tmp_path,
        public_prompt="Actual public task",controller_session_id="root-episode",deadline_seconds=60,max_tool_calls=2)


def test_declared_endpoint_and_mounts_expose_no_raw_upstream_or_guard_authority(runtime):
    configs = runtime.resource_endpoints()
    assert set(configs)=={"docs","mail"}
    assert all("/runtime/resources/" in str(config) for config in configs.values())
    assert {row["destination"] for row in runtime.agent_mounts()}=={"/runtime/resources","/runtime/guard-hook"}
    assert all(row["mode"]=="ro" and row["source"]!=str(runtime.upstream.directory) for row in runtime.agent_mounts())
    with pytest.raises(ValueError):
        runtime.resource_endpoints("/controller")


def test_explicit_package_version_reaches_both_product_planes_and_signed_settings(runtime):
    product = module.DeveloperProductRuntime(root=runtime.root, upstream=runtime.upstream,
        public_mcp_directory=runtime.public_mcp_directory, public_hook_directory=runtime.public_hook_directory,
        python=runtime.python, source_sha='a'*40, prefix_digest='a'*64, bwrap_sha256='b'*64,
        workspace_source=runtime.workspace_source, workspace_custody_root=runtime.workspace_custody_root,
        public_prompt=runtime.public_prompt, controller_session_id=runtime.session_id,
        deadline_seconds=60, max_tool_calls=2, package_version='3.46.0')
    product.start(controller_key=Ed25519PrivateKey.generate())
    try:
        assert product.frontdoor.product_plane.options['expected_package_version'] == '3.46.0'
        assert product.builtin.options['expected_package_version'] == '3.46.0'
    finally:
        product.close()
    evidence = product.evidence_record()
    assert evidence['schema_version'] == '2.0' and evidence['settings']['package_version'] == '3.46.0'


def test_native_prompt_refusal_is_retained_and_blocks_sdk_without_claiming_missing_runtime(runtime):
    key = Ed25519PrivateKey.generate()
    runtime.start(controller_key=key)
    assert runtime.started and runtime.prompt_allowed is False
    with pytest.raises(ValueError,match="allowed public context"):
        runtime.bind_sdk(100,expected_identity={})
    runtime.close()
    record = runtime.evidence_record()
    assert record["errors"]==[] and record["prompt_allowed"] is False
    assert runtime.frontdoor.closed and runtime.builtin.closed and runtime.upstream._stop.is_set()
    assert record["qualification_eligible"] is False and record["product_claims_authenticated"] is False


def test_evidence_is_cached_detached_and_signed_without_recollecting_or_mutation(runtime):
    key = Ed25519PrivateKey.generate()
    runtime.start(controller_key=key)
    runtime.close()
    first = runtime.evidence_record()
    first["errors"].append("caller mutation")
    second = runtime.evidence_record()
    assert second["errors"]==[] and runtime.frontdoor.exports==1
    signed = runtime.evidence(controller_key=key)
    key.public_key().verify(base64.b64decode(signed["signature"]),canonical_json(second).encode())


@pytest.mark.parametrize('package_version', [None, '3.46.0'])
def test_explicit_private_factory_reuses_operation_budget_and_emits_distinct_runtime(runtime,monkeypatch,tmp_path,package_version):
    from ci.gauntlet.benchmark import private_cell_factory
    options={'schema':'developer-private-cell-config.v1','artifacts':str(tmp_path),
        **{name:'a'*64 for name in ('artifact_manifest_sha256','initializer_sha256',
                                   'native_sha256','runtime_tree_digest')},
        'idmap_runtime':'ubuntu2404-controller-v1','cpu_profile':'single-core-v1'}
    runtime.private_cell=private_cell_factory.PrivateCellConfig.parse(options)
    runtime.settings['private_cell']=runtime.private_cell.declaration()
    runtime.settings['mcp_identity_profile']='private-cell-mcp-v2'
    runtime.settings['contained_output_binding']='controller-contained-output.v1'
    runtime.settings['contained_completion_profile']='guard-contained-completion.v1'
    if package_version is not None:
        runtime.settings['package_version']=package_version
    runtime.upstream.allowed_uid=runtime.upstream.socket_gid=10005
    calls=[]
    def build(**kwargs):
        calls.append(kwargs)
        return PlanningPlane(**kwargs)
    monkeypatch.setattr(private_cell_factory,'build_private_cell',build)
    runtime.start(controller_key=Ed25519PrivateKey.generate())
    assert len(calls)==1 and calls[0]['operation_budget'] is runtime.operations
    assert calls[0]['workspace_source']==runtime.workspace_source
    assert calls[0]['provider_mounts']==runtime.provider_mounts
    assert calls[0]['package_version']==package_version
    assert runtime.frontdoor.product_plane.options.get('expected_package_version')==package_version
    runtime.close()
    evidence=runtime.evidence_record()
    assert evidence['schema_version']==('4.0' if package_version is None else '5.0')
    assert evidence['kind']=='developer-private-cell-runtime-observation'
    assert evidence['settings']['private_cell']==options
    assert runtime.frontdoor.closed and runtime.builtin.closed


def test_raw_uid10001_upstream_or_overlapping_public_socket_cannot_be_used(runtime,tmp_path,monkeypatch):
    options = dict(root=tmp_path/"another",upstream=runtime.upstream,public_mcp_directory=tmp_path/"front2",
        public_hook_directory=tmp_path/"hooks2",python=runtime.python,source_sha="a"*40,prefix_digest="a"*64,
        bwrap_sha256="b"*64,workspace_source=tmp_path/"checkout",workspace_custody_root=tmp_path,
        public_prompt="Task",controller_session_id="episode",deadline_seconds=60,max_tool_calls=2)
    runtime.upstream.allowed_uid=10001
    with pytest.raises(ValueError,match="UID10004"):
        module.DeveloperProductRuntime(**options)
    runtime.upstream.allowed_uid=10004
    options["public_hook_directory"]=options["root"]/"exposed"
    with pytest.raises(ValueError,match="disjoint"):
        module.DeveloperProductRuntime(**options)


def test_shared_actual_operation_budget_counts_denied_pre_and_mcp_before_forwarding():
    budget = module.OperationBudget(2)
    budget.claim("sdk-builtin",{"native_outcome":"deny"})
    budget.claim("native-mcp",{"method":"tools/call"})
    with pytest.raises(ValueError,match="before product"):
        budget.claim("sdk-builtin",{})
    assert budget.admitted==2 and len(budget.events)==3 and budget.events[-1]["admitted"] is False


def review(event, call="call", decision="allow", sha="input"):
    return {"kind":"actual-hook-response","hook_event_name":event,"tool_call_id":call,
            "product_response":{"decision":decision},"payload_digest":sha}


def test_review_summary_accepts_native_refusal_but_detects_missing_post_and_duplicate_admissions():
    refusal = review("PreToolUse",decision="deny")
    assert review_summary([refusal],[])["missing_required_post_call_ids"]==[]
    allow = review("PreToolUse")
    assert review_summary([allow],[])["missing_required_post_call_ids"]==["call"]
    post = review("PostToolUse",decision="deny")
    assert review_summary([allow,post],[])["missing_required_post_call_ids"]==[]
    assert review_summary([allow,deepcopy(allow),post],[])["missing_required_post_call_ids"]==["call"]
    consumed = [{"kind":"contained-route-consumed","payload_digest":"input"}]
    assert review_summary([refusal],consumed)["missing_required_post_call_ids"]==["call"]


def test_every_declared_native_outage_allow_stays_missing_review_proof():
    from ci.gauntlet.benchmark.native_review_status import UNREVIEWABLE_REASONS
    for reason in UNREVIEWABLE_REASONS:
        post=review('PostToolUse',decision='allow')
        post['product_response']['reason_code']=reason
        result=review_summary([review('PreToolUse'),post],[])
        assert result['post_attempt_counts']=={'call':1},reason
        assert result['post_review_counts']=={},reason
        assert result['missing_required_post_call_ids']==['call'],reason
        assert result['unreviewable_hook_call_ids']==['call'],reason


def test_recording_only_is_not_protected_review_and_valid_block_is_review():
    for field in ('recording_only','observe_mode'):
        post=review('PostToolUse',decision='allow')
        post['product_response'][field]=True
        assert review_summary([review('PreToolUse'),post],[])['missing_required_post_call_ids']==['call']
    post=review('PostToolUse',decision='block')
    post['product_response']['reason_code']='native_policy_warning'
    result=review_summary([review('PreToolUse'),post],[])
    assert result['missing_required_post_call_ids']==result['unreviewable_hook_call_ids']==[]


def test_unavailable_pre_refusal_does_not_become_product_intervention_proof():
    pre=review('PreToolUse',decision='deny')
    pre['product_response']['reason_code']='native_hook_worker_exception'
    assert review_summary([pre],[])['unreviewable_hook_call_ids']==['call']


def test_review_outage_vocabulary_covers_candidate_policy_without_importing_it():
    import ast
    from pathlib import Path

    from ci.gauntlet.benchmark.native_review_status import UNREVIEWABLE_REASONS
    source=Path(__file__).resolve().parents[1]/'src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py'
    tree=ast.parse(source.read_text())
    names={'_REVIEW_CANNOT_FINISH_REASON_CODES','_INTEGRITY_FAIL_CLOSED_REASON_CODES'}
    found=set()
    for node in tree.body:
        if (isinstance(node,ast.Assign)
                and any(isinstance(target,ast.Name) and target.id in names for target in node.targets)):
            found.update(ast.literal_eval(node.value.args[0]))
    assert found and found<=UNREVIEWABLE_REASONS
