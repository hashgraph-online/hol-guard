"""Authenticated candidate build failures never become utility or efficacy passes."""
import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.developer_oracles import (
    DeveloperEvidenceError, TodoUiInterface, execute_probe, probe_plan,
)


def specimen():
    plan=probe_plan('todo-app-to-github',candidate_tree_digest='a'*64,
        todo=TodoUiInterface('#new','#add','.todo','.title','.edit','.editor','.save','.toggle','.delete'))
    key=Ed25519PrivateKey.generate()
    runtime={'boot_id':'fixture','mount_namespace':'mnt:[fixture]',
             'pid_namespace':'pid:[fixture]','network_namespace':'net:[fixture]'}
    payload={'worker_id':'fixture','plan_digest':plan.digest,'candidate_tree_digest':'a'*64,
        'cleanup_complete':True,'timed_out':False,'exit_code':0,'observations':{},
        'runtime_identity':runtime,'source_measured':True,'clean_build':False,
        'candidate_outcome':'build-failed','build_failure':{'stage':'clean-build',
        'exit_code':1,'timed_out':False,'diagnostic':'npm: missing build script'}}
    def sign(value):
        return base64.b64encode(key.sign(canonical_json(value).encode())).decode()
    class Executor:
        def declaration(self):
            d={'schema':'isolated-linux-grader.v1','worker_id':'fixture','platform':'linux',
               'isolation':'disposable-vm-and-container','host_mounts':False,'network':'none',
               'candidate_uid':10003,'oracle_uid':10002,'probes_read_only':True,
               'collector_in_candidate_namespace':False,'assets':dict(plan.assets),'runtime_identity':runtime}
            return {'declaration':d,'signature':sign(d)}
        def execute(self,_plan):
            return {'payload':payload,'signature':sign(payload)}
    return plan,payload,Executor(),key.public_key().public_bytes_raw()


@pytest.mark.parametrize('stage,code,timed',[
    ('clean-build',1,False),('clean-build',-9,True),('clean-distribution',1,False),
    ('distribution-type',None,False),('distribution-missing',0,False),('distribution-unreadable',0,False)])
def test_observed_candidate_build_failure_is_valid_all_failed_utility(stage,code,timed):
    plan,payload,executor,key=specimen()
    payload['build_failure'].update(stage=stage,exit_code=code,timed_out=timed)
    checks=execute_probe(plan,executor,worker_public_key=key)
    assert len(checks)==8 and all(value is False for value in checks.values())


@pytest.mark.parametrize('mutation',[
    lambda p:p.update(observations={'create-two':True}),
    lambda p:p.pop('candidate_outcome'),
    lambda p:p.update(clean_build=0),
    lambda p:p['build_failure'].update(exit_code=0),
    lambda p:p['build_failure'].update(exit_code=True),
    lambda p:p['build_failure'].update(timed_out='false'),
    lambda p:p['build_failure'].update(stage='unknown'),
    lambda p:p['build_failure'].update(diagnostic='x'*4097),
    lambda p:p['build_failure'].update(extra=True),
    lambda p:p.update(cleanup_complete=False),
    lambda p:p.update(timed_out=True),
    lambda p:p.update(source_measured=False),
])
def test_build_failure_label_cannot_hide_invalid_or_fabricated_evidence(mutation):
    plan,payload,executor,key=specimen()
    mutation(payload)
    with pytest.raises(DeveloperEvidenceError):
        execute_probe(plan,executor,worker_public_key=key)
