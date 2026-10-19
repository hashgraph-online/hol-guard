"""Inert runner contract/negative controls, never model or protected workflow proof."""
import hashlib
import json
import os
import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import ci_runner, ci_runner_config, ci_runner_preflight
from ci.gauntlet.benchmark.campaign import DEFAULT_BUDGETS, compile_campaign
from ci.gauntlet.benchmark.catalog import get_workflow
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.local_campaign import _append
from ci.gauntlet.benchmark.provider_quota import ProviderQuota


def write(path,value):
    path.write_text(canonical_json(value)+'\n')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def specimen(tmp_path):
    root = tmp_path/'assets'
    root.mkdir()
    campaign = compile_campaign([get_workflow('business-finance-invoice-reconciliation')],
        repetitions=1,budgets={**DEFAULT_BUDGETS,'campaign_tokens':100000,'max_retries':0})
    selection = [row['id'] for row in campaign['inventory'] if row['variant']=='clean']
    policy = {'schema':'gauntlet-ci-gate-policy.v1','id':'inert-test',
              'cells':[{'episode_id':key,'outcome':'secure-completion','required_surfaces':[]} for key in selection]}
    assets = {}
    for name in sorted(ci_runner_config.FILE_ROLES):
        path = root/name
        path.write_text('inert public artifact for '+name)
        path.chmod(0o700)
        assets[name] = {'path':name,'kind':'file','sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    for name,kind in ci_runner_config.TREE_ROLES.items():
        (root/name).mkdir()
        assets[name] = {'path':name,'kind':kind,'sha256':'a'*64}
    pins = {'profile':'owned-mlx-serial.v1','quota_config_digest':'b'*64,'model_identity_digest':'c'*64,
            'binding_sha256':'d'*64,'adapter_sha256':'e'*64,'server_sha256':'f'*64,
            'token_cap':3000000,'maximum_requests':10000}
    config = {'schema':'gauntlet-ci-runner.v1','id':'inert-test',
              'campaign':{'path':'campaign.json','sha256':write(root/'campaign.json',campaign)},
              'policy':{'path':'policy.json','sha256':write(root/'policy.json',policy)},
              'selection':selection,'shards':2,'assets':assets,'provider':pins,
              'runtime':{'base_url':'http://host.lima.internal:8002/v1','model_id':'inert-model',
                         'guard_source_sha':'1'*40,'guard_bwrap_sha256':'2'*64,
                         'guard_executor_image_id':'sha256:'+'3'*64}}
    path = tmp_path/'config.json'
    write(path,config)
    return root,path,config


def load(root,path,config):
    return ci_runner_config.load_config(path,expected_digest=digest(config),asset_root=root)


def status(pins, *, known=18):
    return {'binding_sha256':pins['binding_sha256'],'qualification':False,
        'adapter':{'schema':'gauntlet-mlx-quota-adapter.v1','server_sha256':pins['server_sha256'],
          'adapter_sha256':pins['adapter_sha256'],'quota_config_digest':pins['quota_config_digest'],
          'producer_mode':'serial-original-tokenization-and-generation',
          'counting':'full prompt including cached input plus every producer-emitted response token',
          'batching':False,'draft':False,'qualification_eligible':False},
        'quota':{'schema':'gauntlet-provider-quota-status.v1','config_digest':pins['quota_config_digest'],
          'model_identity_digest':pins['model_identity_digest'],'token_cap':pins['token_cap'],
          'charged_tokens':known,'known_tokens':known,'reserved_tokens':0,'requests':1,
          'maximum_requests':pins['maximum_requests'],'pending_requests':0,'halted':False,
          'remaining_tokens':pins['token_cap']-known,'journal_hash':'a'*64,'qualification_eligible':False}}


def test_config_relocation_and_exact_partition(tmp_path):
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    assert loaded['shards'] == [[key] for key in config['selection']]
    assert loaded['runtime']['guard_python'] == str(root/'guard_prefix/bin/python')
    assert loaded['runtime']['protected_adapter'] == 'hol-guard'
    assert loaded['runtime']['isolated'] is loaded['runtime']['product_isolated'] is True


@pytest.mark.parametrize('mutation',[
    lambda c:c.update(shards=True),lambda c:c.update(shards=3),
    lambda c:c.update(selection=c['selection']*2),lambda c:c.update(extra='unknown'),
    lambda c:c['assets']['node'].update(path='../node'),
    lambda c:c['assets']['node'].update(path='a/../node'),
    lambda c:c['assets']['node'].update(path='/usr/bin/node'),
    lambda c:c['assets']['node'].update(path='a//node'),
    lambda c:c['assets']['sdk'].update(kind='file'),
    lambda c:c['runtime'].update(base_url='http://remote.test:8002/v1'),
    lambda c:c['provider'].update(token_cap=99999),
    lambda c:c['assets'].pop('wheel'),
])
def test_malformed_or_unsafe_config_rejected_before_execution(tmp_path,mutation):
    root,path,config = specimen(tmp_path)
    mutation(config)
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


def test_external_pin_and_document_pins_precede_candidate_use(tmp_path):
    root,path,config = specimen(tmp_path)
    with pytest.raises(ValueError,match='external pin'):
        ci_runner_config.load_config(path,expected_digest='0'*64,asset_root=root)
    (root/'campaign.json').write_text('{}')
    with pytest.raises(ValueError,match='campaign bytes'):
        load(root,path,config)


def test_symlink_escape_and_duplicate_input_fields_rejected(tmp_path):
    root,path,config = specimen(tmp_path)
    (root/'escape').symlink_to(tmp_path)
    config['assets']['node']['path'] = 'escape/node'
    write(path,config)
    with pytest.raises(ValueError,match='escapes'):
        load(root,path,config)
    path.write_text('{"schema":1,"schema":2}')
    with pytest.raises(ValueError,match='duplicate'):
        load(root,path,config)


def test_policy_exception_cannot_be_assigned_to_clean_or_guard_cells(tmp_path):
    root,path,config = specimen(tmp_path)
    policy = json.loads((root/'policy.json').read_text())
    policy['cells'][0]['outcome'] = 'attacked-baseline-measurement'
    config['policy']['sha256'] = write(root/'policy.json',policy)
    write(path,config)
    with pytest.raises(ValueError,match='measurement exception'):
        load(root,path,config)


def test_environment_restores_path_and_umask_on_failure(tmp_path):
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    original_path = os.environ.get('PATH')
    original_mask = os.umask(0o027)
    try:
        with pytest.raises(RuntimeError),ci_runner_preflight.controller_environment(loaded):
            assert os.environ['PATH'].split(':')[0] == str(root)
            previous = os.umask(0o077)
            assert previous == 0o077
            raise RuntimeError('synthetic controller interruption')
        assert os.environ.get('PATH') == original_path
        assert os.umask(0o027) == 0o027
    finally:
        os.umask(original_mask)


@pytest.mark.parametrize('target,key,value',[
    ('quota','known_tokens',True),('quota','known_tokens',18.0),('quota','reserved_tokens',1),
    ('quota','pending_requests',1),('quota','halted',True),('quota','remaining_tokens',3000000),
    ('quota','config_digest','0'*64),('quota','model_identity_digest','0'*64),
    ('quota','journal_hash','bad'),('quota','qualification_eligible',True),
    ('adapter','draft',True),('adapter','batching',0),('adapter','server_sha256','0'*64),
])
def test_changed_or_unknown_provider_state_cannot_admit(tmp_path,target,key,value):
    _,_,config = specimen(tmp_path)
    record = status(config['provider'])
    assert ci_runner_preflight.verify_provider_status(record,config['provider'])['known_tokens'] == 18
    record[target][key] = value
    with pytest.raises(ValueError):
        ci_runner_preflight.verify_provider_status(record,config['provider'])


def test_actual_durable_quota_snapshot_satisfies_status_contract(tmp_path):
    _,_,config = specimen(tmp_path)
    quota = ProviderQuota.create((tmp_path/'quota').resolve(),authorization_id='inert-runner-test',
        total_tokens=3000000,maximum_requests=10000,model_identity_digest=config['provider']['model_identity_digest'])
    config['provider']['quota_config_digest'] = quota.expected_config_digest
    record = status(config['provider'])
    record['quota'] = quota.snapshot()
    assert ci_runner_preflight.verify_provider_status(record,config['provider'])['known_tokens'] == 0
    lease = quota.reserve(prompt_tokens=15,output_limit=8,request_digest='a'*64)
    record['quota'] = quota.snapshot()
    with pytest.raises(ValueError):
        ci_runner_preflight.verify_provider_status(record,config['provider'])
    quota.settle(lease,prompt_tokens=15,output_tokens=3)
    record['quota'] = quota.snapshot()
    assert ci_runner_preflight.verify_provider_status(record,config['provider'])['known_tokens'] == 18


def test_aggregate_budget_cannot_restart_at_each_shard(tmp_path):
    for name in ('shard-000','shard-001'):
        (tmp_path/name).mkdir()
    manifest = {'shards':[{'directory':'shard-000'},{'directory':'shard-001'}]}
    _append(tmp_path/'shard-000',[],{'type':'finish','episode_id':'inert',
        'charged_tokens':90,'elapsed_seconds':9,'report':{'inference_started':True,
                                                      'model_usage_known':True,'model_tokens':90}})
    budgets = {'campaign_tokens':100,'campaign_seconds':20}
    reserve = {'model_token_reservation':11,'controller_seconds_reservation':1}
    assert ci_runner.aggregate_admission(tmp_path,manifest,budgets,{},reserve) == 'aggregate-campaign-budget-limit'
    reserve['model_token_reservation'] = 10
    assert ci_runner.aggregate_admission(tmp_path,manifest,budgets,{},reserve) is None
    reserve['controller_seconds_reservation'] = 12
    assert ci_runner.aggregate_admission(tmp_path,manifest,budgets,{},reserve) == 'aggregate-campaign-budget-limit'


def test_cli_invalid_config_exports_nonzero_json_junit_and_manifest(tmp_path):
    root,path,_config = specimen(tmp_path)
    args = SimpleNamespace(config=path,expected_config_digest='0'*64,asset_root=root,
                           action='preflight',output_dir=tmp_path/'output')
    assert ci_runner.main(args) == 2
    result = json.loads((args.output_dir/'result.json').read_text())
    assert result['status'] == 'invalid-evidence' and result['qualification_eligible'] is False
    assert (args.output_dir/'junit.xml').is_file()
    with pytest.raises(FileExistsError):
        ci_runner.main(args)


def test_same_digest_does_not_allow_shard_path_substitution(tmp_path,monkeypatch):
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    state = tmp_path/'state'
    state.mkdir()
    monkeypatch.setattr(ci_runner,'private_state',lambda root,**_:Path(root))
    diagnosis = {'inert':True}
    write(state/'preflight.json',diagnosis)
    manifest = {'schema':'gauntlet-ci-freeze.v1','runner_config_digest':loaded['config_digest'],
        'asset_root':str(root),'selection':config['selection'],'preflight_digest':digest(diagnosis),
        'shards':[{'index':i,'directory':'../escape','selection':selection,
                   'policy_digest':digest(ci_runner._policy(loaded,selection))}
                  for i,selection in enumerate(loaded['shards'])]}
    write(state/'manifest.json',manifest)
    with pytest.raises(ValueError,match='partition'):
        ci_runner.load_frozen(loaded,state,expected_manifest_digest=digest(manifest))


def test_asset_mutation_rejected_as_bytes_not_imported(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark import business_agent_container, native_product_container
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    monkeypatch.setattr(business_agent_container,'freeze_public_tree',lambda _: {'tree_digest':'a'*64})
    monkeypatch.setattr(native_product_container,'root_prefix_inventory',lambda _: {'digest':'a'*64})
    assert ci_runner_config.verify_assets(loaded)['node'] == config['assets']['node']['sha256']
    (root/'native').write_text('raise RuntimeError("never execute captured native source")')
    with pytest.raises(ValueError,match='native differs'):
        ci_runner_config.verify_assets(loaded)


def test_metadata_observer_uses_only_fixed_get_paths_without_redirects(tmp_path,monkeypatch):
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    bodies = [canonical_json({'data':[{'id':'inert-model'}]}).encode(),
              canonical_json(status(config['provider'])).encode()]
    calls = []
    class Connection:
        def __init__(self,host,port,timeout):
            assert (host,port,timeout) == ('192.168.5.2',8002,5)
        def request(self,method,path,headers):
            calls.append((method,path))
            assert headers == {'Connection':'close'}
        def getresponse(self):
            return SimpleNamespace(status=200,read=lambda _:bodies.pop(0))
        def close(self):
            pass
    monkeypatch.setattr(ci_runner_preflight.http.client,'HTTPConnection',Connection)
    observed = ci_runner_preflight.observe_provider(loaded)
    assert observed['status']['quota']['known_tokens'] == 18
    assert calls == [('GET','/v1/models'),('GET','/v1/benchmark-quota')]


def test_preflight_retains_supported_and_unsupported_selected_cells(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark import local_campaign_custody
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    protected = next(row for row in loaded['campaign']['inventory'] if row['protected'] and row['variant']=='clean')
    rule = next(row for row in loaded['policy']['cells'] if row['episode_id']==protected['id'])
    rule['required_surfaces'] = ['native-contained-execution','guard-external-approval']
    monkeypatch.setattr(ci_runner_preflight.sys,'platform','linux')
    monkeypatch.setattr(ci_runner_preflight.os,'geteuid',lambda:0)
    monkeypatch.setattr(ci_runner_preflight,'verify_assets',lambda _: {'inert-test':True})
    monkeypatch.setattr(local_campaign_custody,'freeze_isolation',lambda _: {'inert-test':True})
    monkeypatch.setattr(ci_runner_preflight,'observe_provider',lambda _: {'status':status(config['provider'])})
    result = ci_runner_preflight.preflight(loaded)
    assert result['passed'] is False and result['selected_cases']==2
    assert result['shards'] == loaded['shards']
    assert result['unsupported_cells'] == [{'episode_id':protected['id'],
        'reason':'required surface lacks reviewed conformance',
        'surfaces':['guard-external-approval','native-contained-execution']}]


def test_partial_and_modified_invocation_witnesses_cannot_become_passes(tmp_path,monkeypatch):
    root,path,config = specimen(tmp_path)
    loaded = load(root,path,config)
    state = tmp_path/'state'
    attempt = state/'controller-attempts/attempt-001'
    attempt.mkdir(parents=True)
    monkeypatch.setattr(ci_runner,'private_state',lambda root,**_:Path(root))
    manifest = {'shards':[{}]}
    with pytest.raises(ValueError,match='bounded ordinary file'):
        ci_runner.audit_invocations(loaded,state,manifest,expected_manifest_digest='1'*64,charged_tokens=18)
    write(attempt/'preflight.json',{'config_digest':loaded['config_digest'],'passed':True})
    write(attempt/'provider-before.json',{'status':status(config['provider'])})
    write(attempt/'provider-after.json',{'status':status(config['provider'],known=36)})
    write(attempt/'controller-result.json',{'inert':True})
    files = {name:ci_runner_config.file_digest(attempt/name) for name in
             ('preflight.json','provider-before.json','provider-after.json','controller-result.json')}
    row = {'status':'failed','runner_config_digest':loaded['config_digest'],'manifest_digest':'1'*64,
           'shard':0,'files':files,'provider_tokens_delta':18,'ledger_charge_before':0,'ledger_charge_after':18}
    write(attempt/'result.json',row)
    assert ci_runner.audit_invocations(loaded,state,manifest,expected_manifest_digest='1'*64,charged_tokens=18)==[]
    assert ci_runner.audit_invocations(loaded,state,manifest,expected_manifest_digest='1'*64,charged_tokens=19)==[
        'aggregate-provider-and-ledger-cost-mismatch']
    write(attempt/'provider-after.json',{'status':status(config['provider'],known=37)})
    with pytest.raises(ValueError,match='evidence changed'):
        ci_runner.audit_invocations(loaded,state,manifest,expected_manifest_digest='1'*64,charged_tokens=18)


def test_real_sigterm_becomes_cancelled_artifacts_and_restores_handler(tmp_path,monkeypatch):
    root,path,config = specimen(tmp_path)
    original = signal.getsignal(signal.SIGTERM)
    def terminate(_loaded):
        os.kill(os.getpid(),signal.SIGTERM)
        raise AssertionError('signal handler did not interrupt')
    monkeypatch.setattr(ci_runner,'preflight',terminate)
    args = SimpleNamespace(config=path,expected_config_digest=digest(config),asset_root=root,
                           action='preflight',output_dir=tmp_path/'cancelled')
    assert ci_runner.main(args)==130
    result = json.loads((args.output_dir/'result.json').read_text())
    assert result['status']=='cancelled' and len(result['cells'])==len(config['selection'])
    assert signal.getsignal(signal.SIGTERM)==original


def test_cli_preflight_structured_diagnostics_emit_valid_junit(tmp_path,monkeypatch):
    root,path,config = specimen(tmp_path)
    monkeypatch.setattr(ci_runner,'preflight',lambda _: {'schema':'gauntlet-ci-preflight.v1',
        'passed':False,'errors':[{'code':'synthetic-capability-failure','message':'retained detail'}],
        'selected_cases':len(config['selection']),'qualification_eligible':False})
    args = SimpleNamespace(config=path,expected_config_digest=digest(config),asset_root=root,
                           action='preflight',output_dir=tmp_path/'diagnostics')
    assert ci_runner.main(args)==2
    result = json.loads((args.output_dir/'result.json').read_text())
    assert result['errors']==['synthetic-capability-failure']
    assert result['diagnostics']==[{'code':'synthetic-capability-failure','message':'retained detail'}]
    assert len(result['cells'])==len(config['selection'])


@pytest.mark.skipif(sys.platform!='linux' or os.geteuid()!=0,reason='actual private Linux Root state')
def test_root_state_ancestry_and_exclusive_shard_lock(tmp_path):
    root = ci_runner.private_state(tmp_path/'state',create=True)
    with ci_runner.controller_lock(root):
        assert (root/'ci-controller.lock').is_file()
        with pytest.raises(FileExistsError),ci_runner.controller_lock(root):
            raise AssertionError('another controller acquired the campaign')
    assert not (root/'ci-controller.lock').exists()
    with ci_runner.controller_lock(root):
        pass
    root.chmod(0o750)
    with pytest.raises(ValueError,match='private'):
        ci_runner.private_state(root)
    root.chmod(0o700)
    parent = tmp_path/'untrusted-parent'
    parent.mkdir(mode=0o700)
    leaf = parent/'root-owned-leaf'
    leaf.mkdir(mode=0o700)
    os.chown(parent,10004,10004)
    try:
        with pytest.raises(ValueError,match='ancestry'):
            ci_runner.private_state(leaf)
    finally:
        os.chown(parent,0,0)


@pytest.mark.skipif(sys.platform!='linux' or os.geteuid()!=0,reason='actual private Linux Root state')
def test_private_cell_state_rejects_sticky_ancestry_before_creation(tmp_path):
    # pytest's Root-owned private leaf cannot make /tmp immutable for PID1.
    assert tmp_path.is_relative_to('/tmp')
    root = tmp_path/'private-cell-state'
    with pytest.raises(ValueError,match='ancestry'):
        ci_runner.private_state(root,create=True,immutable_ancestry=True)
    assert not root.exists()


def private_specimen(tmp_path):
    root,path,config = specimen(tmp_path)
    config['schema']='gauntlet-ci-runner.v2'
    (root/'cell').mkdir()
    config['assets']['private_cell']={'path':'cell','kind':'cell-artifacts','sha256':'4'*64}
    config['runtime']['private_cell']={'initializer_sha256':'5'*64,
        'native_sha256':config['assets']['native']['sha256'],'runtime_tree_digest':'6'*64,
        'idmap_runtime':'ubuntu2404-controller-v1','cpu_profile':'single-core-v1'}
    write(path,config)
    return root,path,config


def test_private_cell_config_relocates_without_promoting_conformance(tmp_path):
    root,path,config = private_specimen(tmp_path)
    loaded=load(root,path,config)
    cfg=loaded['runtime']['guard_private_cell']
    assert cfg=={'schema':'developer-private-cell-config.v1','artifacts':str(root/'cell'),
        'artifact_manifest_sha256':'4'*64,**config['runtime']['private_cell']}
    assert loaded['runtime']['guard_executor_image_id']==config['runtime']['guard_executor_image_id']
    assert 'conformance_verified' not in loaded['runtime']


@pytest.mark.parametrize('mutation',[
    lambda c:c.update(schema='gauntlet-ci-runner.v1'),
    lambda c:c['assets'].pop('private_cell'),
    lambda c:c['assets']['private_cell'].update(kind='sdk-tree'),
    lambda c:c['runtime']['private_cell'].update(artifacts='/unapproved/absolute'),
    lambda c:c['runtime']['private_cell'].update(native_sha256='0'*64),
    lambda c:c['runtime']['private_cell'].update(cpu_profile=True),
    lambda c:c['runtime']['private_cell'].update(idmap_runtime='arbitrary'),
    lambda c:c['runtime']['private_cell'].update(conformance_verified=True),
])
def test_private_cell_config_cannot_enter_old_lane_or_select_unpinned_runtime(tmp_path,mutation):
    root,path,config=private_specimen(tmp_path)
    mutation(config)
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


def test_conformance_v3_relocates_pinned_inert_package_and_preserves_old_versions(tmp_path):
    root,path,config=private_specimen(tmp_path)
    config['schema']='gauntlet-ci-runner.v3'
    package=root/'conformance.json'
    package.write_text('{"inert":"not conformance until verified"}')
    config['assets']['conformance']={'path':'conformance.json','kind':'file',
        'sha256':hashlib.sha256(package.read_bytes()).hexdigest()}
    write(path,config)
    loaded=load(root,path,config)
    assert loaded['runtime']['guard_conformance']=={'path':str(package),
        'sha256':config['assets']['conformance']['sha256']}
    assert str(package) in loaded['runtime']['artifacts']
    assert 'local_execution_supported' not in loaded['runtime']
    config['schema']='gauntlet-ci-runner.v2'
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


def test_compact_runner_v4_declares_state_layout_and_refuses_unversioned_selection(tmp_path):
    root,path,config=private_specimen(tmp_path)
    config.update(schema='gauntlet-ci-runner.v4',state_layout='compact-v1')
    package=root/'conformance.json'
    package.write_text('{}')
    config['assets']['conformance']={'path':'conformance.json','kind':'file',
        'sha256':hashlib.sha256(package.read_bytes()).hexdigest()}
    write(path,config)
    loaded=load(root,path,config)
    assert loaded['attempt_layout']=='compact-v1'
    config['schema']='gauntlet-ci-runner.v3'
    write(path,config)
    with pytest.raises(ValueError):
        load(root,path,config)


def test_preflight_diagnoses_missing_original_seed_data_without_inference(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark import developer_seed_inputs, local_campaign_custody
    root,path,config=specimen(tmp_path)
    loaded=load(root,path,config)
    monkeypatch.setattr(developer_seed_inputs,'__file__',str(tmp_path/'missing/benchmark/seed.py'))
    monkeypatch.setattr(ci_runner_preflight.sys,'platform','linux')
    monkeypatch.setattr(ci_runner_preflight.os,'geteuid',lambda:0)
    monkeypatch.setattr(ci_runner_preflight,'verify_assets',lambda _: {})
    monkeypatch.setattr(local_campaign_custody,'freeze_isolation',lambda _: {})
    monkeypatch.setattr(ci_runner_preflight,'observe_provider',lambda _: {'status':status(config['provider'])})
    result=ci_runner_preflight.preflight(loaded)
    assert result['passed'] is False
    assert [row['code'] for row in result['errors']]==['developer_seed_inputs-failed']


def test_preflight_diagnoses_missing_grader_bridge_before_inference(tmp_path,monkeypatch):
    from ci.gauntlet.benchmark import developer_probe_inputs, local_campaign_custody
    root,path,config=specimen(tmp_path)
    loaded=load(root,path,config)
    source=tmp_path/'grader';source.mkdir()
    for name in developer_probe_inputs.ASSET_NAMES:
        (source/name).write_bytes(b'# inert public probe fixture\n')
    (source/'developer_node_bridge.mjs').unlink()
    monkeypatch.setattr(developer_probe_inputs,'SOURCE',source)
    monkeypatch.setattr(ci_runner_preflight.sys,'platform','linux')
    monkeypatch.setattr(ci_runner_preflight.os,'geteuid',lambda:0)
    monkeypatch.setattr(ci_runner_preflight,'verify_assets',lambda _: {})
    monkeypatch.setattr(local_campaign_custody,'freeze_isolation',lambda _: {})
    monkeypatch.setattr(ci_runner_preflight,'observe_provider',lambda _: {'status':status(config['provider'])})
    result=ci_runner_preflight.preflight(loaded)
    assert result['passed'] is False
    assert [row['code'] for row in result['errors']]==['developer_probe_inputs-failed']
    assert 'developer_node_bridge.mjs' in result['errors'][0]['message']
