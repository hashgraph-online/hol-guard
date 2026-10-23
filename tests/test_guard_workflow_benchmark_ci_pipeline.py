"""Orchestration negatives; installed-product proof is the separate actual VM run."""
from contextlib import nullcontext
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from ci.gauntlet.benchmark import ci_pipeline as pipeline
from ci.gauntlet.benchmark.beta_profile import (
    build_feature_ai_profile, build_profile, feature_ai_protocol_mapping)
from ci.gauntlet.benchmark.contracts import canonical_json

SHA = '9'*40


def test_rust_worker_key_descriptor_is_opt_in_and_rejects_text_selectors(monkeypatch):
    monkeypatch.delenv('HOL_GAUNTLET_RUST_SIGNING_KEY_FD', raising=False)
    assert pipeline._rust_worker_signing_key('deterministic') is None
    monkeypatch.setenv('HOL_GAUNTLET_RUST_SIGNING_KEY_FD', '3;python')
    with pytest.raises(ValueError, match='signing-key descriptor'):
        pipeline._rust_worker_signing_key('deterministic')
    assert 'HOL_GAUNTLET_RUST_SIGNING_KEY_FD' not in os.environ


@pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                    reason='sealed Root memfd requires Linux Root')
def test_rust_worker_key_requires_a_sealed_single_use_root_fd(monkeypatch):
    import fcntl
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes(range(32))
    required = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    fd = os.memfd_create('gauntlet-test-key', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    os.write(fd, seed)
    os.lseek(fd, 0, os.SEEK_SET)
    monkeypatch.setenv('HOL_GAUNTLET_RUST_SIGNING_KEY_FD', str(fd))
    with pytest.raises(ValueError, match='sealed Root-owned'):
        pipeline._rust_worker_signing_key('deterministic')
    with pytest.raises(OSError):
        os.fstat(fd)

    fd = os.memfd_create('gauntlet-test-key', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    os.write(fd, seed)
    os.lseek(fd, 0, os.SEEK_SET)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, required)
    monkeypatch.setenv('HOL_GAUNTLET_RUST_SIGNING_KEY_FD', str(fd))
    key = pipeline._rust_worker_signing_key('deterministic')
    assert isinstance(key, Ed25519PrivateKey)
    assert key.public_key().public_bytes_raw() == (
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw())
    assert 'HOL_GAUNTLET_RUST_SIGNING_KEY_FD' not in os.environ
    with pytest.raises(OSError):
        os.fstat(fd)


def loaded():
    campaign, selection, policy = build_profile()
    return {'config': {'schema': 'gauntlet-ci-runner.v7', 'selection': selection},
            'config_digest': 'a'*64, 'campaign': campaign, 'policy': policy,
            'runtime': {'guard_source_sha': SHA}, 'shards': [[key] for key in selection]}


@pytest.fixture
def harness(tmp_path, monkeypatch):
    args = SimpleNamespace(profile='deterministic', config=tmp_path/'config.json',
        expected_config_digest='a'*64, expected_guard_source_sha=SHA,
        asset_root=tmp_path/'assets', state_root=tmp_path/'state', output_dir=tmp_path/'out')
    value = loaded()
    calls = []
    monkeypatch.setattr(pipeline, 'destinations', lambda _: None)
    monkeypatch.setattr(pipeline, 'load_config', lambda *a, **kw: value)
    monkeypatch.setattr(pipeline, 'vm_lease', nullcontext)
    def private(path, create=False, **kw):
        if create:
            path.mkdir(mode=0o700)
        return path
    monkeypatch.setattr(pipeline.ci_runner, 'private_state', private)
    def deterministic(_loaded, root):
        calls.append('deterministic')
        root.mkdir()
        return {'schema':'gauntlet-deterministic-result.v1','status':'passed','exit_code':0,
                'selected_cases':6,'cells':[{'episode_id':key,'status':'passed','reasons':[]}
                                          for key in pipeline.deterministic.ROLES], 'errors':[]}
    monkeypatch.setattr(pipeline.deterministic, 'run_profile', deterministic)
    monkeypatch.setattr(pipeline, 'admit_matrix', lambda *a: {'planned_tokens':900000})
    def freeze(_loaded, root):
        calls.append('freeze');root.mkdir()
        return {'manifest_digest':'b'*64,'preflight_passed':True}
    monkeypatch.setattr(pipeline.ci_runner, 'freeze', freeze)
    gates = {}
    def run(_loaded, root, *, expected_manifest_digest, shard):
        assert expected_manifest_digest == 'b'*64
        calls.append(shard)
        path = root/f'diagnostic-{shard}'
        (path/'gate').mkdir(parents=True)
        key = value['config']['selection'][shard]
        gate = gates.get(shard, {'cells':[{'episode_id':key,'status':'passed','reasons':[]}],'errors':[]})
        (path/'gate/result.json').write_text(canonical_json(gate))
        return {'exit_code':1 if gate['cells'][0]['reasons'] else 0,'diagnostic_directory':str(path)}
    monkeypatch.setattr(pipeline.ci_runner, 'run_shard', run)
    def report(_loaded, root, *, expected_manifest_digest):
        calls.append('report')
        cells = []
        for i, key in enumerate(value['config']['selection']):
            rule = next(row for row in value['policy']['cells'] if row['episode_id']==key)
            status = 'measured-baseline' if rule['outcome']=='attacked-baseline-measurement' else 'passed'
            cells += gates.get(i, {'cells':[{'episode_id':key,'status':status,'reasons':[]}]})['cells']
        bad = any(c['status']=='failed' for c in cells)
        return {'schema':'gauntlet-ci-result.v1','status':'failed' if bad else 'passed',
                'exit_code':1 if bad else 0,
                'selected_cases':len(value['config']['selection']),'cells':cells,'errors':[],
                'charged_model_tokens_all_attempts':1234}
    monkeypatch.setattr(pipeline.ci_runner, 'report', report)
    return args, value, calls, gates


def result(args):
    folder = args.output_dir/'report'
    value = json.loads((folder/'result.json').read_text())
    tree = ET.parse(folder/'junit.xml')
    for name,pin in json.loads((folder/'manifest.json').read_text())['files'].items():
        assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==pin
    return value, tree


def test_default_is_model_free_and_emits_one_upload_root(harness):
    args, value, calls, _ = harness
    assert pipeline.main(args)==0
    report, xml = result(args)
    assert calls==['deterministic']
    assert report['model_tokens']==0 and report['model_usage_known'] is True
    assert report['ci_policy']=='proposed-blocking' and report['production_ci_activated'] is False
    assert len(xml.findall('.//testcase'))==6 and not xml.findall('.//failure')
    assert report['guard_source_sha']==report['expected_guard_source_sha']==SHA


@pytest.mark.parametrize('revision', ['1'*40, SHA[:12], SHA.upper().replace('9','A'), ''])
def test_stale_or_unpinned_candidate_never_runs(harness, revision):
    args, _, calls, _ = harness;args.expected_guard_source_sha=revision
    assert pipeline.main(args)==2
    report, xml = result(args)
    assert calls==[] and report['status']=='invalid-evidence'
    assert xml.findall('.//failure') and not args.state_root.exists()


@pytest.mark.parametrize('mutation', ['subset','policy','budget','legacy'])
def test_live_check_rejects_incomplete_or_weakened_profile(harness, mutation):
    args, value, calls, _ = harness;args.profile='beta-e2e'
    if mutation=='subset':value['config']['selection']=value['config']['selection'][:2]
    elif mutation=='policy':value['policy']['cells'][0]['outcome']='attacked-baseline-measurement'
    elif mutation=='budget':value['campaign']['budgets']['max_retries']=1
    else:value['config']['schema']='gauntlet-ci-runner.v1'
    assert pipeline.main(args)==2
    report, xml=result(args)
    assert calls==[] and report['model_tokens'] is None
    assert xml.findall('.//failure')


def test_feature_ai_profile_accepts_only_complete_declared_pair():
    campaign, selection, policy = build_feature_ai_profile()
    cells = {row['id']: row for row in campaign['inventory']}
    assert len(selection) == 2
    assert [cells[key]['protected'] for key in selection] == [False, True]
    assert {cells[key]['variant'] for key in selection} == {'target-poisoning'}
    assert [row['outcome'] for row in policy['cells']] == [
        'attacked-baseline-measurement', 'secure-completion']
    value = loaded()
    value.update(campaign=campaign, policy=policy)
    value['config']['selection'] = selection
    pipeline.validate_profile(value, 'feature-ai', SHA)
    value['config']['selection'] = selection[:1]
    with pytest.raises(ValueError, match='complete fixed two-cell'):
        pipeline.validate_profile(value, 'feature-ai', SHA)


def test_feature_ai_check_runs_only_fixed_pair_and_retains_model_usage(harness):
    args, value, calls, _ = harness
    campaign, selection, policy = build_feature_ai_profile()
    value.update(campaign=campaign, policy=policy, shards=[[key] for key in selection])
    value['config']['selection'] = selection
    args.profile = 'feature-ai'
    assert pipeline.main(args) == 0
    report, xml = result(args)
    assert calls == ['freeze', 0, 1, 'report']
    assert report['profile'] == 'feature-ai'
    assert report['selected_cases'] == 2 and report['model_tokens'] == 1234
    assert len(xml.findall('.//testcase')) == 2


def test_protocol_probe_pins_provider_visible_marker_to_both_cells(harness):
    args, value, calls, _ = harness
    campaign, selection, policy = build_feature_ai_profile(protocol=True)
    value.update(campaign=campaign, policy=policy, shards=[[key] for key in selection])
    value['config']['selection'] = selection
    value['runtime']['mcp_protocol_profiles'] = feature_ai_protocol_mapping(selection)
    args.profile = 'feature-ai-protocol'
    pipeline.validate_profile(value, args.profile, SHA)
    value['runtime']['mcp_protocol_profiles'] = {}
    with pytest.raises(ValueError, match='complete fixed two-cell'):
        pipeline.validate_profile(value, args.profile, SHA)
    value['runtime']['mcp_protocol_profiles'] = feature_ai_protocol_mapping(selection)
    assert pipeline.main(args) == 0
    assert calls == ['freeze', 0, 1, 'report']
    assert result(args)[0]['profile'] == 'feature-ai-protocol'


def test_live_check_freezes_runs_every_shard_then_audits(harness):
    args, _, calls, _ = harness;args.profile='beta-e2e'
    assert pipeline.main(args)==0
    report, xml=result(args)
    assert calls==['freeze',*range(12),'report']
    assert report['model_tokens']==1234 and report['model_usage_known']
    assert report['frozen_manifest_digest']=='b'*64 and report['ci_policy']=='advisory'
    assert len(xml.findall('.//testcase'))==12 and not xml.findall('.//failure')
    assert len(xml.findall('.//system-out'))==3
    assert [p['phase'] for p in report['phases']]==['invocation','freeze','admission',
        *[f'shard-{i:03d}' for i in range(12)],'aggregate']


def test_real_task_failure_is_retained_and_does_not_skip_other_cells(harness):
    args, value, calls, gates=harness;args.profile='beta-e2e'
    gates[1]={'cells':[{'episode_id':value['config']['selection'][1], 'status':'failed',
                        'reasons':['task-utility-failed']}],'errors':[]}
    assert pipeline.main(args)==1
    report, xml=result(args)
    assert calls==['freeze',*range(12),'report']
    assert report['cells'][1]['reasons']==['task-utility-failed']
    assert len(xml.findall('.//failure'))==1


def test_cleanup_failure_stops_later_admission(harness):
    args, value, calls, gates=harness;args.profile='beta-e2e'
    gates[0]={'cells':[{'episode_id':value['config']['selection'][0], 'status':'failed',
                        'reasons':['cleanup-incomplete']}],'errors':[]}
    assert pipeline.main(args)==2
    report, _=result(args)
    assert calls==['freeze',0,'report']
    assert report['model_usage_known'] is False and report['model_tokens'] is None


def test_cancellation_retains_failure_artifacts_and_audits_without_retry(harness, monkeypatch):
    args, _, calls, _=harness;args.profile='beta-e2e'
    def interrupt(*a, **kw):
        calls.append('interrupted');raise KeyboardInterrupt('synthetic CI cancellation')
    monkeypatch.setattr(pipeline.ci_runner,'run_shard',interrupt)
    assert pipeline.main(args)==130
    report, xml=result(args)
    assert calls==['freeze','interrupted','report']
    assert report['status']=='interrupted' and report['model_tokens'] is None
    assert xml.findall('.//failure')


def test_empty_aggregate_cannot_pass(harness, monkeypatch):
    args, _, _, _=harness;args.profile='beta-e2e'
    monkeypatch.setattr(pipeline.ci_runner,'report',lambda *a, **kw:
        {'selected_cases':0,'cells':[],'exit_code':0,'errors':[]})
    assert pipeline.main(args)==2
    assert result(args)[1].findall('.//failure')


def test_cancellation_stays_130_when_partial_ledger_cannot_be_audited(harness, monkeypatch):
    args, _, _, _=harness;args.profile='beta-e2e'
    def interrupt(*a, **kw):raise KeyboardInterrupt('interrupted model boundary')
    def partial(*a, **kw):raise ValueError('unresolved partial ledger')
    monkeypatch.setattr(pipeline.ci_runner,'run_shard',interrupt)
    monkeypatch.setattr(pipeline.ci_runner,'report',partial)
    assert pipeline.main(args)==130
    report, xml=result(args)
    assert report['model_tokens'] is None and report['model_usage_known'] is False
    assert report['frozen_manifest_digest']=='b'*64
    assert report['audit_diagnostic']['message']=='unresolved partial ledger'
    assert xml.findall('.//failure')


def test_provider_admission_uses_bound_persistent_ceiling(tmp_path):
    root=tmp_path/'state';root.mkdir()
    value=loaded();value['selection_reservations']={'model_token_reservation':900000}
    binding={'maximum_accounted_tokens':1600000}
    path=tmp_path/'provider.json';path.write_text(canonical_json({'binding':binding}))
    value['paths']={'provider_manifest':path}
    value['config']['provider']={'binding_sha256':hashlib.sha256((canonical_json(binding)+'\n').encode()).hexdigest()}
    def witness(known):
        (root/'preflight.json').write_text(canonical_json({'provider':{'status':{'quota':
            {'known_tokens':known,'token_cap':10000000}}}}))
    witness(700000)
    assert pipeline.admit_matrix(value,root)['planned_tokens']==900000
    witness(700001)
    with pytest.raises(ValueError,match='approved provider allowance'):pipeline.admit_matrix(value,root)
    witness(1);value['config']['provider']['binding_sha256']='0'*64
    with pytest.raises(ValueError,match='does not bind'):pipeline.admit_matrix(value,root)


def test_vm_lease_rejects_overlap_and_releases_on_exception(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline.ci_runner,'private_state',lambda p,**kw:p)
    folder=tmp_path/'lease'
    with pytest.raises(RuntimeError):
        with pipeline._lease_at(folder):
            with pytest.raises(ValueError,match='another Gauntlet'):
                with pipeline._lease_at(folder):pytest.fail('overlapping lease admitted')
            raise RuntimeError('synthetic failure')
    with pipeline._lease_at(folder):pass


def test_vm_lease_rejects_symlink(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline.ci_runner,'private_state',lambda p,**kw:p)
    folder=tmp_path/'lease';folder.mkdir();target=tmp_path/'target';target.write_text('preserve')
    (folder/'pipeline.lock').symlink_to(target)
    with pytest.raises(OSError):
        with pipeline._lease_at(folder):pytest.fail('symlink lease admitted')
    assert target.read_text()=='preserve'


def test_destinations_refuse_existing_or_overlapping_evidence(tmp_path):
    args=SimpleNamespace(state_root=Path('/opt/hgc-inert-unique'),output_dir=tmp_path/'out',asset_root=tmp_path/'assets')
    pipeline.destinations(args)
    args.output_dir.mkdir()
    with pytest.raises(FileExistsError):pipeline.destinations(args)
    args.output_dir=tmp_path/'assets/subdir'
    with pytest.raises(ValueError,match='disjoint'):pipeline.destinations(args)


def test_cli_dispatches_single_check_without_manual_freeze_or_shard(monkeypatch, tmp_path):
    from ci.gauntlet.benchmark.__main__ import main
    observed=[]
    monkeypatch.setattr(pipeline,'main',lambda args:observed.append(args) or 0)
    argv=['ci','check','--config',str(tmp_path/'config.json'),
          '--expected-config-digest','a'*64,'--asset-root',str(tmp_path/'assets'),
          '--state-root','/opt/hgc-cli','--output-dir',str(tmp_path/'out'),
          '--expected-guard-source-sha',SHA]
    assert main(argv)==0 and observed[0].profile=='deterministic'
    assert main(argv+['--profile','beta-e2e'])==0 and observed[1].profile=='beta-e2e'
    with pytest.raises(SystemExit) as error:main(argv+['--shard','0'])
    assert error.value.code==2 and len(observed)==2
