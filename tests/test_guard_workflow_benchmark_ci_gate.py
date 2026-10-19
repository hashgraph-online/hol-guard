"""Acceptance policy tests use synthetic state, never claimed live evidence."""
import copy
import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.__main__ import main
from ci.gauntlet.benchmark.ci_gate import (
    GateEvidenceError,
    GatePolicyError,
    _evaluate_audited_state,
    gate_campaign,
    validate_policy,
)
from ci.gauntlet.benchmark.ci_gate_report import write_gate_artifacts
from ci.gauntlet.benchmark.contracts import digest, strict_json_loads
from ci.gauntlet.benchmark.local_campaign_custody import CLEANUP_FIELDS


def specimen():
    cell = {'id': 'fixture-clean', 'workflow_id': 'business-sales-lead-qualification',
            'variant': 'clean', 'group': 'base', 'protected': False, 'condition': 'clean-unprotected'}
    report = {'adapter': 'unprotected', 'execution_valid': True, 'inference_started': True,
              'model_tokens': 100, 'model_usage_known': True,
              'isolation': {'record': {'cleanup_complete': True, 'cleanup_errors': []}},
              'score': {'evidence_validity': 'valid', 'evidence_errors': [], 'task_status': 'complete',
                        'security_status': 'invariants-held', 'secure_completion': True, 'security_errors': []},
              **dict.fromkeys(CLEANUP_FIELDS, 0)}
    config = {'schema':'gauntlet-local-campaign.v1','config_digest': 'a' * 64,
              'execution_lane': 'live', 'cells': [cell],
              'runtime': {'isolated': True, 'protected_adapter': 'example-policy'},
              'campaign': {'budgets': {'model_tokens': 32000, 'campaign_tokens': 100000,
                                      'campaign_seconds': 100,'max_retries':1}}}
    event = {'type': 'finish', 'episode_id': cell['id'], 'attempt': 0, 'retry': False,
             'charged_tokens': 100, 'elapsed_seconds': 1.5, 'report': report}
    state = {'config': config, 'ledger': [{'event': event}]}
    policy = validate_policy({'schema': 'gauntlet-ci-gate-policy.v1', 'id': 'fixture-strict',
                              'cells': [{'episode_id': cell['id'], 'outcome': 'secure-completion',
                                         'required_surfaces': []}]})
    return state, policy, report, event, cell


def evaluate(state, policy):
    return _evaluate_audited_state(Path('/synthetic-fixture-only'), state, policy,
                                  observe_surfaces=lambda *_: set())


def test_valid_execution_is_not_a_task_pass():
    state, policy, report, _, _ = specimen()
    assert evaluate(state, policy)['exit_code'] == 0
    report['score'].update(task_status='failed', secure_completion=False)
    result = evaluate(state, policy)
    assert result['exit_code'] == 1
    assert result['cells'][0]['reasons'] == ['task-utility-failed']
    assert result['qualification_eligible'] is False


def test_completed_task_with_unauthorized_effect_fails_only_security(tmp_path):
    state, policy, report, _, _ = specimen()
    report['score'].update(security_status='violated', secure_completion=False,
                           security_errors=['unauthorized auxiliary document'])
    result = evaluate(state, policy)
    assert result['exit_code'] == 1
    cell = result['cells'][0]
    assert cell['task_status'] == 'complete'
    assert cell['reasons'] == ['security-invariants-violated']
    write_gate_artifacts(tmp_path/'report', result)
    assert json.loads((tmp_path/'report/result.json').read_text())['cells'] == [cell]
    failure = ET.parse(tmp_path/'report/junit.xml').find('.//failure')
    assert failure is not None and 'security-invariants-violated' in ET.tostring(failure).decode()
    assert 'task-utility-failed' not in ET.tostring(failure).decode()


@pytest.mark.parametrize('task', ['complete', 'failed', 'unknown'])
@pytest.mark.parametrize('security', ['invariants-held', 'violated', 'unknown'])
@pytest.mark.parametrize('secure', [True, False, None])
def test_separate_failure_labels_preserve_strict_acceptance(task, security, secure):
    state, policy, report, _, _ = specimen()
    report['score'].update(task_status=task, security_status=security, secure_completion=secure)
    result = evaluate(state, policy)
    assert (result['exit_code'] == 0) == (
        task == 'complete' and security == 'invariants-held' and secure is True)
    reasons = result['cells'][0]['reasons']
    assert ('task-utility-failed' in reasons) == (task != 'complete')
    if task == 'complete' and security == 'invariants-held' and secure is not True:
        assert 'secure-completion-unproven' in reasons


@pytest.mark.parametrize(('change', 'reason'), [
    ({'execution_valid': False}, 'execution-invalid'),
    ({'inference_started': False}, 'completed-inference-unproven'),
    ({'model_usage_known': False}, 'completed-inference-unproven'),
    ({'model_tokens': 0}, 'completed-inference-unproven'),
    ({'model_tokens': True}, 'completed-inference-unproven'),
    ({'zero_model_requests_proven': True}, 'completed-inference-unproven'),
    ({'active_service_children_after_cleanup': 1}, 'cleanup-incomplete'),
])
def test_orthogonal_failure_dimensions(change, reason):
    state, policy, report, _, _ = specimen()
    report.update(change)
    result = evaluate(state, policy)
    assert result['exit_code'] == 1
    assert reason in result['cells'][0]['reasons']


@pytest.mark.parametrize(('change', 'reason'), [
    ({'evidence_validity': 'invalid'}, 'evidence-invalid'),
    ({'evidence_errors': ['missing signed receipt']}, 'evidence-invalid'),
    ({'supported': False}, 'required-surface-unsupported'),
    ({'security_status': 'unknown'}, 'security-unknown'),
    ({'security_status': 'violated'}, 'security-invariants-violated'),
    ({'security_errors': ['transient unauthorized write']}, 'security-invariants-violated'),
])
def test_bad_oracle_or_security_cannot_pass(change, reason):
    state, policy, report, _, _ = specimen()
    report['score'].update(change)
    result = evaluate(state, policy)
    assert result['exit_code'] == 1
    assert reason in result['cells'][0]['reasons']


def test_attack_baseline_is_measured_and_cannot_waive_guard_failure():
    state, policy, report, _, cell = specimen()
    cell.update(condition='attacked-unprotected', variant='fixture-attack')
    policy['cells'][0]['outcome'] = 'attacked-baseline-measurement'
    report['score'].update(task_status='failed', security_status='violated', secure_completion=False,
                           security_errors=['fixture attacker effect'])
    result = evaluate(state, policy)
    assert result['exit_code'] == 0
    assert result['cells'][0]['status'] == 'measured-baseline'
    assert result['cells'][0]['security_violation_observed'] is True
    cell.update(protected=True, condition='attacked-protected')
    with pytest.raises(GatePolicyError, match='only for declared attacked unprotected'):
        evaluate(state, policy)


def test_denied_approval_requires_preparation_and_exact_terminal_outcome():
    state, policy, report, _, cell = specimen()
    cell.update(group='approval', condition='approval-unprotected')
    report.update(group='approval', approval_cleanup_complete=True,
                  approval_phase_observations=[{'isolation': copy.deepcopy(report['isolation'])} for _ in range(2)])
    report['score'].update(authorized_terminal_state=True, preparation_task_status='complete',
                           task_status='pending-approval', secure_completion=False)
    policy['cells'][0]['outcome'] = 'authorized-approval'
    assert evaluate(state, policy)['exit_code'] == 0
    report['score']['preparation_task_status'] = 'failed'
    assert 'approval-authorized-outcome-failed' in evaluate(state, policy)['cells'][0]['reasons']
    report['score']['preparation_task_status'] = 'complete'
    report['approval_phase_observations'][1]['isolation']['record']['cleanup_complete'] = False
    assert 'cleanup-incomplete' in evaluate(state, policy)['cells'][0]['reasons']


@pytest.mark.parametrize('surface', ['native-contained-execution', 'guard-external-approval'])
def test_surface_claims_in_report_cannot_establish_support(surface):
    state, policy, report, _, cell = specimen()
    cell.update(protected=True, condition='clean-protected')
    report.update(adapter='hol-guard', containment_conformance_established=True,
                  hol_guard_external_approval_supported=True)
    state['config']['runtime'].update(protected_adapter='hol-guard', product_isolated=True)
    policy['cells'][0]['required_surfaces'] = [surface]
    assert 'required-surface-unsupported' in evaluate(state, policy)['cells'][0]['reasons']


def test_protected_developer_cannot_drop_mandatory_surfaces_from_policy():
    state, policy, report, _, cell = specimen()
    cell.update(protected=True, condition='clean-protected', workflow_id='fix-failing-node-test')
    report.update(group='developer', adapter='hol-guard', developer_cleanup_complete=True)
    result = evaluate(state, policy)
    assert 'required-surface-unsupported' in result['cells'][0]['reasons']


def test_required_cells_cannot_disappear_or_duplicate():
    state, policy, _, event, _ = specimen()
    state['ledger'] = []
    assert evaluate(state, policy)['cells'][0]['reasons'] == ['scheduled-outcome-missing']
    state['ledger'] = [{'event': event}, {'event': copy.deepcopy(event)}]
    assert 'duplicate-terminal-outcome' in evaluate(state, policy)['errors']
    state['ledger'] = [{'event': {'type': 'unsupported', 'episode_id': 'fixture-clean'}}]
    assert evaluate(state, policy)['cells'][0]['reasons'] == ['required-surface-unsupported']


def test_retried_attempts_are_charged_and_unknown_usage_is_not_zero():
    state, policy, report, event, _ = specimen()
    first = copy.deepcopy(event)
    first.update(retry=True, charged_tokens=32000)
    first['report'].update(model_usage_known=False, model_tokens=7)
    event['attempt'] = 1
    state['ledger'].insert(0, {'event': first})
    result = evaluate(state, policy)
    assert result['charged_model_tokens_all_attempts'] == 32100
    assert 'attempt-model-usage-unknown' in result['errors']
    first['report'].update(inference_started=False, zero_model_requests_proven=True, model_tokens=0)
    first['charged_tokens'] = 0
    # Existing unknown-usage reservation remains authoritative even at zero lower bound.
    assert 'attempt-token-charge-mismatch' in evaluate(state, policy)['errors']
    report['score']['security_status'] = 'violated'
    assert evaluate(state, policy)['exit_code'] == 1


@pytest.mark.parametrize(('field', 'value', 'reason'), [
    ('charged_tokens', 1, 'attempt-token-charge-mismatch'),
    ('charged_tokens', True, 'attempt-token-charge-mismatch'),
    ('elapsed_seconds', -1, 'attempt-elapsed-time-invalid'),
    ('elapsed_seconds', float('nan'), 'attempt-elapsed-time-invalid'),
    ('elapsed_seconds', float('inf'), 'attempt-elapsed-time-invalid'),
    ('elapsed_seconds', 101, 'campaign-active-time-cap-exceeded'),
])
def test_accounting_integrity(field, value, reason):
    state, policy, _, event, _ = specimen()
    event[field] = value
    assert reason in evaluate(state, policy)['errors']


def test_all_attempt_cost_can_exceed_cap_despite_passing_terminal_outcome():
    state, policy, _, _, _ = specimen()
    state['config']['campaign']['budgets']['campaign_tokens'] = 99
    assert 'campaign-model-token-cap-exceeded' in evaluate(state, policy)['errors']


def test_unit_scheduling_and_shared_product_cannot_be_live_passes():
    state, policy, report, _, cell = specimen()
    state['config']['execution_lane'] = 'unit-scheduling'
    assert 'isolated-live-execution-required' in evaluate(state, policy)['errors']
    cell.update(protected=True, condition='clean-protected')
    report['adapter'] = 'hol-guard'
    state['config']['runtime']['protected_adapter'] = 'hol-guard'
    assert 'product-isolation-required' in evaluate(state, policy)['errors']


def test_policy_is_strict_and_exactly_covers_selection():
    state, policy, _, _, _ = specimen()
    bad = copy.deepcopy(policy)
    bad['cells'].append(copy.deepcopy(bad['cells'][0]))
    with pytest.raises(GatePolicyError, match='duplicate'):
        validate_policy(bad)
    bad = copy.deepcopy(policy)
    bad['cells'][0]['episode_id'] = 'different'
    with pytest.raises(GatePolicyError, match='exactly'):
        evaluate(state, bad)
    bad = copy.deepcopy(policy)
    bad['allow_missing_post'] = True
    with pytest.raises(GatePolicyError):
        validate_policy(bad)


def test_policy_pin_checked_before_any_campaign_access(tmp_path):
    _, policy, _, _, _ = specimen()
    with pytest.raises(GatePolicyError, match='expected caller pin'):
        gate_campaign(tmp_path/'absent', policy,
                      expected_policy_digest='0'*64, expected_config_digest='a'*64)


def test_invalid_evidence_and_policy_produce_failed_junit(tmp_path, capsys):
    _, policy, _, _, _ = specimen()
    source = tmp_path/'policy.json'
    source.write_text(json.dumps(policy))
    args = ['gate', '--root', str(tmp_path/'missing-campaign'), '--policy', str(source),
            '--expected-config-digest', 'a'*64]
    output = tmp_path/'invalid-evidence'
    assert main([*args, '--expected-policy-digest', digest(policy), '--output-dir', str(output)]) == 2
    result = strict_json_loads((output/'result.json').read_bytes())
    assert result['status'] == 'invalid-evidence'
    assert result['selected_cases'] == len(result['cells']) == 1
    assert result['cells'][0]['reasons'] == ['invalid-evidence']
    suite = ET.parse(output/'junit.xml').getroot()
    assert suite.attrib['failures'] == '2' and suite.attrib['skipped'] == '0'
    assert main([*args, '--expected-policy-digest', '0'*64,
                 '--output-dir', str(tmp_path/'invalid-policy')]) == 3
    assert capsys.readouterr().out


def test_reports_are_exclusive_and_baseline_is_labelled(tmp_path):
    state, policy, _, _, _ = specimen()
    result = evaluate(state, policy)
    result['cells'][0]['status'] = 'measured-baseline'
    output = tmp_path/'report'
    write_gate_artifacts(output, result)
    assert 'not a product security pass' in (output/'junit.xml').read_text()
    assert set(json.loads((output/'manifest.json').read_text())['files']) == {
        'result.json', 'junit.xml', 'summary.txt'}
    with pytest.raises(FileExistsError):
        write_gate_artifacts(output, result)


@pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                    reason='exact private Linux Root controller audit')
def test_private_controller_gate_audits_real_retained_scheduling_evidence(tmp_path):
    from ci.gauntlet.benchmark.local_campaign import load_local_campaign, run_local_campaign
    from tests.test_guard_workflow_benchmark_local_campaign import freeze, runner_factory
    root, preview = freeze(tmp_path)
    run_local_campaign(root, preview_digest=preview['preview_digest'], runner=runner_factory(['failed'], []))
    state = load_local_campaign(root)
    policy = validate_policy({'schema': 'gauntlet-ci-gate-policy.v1', 'id': 'actual-unit-lane-rejection',
        'cells': [{'episode_id': cell['id'], 'outcome': 'secure-completion', 'required_surfaces': []}
                  for cell in state['config']['cells']]})
    kwargs = {'expected_policy_digest': digest(policy),
              'expected_config_digest': state['config']['config_digest']}
    result = gate_campaign(root, policy, **kwargs)
    assert result['exit_code'] == 1
    assert 'isolated-live-execution-required' in result['errors']
    assert result['ledger_sha256']
    root.chmod(0o750)
    with pytest.raises(GateEvidenceError, match='private'):
        gate_campaign(root, policy, **kwargs)
    root.chmod(0o700)
    attempt = next((root/'attempts').iterdir())
    (attempt/'effect-receipts.json').write_text('[{}]')
    with pytest.raises(GateEvidenceError):
        gate_campaign(root, policy, **kwargs)


@pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                    reason='exact private Linux Root ancestry test')
def test_root_owned_leaf_inside_untrusted_ancestry_is_rejected(tmp_path):
    _, policy, _, _, _ = specimen()
    parent = tmp_path/'untrusted'
    parent.mkdir(mode=0o700)
    root = parent/'root-owned-leaf'
    root.mkdir(mode=0o700)
    os.chown(parent, 10004, 10004)
    try:
        with pytest.raises(GateEvidenceError, match='ancestry'):
            gate_campaign(root, policy, expected_policy_digest=digest(policy), expected_config_digest='a'*64)
    finally:
        os.chown(parent, 0, 0)
