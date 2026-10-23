"""Real retained-ledger scheduling mechanics; no inference or product credit."""
from copy import deepcopy

import pytest

from ci.gauntlet.benchmark.ci_runner import aggregate_admission
from ci.gauntlet.benchmark.local_campaign import _append


def admission(tmp_path,report,*,retry=False):
    # The failed event is on another shard: admission must inspect the whole
    # campaign before any further cell can reach its model/executor.
    shard=tmp_path/'shard-001';shard.mkdir()
    _append(shard,[],{'type':'finish','episode_id':'failed-startup','attempt':0,
        'report':deepcopy(report),'retry':retry,'charged_tokens':0,'elapsed_seconds':2})
    manifest={'shards':[{'directory':'shard-000'},{'directory':'shard-001'}]}
    return aggregate_admission(tmp_path,manifest,{'campaign_tokens':1000,'campaign_seconds':1000},
        {'id':'next-cell'},{'model_token_reservation':100,'controller_seconds_reservation':20})


def startup():
    return {'execution_valid':False,'inference_started':False,'retryable_infrastructure':True,
        'controller_failure_class':'mcp-connect-before-inference','model_tokens':0,
        'model_usage_known':True}


def test_terminal_startup_on_another_shard_stops_further_spending(tmp_path):
    assert admission(tmp_path,startup())=='aggregate-terminal-startup-failure'


def test_explicitly_budgeted_retry_is_not_converted_to_a_terminal_failure(tmp_path):
    assert admission(tmp_path,startup(),retry=True) is None


@pytest.mark.parametrize('change',[
    {'execution_valid':True},
    {'execution_valid':0},
    {'inference_started':True},
    {'inference_started':0},
    {'retryable_infrastructure':False},
    {'retryable_infrastructure':1},
    {'controller_failure_class':'guard-prompt-admission'},
    {'controller_failure_class':None},
])
def test_task_failures_policy_refusals_and_unproven_flags_do_not_claim_startup_failure(tmp_path,change):
    report={**startup(),**change}
    assert admission(tmp_path,report) is None


def test_unknown_usage_keeps_its_stronger_halt_reason(tmp_path):
    report={**startup(),'inference_started':True,'model_usage_known':False}
    assert admission(tmp_path,report)=='aggregate-model-token-usage-unknown'
