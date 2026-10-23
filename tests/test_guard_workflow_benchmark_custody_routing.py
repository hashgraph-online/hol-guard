"""Each live lane must use its own custody verifier without bypassing it."""
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import (
    campaign_product_custody, developer_campaign_isolation, local_campaign,
)


def specimen():
    cell = {'workflow_id': 'python-cli-with-tests', 'variant': 'clean',
            'protected': True, 'group': 'base'}
    config = {'runtime': {'protected_adapter': 'hol-guard', 'model_id': 'fixture',
                          'product_isolated': True}, 'execution_lane': 'live'}
    report = {'workflow_id': cell['workflow_id'], 'variant': 'clean',
              'adapter': 'hol-guard', 'model_id': 'fixture', 'group': 'developer'}
    return config, cell, report


@pytest.mark.parametrize('valid', [True, False])
def test_developer_reports_use_developer_custody_contract(monkeypatch, valid):
    config, cell, report = specimen()
    report['execution_valid'] = valid
    calls = []
    monkeypatch.setattr(developer_campaign_isolation, 'bind_developer_isolation',
        lambda c, r, **kw: calls.append((c, r, kw)))
    monkeypatch.setattr(campaign_product_custody, 'bind_product_report',
        lambda *a, **kw: pytest.fail('business custody cannot interpret a developer report'))
    local_campaign._bind_report(config, cell, report, attempt_path=Path('/retained'))
    assert calls == [(config, report, {'attempt_path': Path('/retained')})]


def test_developer_custody_failure_is_never_swallowed(monkeypatch):
    config, cell, report = specimen()
    def reject(*args, **kwargs):
        raise ValueError('signed developer custody mismatch')
    monkeypatch.setattr(developer_campaign_isolation, 'bind_developer_isolation', reject)
    with pytest.raises(ValueError, match='signed developer custody mismatch'):
        local_campaign._bind_report(config, cell, report, attempt_path=Path('/retained'))


def test_developer_cannot_substitute_business_report(monkeypatch):
    config, cell, report = specimen()
    report['group'] = 'business'
    monkeypatch.setattr(developer_campaign_isolation, 'bind_developer_isolation',
        lambda *a, **kw: pytest.fail('must reject wrong report before binding'))
    with pytest.raises(ValueError, match='developer-specific'):
        local_campaign._bind_report(config, cell, report, attempt_path=Path('/retained'))
