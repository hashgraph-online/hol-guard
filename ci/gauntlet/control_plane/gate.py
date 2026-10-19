"""Additive, separately invoked ruleset; never overwrite existing branch policy."""
from __future__ import annotations

import time

from .config import CONTEXT

NAME = 'HOL Gauntlet PR gate'


def plan(enabled):
    return {'name': NAME, 'target': 'branch', 'enforcement': 'active' if enabled else 'disabled',
            'bypass_actors': [],
            'conditions': {'ref_name': {'include': ['refs/heads/main'], 'exclude': []}},
            'rules': [{'type': 'required_status_checks', 'parameters': {
                'required_status_checks': [{'context': CONTEXT}],
                'strict_required_status_checks_policy': True}}]}


def apply(github, enabled, snapshot):
    if enabled:
        if snapshot.get('discovery_mode') == 'release-tags':
            raise ValueError('Release-only testing cannot enable the PR gate; restore PR discovery and verify a published PR check first')
        if (snapshot.get('collector_status') != 'online'
                or time.time() - snapshot.get('updated_at', 0) > 90
                or snapshot.get('github', {}).get('status') != 'connected'
                or snapshot.get('vm', {}).get('status') != 'running'
                or any(j['state'] == 'unknown' for j in snapshot.get('jobs', []))
                or not any(j['state'] == 'passed' and j.get('posted_state') == 'success'
                           for j in snapshot.get('jobs', []))):
            raise ValueError('Require a healthy connected worker, a real passed/published PR check, '
                             'and no unresolved execution before enabling the gate')
    existing = github.owned_ruleset()
    if not existing and not enabled:
        return {'changed': False, 'reason': 'No Gauntlet-owned ruleset to disable'}
    if existing:
        # Refuse a same-named ruleset that was repurposed to protect other policy.
        detail = github.api(github.repo + '/rulesets/' + str(existing['id']))
        expected = plan(enabled)
        rules = detail.get('rules', [])
        if len(rules) == 1 and rules[0].get('type') == 'required_status_checks':
            parameters = rules[0].get('parameters', {})
            checks = parameters.get('required_status_checks', [])
            if (all(set(c) <= {'context', 'integration_id'} and c.get('integration_id') is None for c in checks)
                    and set(parameters) <= {'required_status_checks', 'strict_required_status_checks_policy',
                                            'do_not_enforce_on_create'}
                    and not parameters.get('do_not_enforce_on_create', False)):
                detail['rules'] = [{'type': 'required_status_checks', 'parameters': {
                    'required_status_checks': [{'context': c['context']} for c in checks],
                    'strict_required_status_checks_policy': parameters.get('strict_required_status_checks_policy')}}]
        for key in ('target', 'conditions', 'rules', 'bypass_actors'):
            if detail.get(key, [] if key == 'bypass_actors' else None) != expected[key]:
                raise ValueError('Gauntlet ruleset differs from owned policy; inspect it manually')
        return github.api(github.repo + '/rulesets/' + str(existing['id']), 'PUT', plan(enabled))
    return github.api(github.repo + '/rulesets', 'POST', plan(True))
