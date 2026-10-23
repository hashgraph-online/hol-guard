"""Use gh's existing credential broker; never copy tokens into the service."""
from __future__ import annotations

import json
import subprocess
from urllib.parse import quote

from .config import CONTEXT, SHA


class GitHub:
    def __init__(self, config):
        self.config = config
        self.repo = 'repos/' + config['repository']

    def api(self, endpoint, method='GET', payload=None):
        command = [self.config['gh'], 'api', '--hostname', 'github.com',
                   '-H', 'Accept: application/vnd.github+json',
                   '-H', 'X-GitHub-Api-Version: 2022-11-28', '--method', method, endpoint]
        if payload is not None:
            command += ['--input', '-']
        result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                                text=True, capture_output=True, timeout=25)
        if result.returncode:
            # gh errors do not include credential values; no environment/token inspection.
            raise RuntimeError(result.stderr.strip()[:1500] or f'GitHub exited {result.returncode}')
        return json.loads(result.stdout) if result.stdout.strip() else None

    def pages(self, endpoint):
        result = []
        for page in range(1, 101):
            rows = self.api(endpoint + ('&' if '?' in endpoint else '?') + f'per_page=100&page={page}')
            result.extend(rows)
            if len(rows) < 100:
                return result
        raise RuntimeError('pagination limit exceeded; incomplete inventory refused')

    def pulls(self):
        return self.pages(self.repo + '/pulls?state=open&base=main')

    def pull(self, number):
        return self.api(self.repo + f'/pulls/{number}')

    def release(self, tag):
        if self.config['release_build_backend'] == 'local-vm':
            from .local_vm import resolve_release
            return resolve_release(self.config, tag)
        release = self.api(self.repo + '/releases/tags/' + quote(tag, safe=''))
        if release.get('draft') or release.get('prerelease') or release.get('tag_name') != tag:
            raise ValueError('published stable release with the exact tag required')
        ref = self.api(self.repo + '/git/ref/tags/' + quote(tag, safe=''))['object']
        for _ in range(8):
            if not SHA.fullmatch(ref.get('sha', '')):
                raise ValueError('invalid release object SHA')
            if ref.get('type') == 'commit':
                return {'tag': tag, 'sha': ref['sha'], 'url': release['html_url']}
            if ref.get('type') != 'tag':
                break
            ref = self.api(self.repo + '/git/tags/' + ref['sha'])['object']
        raise ValueError('release tag does not resolve to a bounded commit')

    def status(self, sha, state, description):
        value = {'state': state, 'context': CONTEXT, 'description': description[:140]}
        if self.config['public_dashboard_url']:
            value['target_url'] = self.config['public_dashboard_url']
        return self.api(self.repo + '/statuses/' + sha, 'POST', value)

    def gate(self):
        rules = self.api(self.repo + '/rules/branches/main')
        required = []
        for rule in rules:
            if rule['type'] == 'required_status_checks':
                required.extend(r['context'] for r in rule.get('parameters', {}).get('required_status_checks', []))
        # Legacy branch protection is also relevant. A 404 is expected for an
        # unprotected branch, but an authentication/network error stays visible.
        try:
            legacy = self.api(self.repo + '/branches/main/protection/required_status_checks')
            required += legacy.get('contexts', [])
            required += [r['context'] for r in legacy.get('checks', [])]
        except RuntimeError as error:
            if 'HTTP 404' not in str(error):
                raise
        return {'required': CONTEXT in required, 'context': CONTEXT,
                'required_contexts': sorted(set(required))}

    def owned_ruleset(self):
        matches = [r for r in self.pages(self.repo + '/rulesets?includes_parents=false')
                   if r['name'] == 'HOL Gauntlet PR gate']
        if len(matches) > 1:
            raise RuntimeError('ambiguous Gauntlet rulesets; inspect manually')
        return matches[0] if matches else None
