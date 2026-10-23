"""Agent commits must work without the controller's private Git environment."""
from pathlib import Path
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.synthetic_developer_services import SyntheticGitService


@pytest.mark.parametrize('primary', ['run-repository', 'tc-repository'])
@pytest.mark.parametrize('linked', [False, True])
def test_task_local_identity_supports_plain_agent_commits(tmp_path, primary, linked):
    home = tmp_path / 'agent-home'
    home.mkdir()
    global_config = home / '.gitconfig'
    global_config.write_text('[user]\n\tname = Operator Canary\n\temail = operator@example.test\n')
    original_global = global_config.read_bytes()
    service = SyntheticGitService(tmp_path / 'git-service', signing_key=Ed25519PrivateKey.generate())
    baseline = service.seed('python-cli-with-tests', primary_repository_id=primary)
    checkout = Path(baseline['checkout_path'])
    # Match a neutral contained process: no inherited controller author variables,
    # global config, credential helper, signing settings or operator identity.
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                   'GIT_TERMINAL_PROMPT': '0'}

    def git(path, *args, check=True):
        return subprocess.run(['/usr/bin/git', '-C', str(path), *args],
                              env=environment, capture_output=True, check=check, timeout=20)

    assert git(checkout, 'config', '--local', '--get', 'user.name').stdout == b'Benchmark Agent\n'
    assert git(checkout, 'config', '--local', '--get', 'user.email').stdout == b'agent@example.test\n'
    if linked:
        linked_checkout = service.root / 'task-linked-worktree'
        git(checkout, 'worktree', 'add', '-b', 'task-control', str(linked_checkout))
        checkout = linked_checkout
    (checkout / 'agent-control.txt').write_text('Agent-generated control artifact.\n')
    git(checkout, 'add', 'agent-control.txt')
    git(checkout, 'commit', '-m', 'Real agent control commit')
    assert git(checkout, 'show', '-s', '--format=%an <%ae>|%cn <%ce>').stdout == (
        b'Benchmark Agent <agent@example.test>|Benchmark Agent <agent@example.test>\n')
    assert global_config.read_bytes() == original_global
    assert git(service.root / 'peer-repository', 'config', '--local', '--get', 'user.name',
               check=False).returncode == 1
    assert git(service.root / (primary + '.git'), 'config', '--local', '--get', 'user.name',
               check=False).returncode == 1
    # Provisioning identity must not fabricate remote delivery or alter seed code.
    assert git(service.root / (primary + '.git'), 'rev-parse', 'main').stdout.strip().decode() == baseline['head']
