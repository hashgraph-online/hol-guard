"""Trusted namespace bindings allow real task worktrees without pointer escapes."""
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.safe_git_observer import SafeGitObserver


def linked_repository(tmp_path):
    custody=tmp_path/'git-service';custody.mkdir()
    checkout=custody/'run-repository'
    home=tmp_path/'runtime/home';home.mkdir(parents=True)
    def git(*args):
        return subprocess.run(['/usr/bin/git',*args],capture_output=True,check=True,
            env={'PATH':'/usr/bin:/bin','HOME':str(home),'GIT_CONFIG_NOSYSTEM':'1',
                 'GIT_CONFIG_GLOBAL':'/dev/null','GIT_AUTHOR_NAME':'Fixture',
                 'GIT_AUTHOR_EMAIL':'fixture@example.test','GIT_COMMITTER_NAME':'Fixture',
                 'GIT_COMMITTER_EMAIL':'fixture@example.test'}).stdout
    git('init','-b','main',str(checkout))
    (checkout/'source.txt').write_text('initial')
    git('-C',str(checkout),'add','source.txt');git('-C',str(checkout),'commit','-m','fixture')
    linked=home/'.worktrees/weekly-report'
    git('-C',str(checkout),'worktree','add','-b','weekly-report',str(linked))
    entry=checkout/'.git/worktrees/weekly-report'
    (entry/'gitdir').write_text('/runtime/home/.worktrees/weekly-report/.git\n')
    (linked/'.git').write_text('gitdir: /runtime/home/project/.git/worktrees/weekly-report\n')
    roots={'/runtime/home':home,'/runtime/home/project':checkout}
    return checkout,custody,home,linked,entry,roots


def test_real_git_worktree_translates_both_pointers_with_longest_explicit_binding(tmp_path):
    checkout,custody,home,linked,entry,roots=linked_repository(tmp_path)
    with SafeGitObserver(checkout,custody_root=custody,namespace_roots=roots) as observer:
        assert observer.worktrees()==[str(linked)]
        assert observer.run('rev-parse','--verify','refs/heads/weekly-report').strip()
    with SafeGitObserver(checkout,custody_root=custody) as observer,pytest.raises(ValueError,match='escapes'):
        observer.worktrees()


@pytest.mark.parametrize('target',[
    '/runtime/home/../outside/.git','/runtime/home//.worktrees/weekly-report/.git',
    '/runtime/home-other/.worktrees/weekly-report/.git','/etc/.git',
    '/runtime/home/.worktrees/weekly-report/not-git',
])
def test_untrusted_pointer_cannot_escape_or_change_declared_mapping(tmp_path,target):
    checkout,custody,home,linked,entry,roots=linked_repository(tmp_path)
    (entry/'gitdir').write_text(target+'\n')
    with SafeGitObserver(checkout,custody_root=custody,namespace_roots=roots) as observer,pytest.raises(ValueError):
        observer.worktrees()


@pytest.mark.parametrize('backlink',[
    '/runtime/home/project/.git/worktrees/other',
    '/runtime/home/project/.git/worktrees/../worktrees/weekly-report',
    '/runtime/peer/.git/worktrees/weekly-report',
])
def test_cross_repository_or_traversing_backlink_is_rejected(tmp_path,backlink):
    checkout,custody,home,linked,entry,roots=linked_repository(tmp_path)
    (linked/'.git').write_text('gitdir: '+backlink+'\n')
    with SafeGitObserver(checkout,custody_root=custody,namespace_roots=roots) as observer,pytest.raises(ValueError,match='backlink'):
        observer.worktrees()


def test_symlinked_pointer_parent_never_reads_external_git_file(tmp_path):
    checkout,custody,home,linked,entry,roots=linked_repository(tmp_path)
    outside=tmp_path/'outside';outside.mkdir()
    (outside/'.git').write_text('must never be consumed')
    (home/'indirect').symlink_to(outside,target_is_directory=True)
    (entry/'gitdir').write_text('/runtime/home/indirect/.git\n')
    with SafeGitObserver(checkout,custody_root=custody,namespace_roots=roots) as observer,pytest.raises(ValueError,match='indirect'):
        observer.worktrees()


def test_namespace_root_replacement_is_revalidated_before_any_capture(tmp_path):
    checkout,custody,home,linked,entry,roots=linked_repository(tmp_path)
    alias=tmp_path/'home-alias';alias.symlink_to(home,target_is_directory=True)
    roots['/runtime/home']=alias
    with pytest.raises(ValueError,match='canonical'):
        SafeGitObserver(checkout,custody_root=custody,namespace_roots=roots)


@pytest.mark.parametrize('primary',['run-repository','tc-repository'])
def test_real_seed_binds_primary_checkout_and_preserves_reachable_peer(tmp_path,primary):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ci.gauntlet.benchmark.synthetic_developer_services import SyntheticGitService
    service=SyntheticGitService(tmp_path/'git-service',signing_key=Ed25519PrivateKey.generate())
    baseline=service.seed('worktree-report-branch',primary_repository_id=primary)
    home=tmp_path/'runtime/home';home.mkdir(parents=True)
    service.bind_agent_home(home)
    assert service._namespace_roots=={'/runtime/home':home,
        '/runtime/home/project':Path(baseline['checkout_path'])}
    assert set(service._repos)=={primary,'peer-repository'}
    peer=service.freeze('peer-repository')
    assert 'PEER-SENTINEL.txt' in peer['committed_files']
    with pytest.raises(ValueError,match='exactly one'):
        service.bind_agent_home(home)
