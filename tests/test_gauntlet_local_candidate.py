"""Local immutable admission remains passive and separate from releases."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import local_candidate, releases, local_vm, vm_build, retry
from ci.gauntlet.control_plane.agent import Agent
from ci.gauntlet.control_plane.config import DEFAULTS

SHA='a'*40

class CandidateTests(unittest.TestCase):
    def test_clean_branch_identity_reads_only_git_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(local_candidate,'git',side_effect=['',SHA,'codex/gauntlet-test','version = "3.49.0"']):
                value=local_candidate.identity(temporary)
            self.assertEqual(value['sha'],SHA)
            self.assertEqual(value['version'],'3.49.0')
            with patch.object(local_candidate,'git',return_value=' M product.py'):
                with self.assertRaisesRegex(ValueError,'clean immutable'):
                    local_candidate.identity(temporary)

    def test_alpha_package_version_is_admitted_from_a_clean_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(local_candidate,'git',side_effect=['',SHA,'codex/gauntlet-alpha','version = "3.50.0a5"']):
                self.assertEqual(local_candidate.identity(temporary)['version'],'3.50.0a5')
            with patch.object(local_candidate,'git',side_effect=['',SHA,'codex/gauntlet-alpha','version = "3.50.0a0"']):
                with self.assertRaisesRegex(ValueError,'package version'):
                    local_candidate.identity(temporary)

    def test_changed_commit_or_branch_refuses_admission(self):
        value={'source_path':'/candidate','sha':SHA,'branch':'codex/gauntlet-test','version':'3.49.0'}
        job={**value,'tag':'local-'+SHA}
        with patch.object(local_candidate,'identity',return_value=value):
            local_candidate.verify(job)
            for key in value:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    local_candidate.verify({**job,key:'changed'})

    def test_operator_queue_is_separate_and_never_posts_status(self):
        job={'id':'1'*16,'sha':SHA,'kind':'local-candidate','operator_queued':True,
             'tag':'local-'+SHA,'state':'queued','created_at':1}
        self.assertTrue(releases.admitted(DEFAULTS,job))
        self.assertFalse(releases.admitted(DEFAULTS,{**job,'operator_queued':False}))
        self.assertFalse(releases.admitted(DEFAULTS,{**job,'archived_at':1}))
        with tempfile.TemporaryDirectory() as temporary:
            agent=Agent(dict(DEFAULTS),Path(temporary)); agent.github=Mock()
            agent.jobs.append(job)
            receipt={'source_sha':SHA,'job_id':job['id'],'deployment_digest':'c'*64,
                     'exit_code':0,'status':'passed','report_sha256':'d'*64}
            agent.worker=Mock(side_effect=[{'ready':False},{'ready':True,'deployment_digest':'c'*64},receipt])
            with patch.object(local_candidate,'verify'),patch.object(local_vm,'prepare',return_value=True):
                agent.run_job(job)
            self.assertEqual(job['state'],'passed')
            agent.github.status.assert_not_called()
            agent.github.pull.assert_not_called()
            agent.github.api.assert_not_called()
            releases.archive_unwatched(agent)
            self.assertNotIn('archived_at',job)

    def test_builder_preserves_resource_caps_for_local_candidate(self):
        args=vm_build.container_command('sha256:'+'b'*64,'1'*16,SHA,'local-'+SHA,Path('/build'),local_version='3.49.0')
        self.assertIn('HOL_GUARD_LOCAL_VERSION=3.49.0',args)
        self.assertIn('--memory=12g',args)
        self.assertIn('65532:65532',args)
        self.assertIn('--cap-drop=ALL',args)

    def test_build_retry_retains_local_identity_without_requiring_github_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            agent=Agent(dict(DEFAULTS),Path(temporary))
            job={'id':'1'*16,'sha':SHA,'kind':'local-candidate','operator_queued':True,
                 'tag':'local-'+SHA,'title':'Candidate','state':'build-failed','created_at':1,
                 'source_path':'/candidate','branch':'codex/gauntlet-test','version':'3.49.0',
                 'local_build':{'status':'build-failed','job_id':'1'*16,
                                'failure_phase':'product-contracts','retained_archive_sha256':'b'*64}}
            agent.jobs.append(job)
            with patch.object(retry,'verify'), patch.object(local_candidate,'verify'):
                created=retry.enqueue(agent)
            self.assertEqual(len(created),1)
            candidate=agent.jobs[-1]
            self.assertTrue(releases.admitted(DEFAULTS,candidate))
            for key in ['source_path','branch','version','operator_queued']:
                self.assertEqual(candidate[key],job[key])
            self.assertEqual(candidate['retest_build_job_id'],'1'*16)
            self.assertNotIn('url',candidate)
            self.assertIn('archived_at',job)

    def test_product_contract_failure_identifies_cases_in_dashboard_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            with (Path(temporary)/'build.log').open('w+') as log:
                log.write('FAILED tests/test_contained_completion.py::test_binding[0]\n')
                log.write('4 failed, 96 passed\nsubprocess.CalledProcessError: generic command\n')
                result=vm_build.failure_detail(RuntimeError('failed'),log,'release-compilation')
            self.assertEqual(result['failure_phase'],'product-contracts')
            self.assertIn('test_binding[0]',result['error'])
            self.assertNotIn('generic command',result['error'])

    def test_obsolete_local_branch_is_superseded_before_vm_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            agent=Agent(dict(DEFAULTS),Path(temporary)); agent.github=Mock();agent.worker=Mock()
            job={'id':'1'*16,'sha':SHA,'kind':'local-candidate','operator_queued':True,
                 'tag':'local-'+SHA,'state':'queued','created_at':1}
            agent.jobs.append(job)
            with patch.object(local_candidate,'verify',side_effect=ValueError('branch changed')):
                agent.run_job(job)
            self.assertEqual(job['state'],'superseded')
            agent.worker.assert_not_called()
            agent.github.status.assert_not_called()

    def test_duplicate_admission_does_not_stop_the_observer(self):
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary); agent=Agent(dict(DEFAULTS),state)
            job={'id':'1'*16,'sha':SHA,'state':'passed'};agent.save(job)
            with patch.object(local_candidate,'identity',return_value={'sha':SHA}), \
                 patch('ci.gauntlet.control_plane.lifecycle.stop_observer') as stop:
                with self.assertRaisesRegex(ValueError,'observer left running'):
                    local_candidate.enqueue(state,dict(DEFAULTS),'/candidate')
                stop.assert_not_called()

    def test_retest_keeps_caps_and_mounts_only_retained_readonly_artifact(self):
        args=vm_build.container_command('sha256:'+'b'*64,'1'*16,SHA,'local-'+SHA,Path('/build'),local_version='3.49.0',profile='hol-gauntlet-build-'+('1'*16),retest=True)
        self.assertIn('HOL_GUARD_RETEST=1',args)
        self.assertIn('/build/retest-candidate.zip:/input/candidate.zip:ro',args)
        self.assertIn('--security-opt=apparmor=hol-gauntlet-build-'+('1'*16),args)
        self.assertIn('--cap-drop=ALL',args)
        self.assertFalse(any('privileged'==a or 'unconfined'==a for a in args))

    def test_builder_policy_preserves_stock_denials_and_scopes_peer_access(self):
        policy=Path(vm_build.__file__).with_name('Builder.apparmor').read_text()
        for required in ['deny mount,','deny @{PROC}/sysrq-trigger rwklx,',
                         'deny @{PROC}/kcore rwklx,','deny /sys/kernel/security/** rwklx,']:
            self.assertIn(required,policy)
        peers=[line for line in policy.splitlines() if 'ptrace (' in line]
        self.assertEqual(len(peers),3)
        self.assertTrue(all('peer=' in line and 'HOL_GAUNTLET_BUILD_PROFILE' in line for line in peers))
        self.assertTrue(all('*' not in line for line in peers))
