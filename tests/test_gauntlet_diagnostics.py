"""Useful failure reports, private raw logs, and retained explicit build retries."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane.agent import Agent
from ci.gauntlet.control_plane.config import DEFAULTS
from ci.gauntlet.control_plane import retry, releases, vm_build

SHA = 'a'*40


class FailureRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.agent = Agent(dict(DEFAULTS), self.root)
        self.job = {'id':'1'*16,'kind':'release','tag':'v3.48.0','sha':SHA,
                    'title':'v3.48.0','url':'https://github.com/test/repo/releases/tag/v3.48.0',
                    'created_at':1,'state':'build-failed',
                    'local_build':{'status':'build-failed','diagnostic_tail':'PRIVATE RAW BUILD LOG',
                                   'error':'entrypoint missing','exit_code':127}}
        self.agent.jobs.append(self.job)
        self.agent.save(self.job)

    def test_failure_returns_actual_log_error_instead_of_only_command(self):
        log = self.root/'build.log'
        with log.open('w') as stream:
            stream.write('ordinary build output\nError: executable /tool/python: no such file or directory\n')
            detail = vm_build.failure_detail(subprocess.CalledProcessError(127,['podman','run']), stream,
                                             'release-compilation')
        self.assertEqual(detail['exit_code'],127)
        self.assertIn('no such file',detail['error'])
        self.assertIn('ordinary build output',detail['diagnostic_tail'])
        self.assertEqual(detail['failure_phase'],'release-compilation')

    def test_dashboard_redacts_raw_tail_without_mutating_private_receipt(self):
        self.agent.publish()
        public = (self.root/'public/snapshot.json').read_text()
        self.assertNotIn('PRIVATE RAW BUILD LOG',public)
        self.assertIn('entrypoint missing',public)
        self.assertEqual(self.job['local_build']['diagnostic_tail'],'PRIVATE RAW BUILD LOG')

    def test_sigkill_is_not_hidden_by_later_python_wrapper_errors(self):
        with (self.root/'build.log').open('w') as log:
            log.write('rustc (signal: 9, SIGKILL: kill)\nsubprocess.CalledProcessError: wrapper exited 1\n')
            detail=vm_build.failure_detail(subprocess.CalledProcessError(1,['podman','run']),log,'release-compilation')
        self.assertIn('SIGKILL',detail['error'])
        self.assertIn('possible',detail['error'])

    def test_retry_new_identity_preserves_failed_job_and_tag_binding(self):
        with patch.object(retry,'verify') as verified:
            created = retry.enqueue(self.agent)
        verified.assert_called_once_with(self.agent.config,self.job)
        self.assertEqual(len(created),1)
        self.assertNotEqual(created[0],self.job['id'])
        self.assertTrue(self.job['archived_at'])
        child = self.agent.jobs[-1]
        self.assertEqual(child['retry_of'],self.job['id'])
        self.assertEqual(child['sha'],SHA)
        self.assertNotIn('local_build',child)
        self.assertEqual(json.loads((self.agent.jobs_dir/(self.job['id']+'.json')).read_text())['state'],
                         'build-failed')
        self.agent.github = Mock()
        self.agent.github.release.side_effect=lambda tag:{'sha': 'b'*40,'url':'https://github.com/test'}
        releases.discover(self.agent)
        self.assertIn('moved',child['source_error'])

    def test_retry_refuses_unproven_remote_termination(self):
        with patch.object(retry,'verify',side_effect=RuntimeError('container still exists')):
            with self.assertRaisesRegex(RuntimeError,'container'):
                retry.enqueue(self.agent)
        self.assertEqual(len(self.agent.jobs),1)
        self.assertNotIn('archived_at',self.job)
        self.assertNotIn('retried_as',self.job)

    def test_unknown_build_is_never_retried(self):
        self.job.update(state='unknown',local_build={'status':'unknown'})
        with patch.object(retry,'verify') as verified:
            self.assertEqual(retry.enqueue(self.agent),[])
        verified.assert_not_called()

    def test_repeated_retry_does_not_duplicate_and_recovers_partial_archival(self):
        with patch.object(retry,'verify'):
            ids = retry.enqueue(self.agent)
            self.job.pop('archived_at')  # simulate interruption after new job persistence
            self.assertEqual(retry.enqueue(self.agent),[])
        self.assertEqual(len(self.agent.jobs),2)
        self.assertEqual(self.job['retried_as'],ids[0])
        self.assertTrue(self.job.get('archived_at'))

    def test_verification_checks_identity_and_refuses_nonzero_vm_exit(self):
        with patch.object(retry.subprocess,'run',return_value=Mock(returncode=0,
            stdout=json.dumps({'job_id':self.job['id'],'source_sha':SHA,'retry_safe':True}))):
            retry.verify(DEFAULTS,self.job)
        with patch.object(retry.subprocess,'run',return_value=Mock(returncode=0,
            stdout=json.dumps({'job_id':'2'*16,'source_sha':SHA,'retry_safe':True}))):
            with self.assertRaisesRegex(ValueError,'identity'):
                retry.verify(DEFAULTS,self.job)
        compile(retry.VERIFY,'<read-only-build-retry-verification>','exec')


if __name__=='__main__':
    unittest.main()
