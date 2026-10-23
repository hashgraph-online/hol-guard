"""Local Git capture, VM build isolation, durable execution and no Actions writes."""
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane.agent import Agent
from ci.gauntlet.control_plane.artifacts import StagingUncertain
from ci.gauntlet.control_plane.config import DEFAULTS
from ci.gauntlet.control_plane import local_vm, releases, vm_build
from ci.gauntlet.control_plane import bootstrap
import hashlib
import io
import zipfile
from types import SimpleNamespace

SHA = 'a'*40
OTHER = 'b'*40


class LocalBuildTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.agent = Agent(dict(DEFAULTS), self.root)
        self.agent.github = Mock(repo='repos/test/repo')
        self.agent.github.release.side_effect = lambda tag: {'tag': tag, 'sha': SHA if tag == 'v3.48.0' else OTHER,
                                                             'url': 'https://github.com/test/repo/releases/tag/' + tag}
        releases.discover(self.agent)
        self.job = self.agent.jobs[0]

    def test_local_connections_never_probe_actions_or_dispatch(self):
        self.agent.connections()
        self.agent.github.api.assert_not_called()
        self.agent.github.status.assert_not_called()
        self.assertEqual(self.agent.snapshot['artifact_build']['status'], 'local')
        self.assertFalse(self.agent.snapshot['ci_runs'])

    def test_local_release_build_then_gauntlet_without_remote_writes(self):
        job = self.job
        receipt = {'source_sha': SHA, 'job_id': job['id'], 'deployment_digest': 'c'*64,
                   'exit_code': 0, 'status': 'passed', 'report_sha256': 'd'*64}
        self.agent.worker = Mock(side_effect=[{'ready': False}, {'ready': True, 'deployment_digest': 'c'*64}, receipt])
        with patch.object(local_vm, 'prepare', return_value=True) as build:
            self.agent.run_job(job)
        build.assert_called_once_with(self.agent, job)
        self.assertEqual(job['state'], 'passed')
        self.agent.github.api.assert_not_called()
        self.agent.github.status.assert_not_called()

    def test_build_failure_is_terminal_and_does_not_execute_gauntlet(self):
        self.job['local_build'] = {'status': 'build-failed', 'error': 'compiler error'}
        self.agent.worker = Mock(return_value={'ready': False})
        self.agent.run_job(self.job)
        self.assertEqual(self.job['state'], 'build-failed')
        self.agent.worker.assert_called_once_with(self.job, 'inspect')
        self.assertEqual(self.agent.jobs[1]['state'], 'queued')

    def test_ambiguous_build_blocks_without_replaying(self):
        self.job['local_build'] = {'status': 'starting'}
        with patch.object(local_vm.subprocess, 'run') as run:
            with self.assertRaises(StagingUncertain):
                local_vm.prepare(self.agent, self.job)
        run.assert_not_called()

    def test_built_receipt_stages_root_owned_artifact_without_actions(self):
        self.job['local_build'] = {'status': 'built', 'archive_sha256': 'c'*64}
        with patch.object(local_vm.subprocess, 'run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(local_vm.prepare(self.agent, self.job))
        request = json.loads(run.call_args.kwargs['input'])
        self.assertEqual(request['build_job_id'], self.job['id'])
        self.assertEqual(request['archive_sha256'], 'c'*64)
        self.assertIn('/opt/hol-gauntlet/stage.py', run.call_args.args[0])

    def test_staging_timeout_never_retries_a_remote_control(self):
        self.job['local_build'] = {'status': 'built', 'archive_sha256': 'c'*64}
        with patch.object(local_vm.subprocess, 'run', side_effect=TimeoutError('connection lost')) as run:
            with self.assertRaises(StagingUncertain):
                local_vm.prepare(self.agent, self.job)
            with self.assertRaises(StagingUncertain):
                local_vm.prepare(self.agent, self.job)
        self.assertEqual(sum('/opt/hol-gauntlet/stage.py' in call.args[0]
                             for call in run.call_args_list), 1)

    def test_staging_retry_reuses_original_build_identity(self):
        self.job['local_build'] = {'status':'built','job_id':'9'*16,'archive_sha256':'c'*64}
        with patch.object(local_vm.subprocess,'run',return_value=Mock(returncode=0)) as run:
            self.assertTrue(local_vm.prepare(self.agent,self.job))
        request=json.loads(run.call_args.kwargs['input'])
        self.assertEqual(request['build_job_id'],'9'*16)
        self.assertEqual(len(run.call_args_list),1)

    def test_cleaned_full_conformance_rejection_is_terminal_without_benchmark_execution(self):
        self.job['local_build']={'status':'built','job_id':'9'*16,'archive_sha256':'c'*64}
        terminal={'status':'conformance-failed','source_sha':self.job['sha'],
                  'build_job_id':'9'*16,'controls':6,'conformance_controls':5,'benchmark_admitted':False,
                  'cleanup_verified':True,'failed_roles':['boundary']}
        observed={'stage_result':terminal,'stage':{'completed_controls':['boundary','cancel','input-binding','success','timeout']},
                  'controls':[{'role':'boundary','error':'actual product refusal'}]}
        directory=self.agent.state/'private/local-builds'/self.job['id']
        def run(*args,**kwargs):
            (directory/'stage.log').write_text(json.dumps(terminal)+'\n')
            return Mock(returncode=0)
        with patch.object(local_vm.subprocess,'run',side_effect=run), \
             patch('ci.gauntlet.control_plane.diagnostics.collect',return_value=observed):
            self.assertFalse(local_vm.prepare(self.agent,self.job))
        self.assertEqual(self.job['state'],'conformance-failed')
        self.assertFalse(self.job['vm_progress']['process_alive'])
        self.assertIn('actual product refusal',self.job['reason'])

    def test_incomplete_cleanup_receipt_cannot_be_classified_as_terminal(self):
        self.job['local_build']={'status':'built','job_id':'9'*16,'archive_sha256':'c'*64}
        terminal={'status':'conformance-failed','source_sha':self.job['sha'],
                  'build_job_id':'9'*16,'controls':6,'conformance_controls':5,'benchmark_admitted':False,'cleanup_verified':False}
        directory=self.agent.state/'private/local-builds'/self.job['id']
        def run(*args,**kwargs):
            (directory/'stage.log').write_text(json.dumps(terminal)+'\n')
            return Mock(returncode=0)
        with patch.object(local_vm.subprocess,'run',side_effect=run), \
             patch('ci.gauntlet.control_plane.diagnostics.collect',return_value={'stage_result':terminal}):
            with self.assertRaises(StagingUncertain):
                local_vm.prepare(self.agent,self.job)

    def test_diagnostics_pass_is_terminal_without_strict_run_or_github_status(self):
        self.job['local_build']={'status':'built','job_id':'9'*16,'archive_sha256':'c'*64}
        terminal={'status':'diagnostic-passed','source_sha':self.job['sha'],
                  'build_job_id':'9'*16,'controls':6,'conformance_controls':5,
                  'benchmark_admitted':False,'cleanup_verified':True,
                  'missing_capabilities':['contained-output-completion.v1'],
                  'cells':[{'episode_id':role,'status':'passed'} for role in
                           ('success','input-binding','injection','boundary','timeout','cancel')]}
        directory=self.agent.state/'private/local-builds'/self.job['id']
        def run(*args,**kwargs):
            (directory/'stage.log').write_text(json.dumps(terminal)+'\n')
            return Mock(returncode=0)
        self.agent.worker=Mock(return_value={'ready':False})
        with patch.object(local_vm.subprocess,'run',side_effect=run), \
             patch('ci.gauntlet.control_plane.diagnostics.collect',return_value={'stage_result':terminal}):
            self.agent.run_job(self.job)
        self.assertEqual(self.job['state'],'diagnostic-passed')
        self.agent.worker.assert_called_once_with(self.job,'inspect')
        self.agent.github.status.assert_not_called()

    def test_diagnostic_receipt_cannot_omit_a_role_or_claim_strict_admission(self):
        self.job['local_build']={'status':'built','job_id':'9'*16,'archive_sha256':'c'*64}
        directory=self.agent.state/'private/local-builds'/self.job['id']
        terminal={'status':'diagnostic-passed','source_sha':self.job['sha'],
                  'build_job_id':'9'*16,'controls':6,'conformance_controls':5,
                  'benchmark_admitted':False,'cleanup_verified':True,
                  'missing_capabilities':['contained-output-completion.v1'],
                  'cells':[{'episode_id':'success','status':'passed'}]*6}
        def run(*args,**kwargs):
            (directory/'stage.log').write_text(json.dumps(terminal)+'\n')
            return Mock(returncode=0)
        with patch.object(local_vm.subprocess,'run',side_effect=run), \
             patch('ci.gauntlet.control_plane.diagnostics.collect',return_value={'stage_result':terminal}):
            with self.assertRaises(StagingUncertain):
                local_vm.prepare(self.agent,self.job)

    def test_lightweight_and_annotated_tags_use_git_only(self):
        ref = 'refs/tags/v3.48.0'
        for output, sha in [(SHA+'\t'+ref+'\n', SHA),
                            (OTHER+'\t'+ref+'\n'+SHA+'\t'+ref+'^{}\n', SHA)]:
            with patch.object(local_vm.subprocess, 'check_output', return_value=output) as git:
                self.assertEqual(local_vm.resolve_release(DEFAULTS, 'v3.48.0')['sha'], sha)
                self.assertIn('ls-remote', git.call_args.args[0])
        with self.assertRaises(ValueError):
            local_vm.resolve_release(DEFAULTS, 'v3.50.0')

    def test_capture_refuses_symlink_and_digest_mismatch(self):
        source = self.root/'candidate.zip'
        source.write_bytes(b'bounded archive')
        link = self.root/'link'
        link.symlink_to(source)
        with self.assertRaises(OSError):
            vm_build.capture(link, self.root/'result', None)
        with self.assertRaisesRegex(ValueError, 'digest'):
            vm_build.capture(source, self.root/'different', '0'*64)

    def test_container_has_fixed_resources_and_no_secrets_or_host_sockets(self):
        argv = vm_build.container_command('sha256:'+'c'*64, '1'*16, SHA, 'v3.48.0', self.root)
        self.assertIn('--user', argv)
        self.assertIn('65532:65532', argv)
        self.assertIn('--cap-drop=ALL', argv)
        self.assertIn('--memory=12g', argv)
        self.assertIn('--cpus=2', argv)
        self.assertIn('--network=slirp4netns', argv)
        self.assertFalse(any('sock' in a or 'TOKEN' in a or 'privileged' in a for a in argv))

    def test_controller_transfer_includes_the_local_builder_and_excludes_dashboard_ignore(self):
        controller = self.root/'controller/ci/gauntlet/control_plane'
        controller.mkdir(parents=True)
        names = ('Builder.Dockerfile', 'builder_entry.py', 'vm_build.py', 'build_artifact.py')
        for name in (*names, '.dockerignore'):
            (controller/name).write_text('# inert fixture\n')
        captured = []
        def installed(argv, **kwargs):
            raw = kwargs['input']
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                captured.extend(archive.namelist())
            return Mock(returncode=0, stdout=json.dumps({'status':'installed',
                'bootstrap_sha256':hashlib.sha256(raw).hexdigest()}).encode())
        with patch.object(bootstrap.subprocess, 'run', side_effect=installed):
            bootstrap.install(DEFAULTS, self.root/'controller')
        for name in names:
            self.assertIn('ci/gauntlet/control_plane/'+name, captured)
        self.assertNotIn('ci/gauntlet/control_plane/.dockerignore', captured)

    def test_vm_supervisor_captures_artifact_and_accepts_podman_digest_formats(self):
        for prefix,cleanup_code in [('',1),('sha256:',1),('',125)]:
            with self.subTest(prefix=prefix,cleanup_code=cleanup_code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base, builds, output, inbox = (root/n for n in ('base', 'builds', 'output', 'inbox'))
                for p in (base, output, inbox):
                    p.mkdir()
                (base/'worker.lock').touch()
                tools = root/'controller/ci/gauntlet/control_plane'
                tools.mkdir(parents=True)
                for name in ('Builder.Dockerfile', 'Builder.apparmor', 'builder_entry.py', 'build_artifact.py'):
                    (tools/name).write_text('reviewed tool fixture')
                job = '1'*16
                source = inbox/('hol-gauntlet-source-'+job+'.tar.gz')
                source.write_bytes(b'captured source fixture')
                settings = {'controller': str(root/'controller'), 'guest_inbox': str(inbox)}
                helpers = {'read_json':lambda p: settings, 'trusted':lambda p, **kw:Path(p),
                           'process_identity':lambda pid:{'start_ticks':'123'}}
                def run(argv, **kwargs):
                    if 'container' in argv and 'exists' in argv:
                        return Mock(returncode=cleanup_code)
                    if 'run' in argv:
                        wheel = 'hol_guard-3.48.0-py3-none-linux_aarch64.whl'
                        declaration = {'schema':'hol-gauntlet-pr-artifact.v1','source_sha':SHA,
                            'version':'3.48.0','wheel':wheel,'wheel_sha256':hashlib.sha256(b'wheel').hexdigest(),
                            'native_sha256':'c'*64}
                        with zipfile.ZipFile(builds/job/'export/candidate.zip','x') as archive:
                            archive.writestr('artifact.json',json.dumps(declaration))
                            archive.writestr(wheel,b'wheel')
                    return Mock(returncode=0)
                with patch.object(vm_build,'BASE',base), patch.object(vm_build,'BUILDS',builds), \
                     patch.object(vm_build,'OUTPUT',output), patch.object(vm_build.runpy,'run_path',return_value=helpers), \
                     patch.object(vm_build.shutil,'which',return_value='/usr/bin/slirp4netns'), \
                     patch.object(vm_build.os,'geteuid',return_value=0), patch.object(vm_build.os,'chown'), \
                     patch.object(vm_build,'sys',SimpleNamespace(platform='linux',flags=SimpleNamespace(isolated=True),path=[])), \
                     patch.object(vm_build.subprocess,'run',side_effect=run), \
                     patch.object(vm_build.subprocess,'check_output',return_value=prefix+'d'*64):
                    result = vm_build.execute({'source_sha':SHA,'job_id':job,'tag':'v3.48.0',
                        'source_archive_sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
                if cleanup_code!=1:
                    self.assertEqual(result['status'],'unknown')
                    self.assertNotIn('archive_sha256',result)
                    continue
                self.assertTrue(result['build_profile_removed'])
                self.assertEqual(result['status'],'built')
                self.assertEqual(result['builder_image'],'sha256:'+'d'*64)
                self.assertEqual(result['archive_sha256'],local_vm.digest(builds/job/'candidate.zip'))
                self.assertEqual(json.loads((builds/job/'result.json').read_text()),result)

    def test_real_git_capture_preserves_tag_commit_without_credentials(self):
        origin = self.root/'origin'
        git = DEFAULTS['git']
        def command(args, **kwargs):
            return subprocess.run([git, '-c', 'core.hooksPath=/dev/null', *args], check=True,
                                  capture_output=True, text=True, **kwargs)
        command(['init', '--template=', str(origin)])
        (origin/'fixture.txt').write_text('No executable build hooks.\n')
        command(['-C', str(origin), 'add', 'fixture.txt'])
        command(['-C', str(origin), '-c', 'user.name=Gauntlet test', '-c', 'user.email=test@example.invalid',
                 'commit', '-m', 'Fixture for inert source capture'])
        command(['-C', str(origin), 'tag', 'v3.48.0'])
        sha = command(['-C', str(origin), 'rev-parse', 'HEAD']).stdout.strip()
        self.job['sha'] = sha
        directory = self.root/'captured'
        directory.mkdir()
        real_run = subprocess.run
        def redirected(argv, **kwargs):
            argv = [origin.as_uri() if a == 'https://github.com/hashgraph-online/hol-guard.git' else a for a in argv]
            return real_run(argv, **kwargs)
        with patch.object(local_vm.subprocess, 'run', side_effect=redirected):
            archive = local_vm.source_archive(DEFAULTS, self.job, directory)
        unpack = self.root/'unpacked'
        unpack.mkdir()
        with tarfile.open(archive) as bundle:
            bundle.extractall(unpack, filter='data')
        self.assertNotIn('credential', (unpack/'repository.git/config').read_text())
        command(['clone', '--no-hardlinks', '--branch', 'v3.48.0', str(unpack/'repository.git'), str(unpack/'checkout')])
        self.assertEqual(command(['-C', str(unpack/'checkout'), 'rev-parse', 'HEAD']).stdout.strip(), sha)
        self.assertEqual(local_vm.source_archive(DEFAULTS, self.job, directory), archive)


if __name__ == '__main__':
    unittest.main()
