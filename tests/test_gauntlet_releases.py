"""Release allowlist, durable migration, artifact identity and VM observations."""
import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane.agent import Agent
from ci.gauntlet.control_plane.artifacts import select_artifact
from ci.gauntlet.control_plane.config import DEFAULTS, atomic_json, load
from ci.gauntlet.control_plane.github import GitHub
from ci.gauntlet.control_plane import gate, releases, vm_worker

SHA = 'a' * 40
OTHER = 'b' * 40


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.agent = Agent(dict(DEFAULTS), self.root)
        self.github = Mock(repo='repos/test/repo', config=dict(DEFAULTS))
        self.github.release.side_effect = lambda tag: {'tag': tag, 'sha': SHA if tag == 'v3.48.0' else OTHER,
                                                       'url': 'https://github.com/test/repo/releases/tag/' + tag}
        self.agent.github = self.github

    def test_two_exact_releases_only_deduplicated_without_pr_reads_or_status(self):
        releases.discover(self.agent)
        releases.discover(self.agent)
        self.assertEqual([j['tag'] for j in self.agent.jobs], ['v3.48.0', 'v3.49.0'])
        self.github.pulls.assert_not_called()
        self.github.status.assert_not_called()
        self.agent.post(self.agent.jobs[0], 'pending', 'test')
        self.github.status.assert_not_called()

    def test_tag_move_is_retained_and_blocks_admission(self):
        releases.discover(self.agent)
        self.github.release.side_effect = lambda tag: {'tag': tag, 'sha': OTHER, 'url': 'https://github.com/test'}
        releases.discover(self.agent)
        job = self.agent.jobs[0]
        self.assertEqual(job['sha'], SHA)
        self.assertIn('moved', job['source_error'])
        self.agent.worker = Mock()
        self.agent.run_job(job)
        self.agent.worker.assert_not_called()

    def test_missing_release_does_not_admit_a_similarly_named_tag(self):
        self.github.release.side_effect = RuntimeError('HTTP 404')
        releases.discover(self.agent)
        self.assertFalse(self.agent.jobs)
        self.assertEqual(len(self.agent.snapshot['github']['release_errors']), 2)

    def test_pr_backlog_archived_but_unknown_remains_visible(self):
        for number, state in enumerate(('queued', 'waiting-candidate', 'passed', 'unknown')):
            self.agent.jobs.append({'id': str(number) * 16, 'pr': number, 'sha': SHA,
                                    'created_at': number, 'state': state})
        releases.archive_unwatched(self.agent)
        self.agent.publish()
        self.assertEqual(self.agent.snapshot['archived_jobs'], 3)
        self.assertEqual(len(self.agent.snapshot['jobs']), 1)
        self.assertEqual(self.agent.snapshot['jobs'][0]['state'], 'unknown')
        self.assertEqual(len(list(self.agent.jobs_dir.glob('*.json'))), 3)
        self.assertFalse(releases.admitted(DEFAULTS, self.agent.jobs[-1]))

    def test_migration_refuses_live_observer_then_preserves_records(self):
        config = self.root/'config.json'
        atomic_json(config, dict(DEFAULTS, discovery_mode='pull-requests'))
        job = {'id': '1'*16, 'pr': 7, 'sha': SHA, 'created_at': 1, 'state': 'queued'}
        self.agent.save(job)
        with (self.root/'private/agent.lock').open('a+') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                releases.configure_release_queue(self.root, config)
        result = releases.configure_release_queue(self.root, config)
        self.assertEqual(result['archived_jobs'], 1)
        self.assertEqual(load(config)['discovery_mode'], 'release-tags')
        self.assertTrue((self.agent.jobs_dir/(job['id'] + '.json')).exists())

    def test_dispatch_recorded_before_remote_write_and_never_repeated(self):
        releases.discover(self.agent)
        job = self.agent.jobs[0]
        def api(endpoint, method='GET', payload=None):
            if method == 'POST':
                durable = json.loads((self.agent.jobs_dir/(job['id'] + '.json')).read_text())
                self.assertEqual(durable['build_dispatch']['status'], 'requesting')
                self.assertEqual(payload['inputs']['source_sha'], SHA)
                raise TimeoutError('response lost')
            return {'sha': OTHER} if endpoint.endswith('/commits/main') else {'state': 'active'}
        self.github.api.side_effect = api
        with self.assertRaisesRegex(RuntimeError, 'uncertain'):
            releases.request_build(self.agent, job)
        self.assertEqual(job['build_dispatch']['status'], 'uncertain')
        calls = self.github.api.call_count
        releases.request_build(self.agent, job)
        self.assertEqual(self.github.api.call_count, calls)

    def test_artifact_requires_dispatch_identity_and_trusted_workflow_commit(self):
        releases.discover(self.agent)
        job = self.agent.jobs[0]
        job['build_dispatch'] = {'controller_sha': OTHER}
        run = {'id': 123, 'head_sha': OTHER, 'head_branch': 'main', 'event': 'workflow_dispatch',
               'display_title': releases.build_title(job), 'path': '.github/workflows/gauntlet-pr-artifacts.yml',
               'status': 'completed', 'conclusion': 'success'}
        artifact = {'id': 99, 'name': 'hol-gauntlet-linux-arm64-' + SHA, 'expired': False}
        for change in ({'head_sha': SHA}, {'event': 'pull_request'}, {'display_title': 'other'}, {'head_branch': 'other'}):
            self.github.api.return_value = {'workflow_runs': [run | change]}
            self.assertIsNone(select_artifact(self.github, job))
        self.github.api.side_effect = [{'workflow_runs': [run]}, {'artifacts': [artifact]}]
        self.assertEqual(select_artifact(self.github, job), (artifact, run))

    def test_release_success_does_not_publish_a_pr_status(self):
        releases.discover(self.agent)
        job = self.agent.jobs[0]
        self.agent.worker = Mock(side_effect=[{'ready': True, 'deployment_digest': 'c'*64},
            {'source_sha': SHA, 'job_id': job['id'], 'deployment_digest': 'c'*64,
             'exit_code': 0, 'status': 'passed', 'report_sha256': 'd'*64}])
        self.agent.run_job(job)
        self.assertEqual(job['state'], 'passed')
        self.github.pull.assert_not_called()
        self.github.status.assert_not_called()

    def test_failed_build_does_not_stall_the_other_release_or_claim_a_benchmark_failure(self):
        self.agent.config['release_build_backend'] = 'github-actions'
        releases.discover(self.agent)
        job = self.agent.jobs[0]
        job['build_dispatch'] = {'controller_sha': OTHER}
        self.agent.worker = Mock(return_value={'ready': False})
        def no_artifact(*args, **kwargs):
            job['build_run'] = {'status': 'completed', 'conclusion': 'failure'}
            return False
        with patch('ci.gauntlet.control_plane.artifacts.prepare_candidate', side_effect=no_artifact):
            self.agent.run_job(job)
        self.assertEqual(job['state'], 'build-failed')
        self.assertEqual(self.agent.jobs[1]['state'], 'queued')
        self.agent.worker.assert_called_once_with(job, 'inspect')
        self.github.status.assert_not_called()

    def test_annotated_tag_resolves_to_commit_and_prereleases_refused(self):
        g = GitHub(dict(DEFAULTS, release_build_backend='github-actions'))
        g.api = Mock(side_effect=[{'tag_name': 'v3.48.0', 'html_url': 'https://github.com/test'},
                                 {'object': {'type': 'tag', 'sha': OTHER}},
                                 {'object': {'type': 'commit', 'sha': SHA}}])
        self.assertEqual(g.release('v3.48.0')['sha'], SHA)
        g.api = Mock(return_value={'tag_name': 'v3.48.0', 'prerelease': True})
        with self.assertRaisesRegex(ValueError, 'stable'):
            g.release('v3.48.0')

    def test_release_mode_cannot_enable_pr_gate(self):
        with self.assertRaisesRegex(ValueError, 'Release-only'):
            gate.apply(self.github, True, {'discovery_mode': 'release-tags'})
        self.github.owned_ruleset.assert_not_called()

    def test_stage_progress_retains_only_operational_fields(self):
        with patch.object(vm_worker, 'process_identity', return_value={'start_ticks': '10'}):
            vm_worker.stage_progress(self.root, SHA, 'conformance-control', ['success'], 'timeout')
        data = json.loads((self.root/'stage-progress.json').read_text())
        self.assertEqual(data['current_control'], 'timeout')
        self.assertEqual(data['completed_controls'], ['success'])
        self.assertNotIn('record', data)

    def test_progress_checks_process_identity_and_returns_no_raw_control(self):
        job = '1'*16
        output = self.root/'output'
        output.mkdir()
        atomic_json(output/(job+'.started.json'), {'source_sha': SHA, 'job_id': job,
                    'pid': 20, 'process_start_ticks': 'original', 'started_at': 1})
        with patch.object(vm_worker, 'OUTPUT', output), patch.object(vm_worker, 'BASE', self.root), \
             patch.object(vm_worker, 'read_json', side_effect=lambda p: json.loads(p.read_text())), \
             patch.object(vm_worker, 'process_identity', return_value={'start_ticks': 'reused'}):
            progress = vm_worker.progress(SHA, job)
        self.assertFalse(progress['process_alive'])
        self.assertEqual(progress['job_id'], job)
        self.assertNotIn('cpu_seconds', progress)

    def test_compiler_progress_exposes_only_crate_and_version_without_raw_log(self):
        job='1'*16
        output=self.root/'output';output.mkdir()
        build=self.root/'builds'/job;build.mkdir(parents=True)
        log=build/'build.log'
        log.write_text('PRIVATE RAW OUTPUT\n Compiling safe_crate v1.2.3 (PRIVATE PATH)\n Compiling second v2.0 EXTRA PRIVATE DATA\n')
        atomic_json(output/(job+'.build-progress.json'),{'source_sha':SHA,'job_id':job,
                    'pid':20,'process_start_ticks':'original','phase':'release-compilation'})
        with patch.object(vm_worker,'OUTPUT',output),patch.object(vm_worker,'BASE',self.root), \
             patch.object(vm_worker,'BUILDS',self.root/'builds'),patch.object(vm_worker,'trusted'), \
             patch.object(vm_worker,'read_json',side_effect=lambda p:json.loads(p.read_text())), \
             patch.object(vm_worker,'process_identity',return_value={'start_ticks':'original'}):
            result=vm_worker.progress(SHA,job)
        self.assertTrue(result['process_alive'])
        self.assertEqual(result['build_log_hints'],['Compiling safe_crate v1.2.3','Compiling second v2.0'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_recorded_failed_control_does_not_look_like_a_pass(self):
        records={'boundary':{'control_completed':False,'error':'private failure'},
                 'success':{'control_completed':True}}
        with patch.object(vm_worker,'process_identity',return_value={'start_ticks':'10'}):
            vm_worker.stage_progress(self.root,SHA,'conformance-control',records,'timeout')
        data=json.loads((self.root/'stage-progress.json').read_text())
        self.assertEqual(data['control_outcomes'][0],{'role':'boundary','completed':False,'has_error':True})
        self.assertNotIn('private failure',json.dumps(data))


if __name__ == '__main__':
    unittest.main()
