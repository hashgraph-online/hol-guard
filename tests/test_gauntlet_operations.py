"""Control-plane acceptance tests: real state machines, HTTP and hostile inputs.

The fake backend below proves orchestration only; never live Guard efficacy.
Uses stdlib unittest so the operations container needs no dependency installer.
"""
from __future__ import annotations

import hashlib
import errno
import io
import json
from pathlib import Path
import signal
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request
import zipfile

from ci.gauntlet.control_plane.agent import Agent
from ci.gauntlet.control_plane.artifacts import inspect_archive, select_artifact
from ci.gauntlet.control_plane.config import DEFAULTS, atomic_json, load
from ci.gauntlet.control_plane import gate
from ci.gauntlet.control_plane.server import handler, snapshot
from ci.gauntlet.control_plane.stage_candidate import wheel_entries
from ci.gauntlet.control_plane import bootstrap
from ci.gauntlet.control_plane import cli
from ci.gauntlet.control_plane.telemetry import admission, GIB

SHA = 'a'*40
OTHER = 'b'*40


def pull(sha=SHA, number=7, **overrides):
    return {'number': number, 'state': 'open', 'draft': False, 'title': '<script>untrusted</script>',
            'html_url': 'https://github.com/test/repo/pull/7', 'head': {'sha': sha},
            'base': {'ref': 'main', 'sha': OTHER}, **overrides}


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.agent = Agent(dict(DEFAULTS, discovery_mode='pull-requests'), self.root)
        self.github = Mock()
        self.github.pulls.return_value = [pull()]
        self.github.pull.return_value = pull()
        self.github.gate.return_value = {'required': False}
        self.agent.github = self.github

    def test_discovers_once_without_changing_rules(self):
        self.github.pulls.return_value += [pull(OTHER, 8, draft=True),
                                           pull(OTHER, 9, base={'ref': 'other', 'sha': OTHER})]
        self.agent.discover()
        self.agent.discover()
        self.assertEqual(len(self.agent.jobs), 1)
        self.github.status.assert_called_once()
        self.github.api.assert_not_called()
        self.assertEqual(self.agent.jobs[0]['sha'], SHA)

    def test_new_head_supersedes_waiting_but_never_replays_terminal(self):
        self.agent.discover()
        first = self.agent.jobs[0]
        self.github.pulls.return_value = [pull(OTHER)]
        self.agent.discover()
        self.assertEqual(first['state'], 'superseded')
        self.assertEqual(len(self.agent.jobs), 2)
        self.agent.jobs[1]['state'] = 'failed'
        self.agent.save(self.agent.jobs[1])
        self.agent.discover()
        self.assertEqual(len(self.agent.jobs), 2)

    def test_waits_for_exact_candidate_without_executing(self):
        self.agent.discover()
        job = self.agent.jobs[0]
        self.agent.worker = Mock(return_value={'ready': False})
        with patch('ci.gauntlet.control_plane.artifacts.prepare_candidate', return_value=False):
            self.agent.run_job(job)
        self.assertEqual(job['state'], 'waiting-candidate')
        self.agent.worker.assert_called_once_with(job, 'inspect')

    def test_automatic_discovery_to_execution_to_status(self):
        self.agent.discover()
        job = self.agent.jobs[0]
        receipt = {'source_sha': SHA, 'job_id': job['id'], 'deployment_digest': 'c'*64,
                   'status': 'passed', 'exit_code': 0, 'report_sha256': 'd'*64, 'model_tokens': 0}
        self.agent.worker = Mock(side_effect=[{'ready': True, 'deployment_digest': 'c'*64}, receipt])
        self.agent.run_job(job)
        self.assertEqual(job['state'], 'passed')
        self.assertEqual(self.agent.worker.call_args_list[1].args[1], 'run')
        self.assertEqual(self.github.status.call_args.args[1], 'success')

    def test_wrong_result_commit_cannot_pass(self):
        self.agent.discover()
        job = self.agent.jobs[0]
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.agent.finish(job, {'source_sha': OTHER})

    def test_exit_zero_without_report_is_invalid(self):
        self.agent.discover()
        job = self.agent.jobs[0]
        self.agent.finish(job, {'source_sha': SHA, 'job_id': job['id'], 'deployment_digest': None,
                                'exit_code': 0, 'status': 'passed'})
        self.assertEqual(job['state'], 'invalid-evidence')

    def test_disconnect_during_running_is_unknown_and_restart_keeps_it(self):
        self.agent.discover()
        job = self.agent.jobs[0]
        self.agent.worker = Mock(side_effect=[{'ready': True, 'deployment_digest': 'c'*64}, TimeoutError()])
        self.agent.run_job(job)
        self.assertEqual(job['state'], 'unknown')
        restarted = Agent(dict(DEFAULTS), self.root)
        restarted.recover()
        self.assertEqual(restarted.jobs[0]['state'], 'unknown')

    def test_restart_marks_running_as_unknown_without_executing(self):
        self.agent.discover()
        job = self.agent.jobs[0]
        job['state'] = 'running'
        self.agent.save(job)
        restarted = Agent(dict(DEFAULTS), self.root)
        self.assertEqual(restarted.jobs[0]['state'], 'running')
        restarted.recover()
        self.assertEqual(restarted.jobs[0]['state'], 'unknown')

    def test_public_snapshot_omits_private_inputs_and_preserves_file_access(self):
        self.agent.discover()
        self.agent.jobs[0]['deployment_digest'] = 'not-for-dashboard'
        self.agent.jobs[0]['private_signing_key'] = 'not-for-dashboard'
        self.agent.publish()
        path = self.root/'public/snapshot.json'
        self.assertNotIn('not-for-dashboard', path.read_text())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o755)


class GateTests(unittest.TestCase):
    def test_plan_has_only_own_main_status_rule(self):
        value = gate.plan(True)
        self.assertEqual(value['conditions']['ref_name']['include'], ['refs/heads/main'])
        self.assertEqual([r['type'] for r in value['rules']], ['required_status_checks'])
        self.assertEqual(value['enforcement'], 'active')

    def test_enable_refuses_without_actual_passing_pr(self):
        github = Mock()
        with self.assertRaisesRegex(ValueError, 'real passed'):
            gate.apply(github, True, {'collector_status': 'online', 'updated_at': time.time(),
                                     'github': {'status': 'connected'}, 'vm': {'status': 'running'}, 'jobs': []})
        github.api.assert_not_called()

    def test_enable_creates_separate_rule_without_touching_others(self):
        github = Mock(repo='repos/test/repo')
        github.owned_ruleset.return_value = None
        state = {'collector_status': 'online', 'updated_at': time.time(),
                 'github': {'status': 'connected'}, 'vm': {'status': 'running'},
                 'jobs': [{'state': 'passed', 'posted_state': 'success'}]}
        gate.apply(github, True, state)
        github.api.assert_called_once_with('repos/test/repo/rulesets', 'POST', gate.plan(True))

    def test_disable_refuses_repurposed_ruleset(self):
        github = Mock(repo='repos/test/repo')
        github.owned_ruleset.return_value = {'id': 99}
        github.api.return_value = {**gate.plan(True), 'rules': [{'type': 'deletion'}]}
        with self.assertRaisesRegex(ValueError, 'differs'):
            gate.apply(github, False, {})
        self.assertEqual(github.api.call_count, 1)

    def test_disable_normalizes_only_harmless_api_defaults(self):
        github = Mock(repo='repos/test/repo')
        github.owned_ruleset.return_value = {'id': 99}
        detail = gate.plan(True)
        detail['rules'][0]['parameters']['required_status_checks'][0]['integration_id'] = None
        detail['rules'][0]['parameters']['do_not_enforce_on_create'] = False
        github.api.side_effect = [detail, {'id': 99, 'enforcement': 'disabled'}]
        gate.apply(github, False, {})
        github.api.assert_called_with('repos/test/repo/rulesets/99', 'PUT', gate.plan(False))


class ArtifactTests(unittest.TestCase):
    def make(self, directory, **changes):
        path = Path(directory)/'artifact.zip'
        data = {'schema': 'hol-gauntlet-pr-artifact.v1', 'source_sha': SHA,
                'version': '3.46.0', 'wheel': 'hol_guard-3.46.0-py3-none-linux_aarch64.whl',
                'wheel_sha256': hashlib.sha256(b'wheel').hexdigest(), 'native_sha256': 'c'*64, **changes}
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('artifact.json', json.dumps(data))
            archive.writestr(data['wheel'], b'wheel')
        return path

    def test_exact_archive_and_reject_wrong_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make(directory)
            self.assertEqual(inspect_archive(path, SHA)['source_sha'], SHA)
            with self.assertRaisesRegex(ValueError, 'source'):
                inspect_archive(path, OTHER)

    def test_rejects_archive_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'filenames'):
                inspect_archive(self.make(directory, wheel='../../candidate.whl'), SHA)

    def test_does_not_reuse_older_success_when_new_run_is_pending(self):
        github = Mock(repo='repos/test/repo', config=dict(DEFAULTS))
        common = {'head_sha': SHA, 'event': 'pull_request', 'path': '.github/workflows/gauntlet-pr-artifacts.yml',
                  'pull_requests': [{'number': 7}]}
        github.api.return_value = {'workflow_runs': [dict(common, id=1, status='completed', conclusion='success'),
                                                   dict(common, id=2, status='in_progress', conclusion=None)]}
        self.assertIsNone(select_artifact(github, {'sha': SHA, 'pr': 7}))
        self.assertEqual(github.api.call_count, 1)

    def test_wheel_top_level_execution_file_refused(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('evil.pth', 'import os')
        with self.assertRaisesRegex(ValueError, 'path/object'):
            wheel_entries(data.getvalue(), {}, SHA)

    def test_valid_native_wheel_is_read_inertly_and_bound_to_commit(self):
        data, native = io.BytesIO(), b'not-executed-native-bytes'
        declaration = {'version': '3.46.0', 'native_sha256': hashlib.sha256(native).hexdigest()}
        manifest = {'source_sha': SHA, 'package_version': '3.46.0', 'runtime_sha256': declaration['native_sha256']}
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('codex_plugin_scanner/_native/runtime-manifest.json', json.dumps(manifest))
            archive.writestr('codex_plugin_scanner/_native/hol-guard-runtime', native)
            archive.writestr('codex_plugin_scanner/__init__.py', 'raise RuntimeError("must not import")')
            archive.writestr('hol_guard-3.46.0.dist-info/METADATA', 'Name: hol-guard\nVersion: 3.46.0\n')
        self.assertEqual(wheel_entries(data.getvalue(), declaration, SHA)[
            'codex_plugin_scanner/_native/hol-guard-runtime'], native)
        with self.assertRaisesRegex(ValueError, 'provenance'):
            wheel_entries(data.getvalue(), declaration, OTHER)

    def test_unpublished_workflow_waits_without_running_anything(self):
        github = Mock(repo='repos/test/repo', config=dict(DEFAULTS))
        github.api.side_effect = RuntimeError('HTTP 404 workflow does not exist')
        self.assertIsNone(select_artifact(github, {'sha': SHA, 'pr': 7}))


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_is_bounded_and_excludes_unrelated_ci_tree(self):
        compile(bootstrap.INSTALL, '<trusted-bootstrap>', 'exec')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'ci/gauntlet').mkdir(parents=True)
            (root/'ci/gauntlet/example.py').write_text('VALUE = 1\n')
            (root/'ci/irrelevant').mkdir()
            (root/'ci/irrelevant/not-for-transfer.txt').write_text('excluded')
            captured = []
            def installed(_argv, **kwargs):
                raw = kwargs['input']
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    captured.extend(archive.namelist())
                return Mock(returncode=0, stdout=json.dumps({'status': 'installed',
                    'bootstrap_sha256': hashlib.sha256(raw).hexdigest()}).encode())
            with patch('ci.gauntlet.control_plane.bootstrap.subprocess.run', side_effect=installed):
                result = bootstrap.install(DEFAULTS, root)
            self.assertEqual(result['status'], 'installed')
            self.assertEqual(set(captured), {'ci/gauntlet/example.py', 'settings.json', 'request.json'})

    def test_denied_process_inspection_is_not_reported_as_stopped(self):
        record = {'pid': 123, 'module': 'ci.gauntlet.control_plane.cli', 'state': '/example'}
        with patch('ci.gauntlet.control_plane.cli.subprocess.run', side_effect=PermissionError('sandbox')):
            with self.assertRaisesRegex(RuntimeError, 'ordinary host terminal'):
                cli.process_alive(record, record['module'], Path('/example'))

    def test_failed_dashboard_launch_never_starts_observer(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state/'private').mkdir()
            config = state/'config.json'
            config.write_text(json.dumps(DEFAULTS))
            args = Mock(native=True, port=8787, no_open=True)
            with patch('ci.gauntlet.control_plane.bootstrap.install', return_value={'status': 'installed'}), \
                 patch('ci.gauntlet.control_plane.cli.start_process') as start, \
                 patch('ci.gauntlet.control_plane.cli.check_dashboard_port'), \
                 patch('ci.gauntlet.control_plane.cli.urllib.request.urlopen', side_effect=OSError('socket denied')), \
                 patch('ci.gauntlet.control_plane.cli.time.sleep'):
                with self.assertRaisesRegex(RuntimeError, 'did not become reachable'):
                    cli.up(args, state, config)
            self.assertEqual(start.call_count, 1)
            self.assertEqual(start.call_args.args[2], 'ci.gauntlet.control_plane.server')


class DashboardPortTests(unittest.TestCase):
    def health(self, value):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(value).encode()
        return response

    def test_torch_generic_health_cannot_be_accepted_as_gauntlet(self):
        response = self.health({'server': 'online', 'application': 'Torch'})
        with patch('ci.gauntlet.control_plane.cli.urllib.request.urlopen', return_value=response):
            self.assertFalse(cli.dashboard_ready('http://127.0.0.1:8791', 'a'*32))

    def test_wrong_gauntlet_instance_is_refused(self):
        response = self.health({'server': 'online', 'service': 'hol-gauntlet-dashboard', 'instance_id': 'b'*32})
        with patch('ci.gauntlet.control_plane.cli.urllib.request.urlopen', return_value=response):
            self.assertFalse(cli.dashboard_ready('http://127.0.0.1:8791', 'a'*32))

    def test_matching_gauntlet_instance_is_accepted(self):
        response = self.health({'server': 'online', 'service': 'hol-gauntlet-dashboard', 'instance_id': 'a'*32})
        with patch('ci.gauntlet.control_plane.cli.urllib.request.urlopen', return_value=response):
            self.assertTrue(cli.dashboard_ready('http://127.0.0.1:8791', 'a'*32))

    def test_occupied_port_leaves_other_service_untouched(self):
        with patch('ci.gauntlet.control_plane.cli.socket.socket') as socket_factory, \
             patch('ci.gauntlet.control_plane.cli.dashboard_ready', return_value=False), \
             patch('ci.gauntlet.control_plane.cli.os.kill') as kill:
            socket_factory.return_value.__enter__.return_value.bind.side_effect = OSError(errno.EADDRINUSE, 'busy')
            with self.assertRaisesRegex(RuntimeError, 'left untouched'):
                cli.check_dashboard_port(8787, 'a'*32)
            kill.assert_not_called()

    def test_original_port_migrates_to_8791_and_opens_ipv4_url(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state/'private').mkdir()
            config = state/'config.json'
            config.write_text(json.dumps(DEFAULTS))
            atomic_json(state/'private/dashboard-mode.json', {'mode': 'native', 'port': 8787})
            args = Mock(native=True, port=None, no_open=True)
            with patch('ci.gauntlet.control_plane.bootstrap.install', return_value={'status': 'installed'}), \
                 patch('ci.gauntlet.control_plane.cli.check_dashboard_port') as port, \
                 patch('ci.gauntlet.control_plane.cli.start_process') as start, \
                 patch('ci.gauntlet.control_plane.lifecycle.wait_observer'), \
                 patch('ci.gauntlet.control_plane.cli.dashboard_ready', return_value=True) as ready:
                cli.up(args, state, config)
            self.assertEqual(port.call_args.args[0], 8791)
            self.assertEqual(ready.call_args.args[0], 'http://127.0.0.1:8791')
            self.assertEqual(start.call_args_list[0].args[3][-1], '8791')
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['port'], 8791)


class RustDashboardHandoffTests(unittest.TestCase):
    def state(self, directory, mode='native'):
        state = Path(directory)
        (state/'private').mkdir()
        (state/'public').mkdir()
        value = {'mode': mode, 'port': 8791}
        if mode == 'rust':
            value['docker_context'] = 'colima'
        atomic_json(state/'private/dashboard-mode.json', value)
        atomic_json(state/'private/dashboard.pid.json', {
            'pid': 1234, 'module': 'ci.gauntlet.control_plane.server', 'state': str(state)})
        return state

    def test_compose_targets_saved_context_and_loopback_port(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            with patch.object(cli.subprocess, 'run') as run:
                cli.rust_dashboard_compose(state, 8791, 'up', '--no-build', '-d', '--wait',
                                           context='colima')
            command = run.call_args.args[0]
            project = 'hol-gauntlet-rust-' + hashlib.sha256(str(state).encode()).hexdigest()[:12]
            self.assertEqual(command[:6], ['docker', '--context', 'colima', 'compose',
                                            '-p', project])
            self.assertEqual(command[-4:], ['up', '--no-build', '-d', '--wait'])
            self.assertEqual(run.call_args.kwargs['env']['GAUNTLET_RUST_PORT'], '8791')
            self.assertEqual(run.call_args.kwargs['env']['GAUNTLET_RUST_IMAGE'], project + ':local')
            self.assertEqual(run.call_args.kwargs['env']['GAUNTLET_PUBLIC_STATE'],
                             str(state/'public'))
            with patch.object(cli.subprocess, 'run') as second:
                cli.rust_dashboard_compose(state/'other', 8794, 'up', '--no-build', '-d', '--wait',
                                           context='colima')
            self.assertNotEqual(second.call_args.args[0][5], project)

    def test_one_command_switch_builds_before_stopping_only_owned_http_process(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            events = []
            with patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'docker_available', return_value=(True, '')), \
                 patch.object(cli, 'process_alive', side_effect=[True, False]), \
                 patch.object(cli, 'rust_dashboard_compose',
                              side_effect=lambda *args, **kwargs: events.append(args[2:])), \
                 patch.object(cli.os, 'kill', side_effect=lambda *args: events.append(('kill', *args))), \
                 patch.object(cli, 'wait_dashboard_identity', return_value='http://127.0.0.1:8791'), \
                 patch.object(cli, 'start_process') as restart:
                cli.switch_dashboard_to_rust(state, docker_context='colima')
            self.assertEqual(events[0], ('build',))
            self.assertEqual(events[1][0:2], ('kill', 1234))
            self.assertEqual(events[2], ('up', '--no-build', '-d', '--wait'))
            restart.assert_not_called()
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text()),
                             {'mode': 'rust', 'port': 8791, 'docker_context': 'colima'})

    def test_failed_rust_health_restores_python_without_changing_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            with patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'docker_available', return_value=(True, '')), \
                 patch.object(cli, 'process_alive', side_effect=[True, False, True]), \
                 patch.object(cli, 'rust_dashboard_compose') as compose, \
                 patch.object(cli.os, 'kill') as kill, \
                 patch.object(cli, 'wait_dashboard_identity',
                              side_effect=[RuntimeError('wrong service'), 'http://127.0.0.1:8791']), \
                 patch.object(cli, 'start_process') as restart:
                with self.assertRaisesRegex(RuntimeError, 'wrong service'):
                    cli.switch_dashboard_to_rust(state, docker_context='colima')
            self.assertEqual([call.args[2:] for call in compose.call_args_list],
                             [('build',), ('up', '--no-build', '-d', '--wait'), ('down',)])
            kill.assert_called_once()
            restart.assert_called_once()
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['mode'],
                             'native')

    def test_termination_during_handoff_restores_python_and_signal_handler(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            previous_handler = signal.getsignal(signal.SIGTERM)
            events = []

            def compose(*args, **kwargs):
                events.append(args[2:])
                if args[2] == 'up':
                    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

            with patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'docker_available', return_value=(True, '')), \
                 patch.object(cli, 'process_alive', side_effect=[True, False, True]), \
                 patch.object(cli, 'rust_dashboard_compose', side_effect=compose), \
                 patch.object(cli.os, 'kill'), \
                 patch.object(cli, 'wait_dashboard_identity', return_value='http://127.0.0.1:8791'), \
                 patch.object(cli, 'start_process') as restart:
                with self.assertRaisesRegex(KeyboardInterrupt, 'Dashboard handoff interrupted'):
                    cli.switch_dashboard_to_rust(state, docker_context='colima')
            self.assertEqual(events, [('build',), ('up', '--no-build', '-d', '--wait'), ('down',)])
            restart.assert_called_once()
            self.assertIs(signal.getsignal(signal.SIGTERM), previous_handler)
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['mode'],
                             'native')

    def test_failed_image_build_leaves_python_dashboard_running(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory)
            with patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'docker_available', return_value=(True, '')), \
                 patch.object(cli, 'rust_dashboard_compose', side_effect=RuntimeError('build failed')), \
                 patch.object(cli, 'process_alive') as inspect, \
                 patch.object(cli.os, 'kill') as kill:
                with self.assertRaisesRegex(RuntimeError, 'build failed'):
                    cli.switch_dashboard_to_rust(state, docker_context='colima')
            inspect.assert_not_called()
            kill.assert_not_called()
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['mode'],
                             'native')

    def test_failed_python_restore_restarts_rust_and_keeps_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory, mode='rust')
            with patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'rust_dashboard_compose') as compose, \
                 patch.object(cli, 'start_process', side_effect=RuntimeError('python failed')), \
                 patch.object(cli, 'process_alive', return_value=False), \
                 patch.object(cli, 'wait_dashboard_identity', return_value='http://127.0.0.1:8791'):
                with self.assertRaisesRegex(RuntimeError, 'python failed'):
                    cli.restore_python_dashboard(state)
            self.assertEqual([call.args[2:] for call in compose.call_args_list],
                             [('down',), ('up', '--no-build', '-d', '--wait')])
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['mode'],
                             'rust')

    def test_restore_and_normal_up_keep_observer_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.state(directory, mode='rust')
            config = state/'config.json'
            config.write_text(json.dumps(DEFAULTS))
            with patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'rust_dashboard_compose') as compose, \
                 patch.object(cli, 'wait_dashboard_identity', return_value='http://127.0.0.1:8791'), \
                 patch.object(cli, 'process_alive', return_value=True), \
                 patch.object(cli, 'start_process') as start:
                cli.restore_python_dashboard(state)
            compose.assert_called_once_with(state, 8791, 'down', context='colima')
            self.assertEqual(start.call_args.args[1], 'dashboard')
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['mode'],
                             'native')
            atomic_json(state/'private/dashboard-mode.json',
                        {'mode': 'rust', 'port': 8791, 'docker_context': 'colima'})
            args = Mock(native=False, port=None, no_open=True)
            with patch('ci.gauntlet.control_plane.bootstrap.install', return_value={'status':'installed'}), \
                 patch.object(cli, 'dashboard_identity', return_value='a'*32), \
                 patch.object(cli, 'check_dashboard_port'), \
                 patch.object(cli, 'docker_available', return_value=(True, '')), \
                 patch.object(cli, 'rust_dashboard_compose') as compose, \
                 patch.object(cli, 'dashboard_ready', return_value=True), \
                 patch('ci.gauntlet.control_plane.lifecycle.wait_observer'), \
                 patch.object(cli, 'start_process') as start:
                cli.up(args, state, config)
            self.assertEqual([call.args[2:] for call in compose.call_args_list],
                             [('build',), ('up', '--no-build', '-d', '--wait')])
            self.assertEqual(start.call_args.args[1], 'agent')
            self.assertEqual(json.loads((state/'private/dashboard-mode.json').read_text())['mode'],
                             'rust')


class HealthTests(unittest.TestCase):
    def test_wrong_vm_allocation_cannot_look_ready_despite_free_space(self):
        state={'host':{'disk_free':69*GIB,'checked_at':time.time()},
               'vm':{'status':'running','disk_free':10*GIB,'disk_total':22*GIB,
                     'memory_available':6*GIB,'memory_total':7.6*GIB,'checked_at':time.time()}}
        reasons=admission(state,DEFAULTS)
        self.assertTrue(any('memory is below' in r for r in reasons))
        self.assertTrue(any('filesystem is below' in r for r in reasons))

    def test_resource_floors_and_staleness_block_admission(self):
        state = {'host': {'disk_free': 69*GIB, 'checked_at': time.time()},
                 'vm': {'status': 'running', 'disk_free': 10*GIB, 'memory_available': 4*GIB,
                        'disk_total':46*GIB,'memory_total':15.6*GIB,'checked_at': time.time()}}
        self.assertEqual(admission(state, DEFAULTS), [])
        state['vm']['disk_free'] = GIB
        self.assertIn('VM disk headroom below configured floor', admission(state, DEFAULTS))
        state['host']['checked_at'] = 0
        self.assertIn('Resource telemetry is stale', admission(state, DEFAULTS))

    def test_stale_snapshot_never_claims_collector_online(self):
        with tempfile.TemporaryDirectory() as directory:
            atomic_json(Path(directory)/'snapshot.json', {'updated_at': time.time()-200, 'jobs': []})
            self.assertEqual(snapshot(directory)['collector_status'], 'stale')

    def test_http_serves_dashboard_and_rejects_other_hosts_and_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            # Exercise real HTTP parsing/response generation with an in-memory
            # transport; no listening socket permission is needed for this test.
            class Transport:
                def __init__(self, request):
                    self.request, self.response = io.BytesIO(request), bytearray()
                def makefile(self, *_args):
                    return self.request
                def sendall(self, data):
                    self.response.extend(data)
            def exchange(path='/', host='localhost', method='GET'):
                transport = Transport(f'{method} {path} HTTP/1.0\r\nHost: {host}\r\n\r\n'.encode())
                handler(directory)(transport, ('127.0.0.1', 1), None)
                return bytes(transport.response)
            page = exchange()
            self.assertIn(b'200 OK', page)
            self.assertIn(b'Every check.', page)
            self.assertIn(b"script-src 'self'", page)
            status = exchange('/api/status').split(b'\r\n\r\n', 1)[1]
            self.assertEqual(json.loads(status)['collector_status'], 'unavailable')
            self.assertIn(b'403 Forbidden', exchange(host='evil.example'))
            self.assertIn(b'501 Unsupported method', exchange(method='POST'))


if __name__ == '__main__':
    unittest.main()
