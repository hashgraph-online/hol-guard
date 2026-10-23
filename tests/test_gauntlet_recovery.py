"""Regression tests for stale collectors, retained upgrades and existing-VM startup."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import zipfile

from ci.gauntlet.control_plane import bootstrap_guest, lifecycle
from ci.gauntlet.control_plane.config import DEFAULTS, atomic_json


class UpgradeTests(unittest.TestCase):
    def archive(self, upgrade=False, filename='ci/gauntlet/example.py'):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr(filename, 'VALUE = 1\n')
            archive.writestr('settings.json', '{"controller_python":"/trusted/python"}')
            archive.writestr('request.json', json.dumps({'upgrade': upgrade}))
        return buffer.getvalue()

    def test_upgrade_flag_does_not_change_controller_source_generation(self):
        ordinary = bootstrap_guest.decode(self.archive(False))
        upgrade = bootstrap_guest.decode(self.archive(True))
        self.assertEqual(ordinary[3], upgrade[3])
        self.assertFalse(ordinary[2])
        self.assertTrue(upgrade[2])

    def test_guest_bootstrap_refuses_traversal_before_mutation(self):
        with self.assertRaisesRegex(ValueError, 'path/object'):
            bootstrap_guest.decode(self.archive(filename='ci/../../outside.py'))

    def test_ordinary_up_cannot_overwrite_existing_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'stage-settings.json'
            path.write_bytes(b'original')
            with patch.object(bootstrap_guest, 'secure'):
                with self.assertRaisesRegex(ValueError, 'repair'):
                    bootstrap_guest.update_file(path, b'replacement', upgrade=False)
            self.assertEqual(path.read_bytes(), b'original')
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_explicit_upgrade_preserves_previous_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'stage-settings.json'
            path.write_bytes(b'original')
            path.chmod(0o444)
            with patch.object(bootstrap_guest, 'secure'):
                bootstrap_guest.update_file(path, b'replacement', upgrade=True)
                bootstrap_guest.update_file(path, b'replacement', upgrade=False)
            backup = path.with_name(path.name + '.previous-' + hashlib.sha256(b'original').hexdigest())
            self.assertEqual(backup.read_bytes(), b'original')
            self.assertEqual(path.read_bytes(), b'replacement')
            self.assertEqual(len(list(Path(directory).iterdir())), 2)


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        (self.state/'private').mkdir()
        (self.state/'public').mkdir()

    def test_fresh_snapshot_from_legacy_restricted_observer_is_not_ready(self):
        atomic_json(self.state/'public/snapshot.json', {'updated_at': time.time(), 'jobs': []})
        self.assertFalse(lifecycle.observer_ready(self.state, 123))

    def test_only_matching_pid_and_current_source_heartbeat_is_ready(self):
        value = {'updated_at': time.time(), 'observer': {'pid': 123,
                 'schema': 'hol-gauntlet-observer.v2', 'source_sha256': lifecycle.observer_source()}}
        atomic_json(self.state/'public/snapshot.json', value)
        self.assertTrue(lifecycle.observer_ready(self.state, 123))
        self.assertFalse(lifecycle.observer_ready(self.state, 999))
        value['observer']['source_sha256'] = 'a'*64
        atomic_json(self.state/'public/snapshot.json', value)
        self.assertFalse(lifecycle.observer_ready(self.state, 123))

    def test_old_heartbeat_cannot_report_current_observer_readiness(self):
        atomic_json(self.state/'public/snapshot.json', {'updated_at': time.time()-120,
                    'observer': {'pid': 123, 'schema': 'hol-gauntlet-observer.v2',
                                 'source_sha256': lifecycle.observer_source()}})
        self.assertFalse(lifecycle.observer_ready(self.state, 123))

    def test_stale_pid_record_never_signals_an_unverified_process(self):
        atomic_json(self.state/'private/agent.pid.json', {'pid': 123})
        with patch('ci.gauntlet.control_plane.cli.process_alive', return_value=False), \
             patch('ci.gauntlet.control_plane.lifecycle.os.kill') as kill:
            lifecycle.stop_observer(self.state)
        kill.assert_not_called()
        self.assertFalse((self.state/'private/agent.pid.json').exists())

    def test_active_job_refuses_controller_repair(self):
        atomic_json(self.state/'private/jobs/abcdef.json', {'id': 'abcdef', 'state': 'running'})
        with self.assertRaisesRegex(RuntimeError, 'reconcile'):
            lifecycle.assert_idle(self.state)

    def test_only_verified_clean_startup_allows_controller_repair(self):
        path=self.state/'private/jobs/abcdef.json'
        atomic_json(path, {'id':'abcdef','state':'unknown'})
        with patch('ci.gauntlet.control_plane.stage_recovery.clean_startup_repair_allowed',return_value=True) as proof:
            with self.assertRaisesRegex(RuntimeError, 'reconcile'):
                lifecycle.assert_idle(self.state)
            lifecycle.assert_idle(self.state,clean_startup_config=DEFAULTS)
            proof.assert_called_once()
        atomic_json(path, {'id':'abcdef','state':'running'})
        with patch('ci.gauntlet.control_plane.stage_recovery.clean_startup_repair_allowed') as proof:
            with self.assertRaisesRegex(RuntimeError, 'reconcile'):
                lifecycle.assert_idle(self.state,clean_startup_config=DEFAULTS)
            proof.assert_not_called()

    def test_denied_observer_stop_prevents_any_vm_changes(self):
        with patch.object(lifecycle, 'stop_observer', side_effect=RuntimeError('ordinary host terminal')), \
             patch.object(lifecycle, 'ensure_vm_running') as vm, \
             patch('ci.gauntlet.control_plane.bootstrap.install') as install:
            with self.assertRaisesRegex(RuntimeError, 'ordinary host terminal'):
                lifecycle.repair(Mock(), self.state, self.state/'config.json', DEFAULTS)
        vm.assert_not_called()
        install.assert_not_called()


class VMTests(unittest.TestCase):
    def test_stopped_existing_vm_starts_once_without_changing_resources(self):
        with patch.object(lifecycle, 'vm_inventory', side_effect=[{'status': 'Stopped'}, {'status': 'Running'}]), \
             patch.object(lifecycle.subprocess, 'run') as run:
            result = lifecycle.ensure_vm_running(DEFAULTS)
        self.assertEqual(result['status'], 'running')
        run.assert_called_once_with([DEFAULTS['limactl'], 'start', '--tty=false', '--timeout=120s', DEFAULTS['vm']],
                                    check=True, timeout=150)

    def test_running_vm_is_not_restarted(self):
        with patch.object(lifecycle, 'vm_inventory', return_value={'status': 'Running'}), \
             patch.object(lifecycle.subprocess, 'run') as run:
            lifecycle.ensure_vm_running(DEFAULTS)
        run.assert_not_called()

    def test_inaccessible_or_broken_vm_is_not_assumed_stopped(self):
        with patch.object(lifecycle, 'vm_inventory', return_value={'status': 'Broken'}), \
             patch.object(lifecycle.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'inspect'):
                lifecycle.ensure_vm_running(DEFAULTS)
        run.assert_not_called()

    def test_missing_vm_is_never_created_implicitly(self):
        with patch.object(lifecycle.subprocess, 'run', return_value=Mock(stdout='[]')) as run:
            with self.assertRaisesRegex(RuntimeError, 'not changed or recreated'):
                lifecycle.vm_inventory(DEFAULTS)
        self.assertEqual(run.call_count, 1)

    def test_readiness_program_compiles_without_executing_it(self):
        compile(lifecycle.VERIFY_VM, '<readiness>', 'exec')


if __name__ == '__main__':
    unittest.main()
