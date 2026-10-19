"""Terminal reconciliation must never replay inference or release an uncertain hold."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci.gauntlet.control_plane import live_local
from ci.gauntlet.control_plane import vm_live
from ci.gauntlet.control_plane import live_provider
from ci.gauntlet.control_plane.config import atomic_json


JOB = 'a' * 16
SHA = 'b' * 40


class LiveTerminalTests(unittest.TestCase):
    def test_feature_ai_reservation_is_bounded_below_full_campaign(self):
        self.assertEqual(live_provider.RESERVATIONS['feature-ai'], 200_000)
        self.assertLess(live_provider.RESERVATIONS['feature-ai'],
                        live_provider.RESERVATIONS['beta-e2e'])

    def test_vm_prepare_accepts_only_fixed_source_bound_live_stage_id(self):
        request = {'action': 'prepare', 'job_id': JOB, 'source_sha': SHA,
                   'provider_sha256': 'c'*64, 'model_sha256': 'd'*64,
                   'stage_id': 'e'*16}
        vm_live.fixed(request, 'prepare')
        with self.assertRaisesRegex(ValueError, 'staging identity'):
            vm_live.fixed({**request, 'stage_id': '../candidate'}, 'prepare')
        with self.assertRaisesRegex(ValueError, 'exact live request'):
            vm_live.fixed({**request, 'unreviewed_path': '/tmp'}, 'prepare')
        vm_live.fixed({**request, 'profile': 'feature-ai'}, 'prepare')
        vm_live.fixed({**request, 'profile': 'feature-ai-protocol'}, 'prepare')
        with self.assertRaisesRegex(ValueError, 'reviewed optional'):
            vm_live.fixed({**request, 'profile': 'unreviewed'}, 'prepare')

    def test_two_cell_receipt_preserves_baseline_effect_and_guard_surface(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'deployment'
            output = Path(temporary)/'output'
            (output/'result/report').mkdir(parents=True)
            root.mkdir()
            (root/'policy.json').write_text(json.dumps({'cells': [
                {'episode_id': 'baseline', 'outcome': 'attacked-baseline-measurement'},
                {'episode_id': 'protected', 'outcome': 'secure-completion'}]}))
            report = {'schema': 'gauntlet-ci-check.v1', 'profile': 'feature-ai',
                      'expected_guard_source_sha': SHA, 'guard_source_sha': SHA,
                      'runner_config_digest': 'c'*64, 'exit_code': 0,
                      'selected_cases': 2, 'status': 'passed',
                      'model_usage_known': True, 'model_tokens': 123,
                      'cells': [
                          {'episode_id': 'baseline', 'status': 'measured-baseline',
                           'security_status': 'violated', 'security_violation_observed': True,
                           'baseline_measurement_only': True},
                          {'episode_id': 'protected', 'status': 'passed',
                           'security_status': 'invariants-held', 'security_violation_observed': False,
                           'baseline_measurement_only': False,
                           'supported_surfaces': ['native-mcp']}]}
            path = output/'result/report/result.json'
            path.write_text(json.dumps(report))
            manifest = {'source_sha': SHA, 'job_id': JOB, 'config_digest': 'c'*64,
                        'profile': 'feature-ai', 'selected_cases': 2}
            helpers = {'read_json': lambda file: json.loads(file.read_text())}
            result = vm_live.terminal_from_report(root, output, manifest, 0, helpers)
            self.assertEqual(result['model_tokens'], 123)
            self.assertTrue(result['cells'][0]['security_violation_observed'])
            self.assertIn('native-mcp', result['cells'][1]['supported_surfaces'])
            report['cells'][1]['status'] = 'measured-baseline'
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'policy-valid'):
                vm_live.terminal_from_report(root, output, manifest, 0, helpers)

    def test_protocol_receipt_marks_model_ingestion_only_after_passing_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'deployment'
            output = Path(temporary)/'output'
            (output/'result/report').mkdir(parents=True)
            root.mkdir()
            (root/'policy.json').write_text(json.dumps({'cells': [
                {'episode_id': 'baseline', 'outcome': 'attacked-baseline-measurement'},
                {'episode_id': 'protected', 'outcome': 'secure-completion'}]}))
            report = {'schema': 'gauntlet-ci-check.v1', 'profile': 'feature-ai-protocol',
                      'expected_guard_source_sha': SHA, 'guard_source_sha': SHA,
                      'runner_config_digest': 'c'*64, 'exit_code': 0,
                      'selected_cases': 2, 'status': 'passed',
                      'model_usage_known': True, 'model_tokens': 123,
                      'cells': [{'episode_id': 'baseline', 'status': 'measured-baseline',
                                 'model_ingestion_proven': True,
                                 'protocol_exposure_stage': 'model-context-forwarded'},
                                {'episode_id': 'protected', 'status': 'passed',
                                 'model_ingestion_proven': True,
                                 'protocol_exposure_stage': 'model-context-forwarded'}]}
            path = output/'result/report/result.json'
            path.write_text(json.dumps(report))
            manifest = {'source_sha': SHA, 'job_id': JOB, 'config_digest': 'c'*64,
                        'profile': 'feature-ai-protocol', 'selected_cases': 2}
            helpers = {'read_json': lambda file: json.loads(file.read_text())}
            result = vm_live.terminal_from_report(root, output, manifest, 0, helpers)
            self.assertTrue(result['model_ingestion_proven'])
            report['cells'][1]['model_ingestion_proven'] = False
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'model-ingestion evidence'):
                vm_live.terminal_from_report(root, output, manifest, 0, helpers)

    def test_vm_receipt_accepts_only_policy_declared_baseline_measurements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'deployment'
            output = Path(temporary)/'output'
            (output/'result/report').mkdir(parents=True)
            root.mkdir()
            rules = [{'episode_id': f'case-{index}',
                      'outcome': 'attacked-baseline-measurement' if index == 0
                                 else 'secure-completion'} for index in range(12)]
            (root/'policy.json').write_text(json.dumps({'cells': rules}))
            report = {'schema': 'gauntlet-ci-check.v1', 'profile': 'beta-e2e',
                      'expected_guard_source_sha': SHA, 'guard_source_sha': SHA,
                      'runner_config_digest': 'c'*64, 'exit_code': 0,
                      'selected_cases': 12, 'status': 'passed',
                      'model_usage_known': True, 'model_tokens': 197,
                      'cells': [{'episode_id': f'case-{index}',
                                 'status': 'measured-baseline' if index == 0 else 'passed'}
                                for index in range(12)]}
            path = output/'result/report/result.json'
            path.write_text(json.dumps(report))
            manifest = {'source_sha': SHA, 'job_id': JOB, 'config_digest': 'c'*64}
            helpers = {'read_json': lambda file: json.loads(file.read_text())}
            result = vm_live.terminal_from_report(root, output, manifest, 0, helpers)
            self.assertEqual((result['status'], result['model_tokens']), ('passed', 197))
            report['cells'][1]['status'] = 'measured-baseline'
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'policy-valid'):
                vm_live.terminal_from_report(root, output, manifest, 0, helpers)

    def test_failed_inner_check_is_a_verified_failure_when_transport_succeeded(self):
        self.assertEqual(live_local.verified_terminal(
            {'status': 'failed', 'exit_code': 1}, 0), 'failed')
        self.assertEqual(live_local.verified_terminal(
            {'status': 'passed', 'exit_code': 1}, 0), 'invalid-evidence')

    def test_failed_transport_cannot_verify_a_report(self):
        with self.assertRaisesRegex(RuntimeError, 'verified terminal'):
            live_local.verified_terminal({'status': 'passed', 'exit_code': 0}, 1)

    def test_reconcile_retains_failure_and_releases_only_its_hold(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state/'public').mkdir()
            (state/'private/live'/JOB).mkdir(parents=True)
            row = {'job_id': JOB, 'source_sha': SHA, 'status': 'unknown',
                   'model_provider_pid': 123, 'completed_cases': 0}
            atomic_json(state/'public/live.json', row)
            atomic_json(state/'private/hold-admissions.json',
                        {'job_id': JOB, 'reason': 'live model E2E'})
            terminal = {'job_id': JOB, 'source_sha': SHA, 'status': 'failed',
                        'exit_code': 1, 'completed_cases': 12, 'model_tokens': 173,
                        'cells': [{'episode_id': 'case-1', 'status': 'failed'}]}
            with patch.object(live_local, 'call_vm', return_value=terminal) as vm, \
                 patch.object(live_local, 'stop_owned_provider', return_value=True) as stop:
                self.assertEqual(live_local.reconcile({}, state, JOB), 1)
            vm.assert_called_once_with({}, {'action': 'status', 'job_id': JOB,
                                            'source_sha': SHA}, timeout=30)
            stop.assert_called_once()
            saved = json.loads((state/'public/live.json').read_text())
            self.assertEqual((saved['status'], saved['model_tokens']), ('failed', 173))
            self.assertFalse((state/'private/hold-admissions.json').exists())
            self.assertEqual(json.loads((state/'private/live'/JOB/'terminal.json').read_text()), terminal)

    def test_reconcile_refuses_nonterminal_vm_and_keeps_hold_and_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state/'public').mkdir()
            (state/'private/live'/JOB).mkdir(parents=True)
            atomic_json(state/'public/live.json',
                        {'job_id': JOB, 'source_sha': SHA, 'status': 'unknown',
                         'model_provider_pid': 123, 'completed_cases': 0})
            hold = state/'private/hold-admissions.json'
            atomic_json(hold, {'job_id': JOB, 'reason': 'live model E2E'})
            with patch.object(live_local, 'call_vm',
                              return_value={'job_id': JOB, 'source_sha': SHA,
                                            'status': 'running'}) as vm, \
                 patch.object(live_local, 'stop_owned_provider') as stop:
                with self.assertRaisesRegex(RuntimeError, 'verified terminal'):
                    live_local.reconcile({}, state, JOB)
            vm.assert_called_once()
            stop.assert_not_called()
            self.assertTrue(hold.exists())


if __name__ == '__main__':
    unittest.main()
