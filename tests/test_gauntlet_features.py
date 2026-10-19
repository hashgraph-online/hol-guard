"""Feature audit must keep source identity and partial evidence visible."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import cli, feature_audit, feature_entry, server, vm_features

AUDIT = 'a'*16
BUILD = 'b'*16
SHA = 'c'*40
REQUEST = {'action': 'run', 'audit_id': AUDIT, 'build_job_id': BUILD,
           'source_sha': SHA, 'source_archive_sha256': 'd'*64,
           'candidate_archive_sha256': 'e'*64}


class FeatureAuditTests(unittest.TestCase):
    def test_feature_audit_resolves_exact_retained_build_after_staging_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary)
            jobs=state/'private/jobs';jobs.mkdir(parents=True)
            build={'status':'built','source_sha':SHA,'job_id':BUILD,
                   'archive_sha256':'e'*64}
            original={'id':BUILD,'kind':'local-candidate','sha':SHA,
                      'local_build':build,'source_archive_sha256':'d'*64,
                      'retried_as':AUDIT}
            (jobs/(BUILD+'.json')).write_text(json.dumps(original))
            passed={'id':AUDIT,'kind':'local-candidate','sha':SHA,
                    'local_build':build,'retry_of':BUILD}
            self.assertEqual(feature_audit.source_archive_for_build(state,passed,build),'d'*64)
            self.assertEqual(feature_audit.request_for_candidate(state,passed,{'sha':SHA},AUDIT),
                             REQUEST)
            original['retried_as']='f'*16
            (jobs/(BUILD+'.json')).write_text(json.dumps(original))
            with self.assertRaisesRegex(ValueError,'linkage'):
                feature_audit.source_archive_for_build(state,passed,build)

    def test_catalog_has_unique_real_test_targets_and_explicit_evidence_modes(self):
        root = Path(__file__).resolve().parents[1]
        groups = feature_entry.catalog()
        self.assertEqual(len({g['id'] for g in groups}), len(groups))
        self.assertGreaterEqual(len(groups), 20)
        self.assertTrue(all(g['tests'] for g in groups))
        self.assertTrue(all((root/test.split('::', 1)[0]).is_file()
                            for group in groups for test in group['tests']))
        self.assertEqual({g['evidence_kind'] for g in groups},
                         {'source-native-contract', 'installed-product-contract'})
        ownership = next(g for g in groups if g['id'] == 'decision_io_gate')
        self.assertEqual(ownership['evidence_kind'], 'source-native-contract')
        self.assertEqual(ownership['tests'], [
            'tests/test_rust_io_ownership_gate.py::test_gate_inventories_reachable_io_and_passes_current_sources'])

    def test_vm_status_rejects_mismatched_identity_and_symlinked_progress(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit = root/AUDIT
            (audit/'output').mkdir(parents=True)
            (audit/'request.json').write_text(json.dumps(REQUEST))
            outside = root/'outside.json'
            outside.write_text(json.dumps({'status': 'passed', 'completed_groups': 21}))
            (audit/'output/progress.json').symlink_to(outside)
            with patch.object(vm_features, 'AUDITS', root):
                result = vm_features.status({**REQUEST, 'action': 'status'})
                self.assertEqual(result['status'], 'running')
                self.assertNotIn('completed_groups', result)
                with self.assertRaisesRegex(ValueError, 'source identity differs'):
                    vm_features.status({**REQUEST, 'action': 'status',
                                        'source_sha': 'f'*40})
                with self.assertRaisesRegex(ValueError, 'exact source-bound'):
                    vm_features.status({**REQUEST, 'action': 'status',
                                        'source_path': '/tmp/other'})

    def test_dashboard_keeps_failed_and_skipped_contracts_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary)
            (public/'snapshot.json').write_text(json.dumps({'updated_at': time.time(), 'jobs': []}))
            report = {'schema': 'hol-gauntlet-feature-operations.v1',
                      'audit_id': AUDIT, 'source_sha': SHA, 'updated_at': time.time(),
                      'status': 'failed', 'groups': [{'id': 'cline', 'status': 'incomplete',
                      'counts': {'tests': 36, 'skipped': 22}}]}
            (public/'feature-audit.json').write_text(json.dumps(report))
            result = server.snapshot(public)['feature_audit']
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['groups'][0]['counts']['skipped'], 22)

    def test_dashboard_keeps_ai_probe_separate_from_contract_and_full_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary)
            (public/'snapshot.json').write_text(json.dumps({'updated_at': time.time(), 'jobs': []}))
            probe = {'schema': 'hol-gauntlet-live-operations.v1',
                     'profile': 'feature-ai', 'job_id': AUDIT, 'source_sha': SHA,
                     'updated_at': time.time(), 'status': 'passed', 'model_tokens': 42000,
                     'cells': [{'baseline_measurement_only': True,
                                'security_violation_observed': True}]}
            (public/'feature-ai.json').write_text(json.dumps(probe))
            result = server.snapshot(public)
            self.assertEqual(result['feature_ai']['model_tokens'], 42000)
            self.assertNotIn('feature_audit', result)
            self.assertNotIn('live_e2e', result)

    def test_dashboard_projects_protocol_ingestion_from_both_retained_cells(self):
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary)
            (public/'snapshot.json').write_text(json.dumps({'updated_at': time.time(), 'jobs': []}))
            cells = [{'model_ingestion_proven': True,
                      'protocol_exposure_stage': 'model-context-forwarded'} for _ in range(2)]
            probe = {'schema': 'hol-gauntlet-live-operations.v1',
                     'profile': 'feature-ai-protocol', 'job_id': AUDIT,
                     'updated_at': time.time(), 'status': 'passed',
                     'model_ingestion_proven': None, 'cells': cells}
            path = public/'feature-ai.json'
            path.write_text(json.dumps(probe))
            self.assertTrue(server.snapshot(public)['feature_ai']['model_ingestion_proven'])
            probe['cells'][1]['model_ingestion_proven'] = False
            path.write_text(json.dumps(probe))
            self.assertFalse(server.snapshot(public)['feature_ai']['model_ingestion_proven'])

    def test_dashboard_server_restarts_only_owned_stale_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state/'private').mkdir()
            pidfile = state/'private/dashboard.pid.json'
            pidfile.write_text(json.dumps({'pid': 123, 'module': 'gauntlet.server',
                                           'state': str(state), 'source_sha256': 'old'}))
            with patch.object(cli, 'process_alive', side_effect=[True, False]), \
                 patch.object(cli.os, 'kill') as killed, \
                 patch.object(cli.subprocess, 'Popen', return_value=Mock(pid=456)):
                pid = cli.start_process(state, 'dashboard', 'gauntlet.server', [],
                                        source_sha256='new')
            self.assertEqual(pid, 456)
            killed.assert_called_once_with(123, cli.signal.SIGTERM)
            self.assertEqual(json.loads(pidfile.read_text())['source_sha256'], 'new')


if __name__ == '__main__':
    unittest.main()
