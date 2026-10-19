"""Retain staging errors automatically without promoting or replaying work."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import diagnostics
from ci.gauntlet.control_plane.config import DEFAULTS


class StageDiagnosticTests(unittest.TestCase):
    def test_collect_binds_identity_and_keeps_details_in_private_directory(self):
        job={'id':'1'*16,'sha':'a'*40}
        value={'source_sha':job['sha'],'job_id':job['id'],'worker_idle':True,
               'controls':[{'role':'boundary','error':'AssertionError: native startup failed',
                            'traceback':'retained private traceback'}]}
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)/'private/local-builds'/job['id']
            with patch.object(diagnostics.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))):
                result=diagnostics.collect(DEFAULTS,job,directory)
            self.assertEqual(result,value)
            self.assertIn('private traceback',(directory/'stage-diagnostic.json').read_text())
            self.assertEqual(diagnostics.summary(result),'Conformance boundary: AssertionError: native startup failed')

    def test_mismatched_diagnostic_is_rejected(self):
        job={'id':'1'*16,'sha':'a'*40}
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(diagnostics.subprocess,'run',return_value=Mock(returncode=0,
                stdout=json.dumps({'source_sha':'b'*40,'job_id':job['id']}))):
                with self.assertRaisesRegex(ValueError,'identity'):
                    diagnostics.collect(DEFAULTS,job,Path(temp))
            self.assertFalse((Path(temp)/'stage-diagnostic.json').exists())

    def test_unknown_or_missing_diagnostics_cannot_claim_success(self):
        self.assertIn('No terminal control error',diagnostics.summary({'controls':[]}))
        compile(diagnostics.READ_STAGE,'<read-only-stage-diagnostics>','exec')

    def test_readiness_failure_reports_recorded_response(self):
        row={'role':'boundary','error':'ValueError: installed native workspace readiness not confirmed',
             'startup_events':[{'kind':'native-workspace-readiness','returncode':69,
                                'response':{'ready':False,'reason_code':'native_policy_not_ready'}}]}
        self.assertIn('native_policy_not_ready',diagnostics.summary({'controls':[row]}))

    def test_successful_readiness_does_not_hide_a_later_sdk_failure(self):
        row={'role':'boundary','error':'AssertionError: boundary probe failed',
             'startup_events':[{'kind':'native-workspace-readiness','returncode':0,'response':{'ready':True}}]}
        self.assertIn('boundary probe failed',diagnostics.summary({'controls':[row]}))

    def test_blank_prompt_assertion_reports_actual_native_denial(self):
        row={'role':'success','error':'AssertionError: ',
             'startup_events':[{'kind':'hook-denial-diagnostic','response':{
                 'decision':'block','reason_code':'native_prompt_unavailable',
                 'reason':'HOL Guard could not complete native prompt review safely.'}}]}
        summary=diagnostics.summary({'controls':[row]})
        self.assertIn('native_prompt_unavailable',summary)
        self.assertIn('Conformance success',summary)


if __name__=='__main__':
    unittest.main()
