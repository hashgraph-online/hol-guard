"""A diagnostic audit must never replace the immutable strict verdict."""
import json
import unittest
from pathlib import Path
import tempfile
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

from ci.gauntlet.control_plane import stage_audit
from ci.gauntlet.control_plane.config import DEFAULTS


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.job={'id':'1'*16,'sha':'a'*40,'kind':'release','state':'failed','deployment_digest':'b'*64}
        self.result={'status':'diagnostic-passed','source_sha':'a'*40,'job_id':'1'*16,
            'deployment_digest':'b'*64,'controls':6,'benchmark_admitted':False,
            'strict_result_preserved':True,'cleanup_verified':True,
            'cells':[{'episode_id':r,'status':'passed'} for r in
                     ('success','input-binding','injection','boundary','timeout','cancel')]}

    def collect(self, result):
        response=SimpleNamespace(returncode=0,stdout=json.dumps(result),stderr='')
        with patch.object(stage_audit.subprocess,'run',return_value=response):
            return stage_audit.collect(DEFAULTS,self.job)

    def test_audit_preserves_failed_strict_verdict(self):
        original=deepcopy(self.job)
        self.assertEqual(self.collect(self.result),self.result)
        self.assertEqual(self.job,original)

    def test_wrong_source_job_deployment_or_missing_control_is_rejected(self):
        mutations=[{'source_sha':'c'*40},{'job_id':'2'*16},{'deployment_digest':'d'*64},
                   {'benchmark_admitted':True},{'strict_result_preserved':False},
                   {'cleanup_verified':False},{'cells':self.result['cells'][:-1]},
                   {'cells':[{'episode_id':'success','status':'passed'}]*6}]
        for change in mutations:
            with self.subTest(change=change),self.assertRaises(ValueError):
                self.collect({**self.result,**change})

    def test_active_job_cannot_be_audited(self):
        self.job['state']='running'
        with patch.object(stage_audit.subprocess,'run') as run,self.assertRaises(ValueError):
            stage_audit.collect(DEFAULTS,self.job)
        run.assert_not_called()

    def test_active_worker_is_not_interrupted_by_audit_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary)
            jobs=state/'private/jobs';jobs.mkdir(parents=True)
            (jobs/'active.json').write_text(json.dumps({**self.job,'state':'preparing'}))
            with patch('ci.gauntlet.control_plane.lifecycle.stop_observer') as stop, \
                 self.assertRaises(RuntimeError):
                stage_audit.audit(state,DEFAULTS,self.job['id'])
            stop.assert_not_called()
