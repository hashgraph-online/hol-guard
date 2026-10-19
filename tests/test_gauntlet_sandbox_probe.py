import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import sandbox_probe
from ci.gauntlet.control_plane.config import DEFAULTS


class SandboxProbeTests(unittest.TestCase):
    def test_only_completed_failure_can_be_probed_and_identity_is_bound(self):
        job={'id':'1'*16,'sha':'a'*40,'state':'conformance-failed'}
        value={'job_id':job['id'],'source_sha':job['sha'],'diagnostic_only':True,'probe_mode':'backend',
               'benchmark_admitted':False,'cleanup_complete':True}
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(sandbox_probe.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))) as run:
                self.assertEqual(sandbox_probe.collect(DEFAULTS,job,Path(temp)),value)
            self.assertEqual(json.loads(run.call_args.kwargs['input']),{'source_sha':job['sha'],'job_id':job['id']})
            self.assertTrue((Path(temp)/'runtime-probe.json').is_file())
        compile(sandbox_probe.PROBE_RUNTIME,'<isolated-runtime-probe>','exec')

    def test_probe_refuses_active_job_or_unproven_vm_execution(self):
        job={'id':'1'*16,'sha':'a'*40,'state':'preparing'}
        with patch.object(sandbox_probe.subprocess,'run') as run:
            with self.assertRaises(ValueError):
                sandbox_probe.collect(DEFAULTS,job,Path('/tmp'))
        run.assert_not_called()
        job['state']='conformance-failed'
        with patch.object(sandbox_probe.subprocess,'run',return_value=Mock(returncode=1,stderr='worker lease busy')):
            with self.assertRaisesRegex(RuntimeError,'lease busy'):
                sandbox_probe.collect(DEFAULTS,job,Path('/tmp'))
