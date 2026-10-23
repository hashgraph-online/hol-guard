import json
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import stage_recovery
from ci.gauntlet.control_plane.config import DEFAULTS
from tests.test_gauntlet_stage_outcome import early_startup_specimen


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.job={'id':'1'*16,'sha':'a'*40,'local_build':{'job_id':'2'*16}}

    def test_retention_is_bound_to_job_source_and_original_build(self):
        value={'job_id':'1'*16,'source_sha':'a'*40,'build_job_id':'2'*16,'retry_safe':True}
        with patch.object(stage_recovery.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))) as run:
            self.assertEqual(stage_recovery.retain(DEFAULTS,self.job),value)
        self.assertEqual(json.loads(run.call_args.kwargs['input']),
                         {k:value[k] for k in ('job_id','source_sha','build_job_id')})

    def test_identity_or_safety_mismatch_never_allows_retry(self):
        for key,bad in [('job_id','3'*16),('source_sha','b'*40),('build_job_id','3'*16),('retry_safe',False)]:
            value={'job_id':'1'*16,'source_sha':'a'*40,'build_job_id':'2'*16,'retry_safe':True,key:bad}
            with patch.object(stage_recovery.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))):
                with self.assertRaises(ValueError):
                    stage_recovery.retain(DEFAULTS,self.job)

    def test_vm_refusal_does_not_get_converted_to_success(self):
        with patch.object(stage_recovery.subprocess,'run',return_value=Mock(returncode=1,stderr='cell still live')):
            with self.assertRaisesRegex(RuntimeError,'cell still live'):
                stage_recovery.retain(DEFAULTS,self.job)
        compile(stage_recovery.RETAIN,'<retained-stage-recovery>','exec')

    def test_clean_startup_repair_needs_exact_vm_cleanup_proof(self):
        compile(stage_recovery.PROBE_CLEAN_STARTUP,'<clean-startup-probe>','exec')
        self.job.update(state='unknown',kind='local-candidate',local_build={'status':'built'})
        proof={'job_id':self.job['id'],'source_sha':self.job['sha'],
               'record_sha256':'c'*64,'record':early_startup_specimen()}
        with patch.object(stage_recovery.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(proof))):
            self.assertTrue(stage_recovery.clean_startup_repair_allowed(DEFAULTS,self.job))
        for change in ('wrong-source','live-resource','missing-vm-proof'):
            bad=json.loads(json.dumps(proof))
            if change=='wrong-source':bad['source_sha']='b'*40
            if change=='live-resource':bad['record']['developer_runtime']['record']['upstream_counts']['active_workers']=1
            if change=='missing-vm-proof':bad['record_sha256']='invalid'
            with self.subTest(change=change),patch.object(stage_recovery.subprocess,'run',
                    return_value=Mock(returncode=0,stdout=json.dumps(bad))):
                self.assertFalse(stage_recovery.clean_startup_repair_allowed(DEFAULTS,self.job))

    def test_preflight_retry_requires_deployment_pin_and_root_confirmation(self):
        self.job.update(state='failed',deployment_digest='c'*64)
        value={'job_id':'1'*16,'source_sha':'a'*40,'build_job_id':'2'*16,
               'retry_safe':True,'preflight_only':True}
        with patch.object(stage_recovery.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))) as run:
            stage_recovery.retain(DEFAULTS,self.job)
        self.assertEqual(json.loads(run.call_args.kwargs['input'])['deployment_digest'],'c'*64)
        value['preflight_only']=False
        with patch.object(stage_recovery.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))):
            with self.assertRaises(ValueError):
                stage_recovery.retain(DEFAULTS,self.job)
        self.job.pop('deployment_digest')
        with patch.object(stage_recovery.subprocess,'run') as run,self.assertRaises(ValueError):
            stage_recovery.retain(DEFAULTS,self.job)
        run.assert_not_called()

    def test_root_retention_refuses_semantic_execution_or_other_preflight_failure(self):
        for change in ('other-error','executed-cell','unknown-usage','wrong-source'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);base=root/'base';output=root/'outputs'
                base.mkdir();output.mkdir();(base/'worker.lock').touch()
                candidate=base/'candidates'/('a'*40);candidate.mkdir(parents=True)
                report_dir=output/('1'*16)/'report';report_dir.mkdir(parents=True)
                report={'schema':'gauntlet-ci-check.v1','profile':'deterministic',
                    'guard_source_sha':'a'*40,'expected_guard_source_sha':'a'*40,
                    'runner_config_digest':'d'*64,'model_tokens':0,'model_usage_known':True,
                    'errors':['ValueError: installed Guard lacks the declared completion module; new matching candidate required'],
                    'cells':[{'status':'failed','reasons':['control-failed-or-not-executed']} for _ in range(6)]}
                if change=='other-error':report['errors']=['native prompt unavailable']
                if change=='executed-cell':report['cells'][0]={'status':'passed','reasons':[]}
                if change=='unknown-usage':report['model_usage_known']=False
                if change=='wrong-source':report['guard_source_sha']='b'*40
                report_path=report_dir/'result.json';report_path.write_text(json.dumps(report))
                receipt={'job_id':'1'*16,'source_sha':'a'*40,'deployment_digest':'c'*64,
                         'status':'failed','exit_code':1,
                         'report_sha256':hashlib.sha256(report_path.read_bytes()).hexdigest()}
                (output/('1'*16+'.json')).write_text(json.dumps(receipt))
                (output/('1'*16+'.started.json')).write_text(json.dumps(receipt))
                request={'job_id':'1'*16,'source_sha':'a'*40,'build_job_id':'2'*16,'deployment_digest':'c'*64}
                actual_path=Path
                def mapped(value):
                    value=str(value)
                    for source,target in (('/opt/hol-gauntlet',base),('/var/lib/hol-gauntlet/outputs',output)):
                        if value==source or value.startswith(source+'/'):
                            return actual_path(str(target)+value[len(source):])
                    return actual_path(value)
                helpers={'trusted':lambda p:p,'read_json':lambda p:json.loads(p.read_text()),
                         'deployment':lambda sha:({'config_digest':'d'*64},'c'*64),
                         'process_identity':lambda pid:None}
                with patch('pathlib.Path',side_effect=mapped), \
                     patch('runpy.run_path',return_value=helpers), \
                     patch('sys.stdin',io.StringIO(json.dumps(request))),self.assertRaises(ValueError):
                    exec(compile(stage_recovery.RETAIN,'<trusted-root-retention>','exec'),{})
                self.assertTrue(candidate.exists())
                self.assertFalse((base/'candidates'/('a'*40+'.failed-'+'1'*16)).exists())
