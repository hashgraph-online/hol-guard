"""Safe VM memory resize and propagation of the compiler memory limit."""
import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane.config import DEFAULTS, atomic_json, load
from ci.gauntlet.control_plane import resources, vm_build

GIB=1024**3


class ResourceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state=Path(temp.name)
        (self.state/'private/jobs').mkdir(parents=True)
        self.config=self.state/'config.json'
        atomic_json(self.config,{**DEFAULTS,'vm_memory_gib':8,'build_memory_gib':4,'vm_disk_gib':24})
        self.args=argparse.Namespace(vm_memory_gib=16,build_memory_gib=12)

    def test_stops_edits_starts_existing_idle_vm_and_confirms_guest_memory(self):
        inventory=[{'status':'Running','memory':8*GIB}, {'status':'Stopped','memory':8*GIB},
                   {'status':'Running','memory':16*GIB}]
        with patch('ci.gauntlet.control_plane.lifecycle.vm_inventory',side_effect=inventory), \
             patch('ci.gauntlet.control_plane.lifecycle.ensure_vm_running') as start, \
             patch('ci.gauntlet.control_plane.telemetry.vm',return_value={'status':'running','memory_total':15.6*GIB}), \
             patch.object(resources.subprocess,'run',return_value=Mock(returncode=0,stdout='idle\n')) as run:
            result=resources.configure(self.args,self.state,self.config,dict(DEFAULTS))
        self.assertEqual(result['vm_memory_gib'],16)
        self.assertEqual(load(self.config)['build_memory_gib'],12)
        self.assertEqual(run.call_args_list[1].args[0],[DEFAULTS['limactl'],'stop','--tty=false',DEFAULTS['vm']])
        self.assertEqual(run.call_args_list[2].args[0],
                         [DEFAULTS['limactl'],'edit','--tty=false','--memory=16',DEFAULTS['vm']])
        self.assertEqual(start.call_args.args[0]['vm_memory_gib'],16)

    def test_active_job_refuses_resize_before_any_remote_action(self):
        atomic_json(self.state/'private/jobs/job.json',{'id':'1'*16,'state':'preparing'})
        with patch.object(resources.subprocess,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'active'):
                resources.configure(self.args,self.state,self.config,dict(DEFAULTS))
        run.assert_not_called()

    def test_disk_growth_uses_the_same_idle_restart_and_verifies_guest_filesystem(self):
        args=argparse.Namespace(vm_memory_gib=16,build_memory_gib=12,vm_disk_gib=48)
        inventory=[{'status':'Running','memory':16*GIB,'disk':24*GIB},
                   {'status':'Stopped','memory':16*GIB,'disk':24*GIB},
                   {'status':'Running','memory':16*GIB,'disk':48*GIB}]
        with patch('ci.gauntlet.control_plane.lifecycle.vm_inventory',side_effect=inventory), \
             patch('ci.gauntlet.control_plane.lifecycle.ensure_vm_running'), \
             patch('ci.gauntlet.control_plane.telemetry.vm',return_value={'status':'running','memory_total':15.6*GIB,'disk_total':46*GIB}), \
             patch('ci.gauntlet.control_plane.disk_resources.shutil.disk_usage',return_value=Mock(free=60*GIB)), \
             patch.object(resources.subprocess,'run',return_value=Mock(returncode=0,stdout='idle\n')) as run:
            result=resources.configure(args,self.state,self.config,dict(DEFAULTS))
        self.assertIn('--disk=48',run.call_args_list[2].args[0])
        self.assertEqual(result['vm_disk_gib'],48)

    def test_remote_worker_must_be_proven_idle_before_stop(self):
        with patch('ci.gauntlet.control_plane.lifecycle.vm_inventory',return_value={'status':'Running','memory':8*GIB}), \
             patch.object(resources.subprocess,'run',return_value=Mock(returncode=1,stdout='',stderr='lease busy')) as run:
            with self.assertRaisesRegex(RuntimeError,'no resize'):
                resources.configure(self.args,self.state,self.config,dict(DEFAULTS))
        self.assertEqual(run.call_count,1)
        self.assertEqual(load(self.config)['vm_memory_gib'],8)

    def test_unverified_guest_memory_does_not_publish_successful_resize(self):
        inventory=[{'status':'Stopped','memory':8*GIB},{'status':'Running','memory':16*GIB}]
        with patch('ci.gauntlet.control_plane.lifecycle.vm_inventory',side_effect=inventory), \
             patch('ci.gauntlet.control_plane.lifecycle.ensure_vm_running'), \
             patch('ci.gauntlet.control_plane.telemetry.vm',return_value={'status':'running','memory_total':8*GIB}), \
             patch.object(resources.subprocess,'run'):
            with self.assertRaisesRegex(RuntimeError,'Guest memory'):
                resources.configure(self.args,self.state,self.config,dict(DEFAULTS))
        self.assertEqual(load(self.config)['vm_memory_gib'],8)

    def test_plain_repair_does_not_shrink_a_manually_enlarged_vm(self):
        args=argparse.Namespace(vm_memory_gib=None,build_memory_gib=None)
        with patch('ci.gauntlet.control_plane.lifecycle.vm_inventory',return_value={'status':'Running','memory':16*GIB}), \
             patch('ci.gauntlet.control_plane.lifecycle.ensure_vm_running'), \
             patch('ci.gauntlet.control_plane.telemetry.vm',return_value={'status':'running','memory_total':15.5*GIB}), \
             patch.object(resources.subprocess,'run') as run:
            result=resources.configure(args,self.state,self.config,dict(DEFAULTS))
        run.assert_not_called()
        self.assertEqual(result['vm_memory_gib'],16)

    def test_rejects_container_budget_without_vm_headroom(self):
        self.args.build_memory_gib=16
        with patch('ci.gauntlet.control_plane.lifecycle.vm_inventory',return_value={'status':'Running','memory':8*GIB}), \
             patch.object(resources.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'reserve'):
                resources.configure(self.args,self.state,self.config,dict(DEFAULTS))
        run.assert_not_called()

    def test_container_receives_twelve_gib_not_old_four_gib(self):
        argv=vm_build.container_command('sha256:'+'a'*64,'1'*16,'a'*40,'v3.48.0',self.state,12)
        self.assertIn('--memory=12g',argv)
        self.assertIn('--memory-swap=12g',argv)
        self.assertNotIn('--memory=4g',argv)

    def test_wait_idle_never_waits_past_unknown_execution(self):
        atomic_json(self.state/'private/jobs/job.json',{'id':'1'*16,'state':'unknown'})
        with self.assertRaisesRegex(RuntimeError,'reconciled'):
            resources.wait_idle(self.state)

    def test_wait_idle_observes_completion_without_stopping_current_job(self):
        job=self.state/'private/jobs/job.json'
        atomic_json(job,{'id':'1'*16,'state':'preparing'})
        with patch.object(resources.time,'sleep',side_effect=lambda _:atomic_json(job,{'id':'1'*16,'state':'build-failed'})) as sleep:
            resources.wait_idle(self.state)
        sleep.assert_called_once()
        compile(resources.QUIET,'<vm-idle-check>','exec')


if __name__=='__main__':
    unittest.main()
