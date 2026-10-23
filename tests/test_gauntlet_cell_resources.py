"""Live resource counters belong to the Root-declared active product cell."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci.gauntlet.control_plane import vm_worker


class CellResourceTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.control=self.root/'control'
        self.profile=self.control/'product/builtin-product/cell.apparmor'
        self.profile.parent.mkdir(parents=True)
        self.name='hol-product-cell-'+'a'*32
        self.profile.write_text('profile '+self.name+' flags=(attach_disconnected) {}\n')
        groups=self.root/'groups';group=groups/(self.name+'.service');group.mkdir(parents=True)
        values={'memory.current':'200000000','memory.max':'1073741824','memory.peak':'300000000',
                'pids.current':'90','pids.max':'128','memory.events':'oom_kill 0\n',
                'pids.events':'max 0\n','cgroup.procs':'42\n'}
        for name,value in values.items():(group/name).write_text(value)
        self.proc=self.root/'proc';p=self.proc/'42';p.mkdir(parents=True)
        (p/'status').write_text('Name:\thol-guard-runti\nVmSize:\t200000 kB\nVmPeak:\t250000 kB\n')
        (p/'limits').write_text('Max address space         1073741824           1073741824           bytes\n')
        (p/'cgroup').write_text('0::/system.slice/'+self.name+'.service\n')
        for target,value in (('CGROUPS',groups),('PROC',self.proc)):
            replaced=patch.object(vm_worker,target,value);replaced.start();self.addCleanup(replaced.stop)
        trusted=patch.object(vm_worker,'trusted');trusted.start();self.addCleanup(trusted.stop)

    def test_real_kernel_fields_distinguish_ram_and_virtual_address_space(self):
        value=vm_worker.cell_resources(self.control)
        self.assertEqual(value['memory_bytes'],200000000)
        self.assertEqual(value['memory_limit_bytes'],1073741824)
        self.assertEqual(value['native_virtual_bytes'],200000*1024)
        self.assertEqual(value['native_address_space_limit_bytes'],1073741824)
        self.assertEqual(value['tasks'],90)
        self.assertEqual(value['task_limit'],128)

    def test_pid_reused_outside_cell_does_not_leak_process_resources(self):
        (self.proc/'42/cgroup').write_text('0::/unrelated.service\n')
        value=vm_worker.cell_resources(self.control)
        self.assertNotIn('native_virtual_bytes',value)

    def test_unrecognized_profile_or_stopped_cell_is_unavailable(self):
        self.profile.write_text('profile ../../another-cell {}')
        self.assertIsNone(vm_worker.cell_resources(self.control))
        self.profile.unlink()
        self.assertIsNone(vm_worker.cell_resources(self.control))
