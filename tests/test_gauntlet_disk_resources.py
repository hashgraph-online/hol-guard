import argparse
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import disk_resources as module
from ci.gauntlet.control_plane.config import DEFAULTS

GIB=1024**3


class DiskTests(unittest.TestCase):
    def test_growth_reserves_host_headroom_and_requests_only_existing_disk_edit(self):
        target=dict(DEFAULTS)
        with patch.object(module.shutil,'disk_usage',return_value=Mock(free=60*GIB)):
            flags=module.plan(argparse.Namespace(vm_disk_gib=48),Path('/tmp'),target,{'disk':24*GIB})
        self.assertEqual(flags,['--disk=48'])
        self.assertEqual(target['vm_disk_gib'],48)

    def test_shrink_unknown_allocation_and_low_host_capacity_refuse_growth(self):
        for requested,current,free in [(24,48*GIB,60*GIB),(48,None,60*GIB),(48,24*GIB,30*GIB)]:
            with patch.object(module.shutil,'disk_usage',return_value=Mock(free=free)):
                with self.assertRaises(ValueError):
                    module.plan(argparse.Namespace(vm_disk_gib=requested),Path('/tmp'),dict(DEFAULTS),{'disk':current})

    def test_plain_repair_preserves_existing_larger_disk(self):
        target=dict(DEFAULTS)
        self.assertEqual(module.plan(argparse.Namespace(),Path('/tmp'),target,{'disk':48*GIB}),[])
        self.assertEqual(target['vm_disk_gib'],48)

    def test_configured_disk_size_without_guest_filesystem_growth_is_not_success(self):
        args=argparse.Namespace(vm_disk_gib=48)
        target={**DEFAULTS,'vm_disk_gib':48}
        with self.assertRaisesRegex(RuntimeError,'filesystem'):
            module.verify(args,target,{'disk':48*GIB},{'disk_total':22*GIB})
        module.verify(args,target,{'disk':48*GIB},{'disk_total':46*GIB})
