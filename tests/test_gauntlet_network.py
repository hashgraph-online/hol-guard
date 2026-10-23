"""Missing VM networking helper provisioning and fail-closed preflight."""
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.control_plane import lifecycle, vm_network
from ci.gauntlet.control_plane.config import DEFAULTS


class BuildNetworkTests(unittest.TestCase):
    def test_existing_helper_is_verified_without_package_changes(self):
        trusted = Mock()
        with patch.object(vm_network.shutil,'which',return_value='/usr/bin/slirp4netns'), \
             patch.object(vm_network.subprocess,'run',return_value=Mock(stdout='slirp4netns version 1.2.1\n')) as run:
            result = vm_network.ensure_slirp(trusted)
        self.assertEqual(result['status'],'ready')
        self.assertFalse(result['installed'])
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0],['/usr/bin/slirp4netns','--version'])
        trusted.assert_called_once()

    def test_missing_helper_installs_only_the_required_package_then_verifies(self):
        with patch.object(vm_network.shutil,'which',side_effect=[None,'/usr/bin/slirp4netns']), \
             patch.object(vm_network.subprocess,'run',return_value=Mock(stdout='slirp4netns version 1.2.1\n')) as run:
            result = vm_network.ensure_slirp(Mock())
        self.assertTrue(result['installed'])
        self.assertEqual(run.call_args_list[0].args[0],['/usr/bin/apt-get','update'])
        self.assertEqual(run.call_args_list[1].args[0],
                         ['/usr/bin/apt-get','install','--yes','--no-install-recommends','slirp4netns'])
        self.assertEqual(run.call_args_list[2].args[0],['/usr/bin/slirp4netns','--version'])

    def test_failed_package_install_is_not_reported_as_ready(self):
        with patch.object(vm_network.shutil,'which',return_value=None), \
             patch.object(vm_network.subprocess,'run',side_effect=subprocess.CalledProcessError(100,['apt-get'])):
            with self.assertRaises(subprocess.CalledProcessError):
                vm_network.ensure_slirp(Mock())

    def test_missing_binary_after_install_is_a_clear_failure(self):
        with patch.object(vm_network.shutil,'which',return_value=None), \
             patch.object(vm_network.subprocess,'run',return_value=Mock(stdout='')):
            with self.assertRaisesRegex(RuntimeError,'still unavailable'):
                vm_network.ensure_slirp(Mock())

    def test_host_requires_verified_helper_and_surfaces_remote_errors(self):
        value = {'status':'ready','backend':'slirp4netns','installed':True}
        with patch.object(lifecycle.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(value))) as run:
            self.assertEqual(lifecycle.prepare_build_network(DEFAULTS),value)
        self.assertIn('/opt/hol-gauntlet/network.py',run.call_args.args[0])
        with patch.object(lifecycle.subprocess,'run',return_value=Mock(returncode=1,stdout='',stderr='apt failed')):
            with self.assertRaisesRegex(RuntimeError,'apt failed'):
                lifecycle.prepare_build_network(DEFAULTS)
        with patch.object(lifecycle.subprocess,'run',return_value=Mock(returncode=0,stdout='{"status":"unknown"}')):
            with self.assertRaisesRegex(ValueError,'verify'):
                lifecycle.prepare_build_network(DEFAULTS)


if __name__=='__main__':
    unittest.main()
