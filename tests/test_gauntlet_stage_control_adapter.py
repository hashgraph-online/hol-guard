"""The staging adapter accepts only fixed identities before any VM execution."""

import io
import stat
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace
from unittest.mock import patch

from ci.gauntlet.benchmark.stage_control_adapter import (
    ROLES, _tap_directory_matches, _tap_root_matches, _tap_socket_matches, main, parse_args,
    staging_config_path,
)


BUILD = 'a' * 16
RUN = 'b' * 16
SOURCE = 'c' * 40
CONFIG = 'd' * 64
MANIFEST = 'e' * 64


class StagingControlAdapterTests(unittest.TestCase):
    def test_exact_role_set_and_candidate_identity(self):
        self.assertEqual(ROLES, {
            'success', 'input-binding', 'injection', 'boundary', 'timeout', 'cancel'
        })
        for role in ROLES:
            self.assertEqual(
                parse_args([BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, role])[-2:], (role, False)
            )
            self.assertEqual(
                parse_args([BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, role,
                            '--sdk-tap-v2'])[-2:], (role, True)
            )
        self.assertEqual(
            str(staging_config_path(BUILD, MANIFEST, CONFIG)),
            '/opt/hol-gauntlet/rust-shadow-candidates/' + BUILD
            + '/provisional-eeeeeeeeeeeeeeee-dddddddddddddddd.json',
        )

    def test_arbitrary_paths_selectors_and_malformed_pins_refuse(self):
        valid = [BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, 'success']
        bad = [
            valid[:-1], valid + ['/tmp/override'],
            valid + ['--sdk-tap-v2', '/tmp/override'],
            valid + ['--sdk-tap-v1'],
            ['../' + BUILD, *valid[1:]],
            [BUILD.upper(), *valid[1:]],
            [BUILD, RUN + '/other', *valid[2:]],
            [*valid[:2], SOURCE[:-1], *valid[3:]],
            [*valid[:3], '3.49.0;sh', *valid[4:]],
            [*valid[:4], CONFIG.upper(), *valid[5:]],
            [*valid[:5], MANIFEST[:-1], valid[6]],
            [*valid[:6], 'all'],
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                parse_args(candidate)

    def test_non_linux_refuses_before_key_or_state_access(self):
        valid = [BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, 'success']
        stderr = io.StringIO()
        with patch('ci.gauntlet.benchmark.stage_control_adapter.sys.platform', 'darwin'), redirect_stderr(stderr):
            self.assertEqual(main(valid), 2)
        self.assertIn('isolated, assertion-enabled Linux Root controller required', stderr.getvalue())

    def test_tap_directory_and_socket_metadata_refuse_wrong_owner_mode_type_or_inode(self):
        root = dict(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0,
                    st_dev=7, st_ino=10)
        directory = dict(st_mode=stat.S_IFDIR | 0o710, st_uid=0, st_gid=10001,
                         st_nlink=2, st_dev=7, st_ino=11)
        socket = dict(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=10001,
                      st_nlink=1, st_dev=7, st_ino=12)
        original_dir = SimpleNamespace(**directory)
        original_root = SimpleNamespace(**root)
        original_socket = SimpleNamespace(**socket)
        self.assertTrue(_tap_root_matches(original_root, original_root))
        self.assertTrue(_tap_directory_matches(original_dir, original_dir))
        self.assertTrue(_tap_socket_matches(original_socket, original_socket))
        for field, changed in (('st_mode', stat.S_IFDIR | 0o710), ('st_uid', 10001),
                               ('st_gid', 10001), ('st_ino', 99),
                               ('st_mode', stat.S_IFLNK | 0o700)):
            with self.subTest(root=(field, changed)):
                self.assertFalse(_tap_root_matches(
                    SimpleNamespace(**(root | {field: changed})), original_root))
        for field, changed in (('st_mode', stat.S_IFDIR | 0o700), ('st_uid', 10001),
                               ('st_gid', 0), ('st_nlink', 1), ('st_ino', 99),
                               ('st_mode', stat.S_IFREG | 0o710)):
            with self.subTest(directory=(field, changed)):
                self.assertFalse(_tap_directory_matches(
                    SimpleNamespace(**(directory | {field: changed})), original_dir))
        for field, changed in (('st_mode', stat.S_IFSOCK | 0o600), ('st_uid', 10001),
                               ('st_gid', 0), ('st_nlink', 2), ('st_ino', 99),
                               ('st_mode', stat.S_IFREG | 0o660)):
            with self.subTest(socket=(field, changed)):
                self.assertFalse(_tap_socket_matches(
                    SimpleNamespace(**(socket | {field: changed})), original_socket))


if __name__ == '__main__':
    unittest.main()
