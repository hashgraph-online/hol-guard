"""Fixed one-role Python executor for a future Rust-owned staging supervisor.

This adapter cannot create a conformance package or admit a candidate. Rust
must pin the controller, provisional config, signing key and one-use job before
launch, and must independently read and score the retained control afterwards.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

from .contracts import canonical_json
from .product_version import validate_version


ROLES = frozenset({'success', 'input-binding', 'injection', 'boundary', 'timeout', 'cancel'})
HEX16 = re.compile(r'[0-9a-f]{16}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_CONTROL_BYTES = 8 * 1024 * 1024
WORKER_LOCK = Path('/opt/hol-gauntlet/worker.lock')
SDK_TAP_ROOT = Path('/var/lib/hol-gauntlet-rust/staging-state')
SDK_TAP_V2 = '--sdk-tap-v2'


def parse_args(argv):
    if len(argv) not in (7, 8) or (len(argv) == 8 and argv[-1] != SDK_TAP_V2):
        raise ValueError('exact build job, staging run, source, version, config, manifest and role required')
    tap_v2 = len(argv) == 8
    build_job, run_id, source, version, config_digest, private_manifest, role = argv[:7]
    if (HEX16.fullmatch(build_job) is None or HEX16.fullmatch(run_id) is None
            or HEX40.fullmatch(source) is None or HEX64.fullmatch(config_digest) is None
            or HEX64.fullmatch(private_manifest) is None or role not in ROLES):
        raise ValueError('invalid fixed staging control identity')
    validate_version(version)
    return build_job, run_id, source, version, config_digest, private_manifest, role, tap_v2


class _SdkTapMount:
    """Hold the one-use Rust socket directory across the controller run."""

    def __init__(self, run_id):
        self.path = SDK_TAP_ROOT / (run_id + '.sdk-tap')
        self.root_fd = self.tap_fd = None
        try:
            self.root_fd = os.open(SDK_TAP_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            root = os.fstat(self.root_fd)
            if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0
                    or stat.S_IMODE(root.st_mode) != 0o700):
                raise ValueError('Root-owned private SDK tap journal required')
            self.root = root
            self.tap_fd = os.open(run_id + '.sdk-tap',
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self.root_fd)
            self.directory = os.fstat(self.tap_fd)
            self.sockets = {family: os.stat(family + '.sock', dir_fd=self.tap_fd, follow_symlinks=False)
                            for family in ('docs', 'mail')}
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        root_held = os.fstat(self.root_fd)
        root_visible = os.stat(SDK_TAP_ROOT, follow_symlinks=False)
        for row in (root_held, root_visible):
            if not _tap_root_matches(row, self.root):
                raise ValueError('Root-owned SDK tap journal identity or mode changed')
        held = os.fstat(self.tap_fd)
        visible = os.stat(self.path.name, dir_fd=self.root_fd, follow_symlinks=False)
        for row in (self.directory, held, visible):
            if not _tap_directory_matches(row, self.directory):
                raise ValueError('Rust SDK tap directory identity or mode changed')
        for family, original in self.sockets.items():
            current = os.stat(family + '.sock', dir_fd=self.tap_fd, follow_symlinks=False)
            for row in (original, current):
                if not _tap_socket_matches(row, original):
                    raise ValueError('Rust SDK tap socket identity or mode changed')

    def close(self):
        if self.tap_fd is not None:
            os.close(self.tap_fd)
            self.tap_fd = None
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None


def _tap_directory_matches(row, original):
    return (stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and row.st_gid == 10001
            and stat.S_IMODE(row.st_mode) == 0o710 and row.st_nlink >= 2
            and (row.st_dev, row.st_ino) == (original.st_dev, original.st_ino))


def _tap_root_matches(row, original):
    return (stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and row.st_gid == 0
            and stat.S_IMODE(row.st_mode) == 0o700
            and (row.st_dev, row.st_ino) == (original.st_dev, original.st_ino))


def _tap_socket_matches(row, original):
    return (stat.S_ISSOCK(row.st_mode) and row.st_uid == 0 and row.st_gid == 10001
            and stat.S_IMODE(row.st_mode) == 0o660 and row.st_nlink == 1
            and (row.st_dev, row.st_ino) == (original.st_dev, original.st_ino))


def staging_config_path(build_job, private_manifest, config_digest):
    return (Path('/opt/hol-gauntlet/rust-shadow-candidates') / build_job
            / ('provisional-' + private_manifest[:16] + '-' + config_digest[:16] + '.json'))


def _read_control(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= MAX_CONTROL_BYTES):
            raise ValueError('retained staging record is unsafe or oversized')
        raw = stream.read(MAX_CONTROL_BYTES + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) != before.st_size or len(raw) > MAX_CONTROL_BYTES
            or any(getattr(before, name) != getattr(after, name) for name in fields)):
        raise ValueError('retained staging record changed while reading')
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _locked_worker():
    descriptor = os.open(WORKER_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        raise ValueError('exclusive Root-owned Python worker lock required')
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def run(argv):
    build_job, run_id, source, version, config_digest, private_manifest, role, tap_v2 = parse_args(argv)
    if (sys.platform != 'linux' or os.geteuid() != 0 or not sys.flags.isolated
            or not sys.dont_write_bytecode or sys.flags.optimize):
        raise ValueError('isolated, assertion-enabled Linux Root controller required')
    from .ci_pipeline import _rust_worker_signing_key, vm_lease
    key = _rust_worker_signing_key('deterministic')
    if key is None:
        raise ValueError('sealed Rust worker controller key required')
    from .ci_runner import private_state
    from .ci_runner_config import load_config, verify_assets
    from .ci_runner_preflight import controller_environment
    from .deterministic_control import run_control
    from ci.gauntlet.control_plane.stage_outcome import require_cleanup

    config = staging_config_path(build_job, private_manifest, config_digest)
    state = Path('/home/hx-' + run_id)
    os.umask(0o022)
    worker_lock = _locked_worker()
    try:
        loaded = load_config(config, expected_digest=config_digest, asset_root=Path('/opt'))
        expected_id = 'rust-shadow-' + source + '-' + build_job + '-' + private_manifest[:16]
        assets = loaded['config']['assets']
        if (loaded['config']['schema'] != 'gauntlet-ci-runner.v7'
                or loaded['config']['id'] != expected_id
                or loaded['runtime']['guard_source_sha'] != source
                or loaded['runtime']['guard_package_version'] != version
                or assets['guard_prefix']['path'] != 'hol-gauntlet/rust-shadow-candidates/' + build_job + '/prefix'
                or assets['private_cell']['sha256'] != private_manifest
                or assets['private_cell']['path'] != 'hol-gauntlet/rust-shadow-candidates/' + build_job + '/cell-artifacts'):
            raise ValueError('staging config differs from fixed shadow candidate')
        verify_assets(loaded)
        try:
            private_state(state, create=True, immutable_ancestry=True)
        except FileExistsError:
            private_state(state, immutable_ancestry=True)
        # Existing Python workers use this second lock for their CI checks.
        # Keep the same lock order as the installed lifecycle path.
        with vm_lease(), controller_environment(loaded):
            tap = _SdkTapMount(run_id) if tap_v2 else None
            try:
                if tap is None:
                    record = run_control(state / role, loaded, role, controller_key=key)
                else:
                    record = run_control(state / role, loaded, role, controller_key=key,
                                         sdk_tap_directory=tap.path)
                    tap.recheck()
            finally:
                if tap is not None:
                    tap.close()
        digest, size = _read_control(state / role / 'control.json')
        cleanup = True
        try:
            require_cleanup(record)
        except ValueError:
            cleanup = False
        result = {
            'schema': 'hol-gauntlet-rust-staging-control-adapter.v1',
            'build_job_id': build_job, 'run_id': run_id, 'source_sha': source,
            'config_digest': config_digest, 'role': role, 'record_sha256': digest,
            'record_bytes': size, 'controller_public_key_hex': key.public_key().public_bytes_raw().hex(),
            'control_completed_claim': record.get('control_completed') is True,
            'cleanup_verified_by_python': cleanup, 'execution_eligible': False,
        }
        if tap_v2:
            result['sdk_tap_v2_requested'] = True
        return result, 0 if cleanup else 2
    finally:
        os.close(worker_lock)


def main(argv=None):
    try:
        result, status = run(sys.argv[1:] if argv is None else argv)
        print(canonical_json(result))
        return status
    except (Exception, KeyboardInterrupt) as error:
        print('staging control adapter unavailable: ' + type(error).__name__ + ': ' + str(error)[:1024],
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
