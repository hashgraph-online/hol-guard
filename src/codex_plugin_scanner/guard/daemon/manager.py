"""Guard daemon lifecycle helpers."""

from __future__ import annotations as annotations

import dataclasses as dataclasses
import hashlib as hashlib
import json as json
import ntpath as ntpath
import os as os
import re as re
import secrets as secrets
import shlex as shlex
import signal as signal
import stat as stat
import subprocess as subprocess
import sys as sys
import sysconfig as sysconfig
import tempfile as tempfile
import threading as threading
import time as time
import urllib.error
import urllib.parse
import urllib.request  # noqa: F401 - exported urllib dependency and loaded submodules
from contextlib import contextmanager as contextmanager
from contextlib import suppress as suppress
from datetime import datetime as datetime
from datetime import timezone as timezone
from pathlib import Path as Path
from typing import BinaryIO as BinaryIO
from typing import Literal as Literal
from typing import TypedDict as TypedDict

from ...version import __version__ as __version__
from .. import windows_processes as windows_processes
from ..frozen_runtime_commands import (
    FROZEN_DAEMON_SERVE_ARG as FROZEN_DAEMON_SERVE_ARG,
)
from ..frozen_runtime_commands import (
    decode_frozen_daemon_serve_payload as decode_frozen_daemon_serve_payload,
)
from ..frozen_runtime_commands import (
    frozen_daemon_serve_command as frozen_daemon_serve_command,
)
from ..live_process_identity import process_start_token as process_start_token
from ..mdm.file_lock import release_file_lock as release_file_lock
from ..private_file_io import private_regular_file_is_valid as private_regular_file_is_valid
from ..private_file_io import read_private_regular_text as read_private_regular_text
from ..windows_paths import (
    windows_command_line_to_argv as windows_command_line_to_argv,
)
from ..windows_paths import (
    windows_process_creation_time as windows_process_creation_time,
)
from ..windows_paths import (
    windows_process_is_running as windows_process_is_running,
)
from ..windows_paths import (
    windows_process_liveness as windows_process_liveness,
)
from ..windows_paths import (
    windows_terminate_process_if_creation_time as windows_terminate_process_if_creation_time,
)
from .discovery import (
    authenticate_daemon_state as authenticate_daemon_state,
)
from .discovery import (
    daemon_discovery_key_path as daemon_discovery_key_path,
)
from .discovery import (
    ensure_daemon_discovery_key as ensure_daemon_discovery_key,
)
from .discovery import (
    load_authenticated_daemon_state as load_authenticated_daemon_state,
)
from .discovery import (
    load_daemon_discovery_key as load_daemon_discovery_key,
)
from .discovery import (
    verify_daemon_state as verify_daemon_state,
)
from .file_locking import lock_daemon_file as _lock_daemon_start_file  # noqa: F401 - lifecycle dependency seam
from .file_locking import try_lock_daemon_file as _try_lock_daemon_file  # noqa: F401 - lifecycle dependency seam
from .lifecycle_journal import record_daemon_lifecycle_event as record_daemon_lifecycle_event
from .start_lock import guard_daemon_start_lock as _guard_daemon_start_lock  # noqa: F401 - lifecycle dependency seam

DEFAULT_GUARD_DAEMON_PORT = 4781
GUARD_DAEMON_PORT_RANGE = 1000
REQUIRED_DAEMON_TABLES = frozenset({"guard_connect_states"})
GUARD_DAEMON_COMPATIBILITY_VERSION = 2
GUARD_DAEMON_START_TIMEOUT_SECONDS = 15.0
GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS = 30.0
GUARD_DAEMON_POLL_INTERVAL_SECONDS = 0.1
GUARD_DAEMON_HOOK_RECOVERY_COOLDOWN_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_STALE_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_MAX_STATES = 512
_GUARD_DAEMON_PRIVATE_FILE_MODE = 0o600
_GUARD_DAEMON_PRIVATE_DIR_MODE = 0o700
_APPROVAL_CENTER_LOCATOR_FILE = "approval-center-locator.json"
_GUARD_DAEMON_PENDING_LAUNCH_FILE = "daemon-launch-pending.json"
_GUARD_DAEMON_WAKE_RESERVATION_FILE = "daemon-wake-reservation.json"
_GUARD_DAEMON_RECOVERY_RESERVATION_FILE = "daemon-recovery-reservation.json"
_GUARD_DAEMON_OWNER_LOCK_FILE = "daemon-owner.lock"
_GUARD_DAEMON_RECOVERY_LOCK_FILE = "daemon-recovery.lock"
_GUARD_DAEMON_STATE_MAX_BYTES = 64 * 1024
_GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES = 4096
_GUARD_DAEMON_WAKE_RESERVATION_MAX_BYTES = 4096
_GUARD_DAEMON_WAKE_RESERVATION_SECONDS = 30.0
_GUARD_DAEMON_RECOVERY_RESERVATION_MAX_BYTES = 4096
_GUARD_DAEMON_RECOVERY_RESERVATION_SECONDS = 30.0
_GUARD_DAEMON_RECOVERY_WORKER_TIMEOUT_SECONDS = 30.0
_GUARD_DAEMON_PROCESS_QUERY_TIMEOUT_SECONDS = 5.0
_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES = 1024 * 1024
_GUARD_DAEMON_PROCESS_QUERY_MONITOR_INTERVAL_SECONDS = 0.01
_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS = 0.25
_RUNTIME_FINGERPRINT_CACHE_MAX_BYTES = 4096
_RUNTIME_FINGERPRINT_HEX_LENGTH = 64
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
_WINDOWS_DETACHED_PROCESS = 0x00000008
_WINDOWS_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_GUARD_DAEMON_POSIX_PS_PATHS = ("/bin/ps", "/usr/bin/ps")
_GUARD_DAEMON_BOOTSTRAP = (
    "import json,runpy,sys; "
    "trusted_prefix=sys.argv.pop(1); "
    "trusted_exec_prefix=sys.argv.pop(1); "
    "trusted_paths=json.loads(sys.argv.pop(1)); "
    "module=sys.argv.pop(1); "
    "sys.prefix=trusted_prefix; "
    "sys.exec_prefix=trusted_exec_prefix; "
    "sys.path[:0]=trusted_paths; "
    "sys.argv[0]=module; "
    "runpy.run_module(module,run_name='__main__',alter_sys=True)"
)
_GUARD_DAEMON_GATED_BOOTSTRAP = (
    "import sys; gate=sys.stdin.buffer.read(1); sys.exit(70) if gate != b'1' else None; " + _GUARD_DAEMON_BOOTSTRAP
)
_GUARD_DAEMON_ENV_KEYS = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "HOL_GUARD_DESKTOP",
        "HOL_GUARD_DESKTOP_RUNTIME_OWNER",
        "HOL_GUARD_DESKTOP_VERSION",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "LOGNAME",
        "PATH",
        "PATHEXT",
        "SHELL",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
)
_GUARD_DAEMON_DESKTOP_ENV_KEYS = ("HOL_GUARD_DESKTOP", "HOL_GUARD_DESKTOP_RUNTIME_OWNER", "HOL_GUARD_DESKTOP_VERSION")
_RECOVERY_LOCKS: dict[str, threading.Lock] = {}
_RECOVERY_LOCKS_GUARD = threading.Lock()
_STATE_WRITE_LOCKS: dict[str, threading.Lock] = {}
_STATE_WRITE_LOCKS_GUARD = threading.Lock()
_EPHEMERAL_REAP_SCHEDULE_LOCK = threading.Lock()
_EPHEMERAL_REAP_IN_FLIGHT = False
_DUPLICATE_RETIRE_SCHEDULE_LOCK = threading.Lock()
_DUPLICATE_RETIRE_IN_FLIGHT: set[str] = set()
_LAST_EPHEMERAL_REAP_AT = 0.0
_runtime_fingerprint_cache: tuple[str, str] | None = None

GuardDaemonHookFailureKind = Literal[
    "authenticated-control-plane-failure",
    "overload",
    "transport-failure",
]


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalCenterLocator:
    """Structured snapshot of where the Guard approval-center daemon is running."""

    guard_home: Path
    daemon_url: str
    approval_url_base: str
    pid: int
    started_at: str
    state_path: Path


class _ExistingGuardDaemon(TypedDict):
    url: str
    auth_token: str
    pid: int


_unlock_daemon_start_file = release_file_lock

# Keep shared state initialized before loading the implementation modules.
# Each implementation resolves dependencies on this original manager module.
from . import manager_ephemeral as _ephemeral  # noqa: E402
from . import manager_launch as _launch  # noqa: E402
from . import manager_lifecycle as _lifecycle  # noqa: E402
from . import manager_live as _live  # noqa: E402
from . import manager_locator as _locator  # noqa: E402
from . import manager_locks as _locks  # noqa: E402
from . import manager_pending_launch as _pending_launch  # noqa: E402
from . import manager_process_inventory as _process_inventory  # noqa: E402
from . import manager_process_query as _process_query  # noqa: E402
from . import manager_recovery as _recovery  # noqa: E402
from . import manager_retirement as _retirement  # noqa: E402
from . import manager_runtime as _runtime  # noqa: E402
from . import manager_state as _state  # noqa: E402

_schedule_stale_ephemeral_guard_daemon_reap = _ephemeral._schedule_stale_ephemeral_guard_daemon_reap
_reap_stale_ephemeral_guard_daemons = _ephemeral._reap_stale_ephemeral_guard_daemons
_ephemeral_guard_daemon_state_paths = _ephemeral._ephemeral_guard_daemon_state_paths
_pytest_temp_roots = _ephemeral._pytest_temp_roots
_path_name_looks_like_pytest_temp_root = _ephemeral._path_name_looks_like_pytest_temp_root
_collect_daemon_state_paths = _ephemeral._collect_daemon_state_paths
_state_path_age_seconds = _ephemeral._state_path_age_seconds
_guard_home_is_ephemeral = _ephemeral._guard_home_is_ephemeral
_ephemeral_guard_home_is_inactive = _ephemeral._ephemeral_guard_home_is_inactive
_runtime_state_age_seconds = _ephemeral._runtime_state_age_seconds

_trusted_daemon_home = _launch._trusted_daemon_home
_daemon_launcher_env = _launch._daemon_launcher_env
_trusted_daemon_prefix = _launch._trusted_daemon_prefix
_trusted_daemon_interpreter = _launch._trusted_daemon_interpreter
_trusted_daemon_python_flags = _launch._trusted_daemon_python_flags
_trusted_daemon_import_paths = _launch._trusted_daemon_import_paths
_isolated_python_module_command = _launch._isolated_python_module_command
_guard_daemon_launch_command = _launch._guard_daemon_launch_command
desktop_preflight_requested = _launch.desktop_preflight_requested
_default_guard_daemon_start_timeout = _launch._default_guard_daemon_start_timeout
_windows_daemon_creation_flags = _launch._windows_daemon_creation_flags

ensure_guard_daemon = _lifecycle.ensure_guard_daemon
ensure_guard_daemon_after_update = _lifecycle.ensure_guard_daemon_after_update
retire_all_guard_daemons_for_home = _lifecycle.retire_all_guard_daemons_for_home
guard_daemon_retirement_is_complete = _lifecycle.guard_daemon_retirement_is_complete
guard_daemon_process_count = _lifecycle.guard_daemon_process_count
guard_daemon_url_for_home = _lifecycle.guard_daemon_url_for_home

load_guard_daemon_url = _live.load_guard_daemon_url
load_running_guard_daemon_identity = _live.load_running_guard_daemon_identity
_live_guard_daemon_url = _live._live_guard_daemon_url
_live_guard_daemon_identity = _live._live_guard_daemon_identity
_load_authenticated_daemon_identity = _live._load_authenticated_daemon_identity
load_guard_daemon_auth_token = _live.load_guard_daemon_auth_token
_daemon_health_request = _live._daemon_health_request
_daemon_healthz_details_payload = _live._daemon_healthz_details_payload
_daemon_healthz_details_match_guard_home = _live._daemon_healthz_details_match_guard_home
_daemon_healthz_details_match_current_runtime = _live._daemon_healthz_details_match_current_runtime
_guard_daemon_url_port = _live._guard_daemon_url_port
_adopt_existing_guard_daemon = _live._adopt_existing_guard_daemon
_adoptable_guard_daemon_ports = _live._adoptable_guard_daemon_ports
_initialize_existing_guard_daemon = _live._initialize_existing_guard_daemon
_retire_duplicate_guard_daemons = _live._retire_duplicate_guard_daemons
_schedule_duplicate_guard_daemon_retirement = _live._schedule_duplicate_guard_daemon_retirement
_retire_current_duplicate_guard_daemons = _live._retire_current_duplicate_guard_daemons
_retire_duplicate_guard_daemons_unlocked = _live._retire_duplicate_guard_daemons_unlocked
_rewrite_kept_daemon_state_if_missing = _live._rewrite_kept_daemon_state_if_missing
_guard_daemon_pid_for_guard_home_port = _live._guard_daemon_pid_for_guard_home_port

repair_approval_center_locator = _locator.repair_approval_center_locator
_locator_path = _locator._locator_path
write_approval_center_locator = _locator.write_approval_center_locator
read_approval_center_locator = _locator.read_approval_center_locator
_approval_center_daemon_is_healthy = _locator._approval_center_daemon_is_healthy
_daemon_state_pid_matches_locator = _locator._daemon_state_pid_matches_locator
_daemon_identity_matches_locator = _locator._daemon_identity_matches_locator
publish_approval_center_locator = _locator.publish_approval_center_locator
ensure_approval_center = _locator.ensure_approval_center

_guard_daemon_recovery_lock = _locks._guard_daemon_recovery_lock
acquire_guard_daemon_owner_lock = _locks.acquire_guard_daemon_owner_lock
release_guard_daemon_owner_lock = _locks.release_guard_daemon_owner_lock
_guard_daemon_state_write_lock = _locks._guard_daemon_state_write_lock

_pending_launch_path = _pending_launch._pending_launch_path
_record_guard_daemon_pending_launch = _pending_launch._record_guard_daemon_pending_launch
load_authenticated_guard_daemon_pending_launch = _pending_launch.load_authenticated_guard_daemon_pending_launch
_clear_guard_daemon_pending_launch_if_current = _pending_launch._clear_guard_daemon_pending_launch_if_current
_clear_spawned_guard_daemon_pending_launch = _pending_launch._clear_spawned_guard_daemon_pending_launch
_guard_daemon_pending_launch_is_active = _pending_launch._guard_daemon_pending_launch_is_active
_guard_daemon_pending_launch_state_is_resolved = _pending_launch._guard_daemon_pending_launch_state_is_resolved
_auth_token_path = _pending_launch._auth_token_path
_private_daemon_file_is_valid = _pending_launch._private_daemon_file_is_valid
_remove_invalid_daemon_discovery_key = _pending_launch._remove_invalid_daemon_discovery_key
_ensure_private_directory = _pending_launch._ensure_private_directory
_write_private_text = _pending_launch._write_private_text
_write_private_atomic_text = _pending_launch._write_private_atomic_text
_set_private_mode = _pending_launch._set_private_mode

_guard_home_from_command = _process_inventory._guard_home_from_command
_guard_home_from_command_parts = _process_inventory._guard_home_from_command_parts
_guard_daemon_port_from_command = _process_inventory._guard_daemon_port_from_command
_guard_daemon_command_matches = _process_inventory._guard_daemon_command_matches
_split_process_command = _process_inventory._split_process_command
_guard_daemon_command_parts_match = _process_inventory._guard_daemon_command_parts_match
_frozen_daemon_serve_context = _process_inventory._frozen_daemon_serve_context
_guard_daemon_process_inventory_for_guard_home = _process_inventory._guard_daemon_process_inventory_for_guard_home
_malformed_command_may_launch_guard = _process_inventory._malformed_command_may_launch_guard
_running_guard_daemon_processes_for_guard_home = _process_inventory._running_guard_daemon_processes_for_guard_home

_spawn_bounded_process_query = _process_query._spawn_bounded_process_query
_process_query_environment = _process_query._process_query_environment
_trusted_posix_ps_path = _process_query._trusted_posix_ps_path
_linux_proc_process_entries = _process_query._linux_proc_process_entries
_terminate_bounded_process_query = _process_query._terminate_bounded_process_query
_capture_bounded_process_query_stdout = _process_query._capture_bounded_process_query_stdout
_bounded_process_query_stdout = _process_query._bounded_process_query_stdout
_running_ephemeral_guard_daemon_processes = _process_query._running_ephemeral_guard_daemon_processes
_elapsed_seconds_from_ps = _process_query._elapsed_seconds_from_ps

recover_guard_daemon_after_hook_failure = _recovery.recover_guard_daemon_after_hook_failure
schedule_guard_daemon_recovery = _recovery.schedule_guard_daemon_recovery
_guard_recovery_is_disabled = _recovery._guard_recovery_is_disabled
_terminate_recovery_worker = _recovery._terminate_recovery_worker
_authenticated_live_current_daemon_url = _recovery._authenticated_live_current_daemon_url
_daemon_generation_is_recent = _recovery._daemon_generation_is_recent
_guard_daemon_wake_reservation_path = _recovery._guard_daemon_wake_reservation_path
_load_guard_daemon_wake_reservation = _recovery._load_guard_daemon_wake_reservation
_claim_guard_daemon_wake_reservation = _recovery._claim_guard_daemon_wake_reservation
clear_guard_daemon_wake_reservation = _recovery.clear_guard_daemon_wake_reservation
_guard_daemon_recovery_reservation_path = _recovery._guard_daemon_recovery_reservation_path
_load_guard_daemon_recovery_reservation = _recovery._load_guard_daemon_recovery_reservation
_claim_guard_daemon_recovery_reservation = _recovery._claim_guard_daemon_recovery_reservation
_guard_daemon_recovery_owner_state = _recovery._guard_daemon_recovery_owner_state
_bind_guard_daemon_recovery_reservation = _recovery._bind_guard_daemon_recovery_reservation
clear_guard_daemon_recovery_reservation = _recovery.clear_guard_daemon_recovery_reservation
schedule_guard_daemon_ensure = _recovery.schedule_guard_daemon_ensure

_guard_daemon_start_in_progress = _retirement._guard_daemon_start_in_progress
_guard_daemon_pid_is_running = _retirement._guard_daemon_pid_is_running
_guard_daemon_parent_pid = _retirement._guard_daemon_parent_pid
_guard_daemon_pid_is_spawned_launch = _retirement._guard_daemon_pid_is_spawned_launch
_guard_daemon_pid_is_proven_dead = _retirement._guard_daemon_pid_is_proven_dead
_wait_for_guard_daemon_pid_death = _retirement._wait_for_guard_daemon_pid_death
_guard_daemon_pid_matches_command = _retirement._guard_daemon_pid_matches_command
_guard_daemon_pid_command_identity = _retirement._guard_daemon_pid_command_identity
_guard_daemon_command_for_pid = _retirement._guard_daemon_command_for_pid
_retire_guard_daemon_process = _retirement._retire_guard_daemon_process
_terminate_spawned_guard_daemon = _retirement._terminate_spawned_guard_daemon
_release_guard_daemon_launch_gate = _retirement._release_guard_daemon_launch_gate
_retire_guard_daemon_pid = _retirement._retire_guard_daemon_pid
_wait_for_started_guard_daemon_url = _retirement._wait_for_started_guard_daemon_url
_wait_for_guard_daemon_url = _retirement._wait_for_guard_daemon_url

_guard_daemon_state_matches_current_runtime = _runtime._guard_daemon_state_matches_current_runtime
_current_guard_daemon_source_root = _runtime._current_guard_daemon_source_root
_runtime_identity_paths = _runtime._runtime_identity_paths
_runtime_tree_signature = _runtime._runtime_tree_signature
_hash_runtime_contents = _runtime._hash_runtime_contents
_runtime_fingerprint_cache_path = _runtime._runtime_fingerprint_cache_path
_is_sha256_hex = _runtime._is_sha256_hex
_load_runtime_fingerprint_cache = _runtime._load_runtime_fingerprint_cache
_store_runtime_fingerprint_cache = _runtime._store_runtime_fingerprint_cache
_current_guard_daemon_runtime_fingerprint = _runtime._current_guard_daemon_runtime_fingerprint
current_guard_daemon_runtime_fingerprint = _runtime.current_guard_daemon_runtime_fingerprint
_configured_port = _runtime._configured_port
_stable_port_for_guard_home = _runtime._stable_port_for_guard_home
_prepend_preferred_port = _runtime._prepend_preferred_port
_candidate_ports = _runtime._candidate_ports
_healthz_payload_is_current = _runtime._healthz_payload_is_current
_healthz_payload_matches_guard_home = _runtime._healthz_payload_matches_guard_home
_live_or_newer_daemon_url = _runtime._live_or_newer_daemon_url

write_guard_daemon_state = _state.write_guard_daemon_state
clear_guard_daemon_state = _state.clear_guard_daemon_state
clear_guard_daemon_state_if_current = _state.clear_guard_daemon_state_if_current
_clear_guard_daemon_state_if_current_unlocked = _state._clear_guard_daemon_state_if_current_unlocked
_clear_authenticated_guard_daemon_state_if_current = _state._clear_authenticated_guard_daemon_state_if_current
_daemon_state_points_to = _state._daemon_state_points_to
_load_state = _state._load_state
_looks_like_guard_daemon_state = _state._looks_like_guard_daemon_state
_state_path = _state._state_path
_daemon_lifecycle_artifact_is_exact_tombstone = _state._daemon_lifecycle_artifact_is_exact_tombstone
_reconcile_invalid_daemon_lifecycle_artifacts = _state._reconcile_invalid_daemon_lifecycle_artifacts
_quarantine_daemon_lifecycle_artifact = _state._quarantine_daemon_lifecycle_artifact
_daemon_lifecycle_artifact_is_quarantinable = _state._daemon_lifecycle_artifact_is_quarantinable
