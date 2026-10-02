"""Linux restrictions cannot degrade into blanket read/exec or no-op isolation."""

import ctypes
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_linux_landlock as boundary


class _Syscall:
    restype = None

    def __init__(self, *, abi=3, fail=None):
        self.abi, self.fail, self.rules = abi, fail, []

    def __call__(self, number, *args):
        if number == 444:
            return self.abi if args[2] == 1 else (-1 if self.fail == "create" else 20)
        if number == 445:
            rule = ctypes.cast(args[2], ctypes.POINTER(boundary._PathRule)).contents
            self.rules.append(rule.allowed_access)
            return -1 if self.fail == "add" else 0
        assert number == 446
        return -1 if self.fail == "restrict" else 0


def _kernel(monkeypatch, *, abi=3, fail=None):
    syscall = _Syscall(abi=abi, fail=fail)
    monkeypatch.setattr(boundary.platform, "system", lambda: "Linux")
    monkeypatch.setattr(boundary.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(
        boundary.ctypes,
        "CDLL",
        lambda *args, **kwargs: SimpleNamespace(syscall=syscall, prctl=lambda *args: -1 if fail == "privileges" else 0),
    )
    monkeypatch.setattr(boundary.os, "O_PATH", 0x200000, raising=False)
    return syscall


def _plan(**kwargs):
    return dict(read_roots=(), read_files=(), list_roots=(), write_roots=(), executables=(), **kwargs)


@pytest.mark.parametrize("abi", [-1, 0, 1, 2])
def test_missing_required_kernel_access_controls_fail_closed(monkeypatch, abi):
    _kernel(monkeypatch, abi=abi)
    with pytest.raises(boundary.LinuxContainmentUnavailableError, match="ABI 3"):
        boundary.enforce_landlock(**_plan())


@pytest.mark.parametrize("phase", ["create", "privileges", "restrict"])
def test_failed_kernel_boundary_cannot_return_success(monkeypatch, phase):
    _kernel(monkeypatch, fail=phase)
    monkeypatch.setattr(boundary.os, "close", lambda fd: None)
    with pytest.raises(boundary.LinuxContainmentUnavailableError):
        boundary.enforce_landlock(**_plan())


def test_failed_rule_installation_aborts_before_execution(monkeypatch):
    _kernel(monkeypatch, fail="add")
    closed = []
    monkeypatch.setattr(boundary.os, "open", lambda path, flags: 21)
    monkeypatch.setattr(boundary.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o600))
    monkeypatch.setattr(boundary.os, "close", closed.append)
    with pytest.raises(boundary.LinuxContainmentUnavailableError, match="install"):
        boundary.enforce_landlock(
            read_roots=(), read_files=(Path("/source"),), list_roots=(), write_roots=(), executables=()
        )
    assert closed == [21, 20]


def test_directory_reads_and_writes_never_grant_execution(monkeypatch):
    syscall = _kernel(monkeypatch)
    monkeypatch.setattr(boundary.os, "open", lambda path, flags: 21)
    monkeypatch.setattr(boundary.os, "fstat", lambda fd: SimpleNamespace(st_mode=stat.S_IFDIR | 0o700))
    monkeypatch.setattr(boundary.os, "close", lambda fd: None)
    boundary.enforce_landlock(
        read_roots=(Path("/runtime"),),
        read_files=(),
        list_roots=(Path("/workspace"),),
        write_roots=(Path("/private"),),
        executables=(),
    )
    assert syscall.rules == [
        boundary._READ_FILE | boundary._READ_DIR,
        boundary._READ_DIR,
        boundary._WRITE_DIRECTORY | boundary._READ_FILE | boundary._READ_DIR,
    ]
    assert all(rights & boundary._EXECUTE == 0 for rights in syscall.rules)


@pytest.mark.parametrize("mode", [stat.S_IFDIR, stat.S_IFLNK])
def test_file_targets_cannot_change_into_directories_or_symlinks(monkeypatch, mode):
    _kernel(monkeypatch)
    opened = []
    monkeypatch.setattr(boundary.os, "open", lambda path, flags: opened.append(flags) or 21)
    monkeypatch.setattr(boundary.os, "fstat", lambda fd: SimpleNamespace(st_mode=mode))
    monkeypatch.setattr(boundary.os, "close", lambda fd: None)
    with pytest.raises(boundary.LinuxContainmentUnavailableError):
        boundary.enforce_landlock(
            read_roots=(), read_files=(Path("/source"),), list_roots=(), write_roots=(), executables=()
        )
    assert opened[0] & boundary.os.O_NOFOLLOW


def test_unsupported_architecture_never_guesses_syscall_numbers(monkeypatch):
    _kernel(monkeypatch)
    monkeypatch.setattr(boundary.platform, "machine", lambda: "unknown")
    with pytest.raises(boundary.LinuxContainmentUnavailableError, match="architecture"):
        boundary.enforce_landlock(**_plan())
