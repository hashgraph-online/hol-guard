"""Group write is trusted only through a group that no other account can use."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_binary_identity as identity
from codex_plugin_scanner.guard import owner_private_group as private_group

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX account database")

OWNER = SimpleNamespace(pw_name="alice", pw_uid=1000, pw_gid=1000)
OTHER = SimpleNamespace(pw_name="bob", pw_uid=1001, pw_gid=1001)


def _accounts(
    monkeypatch: pytest.MonkeyPatch, *, members: list[str], accounts: list[SimpleNamespace] | BaseException
) -> None:
    import grp
    import pwd

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: OWNER if uid == OWNER.pw_uid else OTHER)
    monkeypatch.setattr(grp, "getgrgid", lambda gid: SimpleNamespace(gr_name="alice", gr_gid=gid, gr_mem=members))

    def listing() -> list[SimpleNamespace]:
        if isinstance(accounts, BaseException):
            raise accounts
        return list(accounts)

    monkeypatch.setattr(pwd, "getpwall", listing)


@pytest.mark.parametrize("members", [[], ["alice"]])
def test_user_private_group_is_accepted(monkeypatch: pytest.MonkeyPatch, members: list[str]) -> None:
    _accounts(monkeypatch, members=members, accounts=[OWNER, OTHER])

    assert private_group.group_is_private_to_owner(1000, 1000) is True


@pytest.mark.parametrize(
    ("members", "accounts", "gid"),
    [
        (["alice", "bob"], [OWNER, OTHER], 1000),
        (["bob"], [OWNER, OTHER], 1000),
        ([], [OWNER, SimpleNamespace(pw_name="carol", pw_uid=1002, pw_gid=1000)], 1000),
        ([], [OWNER, OTHER], 1001),
    ],
    ids=["second-member", "other-member-only", "another-primary-user", "another-users-primary-gid"],
)
def test_group_another_account_can_use_is_rejected(
    monkeypatch: pytest.MonkeyPatch, members: list[str], accounts: list[SimpleNamespace], gid: int
) -> None:
    _accounts(monkeypatch, members=members, accounts=accounts)

    assert private_group.group_is_private_to_owner(1000, gid) is False


@pytest.mark.parametrize(
    "accounts",
    [[], [OTHER], OSError("nss unavailable")],
    ids=["empty-listing", "listing-without-owner", "listing-error"],
)
def test_unprovable_account_listing_is_rejected(
    monkeypatch: pytest.MonkeyPatch, accounts: list[SimpleNamespace] | BaseException
) -> None:
    _accounts(monkeypatch, members=[], accounts=accounts)

    assert private_group.group_is_private_to_owner(1000, 1000) is False


def test_unknown_owner_or_group_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import grp

    _accounts(monkeypatch, members=[], accounts=[OWNER])
    monkeypatch.setattr(grp, "getgrgid", lambda gid: (_ for _ in ()).throw(KeyError(gid)))

    assert private_group.group_is_private_to_owner(1000, 1000) is False


def _metadata(mode: int, *, uid: int = 1000, gid: int = 1000) -> os.stat_result:
    return os.stat_result((stat.S_IFREG | mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


@pytest.mark.parametrize(
    ("mode", "uid", "private", "trusted"),
    [
        (0o755, 1000, False, True),
        (0o775, 1000, True, True),
        (0o775, 1000, False, False),
        (0o775, 1001, True, False),
        (0o777, 1000, True, False),
        (0o757, 1000, True, False),
    ],
    ids=["no-group-write", "private-group", "shared-group", "foreign-owner", "world-writable", "world-only"],
)
def test_mode_check_trusts_group_write_only_through_owner_private_group(
    monkeypatch: pytest.MonkeyPatch, mode: int, uid: int, private: bool, trusted: bool
) -> None:
    monkeypatch.setattr(private_group, "group_is_private_to_owner", lambda owner, gid: private)

    assert private_group.writable_only_by_owner(_metadata(mode, uid=uid), 1000) is trusted


@pytest.mark.parametrize(("private", "trusted"), [(True, True), (False, False)])
def test_native_runtime_installed_under_umask_0002_follows_group_privacy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, private: bool, trusted: bool
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _ = runtime.write_bytes(b"native-runtime")
    runtime.chmod(0o775)
    seen: list[tuple[int, int]] = []

    def privacy(owner: int, gid: int) -> bool:
        seen.append((owner, gid))
        return private

    monkeypatch.setattr(private_group, "group_is_private_to_owner", privacy)

    result = identity.validate_native_binary(runtime)

    assert (result is not None) is trusted
    assert seen and seen[0] == (os.getuid(), runtime.stat().st_gid)
