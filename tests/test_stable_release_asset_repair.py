from scripts.stable_release_asset_repair import github_release_needs_asset_repair, stable_dispatch_is_allowed

COMPLETE = (
    "hol_guard-3.7.2-py3-none-any.whl",
    "hol_guard-3.7.2.tar.gz",
    "hol_guard-3.7.2-py3-none-manylinux_2_17_x86_64.whl",
    "hol_guard-3.7.2-py3-none-macosx_13_0_x86_64.whl",
    "hol_guard-3.7.2-py3-none-macosx_11_0_arm64.whl",
    "hol_guard-3.7.2-py3-none-win_amd64.whl",
    "hol-guard-v3.7.2.intoto.jsonl",
)


def test_next_version_is_always_allowed() -> None:
    assert stable_dispatch_is_allowed(
        requested="3.7.3",
        expected_next="3.7.3",
        latest_pypi="3.7.2",
        asset_names=COMPLETE,
    )


def test_latest_published_version_repairs_a_release_without_desktop_files() -> None:
    assert github_release_needs_asset_repair("3.7.2", ())
    assert stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.2",
        asset_names=(),
    )
    assert stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.2",
        release_missing=True,
    )


def test_missing_platform_wheel_still_needs_repair() -> None:
    partial = tuple(name for name in COMPLETE if "win_amd64" not in name)
    assert github_release_needs_asset_repair("3.7.2", partial)
    assert stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.2",
        asset_names=partial,
    )


def test_complete_or_older_release_is_not_republished() -> None:
    assert not github_release_needs_asset_repair("3.7.2", COMPLETE)
    assert not stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.2",
        asset_names=COMPLETE,
    )
    assert not stable_dispatch_is_allowed(
        requested="3.7.1",
        expected_next="3.7.3",
        latest_pypi="3.7.2",
        asset_names=(),
    )


def test_complete_release_absent_from_pypi_can_resume_deferred_publication() -> None:
    assert stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.1",
        asset_names=COMPLETE,
        deferred_pypi=True,
    )
    assert not stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.1",
        asset_names=(),
        deferred_pypi=True,
    )
    assert not stable_dispatch_is_allowed(
        requested="3.7.2",
        expected_next="3.7.3",
        latest_pypi="3.7.1",
        asset_names=COMPLETE,
        release_missing=True,
        deferred_pypi=True,
    )
