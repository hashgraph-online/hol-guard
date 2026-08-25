from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "src" / "codex_plugin_scanner" / "guard"
_FORBIDDEN_SOURCE = (
    "GUARD_CLOUD_REVIEW_ENABLED",
    "guard.approval.resolve",
    "guard.liveRequests",
    "live-request",
    "liveRequestSync",
)


def _review_source_files() -> list[Path]:
    return sorted(_SOURCE.rglob("*.py"))


def test_cloud_review_product_modules_are_unversioned_and_canonical() -> None:
    versioned_paths = [
        path.relative_to(_ROOT).as_posix()
        for path in _SOURCE.rglob("*.py")
        if "review_v2" in path.name or "cloud_review_v2" in path.name
    ]
    live_request_paths = [
        path.relative_to(_ROOT).as_posix() for path in _SOURCE.rglob("*.py") if "live_request" in path.name
    ]
    assert versioned_paths == []
    assert live_request_paths == []


def test_cloud_review_runtime_has_no_retired_alias_or_feature_gate() -> None:
    violations: list[str] = []
    for path in _review_source_files():
        source = path.read_text(encoding="utf-8")
        for forbidden in _FORBIDDEN_SOURCE:
            if forbidden in source:
                violations.append(f"{path.relative_to(_ROOT).as_posix()}: {forbidden}")
    assert violations == []


def test_retired_sqlite_outbox_exists_only_in_one_time_cutover() -> None:
    allowed = _SOURCE / "store_review_event_outbox_schema.py"
    violations = [
        path.relative_to(_ROOT).as_posix()
        for path in _review_source_files()
        if path != allowed and "guard_live_request_outbox" in path.read_text(encoding="utf-8")
    ]
    source = allowed.read_text(encoding="utf-8")
    assert violations == []
    assert "def _migrate_retired_outbox" in source
    assert "drop table guard_live_request_outbox" in source
