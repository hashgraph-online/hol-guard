from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "src" / "codex_plugin_scanner" / "guard"
_FORBIDDEN_SOURCE = (
    "GUARD_CLOUD_REVIEW_ENABLED",
    "guard.approval.resolve",
    "live-request",
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
