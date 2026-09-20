"""The offline wait report binds split sources without changing its measurements."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).parents[1]
_FIXED_SOURCES = (
    "guard/inventory_cisco.py",
    "integrations/scanner_subprocess.py",
    "integrations/cisco_mcp_scanner.py",
    "integrations/cisco_skill_scanner.py",
)


@pytest.fixture
def profile(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(_REPO_ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "guard_test_inventory_wait_profile", _REPO_ROOT / "scripts/profile_inventory_waits.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_fixture(root: Path) -> dict[str, str]:
    names = (
        *_FIXED_SOURCES,
        "guard/runtime/runner.py",
        "guard/runtime/runner_zeta.py",
        "guard/runtime/runner_alpha.py",
    )
    expected: dict[str, str] = {}
    for name in names:
        path = root / "src/codex_plugin_scanner" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = f"# {name}\n".encode()
        path.write_bytes(data)
        expected[name] = hashlib.sha256(data).hexdigest()
    return expected


def test_source_binding_enumerates_sorted_runner_files_and_excludes_other_entries(
    profile: ModuleType, tmp_path: Path
) -> None:
    expected = _source_fixture(tmp_path)
    runtime = tmp_path / "src/codex_plugin_scanner/guard/runtime"
    (runtime / "unrelated.py").write_text("OTHER = True\n", encoding="utf-8")
    (runtime / "runner_notes.txt").write_text("notes", encoding="utf-8")
    (runtime / "runner_directory.py").mkdir()

    actual = profile._profile_source_sha256(tmp_path)

    assert actual == expected
    assert list(actual) == [*_FIXED_SOURCES, *sorted(name for name in expected if name not in _FIXED_SOURCES)]


def test_changed_implementation_bytes_change_the_report_binding(profile: ModuleType, tmp_path: Path) -> None:
    expected = _source_fixture(tmp_path)
    changed = "guard/runtime/runner_alpha.py"
    replacement = b"# different implementation\r\n"
    (tmp_path / "src/codex_plugin_scanner" / changed).write_bytes(replacement)

    actual = profile._profile_source_sha256(tmp_path)

    assert actual[changed] != expected[changed]
    assert actual[changed] == hashlib.sha256(replacement).hexdigest()
    assert {name: value for name, value in actual.items() if name != changed} == {
        name: value for name, value in expected.items() if name != changed
    }


def test_missing_original_runner_anchor_still_refuses_the_report(profile: ModuleType, tmp_path: Path) -> None:
    _source_fixture(tmp_path)
    (tmp_path / "src/codex_plugin_scanner/guard/runtime/runner.py").unlink()

    with pytest.raises(FileNotFoundError):
        profile._profile_source_sha256(tmp_path)


@pytest.mark.parametrize("section", ["all", "process", "cisco", "cloud"])
def test_main_preserves_measurement_selection_samples_and_results(
    profile: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, section: str
) -> None:
    expected_sources = _source_fixture(tmp_path)
    output = tmp_path / "report.json"
    calls: list[tuple[str, int]] = []
    outcomes = {"process": [{"measured": "process"}], "cisco": {"measured": "cisco"}, "cloud": [{"measured": "cloud"}]}

    def measured(name: str, samples: int) -> object:
        calls.append((name, samples))
        return outcomes[name]

    def git_head(command: list[str], *, cwd: Path, text: bool) -> str:
        assert command == ["git", "rev-parse", "HEAD"] and cwd == tmp_path and text is True
        return "fixture-commit\n"

    monkeypatch.setattr(profile, "__file__", str(tmp_path / "scripts/profile_inventory_waits.py"))
    monkeypatch.setattr(
        profile.sys, "argv", ["profile", "--output", str(output), "--samples", "2", "--section", section]
    )
    monkeypatch.setattr(profile.subprocess, "check_output", git_head)
    monkeypatch.setattr(profile.platform, "platform", lambda: "fixture-platform")
    monkeypatch.setattr(profile, "process_profile", lambda samples: measured("process", samples))
    monkeypatch.setattr(profile, "cisco_profile", lambda samples: measured("cisco", samples))
    monkeypatch.setattr(profile, "cloud_client_profile", lambda samples: measured("cloud", samples))

    profile.main()
    report = json.loads(output.read_text(encoding="utf-8"))

    selected = [name for name in ("process", "cisco", "cloud") if section in {"all", name}]
    assert calls == [(name, 2) for name in selected]
    assert report["source_sha256"] == expected_sources
    assert report["head"] == "fixture-commit"
    assert report["schema"] == "guard.inventory-wait-profile.v1"
    assert report["scope"] == "offline component fixture; controlled transport wait is not actual cloud latency"
    assert report["process"] == (outcomes["process"] if "process" in selected else [])
    assert report["cisco"] == (outcomes["cisco"] if "cisco" in selected else {})
    assert report["cloud_client"] == (outcomes["cloud"] if "cloud" in selected else [])
