"""Non-probe shim-admin facts must carry the Windows path-model keys."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_shim_admin import _facts

_WINDOWS_PATH_KEYS = (
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERNAME",
    "NoDefaultCurrentDirectoryInExePath",
)


def test_non_probe_facts_forward_the_windows_path_model_keys(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("USERPROFILE", r"C:\Users\ada")
    monkeypatch.setenv("HOMEDRIVE", "C:")
    monkeypatch.setenv("HOMEPATH", r"\Users\ada")
    monkeypatch.setenv("USERNAME", "ada")
    monkeypatch.setenv("NoDefaultCurrentDirectoryInExePath", "1")
    monkeypatch.setenv("SECRET_TOKEN", "not-forwarded")

    facts = _facts(full_environment=False, shim_dir=tmp_path)
    environ = facts["environ"]
    assert isinstance(environ, dict)
    assert environ["USERPROFILE"] == r"C:\Users\ada"
    assert environ["HOMEDRIVE"] == "C:"
    assert environ["HOMEPATH"] == r"\Users\ada"
    assert environ["USERNAME"] == "ada"
    assert environ["NoDefaultCurrentDirectoryInExePath"] == "1"
    assert "SECRET_TOKEN" not in environ
    for key in _WINDOWS_PATH_KEYS:
        assert key in environ
