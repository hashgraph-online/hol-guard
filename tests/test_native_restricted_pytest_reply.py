import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime.restricted_pytest import prepare_restricted_pytest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize("profile", ["unknown", "pytest-restricted-v1"])
def test_readonly_request_rejects_lowered_or_unknown_native_profile(monkeypatch, tmp_path, profile):
    reply = {
        "profile_version": profile,
        "backend": "macos-seatbelt",
        "backend_executable": "/usr/bin/true",
        "workspace": str(tmp_path),
        "cwd": str(tmp_path),
        "command": ["/usr/bin/python3", "-m", "pytest"],
        "executable": "/usr/bin/python3",
        "allowed_executables": ["/usr/bin/python3"],
        "denied_capabilities": ["network"],
    }
    monkeypatch.setattr(transport, "_call", lambda *args, **kwargs: {"value": reply})
    with pytest.raises(RestrictedPytestError, match="Invalid native restricted launch plan"):
        prepare_restricted_pytest(["python3", "-m", "pytest"], workspace=tmp_path, read_only_workspace=True)
