"""Guard the Pi settings split and its historical collecting test facade."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_COLD_IMPORT = r"""
import importlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
assert not any(name.startswith("codex_plugin_scanner.guard.adapters")
               or name == "tests.test_pi_adapter" or name.startswith("tests.pi_adapter_")
               for name in sys.modules)
sys.path[:0] = [str(root / "src"), str(root)]
first = importlib.import_module(sys.argv[2])
pi = importlib.import_module("codex_plugin_scanner.guard.adapters.pi")
settings = importlib.import_module("codex_plugin_scanner.guard.adapters.pi_settings_discovery")
base = importlib.import_module("codex_plugin_scanner.guard.adapters.base")
facade = importlib.import_module("tests.test_pi_adapter")
assert settings._pi is pi
assert pi._PiFamilyHarnessAdapter.__bases__ == (base.HarnessAdapter,)
assert pi.PiHarnessAdapter.__bases__ == pi.OmpHarnessAdapter.__bases__ == (pi._PiFamilyHarnessAdapter,)
for name in ("_append_settings_artifacts", "_append_package_setting_artifacts",
             "_append_configured_resource_setting_artifacts"):
    assert pi._PiFamilyHarnessAdapter.__dict__[name] is getattr(settings, name)
    for adapter_type in (pi.PiHarnessAdapter, pi.OmpHarnessAdapter):
        adapter = adapter_type()
        bound = getattr(adapter, name)
        assert bound.__self__ is adapter and bound.__func__ is getattr(settings, name)
groups = (
    ("tests.pi_adapter_identity_cases", (("TestPiAdapterIdentity", 9), ("TestPiDetect", 10))),
    ("tests.pi_adapter_install_cases", (("TestPiInstall", 7),)),
    ("tests.pi_adapter_runtime_cases", (("TestPiRuntime", 14),)),
)
classes = {}
for module_name, expected in groups:
    module = importlib.import_module(module_name)
    assert module.__test__ is False
    for class_name, count in expected:
        cls = getattr(facade, class_name)
        assert cls is getattr(module, class_name)
        methods = [(name, function) for name, function in vars(cls).items() if name.startswith("test_")]
        assert len(methods) == count
        for name, function in methods:
            assert function.__qualname__ == class_name + "." + name
            assert Path(function.__code__.co_filename).resolve() == Path(module.__file__).resolve()
            for global_name in function.__code__.co_names:
                if global_name in function.__globals__ and global_name in vars(facade):
                    assert function.__globals__[global_name] is vars(facade)[global_name]
        classes[class_name] = count
assert getattr(facade, "__test__", True) is not False
for module in (first, pi, settings, facade):
    assert Path(module.__file__).resolve().is_relative_to(root)
print(json.dumps({"first": first.__name__, "classes": classes, "methods": sum(classes.values())}, sort_keys=True))
"""


@pytest.mark.parametrize(
    "module_name",
    (
        "codex_plugin_scanner.guard.adapters.pi",
        "codex_plugin_scanner.guard.adapters.pi_settings_discovery",
        "tests.test_pi_adapter",
        "tests.pi_adapter_identity_cases",
        "tests.pi_adapter_install_cases",
        "tests.pi_adapter_runtime_cases",
    ),
)
def test_pi_partition_cold_import_keeps_real_class_bindings(tmp_path: Path, module_name: str) -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", _COLD_IMPORT, str(root), module_name],
        cwd=tmp_path,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    value = json.loads(completed.stdout)
    assert value == {
        "first": module_name,
        "classes": {"TestPiAdapterIdentity": 9, "TestPiDetect": 10, "TestPiInstall": 7, "TestPiRuntime": 14},
        "methods": 40,
    }


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_pi_settings_discovery_uses_current_facade_bindings(tmp_path: Path, monkeypatch, harness: str) -> None:
    from codex_plugin_scanner.guard.adapters import get_adapter
    from codex_plugin_scanner.guard.adapters import pi as facade
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    adapter = get_adapter(harness)
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    root = context.home_dir / adapter.global_config_dir
    settings_path = root / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text("this must be supplied by the patched settings reader", encoding="utf-8")
    extension_path = tmp_path / "shared" / "extension.observed"
    theme_path = tmp_path / "shared" / "theme.observed"
    extension_path.parent.mkdir()
    extension_path.write_text("export default {};", encoding="utf-8")
    theme_path.write_text("{}", encoding="utf-8")
    calls = []

    def payload(path):
        calls.append(("settings", path))
        assert path == settings_path
        return {"packages": ["npm:observed-package"], "extensions": ["extension-pattern"], "themes": ["theme-pattern"]}

    def resolve(path, pattern):
        calls.append(("resolve", path, pattern))
        assert path == settings_path
        return [{"extension-pattern": extension_path, "theme-pattern": theme_path}[pattern]]

    def suffix(value):
        calls.append(("suffix", value))
        assert value == "npm:observed-package"
        return "observed-suffix"

    original_artifact = facade.artifact

    def artifact(**kwargs):
        calls.append(("artifact", kwargs["artifact_type"]))
        return original_artifact(**kwargs)

    monkeypatch.setattr(facade, "_resolve_command", lambda *_args: None)
    monkeypatch.setattr(facade, "json_payload", payload)
    monkeypatch.setattr(facade, "resolve_configured_paths", resolve)
    monkeypatch.setattr(facade, "stable_suffix", suffix)
    monkeypatch.setattr(facade, "artifact", artifact)
    monkeypatch.setattr(facade, "EXTENSION_SUFFIXES", {".observed"})
    monkeypatch.setattr(facade, "THEME_SUFFIXES", {".observed"})

    result = adapter.detect(context)

    assert {item.artifact_id for item in result.artifacts} == {
        f"{harness}:{harness}-global:package:observed-suffix",
        f"{harness}:{harness}-global:extension:extension.observed",
        f"{harness}:{harness}-global:theme:theme.observed",
    }
    assert calls == [
        ("settings", settings_path),
        ("suffix", "npm:observed-package"),
        ("artifact", "package"),
        ("resolve", settings_path, "extension-pattern"),
        ("artifact", "extension"),
        ("resolve", settings_path, "theme-pattern"),
        ("artifact", "theme"),
    ]
