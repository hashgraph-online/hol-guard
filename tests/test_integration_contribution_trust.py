"""Browser driver profiles and provider integrations get trust bindings and ship in the wheel."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import tomllib

REPO = Path(__file__).resolve().parents[1]
BINDING_SCHEMA = "guard.extension-trust-binding.v1"


@pytest.fixture
def refresh(tmp_path, monkeypatch):
    path = REPO / "scripts/refresh_extension_artifacts.py"
    spec = importlib.util.spec_from_file_location("refresh_integration_trust", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for directory in ("command-sources", "mcp-servers", "extensions", "browser-drivers", "provider-integrations"):
        (tmp_path / "contributions" / directory).mkdir(parents=True)
    bindings = tmp_path / "contracts/extensions/trust"
    bindings.mkdir(parents=True)
    detector = module._detector()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(detector, "ROOT", tmp_path)
    monkeypatch.setattr(module, "TRUST_BINDINGS", bindings)
    monkeypatch.setattr(module, "TRUST_MAP", bindings.parent / "build-trust-class-map.v1.json")
    return module


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _contribute(refresh, directory: str, identity: str) -> None:
    _write(refresh.ROOT / "contributions" / directory / f"{identity}.json", {"id": identity})


def _bind(refresh, identity: str, trust_class: str) -> None:
    _write(
        refresh.TRUST_BINDINGS / f"{identity}.v1.json",
        {"schemaVersion": BINDING_SCHEMA, "extension": identity, "trustClass": trust_class},
    )


def test_trust_only_binds_new_profiles_and_manifests_as_external(refresh) -> None:
    _contribute(refresh, "browser-drivers", "browser.example-pilot")
    _contribute(refresh, "provider-integrations", "provider.exampleshield")
    _bind(refresh, "command.core", "first-party")

    assert refresh.main(["--trust-only"]) == 0

    assert refresh._trust_binding_index() == {
        "command.core": "first-party",
        "browser.example-pilot": "external",
        "provider.exampleshield": "external",
    }
    binding = json.loads((refresh.TRUST_BINDINGS / "provider.exampleshield.v1.json").read_text(encoding="utf-8"))
    assert binding == {
        "schemaVersion": BINDING_SCHEMA,
        "extension": "provider.exampleshield",
        "trustClass": "external",
    }
    external = json.loads(refresh.TRUST_MAP.read_text(encoding="utf-8"))["classes"]["external"]
    assert {"browser.example-pilot", "provider.exampleshield"} <= set(external)


def test_trust_only_keeps_an_authored_class(refresh) -> None:
    _contribute(refresh, "browser-drivers", "browser.example-pilot")
    _bind(refresh, "browser.example-pilot", "first-party")

    refresh.sync_trust_map()

    assert refresh._trust_binding_index() == {"browser.example-pilot": "first-party"}


@pytest.mark.parametrize(
    ("directory", "identity"),
    [("browser-drivers", "browser.example-pilot"), ("provider-integrations", "provider.exampleshield")],
)
def test_check_trust_fails_without_a_binding_and_writes_nothing(refresh, directory, identity) -> None:
    _contribute(refresh, directory, identity)

    with pytest.raises(SystemExit, match=identity):
        refresh.main(["--check-trust"])

    assert list(refresh.TRUST_BINDINGS.iterdir()) == []


def test_check_trust_passes_with_bindings(refresh, capsys) -> None:
    _contribute(refresh, "browser-drivers", "browser.example-pilot")
    _bind(refresh, "browser.example-pilot", "external")

    assert refresh.main(["--check-trust"]) == 0
    assert json.loads(capsys.readouterr().out)["authored_trust_complete"] is True


def test_integrations_never_make_command_regeneration_pending(refresh, monkeypatch) -> None:
    _contribute(refresh, "browser-drivers", "browser.example-pilot")
    _contribute(refresh, "provider-integrations", "provider.exampleshield")
    monkeypatch.setattr(refresh, "catalog_ids", lambda: set())

    assert refresh.pending_contribution_ids() == []


def test_readme_is_not_a_contribution(refresh) -> None:
    (refresh.ROOT / "contributions/browser-drivers/README.md").write_text("# Profiles\n", encoding="utf-8")

    assert refresh.integration_contribution_ids() == []


@pytest.mark.parametrize(
    ("directory", "filename", "payload"),
    [
        pytest.param("browser-drivers", "browser.a.json", {"id": "provider.a"}, id="wrong-prefix"),
        pytest.param("browser-drivers", "browser.a.json", {"id": "browser.b"}, id="name-mismatch"),
        pytest.param("browser-drivers", "browser.A.json", {"id": "browser.A"}, id="uppercase-slug"),
        pytest.param("provider-integrations", "provider.x.json", {"name": "x"}, id="missing-id"),
        pytest.param("provider-integrations", "provider.x.json", ["provider.x"], id="not-an-object"),
        pytest.param("provider-integrations", "provider.-x.json", {"id": "provider.-x"}, id="leading-hyphen"),
        pytest.param("provider-integrations", "provider.x.json", {"id": "provider.x/../y"}, id="path-in-id"),
    ],
)
def test_malformed_contribution_ids_are_rejected(refresh, directory, filename, payload) -> None:
    _write(refresh.ROOT / "contributions" / directory / filename, payload)

    with pytest.raises(SystemExit):
        refresh.integration_contribution_ids()


def test_binding_path_accepts_only_known_prefixes(refresh) -> None:
    assert refresh._trust_binding_path("browser.example-pilot").name == "browser.example-pilot.v1.json"
    assert refresh._trust_binding_path("provider.exampleshield").name == "provider.exampleshield.v1.json"
    with pytest.raises(ValueError):
        refresh._trust_binding_path("mcp.example")


def test_repository_integration_contributions_have_bindings() -> None:
    spec = importlib.util.spec_from_file_location("refresh_repo_trust", REPO / "scripts/refresh_extension_artifacts.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for identity in module.integration_contribution_ids():
        assert (REPO / "contracts/extensions/trust" / f"{identity}.v1.json").is_file(), identity


@pytest.mark.parametrize(
    ("directory", "packaged"),
    [
        ("contributions/browser-drivers", "codex_plugin_scanner/guard/contracts/data/browser_drivers/contributions"),
        (
            "contributions/provider-integrations",
            "codex_plugin_scanner/guard/contracts/data/provider_integrations/contributions",
        ),
    ],
)
def test_both_directories_ship_in_the_wheel(directory: str, packaged: str) -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    build = project["tool"]["hatch"]["build"]
    assert build["targets"]["wheel"]["force-include"][directory] == packaged
    assert (REPO / directory / "README.md").is_file()
    assert "contributions" in build["targets"]["sdist"]["only-include"]
    # The core-profile build hook strips bundled command contributions from the wheel. These
    # directories are not command contributions and must survive it.
    hook = (REPO / "scripts/build_command_projection_hook.py").read_text(encoding="utf-8")
    assert directory not in hook and packaged not in hook
    assert not any(directory.startswith(pattern.rstrip("*/")) for pattern in build.get("exclude", []))
