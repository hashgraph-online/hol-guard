from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_policy_docs", ROOT / "scripts" / "generate_policy_docs.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_policy_pages_are_current() -> None:
    generator = _load_generator()
    assert generator.main(["--check"]) == 0


def test_schema_reference_covers_every_definition_and_field() -> None:
    schema = json.loads((ROOT / "spec/guard-policy/v1alpha1/schema.json").read_text(encoding="utf-8"))
    page = (ROOT / "docs/policy/schema-reference.md").read_text(encoding="utf-8")
    for name, definition in schema["$defs"].items():
        assert f"## {name}\n" in page
        for field in definition.get("properties", {}):
            assert f"`{field}`" in page


def test_precedence_page_quotes_the_frozen_section_verbatim() -> None:
    generator = _load_generator()
    semantics = (ROOT / "spec/guard-policy/v1alpha1/semantics.md").read_text(encoding="utf-8")
    excerpt = generator.precedence_excerpt()
    assert excerpt in semantics
    page = (ROOT / "docs/policy/precedence.md").read_text(encoding="utf-8")
    for line in excerpt.splitlines():
        assert (f"> {line}" if line else ">") in page


def test_stale_page_is_detected(tmp_path: Path, monkeypatch, capsys) -> None:
    generator = _load_generator()
    monkeypatch.setattr(generator, "DOCS", tmp_path)
    assert generator.main(["--check"]) == 1
    assert "Out of date" in capsys.readouterr().err
    assert generator.main([]) == 0
    assert generator.main(["--check"]) == 0


def test_every_starter_is_in_the_cross_reference() -> None:
    from codex_plugin_scanner.guard.policy_starters import starter_ids

    page = (ROOT / "docs/policy/STARTERS.md").read_text(encoding="utf-8")
    for identifier in starter_ids():
        assert f"`{identifier}`" in page


def test_cli_reference_documents_every_policy_command() -> None:
    page = (ROOT / "docs/policy/cli.md").read_text(encoding="utf-8")
    for command in ("init", "validate", "test", "check", "status", "explain", "diff", "export", "fmt", "import"):
        assert command in page
