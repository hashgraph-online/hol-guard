"""The rule-contract component list is written twice: once in the Rust build
script that embeds the digests, and once in the native-runtime test that
recomputes them. Only the nightly native job runs that test, so a renamed or
moved component file used to sit broken for a day. Compare the two lists here
instead, where every pull request runs them."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_BUILD = _ROOT / "rust/crates/guard-rule-contract/build.rs"
_NATIVE_TEST = _ROOT / "ci/native_runtime/test_native_rule_contract.py"
_PAIR = re.compile(r'"([^"]+)"\s*,\s*\n?\s*(?:Path\()?"([^"]+)"')


def _table(source: str, opening: str, closing: str) -> dict[str, str]:
    body = source[source.index(opening) :]
    return dict(_PAIR.findall(body[: body.index(closing)]))


def _build_components() -> dict[str, str]:
    table = _table(_BUILD.read_text(encoding="utf-8"), "const COMPONENTS", "];")
    return {
        name: path.replace("../", "rust/crates/", 1) for name, path in table.items()
    }


def _native_test_components() -> dict[str, str]:
    return _table(_NATIVE_TEST.read_text(encoding="utf-8"), "_COMPONENTS = (", "\n)")


def test_native_rule_contract_components_match_the_build_script() -> None:
    build = _build_components()
    native = _native_test_components()
    shared = {name: path for name, path in native.items() if name in build}
    assert shared == build


def test_every_rule_contract_component_file_exists() -> None:
    missing = [path for path in _build_components().values() if not (_ROOT / path).is_file()]
    assert missing == []
