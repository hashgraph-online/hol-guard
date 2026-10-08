"""Keep the extension authoring reference documents scoped and their links usable."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = _ROOT / "docs/guard/extension-builder"
_REFERENCE_FILES = {"README.md", "VALIDATION.md"}
_LINK = re.compile(r"\[[^\]\n]+\]\(([^)\n]+)\)")


def test_only_maintained_reference_documents_are_published() -> None:
    """Additional Markdown files require an explicit change to the public scope."""
    documents = {
        path.relative_to(_DOCS).as_posix()
        for path in _DOCS.rglob("*")
        if path.is_file() and path.suffix.casefold() == ".md"
    }
    assert documents == _REFERENCE_FILES


@pytest.mark.parametrize("filename", sorted(_REFERENCE_FILES))
def test_public_reference_links_resolve(filename: str) -> None:
    """Relative links must resolve to existing files inside this checkout."""
    document = _DOCS / filename
    for target in _LINK.findall(document.read_text(encoding="utf-8")):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        destination = (document.parent / unquote(parsed.path)).resolve()
        assert destination.is_relative_to(_ROOT), target
        assert destination.is_file(), target
