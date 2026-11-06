"""Context-safe rendering for untrusted GitHub-flavored Markdown fields."""

from __future__ import annotations


def escape_markdown_text(value: object) -> str:
    text = " ".join(str(value).split())
    text = text.replace("&", "&amp;").replace("`", "&#96;")
    for character in ("\\", "*", "_", "[", "]", "<", ">", "!", "|"):
        text = text.replace(character, f"\\{character}")
    return text
