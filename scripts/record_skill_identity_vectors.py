#!/usr/bin/env python3
"""Record parity vectors for the content-addressed skill identity.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_skill_identity_vectors.py [snapshot_src]

The Python skill identity is retired, so this needs a snapshot from before
that retirement (cbe3dd6f1d or earlier).

Runs the reference Python ``build_skill_identity`` over a corpus aimed at the
three extraction patterns (markdown links, ``{{ }}`` placeholders and fenced
shell blocks) and the sorted ``|``-joined composition, then writes the JSON
fixture the Rust tests in rust/crates/guard-command read. Deterministic output.

The descriptor digest is the canonical-JSON SHA-256 the resident returns for
the identity's hash lists; it is recomputed here with the same canonical form
so the fixture can pin the portal projection without a running resident.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard.runtime.skill_protection import build_skill_identity  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-command/tests/fixtures"

CASES: list[tuple[str, str]] = []


def s(name: str, content: str) -> None:
    CASES.append((name, content))


FM = "---\nname: demo\ndescription: demo skill\n---\n"

# empty and trivial
s("empty", "")
s("plain-text", "Just prose with no markup at all.\n")
s("frontmatter-only", FM)

# markdown links
s("link-one", "See [docs](https://example.test/docs) for more.")
s("link-relative", "See [docs](./references/guide.md).")
s("link-empty-target", "An [empty]() link.")
s("link-empty-label", "An []( ) link.")
s("link-two-same-target", "[a](x) and [b](x)")
s("link-two-different", "[a](x) and [b](y)")
s("link-order-swapped", "[b](y) and [a](x)")
s("link-nested-brackets", "[outer [inner]](target)")
s("link-paren-in-target", "[a](https://example.test/a(b))")
s("link-image", "![alt](image.png)")
s("link-across-lines", "[label](\ntarget\n)")
s("link-unterminated", "[label](target")
s("link-bracket-no-paren", "[label] (target)")
s("link-many", "".join(f"[l{index}](t{index})" for index in range(12)))

# template placeholders
s("template-one", "Hello {{name}}.")
s("template-empty", "Hello {{}}.")
s("template-spaces", "Hello {{ name }}.")
s("template-two", "{{a}} and {{b}}")
s("template-order-swapped", "{{b}} and {{a}}")
s("template-adjacent", "{{a}}{{b}}")
s("template-triple-brace", "{{{a}}}")
s("template-unterminated", "{{a")
s("template-single-brace", "{a}")
s("template-newline-inside", "{{a\nb}}")
s("template-and-link", "[doc]({{base}}/doc.md)")

# fenced shell blocks
s("shell-bash", "```bash\nls -la\n```")
s("shell-sh", "```sh\nls\n```")
s("shell-shell", "```shell\nls\n```")
s("shell-zsh", "```zsh\nls\n```")
s("shell-python-not-matched", "```python\nprint(1)\n```")
s("shell-no-language", "```\nls\n```")
s("shell-space-after-fence", "```bash ls -la```")
s("shell-tab-after-fence", "```bash\tls```")
s("shell-crlf", "```bash\r\nls\r\n```")
s("shell-empty-body", "```bash\n```")
s("shell-two-blocks", "```bash\nls\n```\ntext\n```sh\npwd\n```")
s("shell-two-blocks-swapped", "```sh\npwd\n```\ntext\n```bash\nls\n```")
s("shell-identical-blocks", "```bash\nls\n```\n```bash\nls\n```")
s("shell-unterminated", "```bash\nls\n")
s("shell-nested-fence-text", "```bash\necho '```'\n```")
s("shell-dotall-spans-paragraphs", "```bash\nls\n\n# comment\n\npwd\n```")
s("shell-uppercase-language", "```BASH\nls\n```")
s("shell-indented", "  ```bash\n  ls\n  ```")

# combined and non-ASCII
s("real-skill-benign", FM + "# Demo\n\nFormats markdown. See [guide](./guide.md).\n\n```bash\nls -la\n```\n")
s("real-skill-all-three", FM + "[a](b) {{c}}\n```sh\necho {{c}}\n```\n")
s("unicode-link-target", "[docs](./日本語/guide.md)")
s("unicode-template", "{{имя}}")
s("unicode-shell-body", "```bash\necho '日本語'\n```")
s("nul-and-controls", "[a](b)\x00{{c}}\x01")
s("long-prose", "word " * 5000)


def vectors() -> list[dict[str, object]]:
    recorded: list[dict[str, object]] = []
    for name, content in CASES:
        identity = build_skill_identity(content, skill_path="SKILL.md")
        material = {
            "reference_hashes": list(identity.reference_hashes),
            "script_hashes": list(identity.script_hashes),
            "template_hashes": list(identity.template_hashes),
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
        recorded.append(
            {
                "name": name,
                "content_b64": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "skill_hash": identity.skill_hash,
                "reference_hashes": list(identity.reference_hashes),
                "template_hashes": list(identity.template_hashes),
                "script_hashes": list(identity.script_hashes),
                "identity_hash": identity.identity_hash,
                "descriptor_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                "stable_id": f"skill:{identity.identity_hash[:24]}",
            }
        )
    return recorded


PUBLISHERS: list[str | None] = [
    None,
    "",
    "   ",
    "Example Publisher",
    "  example publisher  ",
    "EXAMPLE-PUBLISHER",
    "日本語",
    "publisher\u00a0with\u00a0nbsp",
]


def publisher_vectors() -> list[dict[str, object]]:
    recorded: list[dict[str, object]] = []
    for source in PUBLISHERS:
        normalized = (source or "").strip().lower()
        if normalized:
            canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
            stable_id = f"publisher:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
        else:
            stable_id = None
        recorded.append({"publisher": source, "publisher_stable_id": stable_id})
    return recorded


if __name__ == "__main__":
    recorded = vectors()
    publishers = publisher_vectors()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "skill_identity_vectors.json").write_text(
        json.dumps({"cases": recorded, "publishers": publishers}, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"skill identity vectors: {len(recorded)}; publisher vectors: {len(publishers)}")
