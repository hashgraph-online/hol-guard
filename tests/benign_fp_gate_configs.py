"""Synthetic configuration files the static gate writes into its fixture home and parent repository."""

from __future__ import annotations

import base64
import zlib
from pathlib import Path

from ci.gauntlet.extension_catalog_fixtures import CATALOG_PATH, CATALOG_SOURCE

LFS_GITCONFIG = """[filter "lfs"]
\tclean = git-lfs clean -- %f
\tsmudge = git-lfs smudge -- %f
\tprocess = git-lfs filter-process
\trequired = true
[user]
\tname = Fixture Author
\temail = fixture@example.invalid
"""
# Synthetic kubeconfig with no credentials; kubectl is never executed by the gate.
KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- name: example
  cluster:
    server: https://k8s.example.invalid
contexts:
- name: example
  context:
    cluster: example
    user: example
current-context: example
users:
- name: example
  user: {}
"""

# Committed documents named for a secret-management feature. The catalog is an
# ordinary project file; the manifest declares a Kubernetes Secret and keeps
# its review even though its values pass the secret detector.
PARENT_DOCUMENTS = {
    "README.md": "# Parent\n",
    CATALOG_PATH: CATALOG_SOURCE,
    "deploy/app-secrets.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  mode: cHJvZA==\n",
    # Named for a feature, not a store: `auth-evidence/` is to auth what
    # `auth-service/` is, and the document's own name carries the same word.
    "docs/auth-evidence/phase-e-auth-schema.md": "# Phase E schema\n\nNotes on the account table.\n",
}

# A committed screenshot named for the screen it shows: a one-pixel PNG with a
# density chunk, as a capture tool writes it. A recursive search reads pixels,
# not text, so walking past it is not a credential read.
PARENT_IMAGES = {
    "docs/screens/auth-desktop-login.png": base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACXBIWXMAABYlAAAWJQFJUiTwAAAAC0lEQVR4nGP4DwQACfsD/fteaysAAAAASUVORK5CYII="
    ),
}


def _capture(pixel_bytes: int) -> bytes:
    """A PNG the size a real screen capture is, built rather than embedded.

    A full-window retina capture is several megabytes. Checking in that many
    bytes of base64 to prove one walk budget would be absurd, and the pixel
    data itself carries no meaning for the walk: it reads the chunk layout and
    scans for text. So the capture is assembled here from an ordinary header
    and one run of pixel data.
    """
    chunks = [
        (b"IHDR", bytes([0, 0, 11, 72, 0, 0, 7, 128, 8, 6, 0, 0, 0])),
        (b"pHYs", bytes([0, 0, 22, 37, 0, 0, 22, 37, 1])),
        (b"IDAT", bytes(pixel_bytes)),
        (b"IEND", b""),
    ]
    out = bytearray(b"\x89PNG\r\n\x1a\x0a")
    for kind, data in chunks:
        out += len(data).to_bytes(4, "big")
        out += kind
        out += data
        out += zlib.crc32(kind + data).to_bytes(4, "big")
    return bytes(out)


# The same thing at the size captures actually are. Guard proves a committed
# image by reading all of it, and the walk's budget for that was once shared
# with the documents it reads, so one ordinary screenshot exhausted it and the
# whole `docs` tree stopped being provable. Three megabytes is an unremarkable
# full-window capture and larger than the entire document budget.
PARENT_CAPTURES = {
    "docs/screens/auth-desktop-policy-review.png": _capture(3 * 1024 * 1024),
}

# A source directory holding more modules than Guard lists when it expands a
# glob, as a large frontend's `src/` does. `rg pattern <dir>/*.ts` from a
# sibling checkout reads no more than a recursive search of the directory.
PARENT_WIDE_MODULES = {
    f"console/src/module{index:03}.ts": f"export const moduleValue{index} = {index};\n" for index in range(300)
}


def write_parent_documents(parent: Path) -> None:
    """Write the parent repository's committed top-level documents and images."""
    for relative, text in {**PARENT_DOCUMENTS, **PARENT_WIDE_MODULES}.items():
        target = parent / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    for relative, data in {**PARENT_IMAGES, **PARENT_CAPTURES}.items():
        target = parent / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


# A design system's token documents. A design token is a named style value --
# a colour, a spacing step, a type ramp -- so a file named for one carries
# styles rather than credentials. These stay out of the baseline commit: a
# tracked file is already proven by the checkout that holds it, and the
# credential-name screen these exercise is only reached for a file the walk
# cannot prove that way.
PARENT_DESIGN_TOKENS = {
    "docs/design/color-tokens.md": (
        "# Color tokens\n\n- `--surface-raised`: #f7f7f8\n- `--text-muted`: #6b7280\n"
    ),
    "docs/design/spacing-token-drift.generated.md": (
        "# Spacing token drift\n\n- `space-2`: 8px (was 6px)\n"
    ),
}


def write_parent_design_tokens(parent: Path) -> None:
    """Write the parent's design-token documents, untracked, after its commit."""
    for relative, text in PARENT_DESIGN_TOKENS.items():
        target = parent / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def write_sibling_documents(sibling: Path) -> None:
    """Write the home sibling checkout's committed catalog entry and empty marker."""
    (sibling / ".keep").parent.mkdir(parents=True, exist_ok=True)
    (sibling / ".keep").write_text("", encoding="utf-8")
    target = sibling / CATALOG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(CATALOG_SOURCE, encoding="utf-8")


def write_platform_dotfiles(platform: Path) -> None:
    """Write the platform checkout's ignore list and a one-off script it keeps as a dotfile."""
    (platform / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (platform / ".repair-stage.py").write_text("def main():\n    return 0\n", encoding="utf-8")


def write_plain_project(plain: Path) -> None:
    """Write the plain project directory beside the checkout and its hidden config files."""
    _write_text(plain / "README.txt", "Plain notes directory.\n")
    _write_text(plain / "probe_py.py", "print('probe')\n")
    # A project directory beside the checkout that was never `git init`-ed:
    # a handed-over tree, an unpacked archive, a scaffold still being set up.
    # Its hidden files are the ordinary project configuration an agent reads
    # to match the workspace it is working in.
    _write_text(plain / ".gitattributes", "* text=auto eol=lf\n")
    _write_text(plain / ".npmignore", "src/\ntests/\n")
    _write_text(plain / ".node-version", "22.11.0\n")
    _write_text(plain / ".tool-versions", "nodejs 22.11.0\npython 3.12.7\n")
    _write_text(plain / ".browserslistrc", "defaults\nnot IE 11\n")
    _write_text(plain / ".prettierrc", '{\n  "semi": false\n}\n')
    _write_text(plain / ".eslintrc.json", '{\n  "root": true\n}\n')
    _write_text(plain / ".mocharc.json", '{\n  "spec": "tests/**/*.spec.js"\n}\n')
    # Negative control for the same directory: a registry file keeps its
    # review wherever it sits, because that is where a publish token lands.
    _write_text(plain / ".npmrc", "registry=https://registry.npmjs.org/\n")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
