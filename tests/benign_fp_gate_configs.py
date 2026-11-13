"""Synthetic configuration files the static gate writes into its fixture home and parent repository."""

from __future__ import annotations

import base64
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
    for relative, data in PARENT_IMAGES.items():
        target = parent / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def write_sibling_documents(sibling: Path) -> None:
    """Write the home sibling checkout's committed catalog entry and empty marker."""
    (sibling / ".keep").parent.mkdir(parents=True, exist_ok=True)
    (sibling / ".keep").write_text("", encoding="utf-8")
    target = sibling / CATALOG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(CATALOG_SOURCE, encoding="utf-8")
