"""Synthetic configuration files the static gate writes into its fixture home and parent repository."""

from __future__ import annotations

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
}


def write_parent_documents(parent: Path) -> None:
    """Write the parent repository's committed top-level documents."""
    for relative, text in PARENT_DOCUMENTS.items():
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
