"""Synthetic configuration files the static gate writes into its fixture home."""

from __future__ import annotations

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
