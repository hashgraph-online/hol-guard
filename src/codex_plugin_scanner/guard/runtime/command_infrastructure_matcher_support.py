"""Shared executable and global-option grammar for infrastructure command rules."""

from __future__ import annotations

from .command_common_extension_helpers import executable_matcher
from .command_rules import ExecutableMatcher

_EMPTY: frozenset[str] = frozenset()
_EMPTY_OPTION_VALUES: tuple[tuple[str, frozenset[str]], ...] = ()

_DOCKER_EXECUTABLES = frozenset({"docker", "docker.exe"})
_KUBECTL_EXECUTABLES = frozenset({"kubectl", "kubectl.exe"})
_HELM_EXECUTABLES = frozenset({"helm", "helm.exe"})

_DOCKER_GLOBAL_OPTIONS = frozenset(
    {
        "--config",
        "--context",
        "-c",
        "--host",
        "-H",
        "--log-level",
        "-l",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
    }
)
_DOCKER_GLOBAL_FLAGS = frozenset({"--debug", "-D", "--tls", "--tlsverify"})
_KUBECTL_GLOBAL_OPTIONS = frozenset(
    {
        "--as",
        "--as-group",
        "--as-uid",
        "--cache-dir",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--cluster",
        "--context",
        "--kubeconfig",
        "--namespace",
        "-n",
        "--password",
        "--profile-output",
        "--request-timeout",
        "--server",
        "-s",
        "--tls-server-name",
        "--token",
        "--user",
        "--username",
        "-v",
        "--v",
    }
)
_KUBECTL_GLOBAL_FLAGS = frozenset(
    {
        "--disable-compression",
        "--insecure-skip-tls-verify",
        "--match-server-version",
        "--warnings-as-errors",
    }
)
_HELM_GLOBAL_OPTIONS = frozenset(
    {
        "--burst-limit",
        "--kube-apiserver",
        "--kube-as-group",
        "--kube-as-user",
        "--kube-ca-file",
        "--kube-context",
        "--kube-tls-server-name",
        "--kube-token",
        "--kubeconfig",
        "--namespace",
        "-n",
        "--qps",
        "--registry-config",
        "--repository-cache",
        "--repository-config",
    }
)
_HELM_GLOBAL_FLAGS = frozenset({"--debug", "--kube-insecure-skip-tls-verify"})


def docker_matcher(
    *subcommands: str,
    required_flags: frozenset[str] = _EMPTY,
    forbidden_flags: frozenset[str] = _EMPTY,
    interspersed_options_with_values: frozenset[str] = _EMPTY,
    interspersed_flags: frozenset[str] = _EMPTY,
    options_with_values: frozenset[str] = _EMPTY,
    required_option_values: tuple[tuple[str, frozenset[str]], ...] = _EMPTY_OPTION_VALUES,
) -> ExecutableMatcher:
    return executable_matcher(
        _DOCKER_EXECUTABLES,
        *subcommands,
        required_flags=required_flags,
        forbidden_flags=forbidden_flags,
        leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
        interspersed_options_with_values=interspersed_options_with_values,
        interspersed_flags=_DOCKER_GLOBAL_FLAGS | interspersed_flags,
        options_with_values=options_with_values,
        required_option_values=required_option_values,
    )


def kubectl_matcher(
    *subcommands: str,
    required_flags: frozenset[str] = _EMPTY,
    forbidden_flags: frozenset[str] = _EMPTY,
) -> ExecutableMatcher:
    return executable_matcher(
        _KUBECTL_EXECUTABLES,
        *subcommands,
        required_flags=required_flags,
        forbidden_flags=forbidden_flags,
        leading_options_with_values=_KUBECTL_GLOBAL_OPTIONS,
        interspersed_flags=_KUBECTL_GLOBAL_FLAGS,
    )


def helm_matcher(*subcommands: str) -> ExecutableMatcher:
    return executable_matcher(
        _HELM_EXECUTABLES,
        *subcommands,
        leading_options_with_values=_HELM_GLOBAL_OPTIONS,
        interspersed_flags=_HELM_GLOBAL_FLAGS,
    )
