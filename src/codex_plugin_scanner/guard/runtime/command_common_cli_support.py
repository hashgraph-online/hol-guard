"""Shared builders and option grammar for common CLI Extensions."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, executable_path_set_matcher
from .command_rules import AnyMatcher

_EMPTY: frozenset[str] = frozenset()
_RUNNER_OPTIONS = frozenset(
    {
        "--cache",
        "--call",
        "--dir",
        "--filter",
        "--package",
        "--reporter",
        "--workspace",
        "-C",
        "-F",
        "-c",
        "-p",
        "-w",
    }
)
_RUNNER_FLAGS = frozenset(
    {"--aggregate-output", "--silent", "--stream", "--use-stderr", "--workspace-root", "--yes", "-y"}
)
_AWS_OPTIONS = frozenset(
    {
        "--ca-bundle",
        "--cli-binary-format",
        "--cli-connect-timeout",
        "--cli-read-timeout",
        "--color",
        "--endpoint-url",
        "--output",
        "--profile",
        "--query",
        "--region",
    }
)
_AWS_FLAGS = frozenset(
    {
        "--cli-auto-prompt",
        "--debug",
        "--no-cli-auto-prompt",
        "--no-cli-pager",
        "--no-color",
        "--no-paginate",
        "--no-sign-request",
        "--no-verify-ssl",
    }
)
_GCLOUD_OPTIONS = frozenset(
    {
        "--access-token-file",
        "--account",
        "--billing-project",
        "--configuration",
        "--filter",
        "--flags-file",
        "--flatten",
        "--format",
        "--impersonate-service-account",
        "--limit",
        "--page-size",
        "--project",
        "--sort-by",
        "--trace-token",
        "--verbosity",
    }
)
_GCLOUD_FLAGS = frozenset(
    {"--log-http", "--no-log-http", "--quiet", "-q", "--user-output-enabled", "--no-user-output-enabled"}
)
_AZURE_OPTIONS = frozenset({"--output", "-o", "--query", "--subscription"})
_AZURE_FLAGS = frozenset({"--debug", "--help", "--only-show-errors", "--verbose", "-h"})


def _path_bundle(
    executables: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_path_set_matcher(
                executable,
                paths,
                global_options_with_values=options,
                global_flags=flags,
                fail_secure_unknown_options=True,
            )
            for executable in executables
        )
    )


def _flag_bundle(
    executables: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    required_flags: frozenset[str],
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                executable,
                *path,
                required_flags=required_flags,
                global_options_with_values=options,
                global_flags=flags,
                fail_secure_unknown_options=True,
            )
            for executable in executables
            for path in paths
        )
    )


def _prefixed(prefix: tuple[str, ...], paths: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    return tuple((*prefix, *path) for path in paths)


def _node_bundle(
    executable: str,
    package_names: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    combined_options = options | _RUNNER_OPTIONS
    combined_flags = flags | _RUNNER_FLAGS
    matchers = [
        executable_path_set_matcher(
            executable,
            paths,
            global_options_with_values=options,
            global_flags=flags,
            fail_secure_unknown_options=True,
        )
    ]
    for package in package_names:
        matchers.extend(
            (
                executable_path_set_matcher(
                    "npx",
                    _prefixed((package,), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "bunx",
                    _prefixed((package,), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "npm",
                    _prefixed(("exec", package), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "pnpm",
                    (*_prefixed(("exec", package), paths), *_prefixed(("dlx", package), paths)),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
                executable_path_set_matcher(
                    "yarn",
                    _prefixed(("dlx", package), paths),
                    global_options_with_values=combined_options,
                    global_flags=combined_flags,
                    fail_secure_unknown_options=True,
                ),
            )
        )
    return AnyMatcher(matchers=tuple(matchers))


def _node_flag_bundle(
    executable: str,
    package_names: tuple[str, ...],
    paths: tuple[tuple[str, ...], ...],
    *,
    required_flags: frozenset[str],
    options: frozenset[str] = _EMPTY,
    flags: frozenset[str] = _EMPTY,
) -> AnyMatcher:
    combined_options = options | _RUNNER_OPTIONS
    combined_flags = flags | _RUNNER_FLAGS
    matchers = [
        executable_matcher(
            executable,
            *path,
            required_flags=required_flags,
            global_options_with_values=options,
            global_flags=flags,
            fail_secure_unknown_options=True,
        )
        for path in paths
    ]
    for package in package_names:
        for path in paths:
            for launcher, prefix in (
                ("npx", (package,)),
                ("bunx", (package,)),
                ("npm", ("exec", package)),
                ("pnpm", ("exec", package)),
                ("pnpm", ("dlx", package)),
                ("yarn", ("dlx", package)),
            ):
                matchers.append(
                    executable_matcher(
                        launcher,
                        *prefix,
                        *path,
                        required_flags=required_flags,
                        global_options_with_values=combined_options,
                        global_flags=combined_flags,
                        fail_secure_unknown_options=True,
                    )
                )
    return AnyMatcher(matchers=tuple(matchers))
