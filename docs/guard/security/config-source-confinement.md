# Guard config source confinement

CodeQL alerts [343](https://github.com/hashgraph-online/hol-guard/security/code-scanning/343)
and [344](https://github.com/hashgraph-online/hol-guard/security/code-scanning/344)
identify `_read_toml`'s separate pathname `is_file()` and `open()` operations.
The reviewed route authenticates the request and canonicalizes the requested
workspace, and config loading uses three fixed basenames. Those checks did not
prevent a config leaf symlink or a directory replacement from redirecting the
subsequent read. The sink was correlated against foundation source
`e449594e86c717e66e14598a4130475de79c536f` and implementation source
`9db62e8844c2ba2627f55b6b00e58cb5b175185d`. This change does not dismiss an alert or
alter a CodeQL query.

`config_source_io.capture_guard_config` now reads only `config.toml`,
`.ai-plugin-scanner-guard.toml`, or `.hol-guard.toml`. It resolves an intentional
directory alias at the scope boundary and binds the real directory before opening
the config leaf. POSIX uses a retained, descriptor-relative `O_NOFOLLOW` chain;
Windows reuses the existing no-reparse directory handles with write/delete sharing
denied and the existing locked regular-file descriptor. The Windows path does not
create directories or perform output operations. Unsupported descriptor/handle
access has no pathname fallback.

The reader rejects symbolic links, Windows reparse leaves, hard links, directories,
devices and FIFOs as config sources. It reads a regular file once, checks its
identity before and after reading, verifies the exact original byte count, and
checks the retained directory bindings before returning. A same-size rewrite,
growth, truncation, leaf replacement, or parent replacement observed during the
read is rejected. The operation does not claim an immutable snapshot against an
actor who already has the authority to rewrite the same file or authenticated
workspace before the read starts. It does not authenticate a workspace: that
remains the caller's responsibility.

Missing files and missing workspace directories still contribute no configuration
override. An inaccessible or unsafe existing source raises
`GuardConfigSourceError`, a `ValueError`, rather than being parsed as an empty
config. Malformed TOML and invalid UTF-8 still raise. This deliberately changes the
old handling of inaccessible, linked and non-regular config paths: an unreadable
strict configuration must not silently become default settings. Directory aliases
and relative paths remain supported, and returned `GuardConfig` paths retain their
original logical spelling. No owner, permission or ACL requirement is added to
ordinary workspace config files. Config precedence, blocked workspace policy keys
and managed-policy application are unchanged.

The byte ceiling is **1,048,576 bytes (1 MiB)**, inclusive. This is a new acceptance
limit for ordinary Guard TOML loading: that loader previously had no byte limit.
The exact value matches the existing shared safe-file read ceiling and the native
publisher's existing config-capture ceiling. A file over that limit raises before
content is read; a file that grows during the read also raises. The loader never
parses a truncated prefix or falls back to an unbounded read. This limit is a
security input bound, not a change to a frozen Rust performance threshold.

Tests exercise the public `load_guard_config` boundary as well as deterministic
descriptor races. They cover home and both workspace basenames, live and dangling
leaf symlinks, directory aliases, missing and inaccessible files, exact/over-limit
sizes, malformed input, hard links, FIFOs, same-size writes, growth, truncation,
leaf/parent replacements, short reads, descriptor cleanup and unsupported
descriptor capability. The actual Windows handle-sharing test runs only on a
Windows host; a Linux pass does not establish that platform's result.

Local validation on the implementation source cut recorded in
[config-source-validation.json](config-source-validation.json) passed 67 tests,
with the one Windows-only handle-sharing test skipped. Ruff and format checks
passed; the two production source files reported zero type errors and 61
nonfatal warnings. The receipt binds the exact source hashes and preserves the
earlier alias-test assertion failure separately.

The shared reader and `_read_toml` change are independent of the Rust migration
implementation and apply to the foundation PR. The implementation's separately
captured config inputs must use the same reader so an injected capture cannot
reintroduce the former pathname behavior. The old benchmark baseline remains
unchanged.
