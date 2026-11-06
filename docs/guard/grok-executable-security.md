# Grok Executable Trust

Guard launches Grok only after resolving an absolute executable identity. A bare `grok` command and the current
working directory are never used as the final launch target.

## Automatic discovery

Automatic discovery accepts standard system package roots and common per-user package-manager roots, including
Homebrew, npm-global, Bun, Volta, asdf, pnpm, nvm, fnm, mise, and proto layouts. The candidate must:

- have an absolute PATH result and a Grok launcher name appropriate for the current platform
- resolve outside the workspace, Guard state directory, and current working directory
- resolve to a regular executable file
- on POSIX, be owned by root or the current user and not be group- or world-writable
- on POSIX, have a directory chain owned by root or the current user with no group- or world-writable component

Symlinks are resolved before launch. Both the launcher location and final target are checked, and Guard executes the
resolved target rather than the mutable symlink path. Windows discovery recognizes `.exe`, `.cmd`, `.bat`, and `.com`
launchers and requires an absolute path under a standard installation location.

Config-only installations remain visible in detection results even when no trusted executable is available. Guard
reports the executable as unavailable and does not run a version probe against the rejected PATH entry.

## Custom installations

For a custom installation outside the automatic roots, make one explicit selection:

```text
hol-guard run grok --grok-executable /absolute/path/to/grok
```

The selection must still pass the workspace, ownership, mode, symlink-target, and executable checks. Guard stores the
resolved path and SHA-256 identity in `~/.hol-guard/managed/grok/trusted-executable.json` with owner-only permissions.
Later launches re-hash the file. An update or replacement requires the same explicit selection once more; unchanged
launches do not add an approval prompt.

The selection is registered only when Guard reaches the actual launch. `--dry-run` and blocked launches do not mutate
trusted executable state. The option is Grok-specific and is rejected for other harnesses.

## Launch isolation and developer experience

Guard removes code-loader environment variables such as `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `LD_PRELOAD`, and
`DYLD_*` from the Grok process. It also removes empty, relative, workspace, Guard-state, and insecure writable entries
from the child `PATH`. Other environment values and safe tool locations remain available so Grok can continue to use
normal developer tools.

The Grok process intentionally keeps the selected project as its working directory. Moving it to a Guard-owned
directory would hide the project and break normal Grok navigation and file operations. Executable resolution and the
version probe do not rely on that directory: the launch target is absolute, and the probe runs from an owner-only
Guard runtime directory with the sanitized environment.

## Release verification

- Verify workspace and relative PATH collisions are rejected before probe or launch.
- Verify symlinks into the workspace and unsafe owner/mode combinations are rejected.
- Verify a standard trusted installation launches without a new prompt.
- Verify a custom explicit selection is reused while its hash is unchanged and rejected after replacement.
- Verify the production container launches only an absolute Grok path and strips code-loader environment variables.
