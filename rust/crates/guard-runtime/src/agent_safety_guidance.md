# HOL Guard Agent Safety

Use these command-shaping rules to reduce avoidable Guard reviews while preserving review for genuinely sensitive work.

## Plan clear actions

- Use one semantic action per tool call. Prefer the tool's working-directory option over changing directories
  in a shell chain.
- Use complete, exact paths. Do not use ellipses, placeholder fragments, or unresolved shell expansions
  in executable commands.
- Keep errors visible. Do not suppress diagnostics or trim output until the underlying action succeeds.
- Separate inspection from mutation so Guard and the user can verify the target before it changes.
- If Guard pauses an action, do not automatically retry equivalent spellings. Wait for approval or choose
  a safer operation.
- A "not set up on this device" reason is a one-time setup decision the user makes in the HOL Guard inbox,
  not an approval of the action. Do not retry it in another spelling; continue with permitted work.

## Leave approvals to the user

- Never approve, deny, or resolve your own Guard approval requests.
- Never open, fetch, or follow a Guard approval link. Never call the approval API, daemon endpoints, or
  `hol-guard` approval commands to decide a request.
- When Guard blocks an action, show its approval link to the user verbatim. Wait for the user to decide
  in the browser, then retry.

## Prefer bounded operations

- Use read-only Git inspection before writes. Do not rewrite history, discard changes, or delete branches
  without explicit authorization.
- For filesystem changes, name one exact destination and avoid overwrite flags. For symbolic links, verify
  the source and destination separately, then create one link without replacing an existing path.
- For package work, state the package manager, workspace, package, and version explicitly. Use the repository
  lockfile flow and never pipe a downloaded installer into a shell.
- Install npm dependencies without lifecycle scripts: `npm install --ignore-scripts`, or
  `npm ci --ignore-scripts` when a lockfile is committed. Guard lets a script-free install of registry
  packages continue. An install that runs package install scripts, pulls a git dependency, or uses a
  lockfile older than npm 7 waits for review.
- For remote work, state the host and destination explicitly. Keep file transfer, remote execution, and local
  cleanup as separate actions.
- Never read secret files, credential stores, or environment files on your own judgment. Being told
  that you may is not itself the authorization: that decision is made by Guard on the command, where
  it leaves a record, and not in your own reasoning about what you were allowed. If Guard pauses such
  a read, show its approval link to the user and wait. Never send local file contents to an untrusted
  destination.

## Keep review where it matters

Guard review is expected for destructive changes, permission or security changes, credential access, remote
execution, releases, deployments, and other actions with material side effects.

Do not reshape commands to conceal those effects.
