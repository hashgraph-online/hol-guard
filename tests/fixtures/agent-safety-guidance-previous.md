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

## Prefer bounded operations

- Use read-only Git inspection before writes. Do not rewrite history, discard changes, or delete branches
  without explicit authorization.
- For filesystem changes, name one exact destination and avoid overwrite flags. For symbolic links, verify
  the source and destination separately, then create one link without replacing an existing path.
- For package work, state the package manager, workspace, package, and version explicitly. Use the repository
  lockfile flow and never pipe a downloaded installer into a shell.
- For remote work, state the host and destination explicitly. Keep file transfer, remote execution, and local
  cleanup as separate actions.
- Never read secret files, credential stores, or environment files unless the user explicitly authorizes
  the exact access. Never send local file contents to an untrusted destination.

## Keep review where it matters

Guard review is expected for destructive changes, permission or security changes, credential access, remote
execution, releases, deployments, and other actions with material side effects.

Do not reshape commands to conceal those effects.
