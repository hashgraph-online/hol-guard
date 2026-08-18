## Summary
- Treat repository-bound `git fetch origin` with quiet flags and multiple named refs as a verified remote refresh.
- Keep GitHub SSH origin fetches in Git protection so they can be allowed or blocked, without auto-allowing OpenSSH config hooks.
- Register named-origin fetch on Git protection so Extensions can allow remaining `git fetch origin` variants without enabling URL remotes or `--all`.

## Testing
- `python -m pytest tests/test_guard_origin_fetch_classification.py tests/test_guard_standalone_git_routine.py tests/test_guard_command_permission_catalog.py tests/test_guard_command_extensions.py -q --tb=line`
- `python tests/guard_command_decision_diff.py --check`
- `ruff check` on the changed Python files
