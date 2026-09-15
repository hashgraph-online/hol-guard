## Summary
- Start the approval-center HTTP server and write the daemon URL before hook-worker handshake and runtime artifact reconciliation.
- Skip the Guard command hub for `daemon --serve` and skip secret-store priming during store construct so the child can answer before the bootstrap timeout.
- Launch that daemon from the Desktop-owned Core executable when `desktop bootstrap` starts it.
- Release the service ownership lock after listen-ready so `stop()` can contain a `serve()` race during cold-home work, and retry post-listen store recovery after SQLite quarantine.

## Testing
- `uv run python -m pytest tests/test_guard_daemon_listen_ready.py tests/test_guard_daemon_stress_script.py tests/test_guard_daemon_sqlite_start_recovery.py tests/test_guard_daemon_lifecycle_transition.py tests/test_guard_daemon_review_regressions.py tests/test_guard_daemon_startup_rollback.py tests/test_guard_desktop_dashboard_session.py tests/test_cli_startup_latency_contract.py --tb=short`
- `uv build`
- `uv tool run --from dist/hol_guard-3.0.1-py3-none-any.whl hol-guard --version`
