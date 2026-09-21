# Maintenance fixture reader dependency

The long-lived daemon maintenance fixture bypasses server construction with `object.__new__`. After explicit scoped-reader propagation, its fake server lacked `hook_config_reader`, causing the existing best-effort exception handler to run before the mocked configuration load. Its load double also lacked the optional keyword. The test-only correction supplies both dependencies. The original global-home/no-workspace assertion, maintenance frequency, retention value and production behavior remain unchanged.

The complete retained hosted failure is foundation job105364728372, PR head `cdd14176ef0e0a258d4655c64210524d7047a257`, through synthetic merge `c92e557349cabd633db408912c644471c002ee4d`. Original fixture bytes match that PR head and are identical in main. This is not a claim of a main hosted failure.

The **foundation** local after-run executes only the actual failed node once: **1 passed in 0.27 seconds**. Pytest uses the shared lock and ordinary `/tmp` fixtures; direct Ruff check and format check pass. No production files or deadlines were changed. These results do not replace a complete hosted shard or release gate.

The [manifest](manifest.json) pins original/current owned source bytes, raw receipts, the original branch HEAD and exact command scope. Deterministic gzip preserves the complete original source and hosted log, with both encoded and decoded hashes. [Focused output](focused-test.txt), [Ruff](ruff-check.txt) and [format](ruff-format-check.txt) remain separate. Source identity covers this owned test file, not every concurrently edited file in the checkout.
