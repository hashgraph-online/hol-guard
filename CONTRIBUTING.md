# Contributing to Codex Plugin Scanner

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/hashgraph-online/codex-plugin-scanner.git
cd codex-plugin-scanner
pip install -e ".[dev]"
pytest
```

## Adding New Checks

1. Create a new check function in the appropriate file under `src/codex_plugin_scanner/checks/`.
2. Add it to the corresponding `run_*_checks()` function.
3. Write tests in `tests/`.
4. Update the README's checks table.
5. Submit a PR.

## Code Style

- Python 3.10+
- Ruff for linting and formatting
- All checks must return a `CheckResult` with accurate point values

## Pull Request Process

1. Fork the repo
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `pytest` passes and `ruff check` is clean
5. Submit PR against `main`

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
