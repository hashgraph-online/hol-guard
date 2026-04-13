# Contributing to AI Plugin Scanner

Thanks for contributing to `ai-plugin-scanner`.

This repository ships:

- `hol-guard` for local harness protection
- `plugin-scanner` for CI and maintainer checks across supported AI plugin ecosystems
- `codex-plugin-scanner` as a compatibility package alias

## Before You Start

- Search existing [issues](https://github.com/hashgraph-online/ai-plugin-scanner/issues) before opening a new report.
- Use [discussions](https://github.com/hashgraph-online/ai-plugin-scanner/discussions) for design questions, proposals, and broader feedback.
- Open a pull request for code or documentation changes. PRs against `main` are the normal contribution path.

## Development Setup

```bash
git clone https://github.com/hashgraph-online/ai-plugin-scanner.git
cd ai-plugin-scanner
uv sync --extra dev
```

If you prefer a virtualenv-first workflow, the repository can also be installed in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Validation Requirements

All non-trivial changes should include or update automated tests.

Run the standard validation commands before opening or updating a pull request:

```bash
# If using uv:
uv run python -m ruff check src tests
uv run python -m ruff format --check src tests
uv run pytest --tb=short

# If using pip (with the virtualenv activated):
python -m ruff check src tests
python -m ruff format --check src tests
pytest --tb=short
```

If you changed packaging or release logic, also verify the build:

```bash
# If using uv:
uv run python -m build

# If using pip:
python -m build
```

## Contribution Process

1. Fork the repository.
2. Create a feature branch from `main`.
3. Make the smallest coherent change that fixes the issue or adds the feature.
4. Add or update tests for new functionality and changed behavior.
5. Run the validation commands above.
6. Open a pull request against `main` with a clear summary of what changed and why.

## Contribution Expectations

- Python code should remain compatible with the versions declared in `pyproject.toml`.
- Keep command examples and package names aligned with the current product names: `hol-guard`, `plugin-scanner`, and `ai-plugin-scanner`.
- Update user-facing docs when the CLI surface, GitHub Action contract, trust scoring behavior, or published workflows change.
- Do not commit secrets, credentials, or local environment files.

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
