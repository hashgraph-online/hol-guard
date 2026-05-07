# HOL Guard Release Checklist

Complete every item below before tagging a new release that touches any Guard integration path.

---

## 1 — Pre-Release Tests

- [ ] `pytest tests/ -q` — all tests pass
- [ ] `ruff check src/` — zero violations
- [ ] `ruff format --check src/` — zero reformats needed

---

## 2 — Smoke Evidence (T608)

For each harness whose integration path changed in this release, complete the corresponding
section of `docs/guard/smoke-tests.md` and attach evidence (log excerpt or screenshot) to
the release notes.

| Harness | Changed? | Evidence Required |
|---------|----------|-------------------|
| codex | ☐ | T588–T590 |
| codex-app | ☐ | T591 |
| claude-code | ☐ | T592–T594 |
| opencode | ☐ | T595–T596 |
| copilot | ☐ | T597–T598 |
| copilot-ide | ☐ | T599 |
| gemini | ☐ | T600 |
| cursor | ☐ | T601 |
| hermes | ☐ | T602 |
| openclaw | ☐ | T603 |

---

## 3 — Harness Contract Accuracy

- [ ] Run `hol-guard doctor --harnesses --json` and verify each contract reflects current
  installation paths and event surfaces.
- [ ] Update `docs/guard/harness-support.md` if any contract changed.

---

## 4 — Threat Intel Bundle Freshness

- [ ] Confirm the production threat intel bundle `expires_at` is at least 24 hours in
  the future at release time.
- [ ] Confirm the bundle version is strictly greater than the previous release bundle.

---

## 5 — Changelog and Version Bump

- [ ] Update `CHANGELOG.md` with a human-readable summary of changes.
- [ ] Bump the package version in `pyproject.toml`.
- [ ] Tag the release commit with `v<version>`.

---

## 6 — Post-Release Verification

- [ ] Install the released package in a clean virtual environment:
  `pip install hol-guard==<version>`
- [ ] Run `hol-guard doctor` and confirm no errors.
- [ ] Run `hol-guard bootstrap codex` (or affected harness) and confirm the hook activates.
