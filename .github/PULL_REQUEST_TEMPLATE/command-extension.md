## Command extension contribution

<!-- Use this template for a declarative command extension or coverage update. -->

### What changed

<!-- Name the extension and the command families covered. Link a proposal only when the boundary is new or materially changes authority. -->

### Fast validation

```sh
uv run --no-sync hol-guard extensions handoff --repo . \
  --source contributions/command-sources/command.<name>.json \
  --fixture tests/fixtures/command-source-<slug>.v1.json
```

<!-- Include any focused fixture or native checks you ran. Do not hand-edit generated projections: use the Builder apply/prepare flow. -->

### Checklist

- [ ] The source, fixture, and external trust-map entry use the same extension ID.
- [ ] Generated descriptor, native program, catalog, and package resources are included.
- [ ] Cases cover the intended destructive operations and their safe counterparts.
- [ ] Optional public listing data contains no private email, secrets, or inferred claim authority.
- [ ] For a personal-fork PR, I enabled **Allow edits from maintainers** if I want Gitar to commit mechanical repairs. If GitHub says this also grants access to secrets, I left it disabled and will apply suggestions myself.

Gitar automatically applies mechanical PR and CI repairs. Use `gitar auto-apply:off` in a PR comment if you want analysis without branch changes.
