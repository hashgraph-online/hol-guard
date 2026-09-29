## Command extension contribution

<!-- Use this template for a declarative command extension or coverage update. -->

### What changed

<!-- Name the extension and the command families covered. This PR is the scope-review surface; no separate issue is required. -->

### Upstream source and version

<!-- Link the authoritative upstream repository/docs and pin the version, tag, or commit used for this boundary. -->

### Capability boundary

<!-- List the state-changing/destructive operations that need review and the safe/read-only counterparts that must stay automatic. -->

### Fast validation

```sh
uv run --no-sync hol-guard extensions handoff --repo . \
  --source contributions/command-sources/command.<name>.json \
  --fixture tests/fixtures/command-source-<slug>.v1.json
```

<!-- Include any focused fixture or native checks you ran. Do not hand-edit generated projections: use the Builder apply/prepare flow. -->

### Checklist

- [ ] The source, fixture, and external trust-map entry use the same extension ID.
- [ ] The canonical source, portable fixture, and external trust entry are included. Generated projections may be synchronized by the Builder, Gitar, or a maintainer after scope review.
- [ ] Cases cover the intended destructive operations and their safe counterparts.
- [ ] Optional public listing data contains no private email, secrets, or inferred claim authority.
- [ ] For a personal-fork PR, I enabled **Allow edits from maintainers** if I want Gitar to commit mechanical repairs. If GitHub says this also grants access to secrets, I left it disabled and will apply suggestions myself.

Gitar automatically applies mechanical PR and CI repairs. Use `gitar auto-apply:off` in a PR comment if you want analysis without branch changes.
