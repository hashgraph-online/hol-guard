## Cloud action pack contribution

<!-- Use this template for a new or changed pack in contributions/cloud-actions/. Guide: docs/guard/extensions/cloud-action-pack-contributing.md -->

### Provider and source

<!-- Name the provider and link the documentation or OpenAPI/MCP description you used, pinned to a version or date. -->

### Actions and risk

<!-- List the actions added or changed, their class, effect and reversibility, and the risky families the fixtures cover (bulk, permanent delete, external sharing, many recipients, money). Explain any class or reversibility lowered from the generated draft. -->

### Widening

<!-- For a change to an existing pack, paste the widening codes from the `diff` op and justify each. Write "new pack" otherwise. -->

### CLI check

<!-- Run these with the released CLI (`pipx install hol-guard`). Remove local paths and real identifiers. -->

- HOL Guard version (`hol-guard --version`):
- `hol-guard extensions validate --cloud <pack>` result:
- `hol-guard command explain --cloud` for one risky action and its safe counterpart:

### Checklist

- [ ] Hosts, scopes and argument bounds match the provider's documentation for the pinned version.
- [ ] Every action has at least one safe and one risky fixture, and all fixtures use synthetic data.
- [ ] `provider.publisher.verified` is `false`; maintainers set it.
- [ ] I understand that merging does not turn the pack on for hosted use.
