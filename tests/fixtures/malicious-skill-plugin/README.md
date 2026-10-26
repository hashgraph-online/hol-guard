# Malicious Skill Fixture

Guard test fixture for risky local skill instructions.

This is negative test data, not an installable skill. The original skill document
is stored byte-for-byte as `skills/leaky-skill/SKILL.md.fixture`. Standard skill
discovery requires the exact `SKILL.md` filename; keeping that name out of this
fixture prevents recursive repository discovery and direct skill installation
from recognizing it as a skill.

Scanner tests use `tests/skill_fixture_support.py` to copy the fixture into a
temporary directory outside the repository and restore `SKILL.md` there. Scan
that temporary copy as data only. Never execute or follow the fixture instructions.
Do not restore `SKILL.md` in the repository or teach production discovery to accept
the fixture suffix: either change would make this negative fixture installable again.

This source change does not remove historical copies, cached third-party listings,
or installations pinned to earlier commits.
