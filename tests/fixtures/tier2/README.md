# Tier 2 package evaluation fixtures

These files are inert parser and policy test inputs. The tests do not install or
execute the packages declared in them.

The Composer manifests and lockfiles are stored as `composer.json.fixture` and
`composer.lock.fixture` so dependency inventory tools do not mistake their sample
packages for HOL Guard dependencies. The fixture lab restores the canonical names
only inside its temporary test workspace before invoking the real parsers and
package evaluator. The stored package names and versions are intentional test
data and must not be upgraded as application dependencies.

The `safe` and `vulnerable` directory names describe the expected result against
the mocked advisory bundle in `tests/test_guard_tier2_labs_phase13.py`. They do not
claim that those package versions are free of advisories in a live vulnerability
database. Both positive and negative detection cases must remain covered.
