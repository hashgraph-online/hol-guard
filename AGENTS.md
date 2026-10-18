# Repository review guidance

## File-size review policy

The repository's 500-line maintainability guideline applies to source-code files, not declarative data files.

Do not raise line-count, file-length, "file too large", or split-the-file findings for `*.json` files. This includes command-extension sources under `contributions/command-sources/`, portable fixtures under `tests/fixtures/`, generated JSON, schemas, manifests, contracts, and other declarative JSON.

Large JSON files are expected when they enumerate command matchers, fixtures, schemas, or generated data. Review them for correctness, security, schema validity, duplication, malformed data, trust-boundary mistakes, and unnecessary generated churn, but never require splitting or shrinking them solely because of line count or file size.

Continue applying the 500-line guideline to source code where appropriate.

## Approval invariant

Every command Guard pauses for review must offer Allow once and Always allow, and every part of Guard must honor an approval until the user removes it or the command's hash changes. Read `docs/guard/approval-invariant.md` before changing approval tokens, retry bindings, scope contracts, saved decisions or the review card. A change that makes a review once-only, or drops Always allow for a class of commands, breaks this invariant. Findings about what an approval token binds, and how to bind it more tightly without removing a choice, are in scope.
