# Repository review guidance

## File-size review policy

The repository's 500-line maintainability guideline applies to source-code files, not declarative data files.

Do not raise line-count, file-length, "file too large", or split-the-file findings for `*.json` files. This includes command-extension sources under `contributions/command-sources/`, portable fixtures under `tests/fixtures/`, generated JSON, schemas, manifests, contracts, and other declarative JSON.

Large JSON files are expected when they enumerate command matchers, fixtures, schemas, or generated data. Review them for correctness, security, schema validity, duplication, malformed data, trust-boundary mistakes, and unnecessary generated churn, but never require splitting or shrinking them solely because of line count or file size.

Continue applying the 500-line guideline to source code where appropriate.
