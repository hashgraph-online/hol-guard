# Remaining reviewed command matcher operations

The database and specialized modules implement the final eight reviewed matcher
families through typed, immutable configuration. `DatabaseMatcher::from_config`
and `SpecializedMatcher::from_config` deserialize a config once; their
`match_segments_with_deadline` methods return ordered segment indexes or an
explicit error. Unknown operations, unknown config fields, uncertain commands,
resource limits, and expired caller deadlines cannot become empty evidence.

| Operation | Python reference | Preserved behavior |
| --- | --- | --- |
| `argument-command.v1` | `ArgumentCommandMatcher` | Minimum argument position, command abbreviation, required payload, Python whitespace |
| `command-sequence.v1` | `CommandSequenceMatcher` | Unique command prefixes, command arities, case-sensitive short options, raw forbidden flag scan |
| `leading-subcommand.v1` | `LeadingSubcommandMatcher` | Leading and interleaved option values, exit flags before `--`, required flag evidence |
| `php-artisan-script.v1` | `PhpArtisanScriptMatcher` | PHP interpreter options, script basename, Artisan option values and flag assignments |
| `zero-operand-flags.v1` | `_ZeroOperandFlagMatcher` | Leading flag parsing, required flags, absence of operands |
| `curl-elasticsearch-delete.v1` | `CurlElasticsearchDeleteMatcher` | Last request method, `--next` operation boundaries, all 140 long and 26 short value options, service target recognition |
| `repo2nb-expansion.v1` | `Repo2nbUnresolvedExpansionMatcher` | Launcher-specific prefixes, wrapper option consumption, remaining-argument expansion markers |
| `reviewed-literal.v1` | `ReviewedLiteralCommandMatcher` | Bounded literal ASCII grammar, exact canonical invocation, parser provenance and structural checks |

The semantic profile is **CPython 3.12 / Unicode 15.0.0**. PHP and repo2nb configurations admit ASCII comparison strings; opaque Unicode
operands preserve CPython comparison results using the two non-ASCII lowercase
mappings that can introduce ASCII (`İ` and `K`). The generator checks that
assumption exhaustively against Unicode 15.0.0. Non-ASCII configurations in
these grammars reject admission. Other case conversions outside the implemented
ASCII grammar and non-ASCII URL authorities requiring NFKC validation return
explicit unsupported errors. Opaque Unicode payloads and URL paths remain
supported where normalization is unnecessary. The
caller must preserve uncertainty from these errors; it must not convert an error
into a successful match or a no-match result.

Reviewed literals use an internal `#[serde(skip)] exact_raw_text` provenance bit
provided by the canonical parser. The bit establishes that the parser's trimmed
raw text equals normalized text; Python also strips outer command whitespace.
Deserialized models cannot assert this proof. Native exact parsing excludes
redirections and embedded commands. Literal matching additionally requires the
expected normalized spelling, a single matching segment, and no wrappers,
environment overrides, or pipeline membership. This evidence belongs only to its
owning rule; it is not a global command approval.

Both entry points enforce the existing canonical command limits: 32,768 bytes,
128 segments, and 2,048 tokens. They preserve the caller's `Instant` deadline,
checking before evaluation, between segments and iterative grammar/operation
steps, and before returning evidence. No matcher starts a replacement deadline.

`remaining-matchers.v1.json` contains 721 canonical reference cases. Seven cases
record Python results alongside the required native capability error. The corpus
includes option-value confusion, unknown options, ambiguous abbreviations,
consumed help flags, method overrides, mixed curl operations, malformed URLs,
IPv6, wrapper arguments, Unicode boundaries, and ordered multi-segment evidence.
Forty-six additional parser cases exercise the PHP/repo2nb classifiers on 23
Unicode-bearing commands. Rust tests additionally cover actual parser integration, invalid configuration,
expired deadlines, command limits, and forged literal provenance. The fixture
generator verifies the exact curl option tables as well as all reference cases.

Regenerate or check from the repository root with the locked Python 3.12 environment:

```sh
PYTHONPATH=src python rust/crates/guard-command/testdata/generate_remaining_matcher_fixtures.py --check
```

The Rust modules are registered by the native program integration. Their tests
run with `cargo test -p guard-command --lib` from `rust/` after that registration.
