# Foundation ownership-gate backport validation

The six-file backport makes the held config reader's I/O categories explicit by
lexical function and primitive operation, keeps nested/sibling operations from
inheriting those exceptions, and records synchronous posture reachability in the
ownership inventory. The architecture contract also names `config_source_io.py`.
This commit changes ownership tooling/tests/contracts, not product source or the
security disposition.

The final correction makes `FunctionRecordLike.path`, `.qualname` and `.node`
read-only protocol properties so frozen `FunctionRecord` values satisfy the
interface. Four unused private AST visitor parameters are named `node`, matching
`ast.NodeVisitor`. The gate's resolver algorithm and visitor bodies are unchanged
by this correction. An AST comparison, after excluding the protocol declaration
and normalizing those four unused labels, matches the complete earlier module.

All attempts are retained in [manifest.json](manifest.json):

- [Initial Ruff attempt](initial-ruff/manifest.json): failed; original output retained.
- [Lint-corrected attempt](lint-corrected/manifest.json): Ruff/format passed; the two
  gate test files report **26 passed in 73.73 seconds**, while the original driver
  records **81.412 seconds** for the complete test command. Focused basedpyright
  then failed with five errors and 16 warnings. Those failure bytes are unchanged.
- [Type-corrected attempt](type-corrected/manifest.json): Ruff and format passed;
  basedpyright analyzed the three scripts with **zero errors and 16 unchanged
  warnings**, exit 0. These are not zero-warning results.
- [Annotation/interface equivalence](type-corrected/annotation-equivalence.json)
  binds the previously tested and corrected resolver hashes. The passing
  resolver/gate tests were not repeated for the final type-only correction.

Each new validation command acquires the common measurement lock independently
with `flock --close -w180`; reported elapsed times include lock acquisition where
explicitly labeled. The original manifests keep their original time fields.
No benchmark, build, product mutation, release qualification or runtime activation
is implied by this evidence. Every copied raw file is byte-counted and SHA256
bound in the top-level manifest.
