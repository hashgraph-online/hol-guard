# CIGAR preview 3.61 (2026-11-19)

Results for the 3.61.0a1 and 3.61.0a2 preview builds. The setup, seeds and arms are described in [cigar-long-task.md](cigar-long-task.md); earlier results are in [cigar-a121-preview.md](cigar-a121-preview.md).

Full Guard against no Guard. The no-Guard runs are the ones from the 3.60.0a121 preview: one for the 32 seeds (benchmark seeds 116–131 and held-out seeds 200–215), and two for the 16 random seeds (581 to 9298). Totals are raw sums over every session, with no seed left out.

| harness | build | set | no Guard | full Guard | cost saved | tokens saved | passed (Guard / no Guard) |
|---|---|---|---|---|---|---|---|
| Claude Code | 3.61.0a1 | 32 seeds | $15.15, 99.6M | $7.88, 44.3M | 48.0% | 55.5% | 30 / 31 |
| Claude Code | 3.61.0a1 | 16 random seeds | $7.75–7.83, 51.4–51.9M | $3.00, 15.5M | 61.3–61.7% | 69.9–70.2% | 15 / 14 and 13 |
| Oh My Pi (CIGAR) | 3.61.0a1 | 32 seeds | $0.73, 43.4M | $0.30, 12.5M | 59.3% | 71.3% | 29 / 32 |
| Oh My Pi (CIGAR) | 3.61.0a1 | 16 random seeds | $0.34–0.45, 19.7–24.9M | $0.12, 5.1M | 64.9–73.6% | 74.1–79.5% | 13 / 14 |
| Oh My Pi (CIGAR) | 3.61.0a2 | 32 seeds | $0.73, 43.4M | $0.41, 15.2M | 44.3% | 65.0% | 30 / 32 |
| Oh My Pi (CIGAR) | 3.61.0a2 | 16 random seeds | $0.34–0.45, 19.7–24.9M | $0.13, 5.5M | 61.9–71.3% | 72.2–78.1% | 14 / 14 |

Codex on 3.60.0a122, 16 random seeds with its no-Guard run in the same batch: $0.29, 16.4M without Guard, $0.09, 4.3M with it; 67.8% cost and 74.2% tokens saved; 14 passed against 15.

## Oh My Pi edit headers with extra text

3.61.0a2 adds the fix in #8074. Oh My Pi accepts an edit header wrapped in brackets or a stray `*** Begin Patch` line and still opens the right file; Guard now reads such a header the same way, so the edit is allowed instead of held for review. A path with `..` is never treated as a missing file.

On the 16 random seeds one more session passed (14, was 13) and the run held 4 calls. On the 32 seeds 30 sessions passed (was 29) and the run held 13 calls:

| held call | count |
|---|---|
| `eval` scripts that write files | 4 |
| edits whose body is not a patch (leaked reasoning or a tool error in place of the patch) | 4 |
| tool output that looked like a secret (`password` tests, a lexer file) | 3 |
| a doctest check through `python -c` that Guard read as using the network | 1 |
| `git checkout --` to restore files | 1 |

One session explains the lower 32-seed cost saving. In seed 205 the agent was renaming a method; Guard held its `eval` script for review, the agent then emptied the files itself, and its `git checkout --` restore was held as well. The step ran until the one-hour limit and cost $0.15, three times the no-Guard session. Without that seed, the 32-seed saving is 62.6% cost and 72.0% tokens.

The four edits that are not a patch are the next fix: like the edits in #8018, they can never apply, so Guard should block them at once with a reason instead of holding them for review.
