# Sonar CI performance

## Measured baseline

Main commit `f49e3b581c87498387e5afc46523c7c291b581db`, CI run
[36909771491](https://github.com/hashgraph-online/hol-guard/actions/runs/36909771491),
[Sonar job 110529238010](https://github.com/hashgraph-online/hol-guard/actions/runs/36909771491/job/110529238010),
October 1, 2026:

| Phase | Observed duration |
| --- | ---: |
| Sonar job | 9m 03s |
| Waiting for all 128 coverage producers, after setup | 170s |
| Downloading coverage artifacts | 4s |
| Combining coverage and generating XML | 20s |
| Scanner invocation | 285s |
| Python sensor, within scanner invocation | 128s |
| Python security sensor, within scanner invocation | 24s |
| Quality gate polling | 12s |

The Python analyzer reported 0 cached files out of 2,526 on this main-branch
analysis. Analyzer downloads and the scanner CLI were already cached. Rust's
pre-analysis Clippy check took 8.6 seconds, so repeating scanner installation
or removing Clippy would not address the dominant delay.

The engine reported a 3,998 MB allocated heap and only 318 MB free before
reading its Python architecture graph. That is evidence of substantial heap
use, not a measurement of garbage-collection pause time.

## Resource tuning

The dedicated Sonar job remains on the existing `ubuntu-latest` public runner.
Only its analysis step receives `SONAR_SCANNER_JAVA_OPTS=-Xmx6g` and
`-Dsonar.python.analysis.threads=4`. The heap setting provides headroom for the
analysis graph; the thread setting uses the four logical CPUs on this runner
without overcommitting them. This is not a purchase or larger-runner change.

These are documented scanner controls:

- [SonarScanner CLI memory settings](https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/scanners/sonarscanner)
- [Python parallel analysis](https://docs.sonarsource.com/sonarqube-server/2026.1/analyzing-source-code/languages/python)
- [Public GitHub runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

The source/test scope, existing duplication exclusions, Clippy invocation,
coverage shard count, current-attempt artifact matching, token boundaries,
quality gate, and required checks are unchanged. The speed change does not
skip a sensor or suppress a finding.

## Validation and interpretation

Compare complete runs on similar revisions and the same event type. A PR
analysis can reuse target-branch analysis data; a shorter PR scan alone does
not establish a faster full main-branch analysis. Record scanner and Python
sensor time separately from coverage waiting, runner queueing, and total CI
completion. Check that the quality gate and all other required workflows pass.

The target remains approximately four minutes. This change is a resource-tuning
experiment against the measured scan bottleneck, not a claim that the target
has been achieved. A full main-branch run is required to measure its effect on
that baseline. Remove the analysis step's `with.args` and
`SONAR_SCANNER_JAVA_OPTS` setting to roll back; retain the same analysis scope
and quality gates during rollback.

## Native qualification bottleneck

The same baseline's [Native wheel CI run 36909770847](https://github.com/hashgraph-online/hol-guard/actions/runs/36909770847)
took 8m54s from creation to final workflow update. Its slowest
[Intel regression shard, job 110529879594](https://github.com/hashgraph-online/hol-guard/actions/runs/36909770847/job/110529879594),
spent 210.5 seconds installing dependencies, including 204 seconds building
`cryptography==50.0.0` from source. Installing the prepared packages then took
271 milliseconds. The log records a cache miss followed by `save-cache is false`.

Native regression shard zero now saves the full dependency cache for each
platform. Other regression shards and macOS proof jobs restore without writing.
All use the same `native-ci-v1` suffix, root `pyproject.toml` and `uv.lock` inputs,
and unpruned cache setting. Setup-uv still separates OS, architecture and Python
version in its key. The dedicated suffix prevents unrelated jobs with smaller
dependency sets from becoming the immutable cache's first writer.

The cache contains dependency wheels, not a reusable qualification result.
Every job still installs the wheel built by its own workflow run, uses frozen
dependencies, executes the unchanged manifest shard, and reconciles all reports.
No test, platform, source compiler, proof, deadline or required job was removed.
GitHub scopes PR-written caches to that PR; main cannot restore a PR's cache.

A cold cache still requires the source build. Savings must be measured on a
subsequent run that logs a successful restore and no cryptography rebuild. A
lockfile change creates a new cache key and may require another cold build.

## First successful Sonar observation

On PR head `adbd873cc2929b737f93726aa4fc2beb99a8d6b7`,
[CI run 36918391670](https://github.com/hashgraph-online/hol-guard/actions/runs/36918391670)
passed. Sonar job 110557995232 took 370 seconds, including 173 seconds waiting
for coverage, 106 seconds in the scanner and 13 seconds in its quality gate.
The Python sensor took 36.567 seconds. The log confirms the 6 GiB JVM setting.
These PR measurements are not a controlled comparison with the full main scan.
The native-cache change was not yet present in that revision.
