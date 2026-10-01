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
