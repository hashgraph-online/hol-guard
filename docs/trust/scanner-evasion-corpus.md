# Scanner evasion corpus

Static scanners for agent skills and plugins can be evaded. Public research in 2026 bypassed every skill scanner it tested with encoding, split commands and payloads kept outside the scanned files ([CSA research note, June 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/)). This corpus records which of those techniques the plugin scanner in this repository catches today and which it misses.

## How it works

- Every case is a synthetic, inert skill in [`tests/fixtures/scanner-evasion-corpus/corpus.json`](../../tests/fixtures/scanner-evasion-corpus/corpus.json). Hosts use reserved names (`.example`, `.invalid`). Nothing is executed.
- [`tests/test_scanner_evasion_corpus.py`](../../tests/test_scanner_evasion_corpus.py) writes each case to a temporary directory, scans it with the Cisco skill scanner off, and checks the outcome against the corpus. It runs in CI with the rest of the test suite.
- A case counts as **detected** when the scan reports a medium, high or critical finding on one of its files. Benign controls must stay **clean**.
- A **missed** case is a known gap, recorded on purpose. When the scanner learns to catch one, the test fails until the corpus and this page are updated together.

## Results

11 evasion cases (one is a plain control): 4 detected, 7 missed. The benign control stays clean.

| Case | Class | Outcome | Technique |
| --- | --- | --- | --- |
| `control-plain-exfil` | control | detected | A plain shell command that reads `.env` and posts it to a remote host. |
| `split-across-lines` | split stream | detected | The same command split over continued lines in a fenced block. |
| `zero-width-joined-command` | unicode | missed | A zero-width space inside each command and file name. A shell would reject the text as written, but a model reading it sees the plain command and may retype it without the hidden characters. |
| `html-comment-hidden` | hidden content | detected | The command sits in an HTML comment that renderers hide. |
| `remote-fetched-payload` | remote payload | detected | The instruction pipes a downloaded script into a shell, so the payload is never in the repository. |
| `base64-decoded-command` | encoding | missed | The command is base64-encoded and decoded into a shell. |
| `ansi-c-escaped-command` | encoding | missed | The command name is written as ANSI-C hex escapes. |
| `split-variable-command` | split stream | missed | The command and file name are assembled from shell variables. |
| `payload-in-bundled-script` | indirection | missed | The skill runs a bundled shell script that holds the command. |
| `python-exec-base64` | indirection | missed | A bundled Python script executes a base64-encoded payload. |
| `natural-language-exfil` | natural language | missed | Plain prose asks the agent to copy `.env` into its reply, with no command. |
| `benign-security-advice` | benign control | clean | Advice that names the risky patterns without asking for them. |

For `remote-fetched-payload`, the scanner flags the download-and-run instruction. It cannot see what the downloaded script would do.

## What this means

A scan result reports what the scanner's checks found in the files it read. It does not show that a skill or plugin is free of risk. Runtime protection, such as HOL Guard's approval gates, covers behaviour that static scanning cannot see.
