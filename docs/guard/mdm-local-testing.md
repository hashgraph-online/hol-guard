# Local MDM testing

HOL Guard provides a portable, vendor-neutral MDM conformance lab. It runs the real lifecycle,
integrity, health lease, managed-policy, enterprise-network, observer, and remediation test suites
inside any Python or Docker environment and emits canonical JSON evidence.

```bash
uv run --extra dev --frozen python scripts/mdm/run-local-lab.py --json
```

Use `--suite <name>` to run one or more focused suites. The report contains commands, bounded
summaries, output digests, covered capabilities, and an explicit native-certification section.
Portable results never claim Apple or Windows certification.

The `MDM local conformance lab` workflow runs the same evidence generator on free public-repository
Ubuntu, macOS, and Windows GitHub runners and retains each JSON report. `--output <path>` writes the
canonical report for any attached self-hosted native runner.

The lab intentionally leaves these gates unevaluated until a native host is attached: Apple APNs
enrollment and supervision, signing/notarization, Windows CSP enrollment and SYSTEM context,
Authenticode/WDAC, and real-vendor command delivery. A macOS host and a Windows evaluation VM can
run the same command for fast native feedback. Final certification still requires retained evidence
from the supported MDM product.

For an optional open-source Apple control plane, NanoMDM can deliver protocol commands after APNs
and device enrollment are configured. Self-hosted Fleet can also act as a control plane, but some
MDM capabilities require a commercial license and Windows enrollment can require Microsoft Entra.
Neither dependency is required for the portable lab.
