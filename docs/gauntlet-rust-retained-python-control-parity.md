# Python differential over retained six-role Rust staging controls

On 2026-10-21, a read-only diagnostic ran the pinned Python
`verify_control` and `evaluate_control` functions over the same six retained
v5 records opened by the Rust suite. The controller source was installed at
`/opt/hol-gauntlet/controller-2932d5a8ce25ac91` on the Linux ARM VM; the
fixed isolated interpreter was
`/opt/hol-benchmark-controller-20261013/.venv/bin/python`. The diagnostic
script is [python_retained_v5_controls_20261021.py](../ci/gauntlet-rs/proofs/python_retained_v5_controls_20261021.py), SHA-256
`13954c515cd545f4bc028d895e04444c76a2a0a7d320f77146a7c8d0071e420e`.
Its local, transferred and Root-owned VM bytes matched that hash.

The script first checked the exact immutable v5 host manifest digest
`c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551`,
build `b70d59e2681c4a3f`, source
`76c31929833b5571d25a56d9783e24a0997d5422`, config
`8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492`,
six role names, each retained raw-control SHA-256, and each controller key
against its durable prelaunch host pin. It derived the expected runtime tuple
from the signed success record in the same way as the Python staging adapter.
That tuple is **not** an independently reviewed source or installer anchor.

The exact read-only VM command was:

```text
/opt/homebrew/bin/limactl shell hol-beta-bootstrap-20261016-004 -- sudo -n /opt/hol-benchmark-controller-20261013/.venv/bin/python -I -B /root/gauntlet-python-retained-v5-13954c51.py
```

It exited zero and reported `passed` for success, input-binding, injection,
boundary, timeout and cancel. The Python score path separately recomputed the
injection forbidden-command and MCP disposition checks. The output declared
zero model requests/tokens and `execution_eligible:false`; no provider was
started. The script wrote no files and did not import the candidate package
into Root. A local AST syntax parse passed before transfer.

This is a differential diagnostic for the retained controls: it shows they
meet the current Python `verify_control`/`evaluate_control` contract under the
same-record expected tuple. It does not provide a Rust verdict, independent
kernel/SDK/Native effect scoring, a conformance package, reviewed source or
installer pins, installed controls, model inference or PR-gate readiness. The
Rust suite's terminals remain `invalid-evidence`.
