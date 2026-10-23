# Collector transport for the proposed product VM

Status: authenticated transport and actual two-VM controls pass. No product-session
operations, real SDK conformance, protected workflow support or qualification are
enabled by this transport. Production CI/CD remains unchanged.

## Boundary and protocol

`vm_bridge_frames.py` authenticates bounded JSON records between two trusted
collectors outside all agent/product namespaces. Use a fresh32byte random key and
session UUID for every connection. Convey the key only through an already
authenticated private management channel; the first private bootstrap does not
authenticate an arbitrary public connection. No listener or credential-file loader
is provided. Keys must never enter actor inputs, inherited descriptors, logs,
environment, arguments or public artifacts. The local controls generated keys in
memory and used existing authenticated Lima management stdio without reading any
existing private-key file.

Each HMAC-SHA256 covers a domain-separated canonical message with schema, session,
both collector roles, both boot identities, direction, exact sequence and body.
The receiver checks the authenticator with `hmac.compare_digest`, following the
[Python HMAC guidance](https://docs.python.org/3/library/hmac.html). Replay, ordering,
reflection, stale boot/session, unknown fields, duplicate/nonfinite JSON and budget
violations invalidate the connection. Failed writes reserve their sequence and
cannot be retried as if execution were known not to have occurred. A new transport
is not permission to retry an uncertain product operation or model episode.

Limits are12MiB per frame,10,000frames and256MiB per direction, with shared JSON
depth/node limits. Caller configuration can only lower aggregate limits. The
controls use64frames/1MiB per direction. A four-byte network-order length is checked
before body allocation/read. `vm_bridge_io.py` uses nonblocking dedicated pipes or
private Unix stream sockets and monotonic deadlines; regular files, datagrams and
network sockets are refused. See the [Python descriptor API](https://docs.python.org/3/library/os.html#os.set_blocking).

`vm_bridge_rpc.py` binds every reply to its exact request UUID and operation. Only
callbacks in a fixed trusted registry can run. Requests cannot select a shell,
module, executable or arbitrary file reader through this layer. Unknown operations
have no callback effects. Trusted callback failures return authenticated errors,
not successful results. Callbacks must independently enforce resource, argument,
ownership and cleanup rules; transport authentication does not supply them.

Product bytes must be separately bounded and treated as opaque data before a
collector places them in an authenticated response. Never connect actor stdout
directly to the management transport or let actor data become a bootstrap/request.
The collectors retain authority outside the actor's UID/PID/mount/FD visibility.
This authentication is transport custody, not independent scorer review, trusted
base eligibility or product intervention credit.

## Actual controls

`vm_bridge_control.py` is a Root-only test endpoint with exactly `observe`, `echo`
and `close`. It never imports Guard/task code or executes a caller-selected command.
Its bootstrap pins both real kernel boot IDs and all five trusted source files.
Root output ancestry is exclusive/canonical. Public records contain only a one-way
random-key fingerprint, never key material. No persistent credential was created.

A host relay connected the actual controller VM and product VM over their private
management stdio. Their identical user-mode NAT addresses were not used as a
cross-VM endpoint. Five authenticated RPCs completed: observe, opaque echo,
unknown-exec refusal, observe, close. A shell-like payload and nested fake request
remained data; the predeclared sentinel stayed absent. The relay also enforces
1MiB per guest stream,1MiB queues,64KiB stderr and a30second wall bound.

A separate fresh session flipped one MAC character. The product collector rejected
it before every callback, received/sent counters stayed zero, and both endpoints
failed closed. Raw failed endpoint records and exit1 remain retained as the expected
negative outcome. All four original worker PIDs are absent and both management
clients are terminal. No model, SDK or product was exercised in these controls.

Public export manifest SHA256 values:

- Controller: `63a87c8c711e6ed4eeba7e9644a853eac4925ca07ad3218278ea4a9451ea3dba`.
- Product collector: `653a6b25878ed3f348e72f2f4120dd35011f8fb6f5854506b16d98724816723f`.
- Bootstrap source manifest: `2b95ac3347dd5a0e468daded2a096f9aa9d18326c7f6b8fb17467640d2733eff`.

Workspace evidence is under `../local-evidence-20261014/vm-bridge-*`. The inert
five-check audit SHA256 is
`ff3e93ca68c0af89f61b1969c00bddfa5d93750832cc16f72b96ba3945046d9f`.
It checks pinned artifacts, current source, realms/counters, exact callback effects,
fresh sessions and terminal observations without importing captured code.
Focused regression:194passed,2Root-only skips; both exact Root cases pass separately.
Twenty-one new pipe/codec/RPC cases cover authentication and context mutation,
replay, frame budgets, EOF, write backpressure, malformed data, error outcomes,
descriptor types, exact response binding and opaque injection.

## Next integration

Implement a persistent product cell and trusted narrow session/process/task
operations; add a Root-only controller-side broker for the existing SDK supervisor.
No operation may execute product code as Root or choose arbitrary host commands.
Every product invocation needs measured UID/capability/FD drop, readonly inputs,
exact task idmapping, applying LSM and seccomp, shared resource scope, cancellation
and terminal process/mount/session cleanup. Namespace entry alone does not inherit
another process's syscall/LSM restrictions. Bind observations to boot realm and
actual process start identity, never synthetic Podman fields.

Preserve native receipt/double admission/overlay/Post semantics. Finish written
equivalence and actual native/SDK conformance before freezing protected workflows.
Resolve private-loopback app utility explicitly, retaining external egress denial.
Then integrate the configured runner and execute the fresh paired matrix under the
same whole-goal provider counter. User independent review remains pending the
eventual completed immutable package; existing trust governance remains unchanged.
