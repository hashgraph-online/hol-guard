# Bind a hosted action

A command source or MCP server contribution is local-only until a sibling
`guard.cloud-action-binding-contribution.v1` document names the hosted actions
it covers. Each binding ties one `actionId` to a `permissionId` the command
source declares, or a `tool` the MCP server declares, and adds only what can
make hosted use stricter:

- `effect`: `read`, `write`, `destructive` or `admin`.
- `resource` (optional): the argument that names the affected resource.
- `requiredCapabilities`: restrictions the hosting service must enforce.
  `cloud-executable` bindings need at least `egress-pinned` and
  `bounded-output`.
- `cloudSupport`: `portable-policy` when hosted policy evaluates the action and
  nothing runs, or `cloud-executable` when a reviewed remote MCP server may run
  it. Command sources and locally launched MCP servers are never
  `cloud-executable`.

Bindings carry no defaults, decisions, code, includes, endpoints or
credentials. A remote binding uses the endpoint from the server contribution
it extends.

[`examples/cloud-binding-build.json`](examples/cloud-binding-build.json) binds
the synthetic command source and a fictional remote MCP server. Build the
compiler as described in
[Compile source with Rust](README.md#compile-source-with-rust), export the
trust map and packaged build, add them to the example, then validate it
offline:

```sh
rust/target/release/guard-command-source export-trust > contracts/extensions/build-trust-class-map.v1.json
rust/target/release/guard-command-source export-built > packaged-build.json
jq --slurpfile trust contracts/extensions/build-trust-class-map.v1.json \
  --slurpfile built packaged-build.json \
  '.trust=$trust[0] | .validation_base={catalog:$built[0].catalog,programs:[]}' \
  docs/guard/extension-builder/examples/cloud-binding-build.json > cloud-binding-build.json
rust/target/release/guard-command-source validate < cloud-binding-build.json
rust/target/release/guard-command-source compile < cloud-binding-build.json > cloud-binding-compiled.json
```

`validate` reports `cloud_actions` and `cloud_binding_digest`. `compile` adds a
`cloud_bindings` artifact beside the program; the program itself is the same
with or without bindings. A binding must extend a source in the same request,
at most once per extension, and an action ID may appear only once. Validation
needs no account, network access or provider credentials.

[`examples/cloud-binding-rejected.json`](examples/cloud-binding-rejected.json)
lists bindings that must fail: a default decision, a permission from another
extension, an unknown effect or portability label, an include, a callback, an
endpoint override, a hosted action without pinned egress, a malformed resource
argument, the catch-all tool, a command run in the cloud and a repeated action
ID. Each case changes the example above and names the expected `code` and
`pointer`. The pointer locates the rejected binding in the request
(`/cloud_bindings/1/bindings/0`); the error never repeats its values. Check
every case against your compiler. A rejection exits 2, so the loop checks the
status and the JSON separately:

```sh
jq -c '.cases[]' docs/guard/extension-builder/examples/cloud-binding-rejected.json |
  while read -r case; do
    name=$(jq -r .name <<<"$case")
    jq --argjson case "$case" 'reduce $case.set[] as $s (.; setpath($s.path; $s.value))' \
      cloud-binding-build.json > case-build.json
    status=0
    result=$(rust/target/release/guard-command-source validate < case-build.json) || status=$?
    if [ "$status" -ne 2 ]; then
      echo "unexpected status $status: $name"
    elif ! jq --argjson case "$case" -e '.code == $case.code and .pointer == $case.pointer' \
      >/dev/null <<<"$result"; then
      echo "unexpected result: $name"
    fi
  done
```

`compile-stream` reports the same location as `/records/N/bindings/M`, where
`N` counts command, MCP and then binding records.

## When to add a binding

Most contributions need none. Without a binding a command source or MCP server
stays local-only: it validates, compiles, applies and hands off exactly as
before, and the generated review kit does not mention hosted actions. Add a
binding only when a hosted service should recognize a specific action of an
extension you already contribute. Command sources and locally launched MCP
servers can only reach `portable-policy`; the compiler rejects
`cloud-executable` for them with `cloud_binding_local_only_target`.

## What `compile` produces

The `cloud_bindings` artifact records, for each action, the target it
exercises (the command permission, or the MCP tool and, for a remote server,
its endpoint),
its effect, resource, required capabilities and support label, plus a
`binding_digest` over that meaning. The artifact as a whole carries the
`program_digest` of the program compiled in the same request, the
`compiler_version` and an `artifact_digest`. Each digest covers something
different:

- `binding_digest` covers what one action means: its extension, target,
  effect, resource, required capabilities and support label. Changing the
  binding changes it. Changing a source rule or tool state does not.
- `program_digest` covers the compiled program. Changing the source changes it.
  Changing a binding does not.
- `artifact_digest` covers the whole artifact, including `program_digest` and
  every `binding_digest`, so it changes when either the source or a binding
  changes.

Check a reviewed binding against `artifact_digest`; a binding cannot then
quietly follow a later version of the source.

## Review a binding

Reviewers check that:

- every action names a permission or tool declared by the source in the same
  request;
- the effect is not understated: an action that deletes or overwrites data is
  `destructive`, not `write`;
- the resource argument is the one that names the affected resource;
- `cloud-executable` appears only on a reviewed remote MCP server and keeps
  `egress-pinned` and `bounded-output`;
- examples and fixtures use synthetic names only, with no real accounts,
  workspaces, hostnames or credentials;
- every case in the rejected example still fails with its expected code.

## What a merged binding changes today

Nothing in local protection: decisions and the compiled program are the same
with or without it. Release builds do not yet package binding artifacts, so
merging a binding does not make any action available in Guard Cloud. Making a
hosted action available is a separate, reviewed step; a contribution never
turns one on.
