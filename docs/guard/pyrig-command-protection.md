# pyrig command protection

`command.pyrig` is an External, opt-in extension for the standard
[pyrig CLI](https://github.com/Winipedia/pyrig). Its permissions have a review
floor when enabled; disabling a permission blocks the matching operation.
The extension does not activate itself or grant allow authority.

## Reviewed operations

| Command | Permission suffix | Effects |
| --- | --- | --- |
| `pyrig init` | `initialize` | Removes removable managed configuration, synchronizes files, initializes Git, stages files, and creates an initial commit. |
| `pyrig sync [files...]` | `synchronize` | Creates or updates managed configuration and mirrored tests; imports source modules during mirrored-test discovery. |
| `pyrig scratch` | `execute-scratch` | Executes project-root `.scratch.py` as Python code. |
| `pyrig mk cmd <name> [--shared]` | `scaffold-command` | Appends source to a project or shared CLI module. |
| `pyrig mk inits` | `create-init-files` | Creates missing source/test `__init__.py` files. |
| `pyrig mk subcls [module class]` | `scaffold-subclass` | Imports a selected module and writes subclass source. |
| `pyrig rm pyc` | `remove-bytecode` | Recursively removes source/test `__pycache__` directories. |
| `pyrig rm pyrig` | `remove-integration` | Removes managed hooks and development dependencies; generated files remain. |

Permission IDs are `command.pyrig.permission.<suffix>`. The reviewed behavior
is based on pyrig 18.99.1 at commit
`1cc37371a4089f2dbe59c6acdb1b29ff12734aa7`. Project overrides and installed
plugins may alter behavior; these rules do not inspect or certify that code.

## Invocation coverage and limits

The extension matches `pyrig`, `pyrig.exe`, and `pyrig.cmd`, including
path-qualified entrypoints and leading CLI options. It also matches
`uv run pyrig ...`, with supported launcher flags and value options such as
`--no-sync` and `--project`. Other launchers, arbitrary project-named CLIs,
and custom/plugin operations are not covered by these operation rules.
Independent native protections still apply; the fixture's `env pyrig scratch`
case demonstrates an independent block, not a pyrig rule match.

Operation `--help` narrows only that operation's matching segments.
`--help` after `--` is an operand, not a help exemption. Root/group help and
the inherited `version` command do not match operation rules. None of these
cases grants global allow: unknown-executable and independent policy floors
can still require review. There is no invented dry-run exemption.

## Contributor validation

The [canonical source](../../contributions/command-sources/command.pyrig.json),
[portable fixture](../../tests/fixtures/command-source-pyrig.v1.json), and
[external binding](../../contracts/extensions/trust/command.pyrig.v1.json)
are authored inputs. The fixture embeds the exact source in its build envelope.
After changing the source, synchronize that embedded copy before testing.

Use an admitted packaged `guard-command-source` compiler with matching
contracts, or the repository's native compiler:

```sh
"$COMPILER" validate < <(jq '.build' tests/fixtures/command-source-pyrig.v1.json)
"$COMPILER" test < tests/fixtures/command-source-pyrig.v1.json
```

These Bash commands evaluate synthetic command text without executing pyrig.
Require a successful native result and `target_commands_executed: 0`; JSON
syntax checks alone do not validate matching behavior. The fixture uses an
addition envelope with `base: "packaged"`; after the extension is embedded in
a release, follow the
[integrated fixture workflow](extension-builder/VALIDATION.md#validate-an-integrated-command-fixture)
instead. Shared descriptors, catalogs, and program resources remain generated,
maintainer-published projections.
