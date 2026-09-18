# Emergency Git inspection contract

The mechanical emergency classifier accepts only the exact parsed argument vectors `git version` and `git --version` for Git. Extra arguments, global options, wrappers, case-folded command names, and paths merely ending in `git` do not receive this exemption. Quoting or whitespace that produces the same two-token vector remains equivalent.

This intentionally narrows the previous Git emergency exemption. Repository inspection commands can execute locally configured helpers without an explicit execution flag:

| Command in the local witness | Configuration or attributes that executed the benign helper |
| --- | --- |
| `git diff` | `diff.external` |
| `git diff`, `git show`, `git log -p` | `.gitattributes` selecting a configured `diff.<driver>.textconv` |
| `git status` | `core.fsmonitor` |
| `git log` with terminal stdout | `core.pager` |

All six regression witnesses executed a helper that only wrote a marker inside the temporary fixture and returned harmless output. Against the previous classifier, all six were incorrectly granted the emergency exemption. The retained exact version queries did not execute the configured helpers, including with `pager.version=true` and terminal stdout.

The fallback has no authenticated snapshot of Git configuration, attributes, repository state, or helper identity. It therefore cannot prove that a repository read is execution-free. Flags such as `--no-ext-diff` and `--no-textconv` do not widen this fallback contract. Configuration verification belongs in an authoritative evaluator with the appropriate input and identity contract. The emergency check does not read Git configuration, traverse repositories, or spawn Git. Its version classification describes the built-in Git argument form; executable installation and command resolution remain existing host/runtime responsibilities.

The affected classifier is `src/codex_plugin_scanner/guard/daemon/hook_availability_floor.py::hook_action_is_emergency_safe`, reached through the native policy preparation barrier, bounded CLI emergency failure handling, and the Cline/Cursor fallback adapters. The normal `availability_harness_response` retains its current ordinary-unavailability warn/allow behavior. Watch and explicit session-continuation handling remain unchanged. A prepared native policy is admitted as before, and completed native Allow, Review, and Block results remain authoritative.

For a bounded CLI failure that requires pausing, `git status` now follows that existing pause path instead of receiving an emergency exemption. For an ordinary unavailable response, the same command still receives the established warn/allow outcome. This is a narrow security correction to classification, not a change to the availability policy.

The production module remains under its existing `native_edge_launcher` ownership entry in `hook-data-plane-ownership.v2.json`. The change adds no production I/O or imports and reduces the module from 497 to 453 lines. Dedicated tests cover exact argv, configuration-driven execution, extra-option/path/wrapper bypass attempts, ready-policy admission, ordinary unavailable responses, and Watch/session continuity. The helper-execution witnesses run on POSIX with local Git; Windows skips those process/terminal witnesses while retaining the platform-independent classification and response tests.

The focused classifier, availability, bounded CLI, Watch, native-response consistency, daemon continuity, and Cline transport suites passed all 179 tests. Ruff and formatting passed. Scoped BasedPyright reported zero errors and 30 existing/private/unknown typing warnings. The authority ownership gate passed. This branch's frozen integration baseline reports ten unclassified I/O operations in command-control binding and native runtime identity helpers; root integration separately addresses those classifications in `6e598ee02`. The Git correction adds no source I/O.
